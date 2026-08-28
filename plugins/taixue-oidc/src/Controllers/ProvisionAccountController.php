<?php

namespace Taixue\Oidc\Controllers;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Taixue\Oidc\EndpointFailure;
use Taixue\Oidc\OidcAudit;
use Taixue\Oidc\OidcFlowException;
use Taixue\Oidc\ProvisioningNotifier;
use Taixue\Oidc\SkinAccountProvisioner;

class ProvisionAccountController
{
    public function __invoke(
        Request $request,
        Dispatcher $events,
        OidcAudit $audit,
        SkinAccountProvisioner $accounts,
        ProvisioningNotifier $notifier
    ) {
        $subject = null;
        $uid = null;
        try {
            if (!filter_var(env('TAIXUE_OIDC_CREATE_ENABLED', false), FILTER_VALIDATE_BOOL)) {
                throw new OidcFlowException(
                    'create_endpoint_disabled',
                    '皮肤站账号自动创建尚未启用。'
                );
            }
            $subject = trim((string) $request->input('subject', ''));
            $playerName = trim((string) $request->input('player_name', ''));
            $requestId = trim((string) $request->header('X-Request-ID', ''));
            $timestamp = trim((string) $request->header('X-Taixue-Timestamp', ''));
            $signature = trim((string) $request->header('X-Taixue-Signature', ''));
            $secret = (string) env('TAIXUE_OIDC_CREATE_SECRET', '');
            $skew = max(30, (int) env('TAIXUE_OIDC_CREATE_CLOCK_SKEW_SECONDS', 300));

            if (!preg_match('/^[0-9]{1,20}$/', $subject) ||
                !preg_match('/^[A-Za-z0-9_]{3,16}$/', $playerName) ||
                !preg_match('/^[A-Za-z0-9._:-]{8,64}$/', $requestId) ||
                !preg_match('/^[0-9]{10}$/', $timestamp) || strlen($secret) < 32) {
                throw new OidcFlowException('create_request_invalid', '皮肤站账号创建请求无效。');
            }
            $timestampValue = (int) $timestamp;
            if (abs(time() - $timestampValue) > $skew) {
                throw new OidcFlowException('create_request_expired', '皮肤站账号创建请求已经过期。');
            }
            $payload = self::payload($subject, $playerName, $requestId, $timestampValue);
            $expected = 'v1='.hash_hmac('sha256', $payload, $secret);
            if (!hash_equals($expected, $signature)) {
                throw new OidcFlowException('create_signature_invalid', '皮肤站账号创建请求签名无效。');
            }

            // Timestamp authenticates freshness but is intentionally excluded
            // from the replay identity so a durable retry can use a fresh
            // timestamp with the same request ID and semantic payload.
            $payloadHash = hash('sha256', self::semanticPayload($subject, $playerName));
            DB::transaction(function () use ($requestId, $subject, $payloadHash) {
                $existing = DB::table('taixue_oidc_provision_requests')
                    ->where('request_id', $requestId)->lockForUpdate()->first();
                if ($existing && (!hash_equals((string) $existing->payload_hash, $payloadHash) ||
                    (string) $existing->subject !== $subject)) {
                    throw new OidcFlowException(
                        'create_request_replayed',
                        '皮肤站账号创建请求标识已被其他请求使用。'
                    );
                }
                if (!$existing) {
                    DB::table('taixue_oidc_provision_requests')->insert([
                        'request_id' => $requestId,
                        'payload_hash' => $payloadHash,
                        'subject' => $subject,
                        'uid' => null,
                        'created_at' => now(),
                        'updated_at' => now(),
                    ]);
                }
            });

            $link = $accounts->provision(
                $subject, $playerName, null, $playerName, $events, $audit
            );
            $uid = (int) $link->uid;
            DB::transaction(function () use ($requestId, $uid) {
                $stored = DB::table('taixue_oidc_provision_requests')
                    ->where('request_id', $requestId)->lockForUpdate()->first();
                if (!$stored || ($stored->uid !== null && (int) $stored->uid !== $uid)) {
                    throw new OidcFlowException('create_result_changed', '皮肤站账号创建结果发生冲突。');
                }
                DB::table('taixue_oidc_provision_requests')->where('request_id', $requestId)
                    ->update(['uid' => $uid, 'updated_at' => now()]);
            });

            // Reply only after the user service has durably accepted the
            // signed receipt. Retrying this endpoint is safe after either
            // response is lost.
            $notifier->notify($subject, $uid, $playerName, $requestId);
            $audit->record('PROVISION', 'SUCCEEDED', $uid, $subject, [
                'source' => 'user_service_worker',
            ]);
            return response()->json(['ok' => true, 'uid' => $uid]);
        } catch (\Throwable $error) {
            if (!$error instanceof OidcFlowException) {
                report($error);
            }
            $reason = $error instanceof OidcFlowException ? $error->reason() : 'internal_error';
            try {
                $audit->record('PROVISION', EndpointFailure::outcome($error), $uid, $subject, [
                    'reason' => $reason,
                ]);
            } catch (\Throwable $auditError) {
                report($auditError);
            }
            $audit->warn('PROVISION', $reason);
            return response()->json(
                ['ok' => false, 'error' => $reason],
                self::failureStatus($reason, $error)
            );
        }
    }

    public static function payload(
        string $subject,
        string $playerName,
        string $requestId,
        int $timestamp
    ): string {
        return "v1-create\n{$timestamp}\n{$requestId}\n{$subject}\n".
            strtolower(trim($playerName));
    }

    public static function semanticPayload(string $subject, string $playerName): string
    {
        return "v1-create-request\n{$subject}\n".strtolower(trim($playerName));
    }

    private static function failureStatus(string $reason, \Throwable $error): int
    {
        if ($reason === 'create_signature_invalid') {
            return 401;
        }
        if ($reason === 'create_request_expired') {
            return 408;
        }
        if (in_array($reason, [
            'create_request_replayed',
            'create_result_changed',
            'email_collision',
            'local_account_missing',
            'player_name_collision',
            'player_name_invalid',
            'provisioning_rejected',
            'skin_player_cardinality_invalid',
        ], true)) {
            return 409;
        }
        return EndpointFailure::status($error);
    }
}
