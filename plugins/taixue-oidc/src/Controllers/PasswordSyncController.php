<?php

namespace Taixue\Oidc\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Taixue\Oidc\EndpointFailure;
use Taixue\Oidc\OidcAudit;
use Taixue\Oidc\OidcFlowException;

class PasswordSyncController
{
    public function __invoke(Request $request, OidcAudit $audit)
    {
        $subject = null;
        $uid = null;
        try {
            $subject = trim((string) $request->input('subject', ''));
            $uid = (int) $request->input('uid', 0);
            $eventId = (int) $request->input('event_id', 0);
            $passwordHash = (string) $request->input('password_hash', '');
            $requestId = trim((string) $request->header('X-Request-ID', ''));
            $timestamp = trim((string) $request->header('X-Taixue-Timestamp', ''));
            $signature = trim((string) $request->header('X-Taixue-Signature', ''));
            $secret = (string) env('TAIXUE_OIDC_PASSWORD_SYNC_SECRET', '');
            $skew = max(30, (int) env('TAIXUE_OIDC_CREATE_CLOCK_SKEW_SECONDS', 300));

            if (!preg_match('/^[0-9]{1,20}$/', $subject) || $uid <= 0 || $eventId <= 0 ||
                !preg_match('/^\$SHA\$[a-f0-9]{16}\$[a-f0-9]{64}$/', $passwordHash) ||
                !preg_match('/^[A-Za-z0-9._:-]{8,64}$/', $requestId) ||
                !preg_match('/^[0-9]{10}$/', $timestamp) || strlen($secret) < 32) {
                throw new OidcFlowException('password_sync_request_invalid', '密码同步请求无效。');
            }
            $timestampValue = (int) $timestamp;
            if (abs(time() - $timestampValue) > $skew) {
                throw new OidcFlowException('password_sync_request_expired', '密码同步请求已经过期。');
            }
            $hashDigest = hash('sha256', $passwordHash);
            $expected = 'v1='.hash_hmac(
                'sha256',
                self::payload($subject, $uid, $eventId, $hashDigest, $requestId, $timestampValue),
                $secret
            );
            if (!hash_equals($expected, $signature)) {
                throw new OidcFlowException('password_sync_signature_invalid', '密码同步签名无效。');
            }

            $payloadHash = hash('sha256', "v1-password-request\n{$subject}\n{$uid}\n{$eventId}\n{$hashDigest}");
            DB::transaction(function () use ($subject, $uid, $eventId, $passwordHash, $requestId, $payloadHash) {
                $link = DB::table('taixue_oidc_links')
                    ->where('subject', $subject)->lockForUpdate()->first();
                if (!$link || (int) $link->uid !== $uid) {
                    throw new OidcFlowException('password_sync_binding_mismatch', '太学账号与皮肤站账号绑定不匹配。');
                }
                $existing = DB::table('taixue_oidc_password_sync_requests')
                    ->where('request_id', $requestId)->lockForUpdate()->first();
                if ($existing && (!hash_equals((string) $existing->payload_hash, $payloadHash) ||
                    (string) $existing->subject !== $subject || (int) $existing->uid !== $uid)) {
                    throw new OidcFlowException('password_sync_request_replayed', '密码同步请求标识已被其他请求使用。');
                }
                if (!$existing) {
                    DB::table('taixue_oidc_password_sync_requests')->insert([
                        'request_id' => $requestId,
                        'payload_hash' => $payloadHash,
                        'subject' => $subject,
                        'uid' => $uid,
                        'created_at' => now(),
                        'updated_at' => now(),
                    ]);
                }
                $version = DB::table('taixue_oidc_password_versions')
                    ->where('subject', $subject)->lockForUpdate()->first();
                if ($version && ((int) $version->uid !== $uid ||
                    ((int) $version->event_id === $eventId &&
                    !hash_equals((string) $version->payload_hash, $payloadHash)))) {
                    throw new OidcFlowException('password_sync_version_conflict', '密码同步版本归属发生冲突。');
                }
                if ($version && (int) $version->event_id > $eventId) {
                    return;
                }
                if (!$version || (int) $version->event_id < $eventId) {
                    // MySQL reports zero affected rows when the verifier is
                    // already identical. That is an idempotent success, not a
                    // missing user. Lock and test existence separately so a
                    // same-password change and the operational canary can
                    // still advance the durable version record.
                    $user = User::where('uid', $uid)->lockForUpdate()->first();
                    if (!$user) {
                        throw new OidcFlowException('password_sync_user_missing', '绑定的皮肤站账号不存在。');
                    }
                    if (!hash_equals((string) $user->password, $passwordHash)) {
                        $user->password = $passwordHash;
                        $user->saveOrFail();
                    }
                    DB::table('taixue_oidc_password_versions')->updateOrInsert(
                        ['subject' => $subject],
                        ['uid' => $uid, 'event_id' => $eventId, 'payload_hash' => $payloadHash,
                            'created_at' => $version ? $version->created_at : now(), 'updated_at' => now()]
                    );
                }
            });
            $audit->record('PASSWORD_SYNC', 'SUCCEEDED', $uid, $subject, [
                'source' => 'user_service_worker',
                'request_id' => $requestId,
            ]);
            return response()->json(['ok' => true]);
        } catch (\Throwable $error) {
            if (!$error instanceof OidcFlowException) { report($error); }
            $reason = $error instanceof OidcFlowException ? $error->reason() : 'internal_error';
            try { $audit->record('PASSWORD_SYNC', EndpointFailure::outcome($error), $uid, $subject, ['reason' => $reason]); } catch (\Throwable $auditError) { report($auditError); }
            $status = $reason === 'password_sync_signature_invalid' ? 401 :
                ($reason === 'password_sync_request_expired' ? 408 :
                (in_array($reason, ['password_sync_binding_mismatch', 'password_sync_request_replayed', 'password_sync_user_missing', 'password_sync_version_conflict'], true) ? 409 : EndpointFailure::status($error)));
            return response()->json(['ok' => false, 'error' => $reason], $status);
        }
    }

    public static function payload(string $subject, int $uid, int $eventId, string $hashDigest, string $requestId, int $timestamp): string
    {
        return "v1-password\n{$timestamp}\n{$requestId}\n{$subject}\n{$uid}\n{$eventId}\n{$hashDigest}";
    }
}
