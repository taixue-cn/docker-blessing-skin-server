<?php

namespace Taixue\Oidc\Controllers;

use App\Events;
use App\Models\User;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Taixue\Oidc\EndpointFailure;
use Taixue\Oidc\LinkConsistency;
use Taixue\Oidc\OidcClient;
use Taixue\Oidc\OidcAudit;
use Taixue\Oidc\OidcFlowException;
use Taixue\Oidc\OidcSession;
use Taixue\Oidc\ProvisioningNotifier;
use Taixue\Oidc\RolloutPolicy;
use Taixue\Oidc\SafeRedirect;
use Taixue\Oidc\SkinAccountProvisioner;
use Taixue\Oidc\UnifiedIdentityBoundary;

class AuthController
{
    public function redirectToProvider(OidcClient $client)
    {
        return $client->start();
    }

    public function callback(
        OidcClient $client,
        Dispatcher $events,
        RolloutPolicy $rollout,
        OidcAudit $audit,
        ProvisioningNotifier $provisioning,
        SkinAccountProvisioner $accounts
    )
    {
        $subject = null;
        $uid = null;
        try {
            $result = $client->complete();
            $flow = $result['flow'];
            $claims = $result['claims'];
            $subject = $claims['sub'];
            $intent = (string) ($flow['intent'] ?? 'login');
            if ($intent !== 'login') {
                throw new OidcFlowException(
                    'unsupported_intent',
                    '账号关联和身份资料统一由太学账号系统管理。'
                );
            }
            if (!$rollout->allowsClaims($claims, $intent)) {
                $audit->record(
                    $intent === 'link' ? 'LINK' : 'LOGIN',
                    'REJECTED',
                    null,
                    $subject,
                    ['reason' => 'rollout_denied']
                );
                return $this->error(
                    $rollout->denialMessage(),
                    $audit->requestId()
                );
            }

            $claimedUid = $this->claimedBsUid($claims);
            $link = DB::table('taixue_oidc_links')->where('subject', $claims['sub'])->first();
            if ($link && $claimedUid) {
                LinkConsistency::assertSubjectOwner($link, $claimedUid);
            }
            if (!$link && $claimedUid) {
                $link = $this->linkTrustedBsUid($claimedUid, $claims['sub'], $audit);
            }
            if (!$link && filter_var(env('TAIXUE_OIDC_AUTO_REGISTER', false), FILTER_VALIDATE_BOOL)) {
                $link = $accounts->provision(
                    $claims['sub'],
                    $this->claimedPlayerName($claims),
                    ($claims['email_verified'] ?? false) ? ($claims['email'] ?? null) : null,
                    $claims['display_name'] ?? $claims['name'] ?? null,
                    $events,
                    $audit
                );
            }
            if (!$link) {
                $audit->record('LOGIN', 'REJECTED', null, $subject, ['reason' => 'account_unlinked']);
                return response()->view('Taixue\Oidc::unlinked', [
                    'request_id' => $audit->requestId(),
                    'account_settings_url' => rtrim(
                        (string) env('TAIXUE_OIDC_ISSUER', 'https://auth.taixue.cc'),
                        '/'
                    ).'/settings',
                ], 403)->header('X-Request-ID', $audit->requestId());
            }

            $uid = (int) $link->uid;
            $user = User::find($link->uid);
            if (!$user) {
                throw new OidcFlowException(
                    'local_account_missing',
                    '绑定的皮肤站账号不存在，请联系管理员修复。'
                );
            }
            $playerName = $this->claimedPlayerName($claims);
            $players = $user->players()->limit(2)->get();
            if ($players->count() !== 1 || strcasecmp((string) $players->first()->name, $playerName) !== 0) {
                throw new OidcFlowException(
                    'skin_player_cardinality_invalid',
                    '皮肤站账号必须恰好关联一个同名玩家，请联系管理员修复。'
                );
            }
            if ((bool) ($link->provisioned ?? false)) {
                // Retry on every provisioned login to close the crash window
                // between the two databases. The signed receipt is idempotent.
                $provisioning->notify(
                    $claims['sub'],
                    $uid,
                    $playerName,
                    $audit->requestId()
                );
            }

            $events->dispatch('auth.login.ready', [$user]);
            // OIDC does not expose Blessing Skin's local "remember me" choice.
            // Never mint a long-lived recaller cookie implicitly: the local
            // browser session remains bounded by the configured session TTL
            // while back-channel logout is still a separate rollout gate.
            Auth::login($user, false);
            request()->session()->regenerate();
            OidcSession::begin($claims, $uid);
            try {
                $events->dispatch('auth.login.succeeded', [$user]);
                event(new Events\UserLoggedIn($user));
                $audit->record('LOGIN', 'SUCCEEDED', $uid, $subject, ['source' => 'taixue_oidc']);
            } catch (\Throwable $loginError) {
                // Do not leave a browser authenticated when the success event
                // or its mandatory audit record could not be completed.
                Auth::logout();
                request()->session()->invalidate();
                request()->session()->regenerateToken();
                throw $loginError;
            }

            return redirect($this->safeRedirectTarget(
                session()->pull('last_requested_path')
            ));
        } catch (\Throwable $e) {
            if (!$e instanceof OidcFlowException) {
                report($e);
            }

            $reason = $e instanceof OidcFlowException
                ? $e->reason()
                : 'internal_error';
            try {
                $audit->record(
                    'CALLBACK',
                    EndpointFailure::outcome($e),
                    $uid,
                    $subject,
                    ['reason' => $reason]
                );
            } catch (\Throwable $auditError) {
                report($auditError);
            }
            $audit->warn('CALLBACK', $reason);

            $message = $e instanceof OidcFlowException
                ? $e->getMessage()
                : '太学账号登录暂时不可用，请稍后重试。';

            return $this->error($message, $audit->requestId(), EndpointFailure::status($e));
        }
    }

    private function linkTrustedBsUid(int $uid, string $subject, OidcAudit $audit)
    {
        return DB::transaction(function () use ($uid, $subject, $audit) {
            $user = User::find($uid);
            if (!$user) {
                throw new OidcFlowException('local_account_missing', '太学账号绑定的皮肤站账号不存在，请联系管理员修复。');
            }

            $bySubject = DB::table('taixue_oidc_links')->where('subject', $subject)->lockForUpdate()->first();
            if ($bySubject) {
                LinkConsistency::assertSubjectOwner($bySubject, $uid);
                return $bySubject;
            }
            $byUser = DB::table('taixue_oidc_links')->where('uid', $uid)->lockForUpdate()->first();
            if ($byUser && $byUser->subject !== $subject) {
                throw new OidcFlowException('local_account_already_linked', '皮肤站账号已绑定其他太学账号，请联系管理员处理冲突。');
            }
            if (!$byUser) {
                DB::table('taixue_oidc_links')->insert([
                    'uid' => $uid,
                    'subject' => $subject,
                    'provisioned' => false,
                    'created_at' => now(),
                    'updated_at' => now(),
                ]);
                $audit->record('LINK', 'SUCCEEDED', $uid, $subject, [
                    'source' => 'signed_bs_uid',
                ]);
            }

            return (object) ['uid' => $uid, 'subject' => $subject];
        });
    }

    private function claimedBsUid(array $claims): ?int
    {
        if (!array_key_exists('bs_uid', $claims)) {
            return null;
        }

        $value = filter_var($claims['bs_uid'], FILTER_VALIDATE_INT, [
            'options' => ['min_range' => 1, 'max_range' => 4294967295],
        ]);
        if ($value === false) {
            throw new OidcFlowException('signed_uid_invalid', '太学账号返回了无效的皮肤站账号标识。');
        }

        return $value;
    }

    private function claimedPlayerName(array $claims): string
    {
        $name = $claims['name'] ?? null;
        if (!is_string($name) || trim($name) === '') {
            throw new OidcFlowException('player_name_claim_missing', '太学账号没有返回有效的玩家名。');
        }

        return trim($name);
    }

    private function error(string $message, string $requestId, int $status = 400)
    {
        // Automatic entry must never turn a recoverable migration conflict
        // into a redirect loop. During gray rollout, expose an explicit local
        // recovery URL that carries the middleware's explicit bypass marker.
        // Unified-only mode removes that second authentication source.
        $navigation = UnifiedIdentityBoundary::recoveryNavigation(
            UnifiedIdentityBoundary::enabled(),
            url('/')
        );

        return response()->view('Taixue\Oidc::error', [
            'message' => $message,
            'request_id' => $requestId,
            'retry_url' => $navigation['retry_url'],
            'local_recovery_url' => $navigation['local_recovery_url'],
        ], $status)->header('X-Request-ID', $requestId);
    }

    private function safeRedirectTarget($candidate): string
    {
        return SafeRedirect::resolve($candidate, url('/'), url('/user'));
    }
}
