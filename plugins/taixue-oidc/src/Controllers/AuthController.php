<?php

namespace Taixue\Oidc\Controllers;

use App\Events;
use App\Models\User;
use Blessing\Filter;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Taixue\Oidc\LinkConsistency;
use Taixue\Oidc\FreshAuthGrant;
use Taixue\Oidc\OidcClient;
use Taixue\Oidc\OidcAudit;
use Taixue\Oidc\OidcFlowException;
use Taixue\Oidc\RolloutPolicy;
use Vectorface\Whip\Whip;

class AuthController
{
    public function redirectToProvider(OidcClient $client)
    {
        return $client->start('login');
    }

    public function callback(
        OidcClient $client,
        Dispatcher $events,
        RolloutPolicy $rollout,
        OidcAudit $audit
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
            if (!$rollout->allowsIntent($claims['sub'], $intent)) {
                $audit->record('LOGIN', 'REJECTED', null, $subject, ['reason' => 'rollout_denied']);
                return $this->error(
                    '太学账号登录正在小范围灰度，此账号暂未开放。原皮肤站登录仍可正常使用。',
                    $audit->requestId()
                );
            }

            if ($intent === 'link') {
                return $this->completeLink($flow, $claims, $audit);
            }
            if ($intent === 'unlink') {
                return $this->completeUnlink($flow, $claims, $audit);
            }
            if ($intent === 'local_password') {
                return $this->completeLocalPasswordAuthorization($flow, $claims, $audit);
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
                $link = $this->register($claims, $events, $audit);
            }
            if (!$link) {
                $audit->record('LOGIN', 'REJECTED', null, $subject, ['reason' => 'account_unlinked']);
                return response()->view('Taixue\Oidc::unlinked', [
                    'request_id' => $audit->requestId(),
                ], 403)->header('X-Request-ID', $audit->requestId());
            }

            $uid = (int) $link->uid;
            $user = User::find($link->uid);
            if (!$user) {
                throw new \RuntimeException('绑定的皮肤站账号不存在，请联系管理员修复。');
            }

            $events->dispatch('auth.login.ready', [$user]);
            Auth::login($user, true);
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

            return redirect(session()->pull('last_requested_path', url('/user')));
        } catch (\Throwable $e) {
            if (!$e instanceof \RuntimeException) {
                report($e);
            }

            $reason = $e instanceof OidcFlowException
                ? $e->reason()
                : ($e instanceof \RuntimeException ? 'account_state_rejected' : 'internal_error');
            try {
                $audit->record('CALLBACK', 'FAILED', $uid, $subject, ['reason' => $reason]);
            } catch (\Throwable $auditError) {
                report($auditError);
            }
            $audit->warn('CALLBACK', $reason);

            $message = $e instanceof \RuntimeException
                ? $e->getMessage()
                : '太学账号登录暂时不可用，请稍后重试。';

            return $this->error($message, $audit->requestId());
        }
    }

    private function completeLink(array $flow, array $claims, OidcAudit $audit)
    {
        $user = Auth::user();
        if (!$user || (int) ($flow['uid'] ?? 0) !== (int) $user->uid) {
            throw new \RuntimeException('皮肤站登录状态已变化，请重新发起绑定。');
        }
        $claimedUid = $this->claimedBsUid($claims);
        if ($claimedUid && $claimedUid !== (int) $user->uid) {
            throw new \RuntimeException('太学账号已绑定另一个皮肤站账号，请先在统一账号中心处理冲突。');
        }

        DB::transaction(function () use ($user, $claims, $audit) {
            $bySubject = DB::table('taixue_oidc_links')->where('subject', $claims['sub'])->lockForUpdate()->first();
            if ($bySubject && (int) $bySubject->uid !== (int) $user->uid) {
                throw new \RuntimeException('这个太学账号已经绑定了其他皮肤站账号。');
            }
            $byUser = DB::table('taixue_oidc_links')->where('uid', $user->uid)->lockForUpdate()->first();
            if ($byUser && $byUser->subject !== $claims['sub']) {
                throw new \RuntimeException('当前皮肤站账号已经绑定了其他太学账号。');
            }
            if (!$byUser) {
                DB::table('taixue_oidc_links')->insert([
                    'uid' => $user->uid,
                    'subject' => $claims['sub'],
                    'provisioned' => false,
                    'created_at' => now(),
                    'updated_at' => now(),
                ]);
            }
            $audit->record('LINK', 'SUCCEEDED', (int) $user->uid, $claims['sub'], [
                'source' => 'authenticated_accounts',
            ]);
        });

        return redirect('/user/taixue-account')->with('success', '太学账号绑定成功。');
    }

    private function linkTrustedBsUid(int $uid, string $subject, OidcAudit $audit)
    {
        return DB::transaction(function () use ($uid, $subject, $audit) {
            $user = User::find($uid);
            if (!$user) {
                throw new \RuntimeException('太学账号绑定的皮肤站账号不存在，请联系管理员修复。');
            }

            $bySubject = DB::table('taixue_oidc_links')->where('subject', $subject)->lockForUpdate()->first();
            if ($bySubject) {
                LinkConsistency::assertSubjectOwner($bySubject, $uid);
                return $bySubject;
            }
            $byUser = DB::table('taixue_oidc_links')->where('uid', $uid)->lockForUpdate()->first();
            if ($byUser && $byUser->subject !== $subject) {
                throw new \RuntimeException('皮肤站账号已绑定其他太学账号，请联系管理员处理冲突。');
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
            throw new \RuntimeException('太学账号返回了无效的皮肤站账号标识。');
        }

        return $value;
    }

    private function register(array $claims, Dispatcher $events, OidcAudit $audit)
    {
        return DB::transaction(function () use ($claims, $events, $audit) {
            $existing = DB::table('taixue_oidc_links')->where('subject', $claims['sub'])->lockForUpdate()->first();
            if ($existing) {
                return $existing;
            }

            $email = ($claims['email_verified'] ?? false) ? ($claims['email'] ?? null) : null;
            if ($email && User::where('email', $email)->exists()) {
                throw new \RuntimeException('同邮箱的皮肤站账号已经存在。请先用原方式登录，再到账号页面完成绑定。');
            }

            $user = new User();
            $user->email = $email ?: 'oidc-'.hash('sha256', $claims['sub']).'@users.invalid';
            $user->nickname = Str::limit($claims['display_name'] ?? $claims['name'] ?? '太学用户', 255, '');
            $user->score = option('user_initial_score');
            $user->avatar = 0;
            $password = app('cipher')->hash(Str::random(64), config('secure.salt'));
            $user->password = resolve(Filter::class)->apply('user_password', $password);
            $ip = (new Whip())->getValidIpAddress();
            $user->ip = resolve(Filter::class)->apply('client_ip', $ip);
            $user->permission = User::NORMAL;
            $user->register_at = now();
            $user->last_sign_at = now()->subDay();
            $registration = ['email' => $user->email, 'nickname' => $user->nickname];
            $events->dispatch('auth.registration.attempt', [$registration]);
            $events->dispatch('auth.registration.ready', [$registration]);
            $user->save();
            $events->dispatch('auth.registration.completed', [$user]);
            event(new Events\UserRegistered($user));

            DB::table('taixue_oidc_links')->insert([
                'uid' => $user->uid,
                'subject' => $claims['sub'],
                'provisioned' => true,
                'created_at' => now(),
                'updated_at' => now(),
            ]);
            $audit->record('REGISTER', 'SUCCEEDED', (int) $user->uid, $claims['sub'], [
                'source' => 'taixue_oidc',
            ]);

            return (object) ['uid' => $user->uid, 'subject' => $claims['sub']];
        });
    }

    private function completeUnlink(array $flow, array $claims, OidcAudit $audit)
    {
        $user = Auth::user();
        if (!$user || (int) ($flow['uid'] ?? 0) !== (int) $user->uid) {
            throw new \RuntimeException('皮肤站登录状态已变化，请重新发起解绑。');
        }
        $claimedUid = $this->claimedBsUid($claims);
        if ($claimedUid && $claimedUid !== (int) $user->uid) {
            throw new \RuntimeException('当前太学账号与待解绑的皮肤站账号不一致。');
        }

        DB::transaction(function () use ($user, $claims, $audit) {
            $link = DB::table('taixue_oidc_links')
                ->where('uid', $user->uid)
                ->lockForUpdate()
                ->first();
            if (!$link || $link->subject !== $claims['sub']) {
                throw new \RuntimeException('账号绑定已经变化，请刷新后重试。');
            }
            if ($link->provisioned) {
                throw new \RuntimeException('此账号尚未设置可用的本地密码，暂时不能解除绑定。');
            }

            DB::table('taixue_oidc_links')->where('uid', $user->uid)->delete();
            $audit->record('UNLINK', 'SUCCEEDED', (int) $user->uid, $claims['sub'], [
                'source' => 'fresh_taixue_authentication',
            ]);
        });

        return redirect('/user/taixue-account')->with('success', '已解除太学账号绑定。');
    }

    private function completeLocalPasswordAuthorization(array $flow, array $claims, OidcAudit $audit)
    {
        $user = Auth::user();
        if (!$user || (int) ($flow['uid'] ?? 0) !== (int) $user->uid) {
            throw new \RuntimeException('皮肤站登录状态已变化，请重新发起备用密码设置。');
        }
        $claimedUid = $this->claimedBsUid($claims);
        if ($claimedUid && $claimedUid !== (int) $user->uid) {
            throw new \RuntimeException('当前太学账号与皮肤站账号不一致。');
        }
        $link = DB::table('taixue_oidc_links')->where('uid', $user->uid)->first();
        if (!$link || $link->subject !== $claims['sub'] || !$link->provisioned) {
            throw new \RuntimeException('账号绑定状态已经变化，请刷新后重试。');
        }

        request()->session()->regenerate();
        FreshAuthGrant::issue((int) $user->uid, $claims['sub']);
        $audit->record('LOCAL_PASSWORD_AUTH', 'SUCCEEDED', (int) $user->uid, $claims['sub'], [
            'source' => 'fresh_taixue_authentication',
        ]);

        return redirect('/user/taixue-account/local-password');
    }

    private function error(string $message, string $requestId)
    {
        return response()->view('Taixue\Oidc::error', [
            'message' => $message,
            'request_id' => $requestId,
        ], 400)->header('X-Request-ID', $requestId);
    }
}
