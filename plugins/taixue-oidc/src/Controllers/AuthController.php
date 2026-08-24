<?php

namespace Taixue\Oidc\Controllers;

use App\Events;
use App\Models\User;
use Blessing\Filter;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Taixue\Oidc\OidcClient;
use Taixue\Oidc\RolloutPolicy;
use Vectorface\Whip\Whip;

class AuthController
{
    public function redirectToProvider(OidcClient $client)
    {
        return $client->start('login');
    }

    public function callback(OidcClient $client, Dispatcher $events, RolloutPolicy $rollout)
    {
        try {
            $result = $client->complete();
            $flow = $result['flow'];
            $claims = $result['claims'];
            if (!$rollout->allows($claims['sub'])) {
                return $this->error('太学账号登录正在小范围灰度，此账号暂未开放。原皮肤站登录仍可正常使用。');
            }

            if (($flow['intent'] ?? null) === 'link') {
                return $this->completeLink($flow, $claims);
            }

            $link = DB::table('taixue_oidc_links')->where('subject', $claims['sub'])->first();
            if (!$link && ($claimedUid = $this->claimedBsUid($claims))) {
                $link = $this->linkTrustedBsUid($claimedUid, $claims['sub']);
            }
            if (!$link && filter_var(env('TAIXUE_OIDC_AUTO_REGISTER', false), FILTER_VALIDATE_BOOL)) {
                $link = $this->register($claims, $events);
            }
            if (!$link) {
                return response()->view('Taixue\Oidc::unlinked', ['claims' => $claims], 403);
            }

            $user = User::find($link->uid);
            if (!$user) {
                return $this->error('绑定的皮肤站账号不存在，请联系管理员修复。');
            }

            $events->dispatch('auth.login.ready', [$user]);
            Auth::login($user, true);
            $events->dispatch('auth.login.succeeded', [$user]);
            event(new Events\UserLoggedIn($user));

            return redirect(session()->pull('last_requested_path', url('/user')));
        } catch (\Throwable $e) {
            if (!$e instanceof \RuntimeException) {
                report($e);
            }

            $message = $e instanceof \RuntimeException
                ? $e->getMessage()
                : '太学账号登录暂时不可用，请稍后重试。';

            return $this->error($message);
        }
    }

    private function completeLink(array $flow, array $claims)
    {
        $user = Auth::user();
        if (!$user || (int) ($flow['uid'] ?? 0) !== (int) $user->uid) {
            return $this->error('皮肤站登录状态已变化，请重新发起绑定。');
        }
        $claimedUid = $this->claimedBsUid($claims);
        if ($claimedUid && $claimedUid !== (int) $user->uid) {
            return $this->error('太学账号已绑定另一个皮肤站账号，请先在统一账号中心处理冲突。');
        }

        DB::transaction(function () use ($user, $claims) {
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
        });

        return redirect('/user/taixue-account')->with('success', '太学账号绑定成功。');
    }

    private function linkTrustedBsUid(int $uid, string $subject)
    {
        return DB::transaction(function () use ($uid, $subject) {
            $user = User::find($uid);
            if (!$user) {
                throw new \RuntimeException('太学账号绑定的皮肤站账号不存在，请联系管理员修复。');
            }

            $bySubject = DB::table('taixue_oidc_links')->where('subject', $subject)->lockForUpdate()->first();
            if ($bySubject) {
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

    private function register(array $claims, Dispatcher $events)
    {
        return DB::transaction(function () use ($claims, $events) {
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

            return (object) ['uid' => $user->uid, 'subject' => $claims['sub']];
        });
    }

    private function error(string $message)
    {
        return response()->view('Taixue\Oidc::error', ['message' => $message], 400);
    }
}
