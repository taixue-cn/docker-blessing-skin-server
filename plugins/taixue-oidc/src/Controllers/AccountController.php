<?php

namespace Taixue\Oidc\Controllers;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Taixue\Oidc\FreshAuthGrant;
use Taixue\Oidc\OidcClient;
use Taixue\Oidc\OidcAudit;

class AccountController
{
    public function show(OidcClient $client)
    {
        $link = DB::table('taixue_oidc_links')->where('uid', Auth::id())->first();

        return view('Taixue\Oidc::account', [
            'link' => $link,
            'passwordChangeUrl' => $client->passwordChangeUrl(),
            'success' => session()->pull('success'),
            'error' => session()->pull('error'),
        ]);
    }

    public function redirectToProvider(OidcClient $client)
    {
        return $client->start('link', (int) Auth::id());
    }

    public function redirectToLocalPassword(OidcClient $client, OidcAudit $audit)
    {
        $link = DB::table('taixue_oidc_links')->where('uid', Auth::id())->first();
        if (!$link || !$link->provisioned) {
            $audit->record('LOCAL_PASSWORD_AUTH', 'REJECTED', (int) Auth::id(), $link->subject ?? null, [
                'reason' => $link ? 'local_password_already_available' : 'account_unlinked',
            ]);
            return redirect('/user/taixue-account')
                ->with('error', '当前账号不需要建立本地备用密码。');
        }

        return $client->start('local_password', (int) Auth::id());
    }

    public function showLocalPassword(OidcAudit $audit)
    {
        $link = DB::table('taixue_oidc_links')->where('uid', Auth::id())->first();
        if (!$link || !$link->provisioned ||
            !FreshAuthGrant::validFor((int) Auth::id(), (string) $link->subject)) {
            $audit->record('LOCAL_PASSWORD_SETUP', 'REJECTED', (int) Auth::id(), $link->subject ?? null, [
                'reason' => 'fresh_auth_required',
            ]);
            return redirect('/user/taixue-account')
                ->with('error', '设置授权已失效，请重新验证太学账号。');
        }

        return view('Taixue\Oidc::local-password');
    }

    public function storeLocalPassword(
        Request $request,
        Dispatcher $events,
        OidcAudit $audit
    ) {
        $data = $request->validate([
            'password' => 'required|string|min:8|max:32|confirmed',
        ]);
        $user = Auth::user();
        $link = DB::table('taixue_oidc_links')->where('uid', $user->uid)->first();
        if (!$link || !$link->provisioned ||
            !FreshAuthGrant::consumeFor((int) $user->uid, (string) $link->subject)) {
            $audit->record('LOCAL_PASSWORD_SETUP', 'REJECTED', (int) $user->uid, $link->subject ?? null, [
                'reason' => 'fresh_auth_required',
            ]);
            return redirect('/user/taixue-account')
                ->with('error', '设置授权已失效，请重新验证太学账号。');
        }

        $events->dispatch('user.password.updating', [$user, $data['password']]);
        DB::transaction(function () use ($user, $link, $data, $audit) {
            $locked = DB::table('taixue_oidc_links')
                ->where('uid', $user->uid)
                ->lockForUpdate()
                ->first();
            if (!$locked || !$locked->provisioned || $locked->subject !== $link->subject) {
                throw new \RuntimeException('账号绑定状态已经变化，请刷新后重试。');
            }
            if (!$user->changePassword($data['password'])) {
                throw new \RuntimeException('本地备用密码保存失败，请稍后重试。');
            }
            DB::table('taixue_oidc_links')->where('uid', $user->uid)->update([
                'provisioned' => false,
                'updated_at' => now(),
            ]);
            $audit->record('LOCAL_PASSWORD_SETUP', 'SUCCEEDED', (int) $user->uid, $link->subject, [
                'source' => 'fresh_taixue_authentication',
            ]);
        });
        $events->dispatch('user.password.updated', [$user]);
        $request->session()->regenerate();

        return redirect('/user/taixue-account')
            ->with('success', '皮肤站本地备用密码已建立。现在可以安全解除太学账号绑定。');
    }

    public function unlink(OidcClient $client, OidcAudit $audit)
    {
        $link = DB::table('taixue_oidc_links')->where('uid', Auth::id())->first();
        if ($link && $link->provisioned) {
            $audit->record('UNLINK', 'REJECTED', (int) Auth::id(), $link->subject, [
                'reason' => 'no_local_recovery_credential',
            ]);
            return redirect('/user/taixue-account')
                ->with('error', '请先验证太学账号并建立本地备用密码，再解除绑定。');
        }
        if (!$link) {
            return redirect('/user/taixue-account')->with('error', '当前账号没有太学账号绑定。');
        }

        return $client->start('unlink', (int) Auth::id());
    }
}
