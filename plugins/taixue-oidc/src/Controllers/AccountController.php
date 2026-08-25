<?php

namespace Taixue\Oidc\Controllers;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Taixue\Oidc\OidcClient;
use Taixue\Oidc\OidcAudit;

class AccountController
{
    public function show()
    {
        $link = DB::table('taixue_oidc_links')->where('uid', Auth::id())->first();

        return view('Taixue\Oidc::account', [
            'link' => $link,
            'success' => session()->pull('success'),
            'error' => session()->pull('error'),
        ]);
    }

    public function redirectToProvider(OidcClient $client)
    {
        return $client->start('link', (int) Auth::id());
    }

    public function unlink(OidcClient $client, OidcAudit $audit)
    {
        $link = DB::table('taixue_oidc_links')->where('uid', Auth::id())->first();
        if ($link && $link->provisioned) {
            $audit->record('UNLINK', 'REJECTED', (int) Auth::id(), $link->subject, [
                'reason' => 'no_local_recovery_credential',
            ]);
            return redirect('/user/taixue-account')
                ->with('error', '此账号由太学账号创建。请先由管理员设置可用的本地密码，再解除绑定。');
        }
        if (!$link) {
            return redirect('/user/taixue-account')->with('error', '当前账号没有太学账号绑定。');
        }

        return $client->start('unlink', (int) Auth::id());
    }
}
