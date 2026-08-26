<?php

use App\Services\Hook;
use Blessing\Filter;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\View;
use Taixue\Oidc\RolloutPolicy;
use Taixue\Oidc\OidcSessionGuard;

return function (Filter $filter, Dispatcher $events) {
    if (!filter_var(env('TAIXUE_OIDC_ENABLED', false), FILTER_VALIDATE_BOOL)) {
        return;
    }
    // Keep the side-effect-free readiness endpoint available when an enabled
    // deployment is misconfigured, so automation observes 503 instead of a
    // misleading 404. No login or account route is registered until the
    // Secure-cookie gate below passes.
    Hook::addRoute(function () {
        Route::get(
            'auth/taixue/ready',
            [\Taixue\Oidc\Controllers\ReadinessController::class, '__invoke']
        );
    });

    // Password recovery is the safety net for both migration and rollback.
    // Keep these links visible even when an enabled OIDC deployment fails the
    // Secure-cookie gate, so a configuration mistake cannot trap local users.
    View::composer('Taixue\Oidc::login-help', function ($view) {
        $taixueRecoveryUrl = null;
        try {
            $taixueRecoveryUrl = \Taixue\Oidc\OidcClient::standardPasswordRecoveryUrl(
                (string) env('TAIXUE_OIDC_ISSUER', 'https://auth.taixue.cc')
            );
        } catch (\Throwable $error) {
            report($error);
        }

        $view->with([
            'localRecoveryEnabled' => config('mail.default') !== '',
            'localRecoveryUrl' => url('auth/forgot'),
            'taixueRecoveryUrl' => $taixueRecoveryUrl,
        ]);
    });
    $filter->add('auth_page_rows:login', function ($rows) {
        $length = count($rows);
        array_splice($rows, max(0, $length - 1), 0, ['Taixue\Oidc::login-help']);

        return $rows;
    });

    if (!config('session.secure')) {
        logger()->critical(
            'Taixue OIDC disabled because SESSION_SECURE_COOKIE is not enabled'
        );
        return;
    }

    app()->singleton(RolloutPolicy::class, fn () => RolloutPolicy::fromEnvironment());

    if (filter_var(env('TAIXUE_OIDC_SHOW_LOGIN_BUTTON', false), FILTER_VALIDATE_BOOL)) {
        View::composer('Taixue\Oidc::login', function ($view) {
            $view->with('label', env('TAIXUE_OIDC_LABEL', '使用太学账号登录'));
        });

        $filter->add('auth_page_rows:login', function ($rows) {
            $helpIndex = array_search('Taixue\Oidc::login-help', $rows, true);
            $insertAt = $helpIndex === false ? max(0, count($rows) - 1) : $helpIndex;
            array_splice($rows, $insertAt, 0, ['Taixue\Oidc::login']);

            return $rows;
        });
    }

    if (filter_var(env('TAIXUE_OIDC_SHOW_ACCOUNT_MENU', false), FILTER_VALIDATE_BOOL)) {
        Hook::addMenuItem('user', 0, [
            'title' => 'Taixue\Oidc::general.account-menu',
            'link' => '/user/taixue-account',
            'icon' => 'fa-link',
        ]);
    }

    Hook::addMenuItem('admin', 5, [
        'title' => 'Taixue\Oidc::general.admin-menu',
        'link' => '/admin/taixue-oidc',
        'icon' => 'fa-shield-alt',
    ]);

    Hook::addRoute(function () {
        // The OP calls this server-to-server endpoint. It deliberately stays
        // outside the browser `web` group and therefore outside CSRF/session
        // middleware; authenticity comes from the signed Logout Token.
        Route::post(
            'auth/taixue/backchannel-logout',
            [\Taixue\Oidc\Controllers\BackchannelLogoutController::class, '__invoke']
        );
        Route::post(
            'auth/taixue/coordinated-logout',
            [\Taixue\Oidc\Controllers\CoordinatedLogoutController::class, '__invoke']
        );
        Route::namespace('Taixue\Oidc\Controllers')
            ->middleware('web')
            ->group(__DIR__.'/routes.php');
    });

    // Session-driver independent revocation: only OIDC-created sessions carry
    // provenance, and at most one indexed revocation lookup is made per 30s.
    app('router')->pushMiddlewareToGroup('web', OidcSessionGuard::class);

    $markLocalPasswordAvailable = static function ($user): void {
        DB::table('taixue_oidc_links')
            ->where('uid', $user->uid)
            ->update(['provisioned' => false, 'updated_at' => now()]);
    };

    // Any login path starts without stale OIDC provenance. The OIDC callback
    // adds fresh provenance only after the local login succeeds.
    $events->listen('auth.login.ready', static function (): void {
        session()->forget(\Taixue\Oidc\OidcSession::KEY);
    });

    $events->listen('user.profile.updated', function ($user, $action) use ($markLocalPasswordAvailable) {
        if ($action === 'password') {
            $markLocalPasswordAvailable($user);
        }
    });
    $events->listen('user.password.updated', $markLocalPasswordAvailable);
    // Blessing Skin's built-in forgot-password flow does not dispatch either
    // user password event above. It dispatches auth.reset.after only after the
    // new local password has been persisted. Accept only the user argument so
    // the plaintext password carried as the second event argument is ignored.
    $events->listen('auth.reset.after', $markLocalPasswordAvailable);
};
