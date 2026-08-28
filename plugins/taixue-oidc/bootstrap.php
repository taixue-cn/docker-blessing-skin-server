<?php

use App\Services\Hook;
use Blessing\Filter;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Facades\View;
use Taixue\Oidc\RolloutPolicy;
use Taixue\Oidc\OidcSessionGuard;
use Taixue\Oidc\UnifiedIdentityBoundary;

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
            'taixueRecoveryUrl' => $taixueRecoveryUrl,
            'taixueRecoveryLabel' => trans('Taixue\Oidc::general.recovery.taixue'),
            'recoveryHint' => trans('Taixue\Oidc::general.recovery.hint'),
        ]);
    });
    View::composer('Taixue\Oidc::identity-managed', function ($view) {
        $issuer = rtrim((string) env('TAIXUE_OIDC_ISSUER', 'https://auth.taixue.cc'), '/');
        // The standard recovery helper validates the configured HTTPS issuer.
        $view->with([
            'accountSettingsUrl' => $issuer.'/settings',
            'passwordRecoveryUrl' => \Taixue\Oidc\OidcClient::standardPasswordRecoveryUrl($issuer),
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
        // Dedicated HMAC authentication and a replay ledger protect this
        // server-to-server domain provisioning endpoint.
        Route::post(
            'auth/taixue/provision-account',
            [\Taixue\Oidc\Controllers\ProvisionAccountController::class, '__invoke']
        );
        Route::post(
            'auth/taixue/sync-password',
            [\Taixue\Oidc\Controllers\PasswordSyncController::class, '__invoke']
        );
        Route::post(
            'auth/taixue/repair-cardinality',
            [\Taixue\Oidc\Controllers\CardinalityRepairController::class, '__invoke']
        );
        Route::namespace('Taixue\Oidc\Controllers')
            ->middleware('web')
            ->group(__DIR__.'/routes.php');
    });

    // Session-driver independent revocation: only OIDC-created sessions carry
    // provenance, and at most one indexed revocation lookup is made per 30s.
    app('router')->pushMiddlewareToGroup('web', OidcSessionGuard::class);
    app('router')->pushMiddlewareToGroup('web', UnifiedIdentityBoundary::class);
    // Blessing Skin's OAuth API repeats native role-based identity mutation
    // endpoints. Apply the same boundary there: repairs must go through the
    // unified CheckUserPermission-backed administration flow.
    app('router')->pushMiddlewareToGroup('api', UnifiedIdentityBoundary::class);

    $removeGridWidgets = static function (array $grid, array $retiredWidgets): array {
        foreach ($grid['widgets'] ?? [] as $rowIndex => $columns) {
            foreach ($columns as $columnIndex => $widgets) {
                $grid['widgets'][$rowIndex][$columnIndex] = array_values(array_filter(
                    $widgets,
                    fn ($widget) => !in_array($widget, $retiredWidgets, true)
                ));
            }
        }

        return $grid;
    };
    foreach (['grid:user.index', 'grid:user.closet'] as $emailVerificationGrid) {
        $filter->add($emailVerificationGrid, function ($grid) use ($removeGridWidgets) {
            if (!UnifiedIdentityBoundary::protectsCurrentUserIdentity()) {
                return $grid;
            }

            return $removeGridWidgets($grid, ['user.widgets.email-verification']);
        });
    }
    $filter->add('grid:user.profile', function ($grid) use ($removeGridWidgets) {
        if (!UnifiedIdentityBoundary::protectsCurrentUserIdentity()) {
            return $grid;
        }
        $grid = $removeGridWidgets($grid, [
            'user.widgets.profile.password',
            'user.widgets.profile.email',
            'user.widgets.profile.delete-account',
        ]);
        if (!isset($grid['widgets'][0][0]) || !is_array($grid['widgets'][0][0])) {
            $grid['widgets'][0][0] = [];
        }
        $grid['widgets'][0][0][] = 'Taixue\Oidc::identity-managed';

        return $grid;
    });
    $filter->add('extra:user.player', function ($extra) {
        if (!UnifiedIdentityBoundary::protectsCurrentUserIdentity()) {
            return $extra;
        }
        $issuer = rtrim((string) env('TAIXUE_OIDC_ISSUER', 'https://auth.taixue.cc'), '/');
        $extra['identityManaged'] = true;
        $extra['identityManagedTitle'] = trans('Taixue\Oidc::general.player.managed-title');
        $extra['identityManagedDescription'] = trans('Taixue\Oidc::general.player.managed-description');
        $extra['identitySettingsUrl'] = $issuer.'/settings';
        $extra['identitySettingsLabel'] = trans('Taixue\Oidc::general.player.settings-label');

        return $extra;
    });
    // The ordinary form remains usable throughout gray rollout. After the
    // explicit unified-only gate is enabled, reject direct POSTs as well as
    // redirecting GETs so the hidden legacy endpoint cannot become a second
    // authoritative web authentication source.
    $filter->add('can_login', [UnifiedIdentityBoundary::class, 'rejectLocalLogin']);
    $filter->add('user_can_edit_profile', [UnifiedIdentityBoundary::class, 'rejectIdentityMutation']);
    foreach (['can_add_player', 'can_delete_player', 'can_rename_player'] as $playerMutation) {
        $filter->add($playerMutation, [UnifiedIdentityBoundary::class, 'rejectPlayerMutation']);
    }

    // Any login path starts without stale OIDC provenance. The OIDC callback
    // adds fresh provenance only after the local login succeeds.
    $events->listen('auth.login.ready', static function (): void {
        session()->forget(\Taixue\Oidc\OidcSession::KEY);
    });

};
