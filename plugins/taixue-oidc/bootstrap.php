<?php

use App\Services\Hook;
use Blessing\Filter;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\View;
use Taixue\Oidc\RolloutPolicy;

return function (Filter $filter, Dispatcher $events) {
    if (!filter_var(env('TAIXUE_OIDC_ENABLED', false), FILTER_VALIDATE_BOOL)) {
        return;
    }

    app()->singleton(RolloutPolicy::class, fn () => RolloutPolicy::fromEnvironment());

    if (filter_var(env('TAIXUE_OIDC_SHOW_LOGIN_BUTTON', false), FILTER_VALIDATE_BOOL)) {
        View::composer('Taixue\Oidc::login', function ($view) {
            $view->with('label', env('TAIXUE_OIDC_LABEL', '使用太学账号登录'));
        });

        $filter->add('auth_page_rows:login', function ($rows) {
            $length = count($rows);
            array_splice($rows, max(0, $length - 1), 0, ['Taixue\Oidc::login']);

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

    Hook::addRoute(function () {
        Route::namespace('Taixue\Oidc\Controllers')
            ->middleware('web')
            ->group(__DIR__.'/routes.php');
    });

    $events->listen('user.profile.updated', function ($user, $action) {
        if ($action === 'password') {
            DB::table('taixue_oidc_links')->where('uid', $user->uid)->update(['provisioned' => false]);
        }
    });
    $events->listen('user.password.updated', function ($user) {
        DB::table('taixue_oidc_links')->where('uid', $user->uid)->update(['provisioned' => false]);
    });
};
