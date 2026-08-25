<?php

Route::get('auth/taixue', 'AuthController@redirectToProvider')
    ->middleware('guest')
    ->name('taixue-oidc.login');
Route::get('auth/taixue/callback', 'AuthController@callback')
    ->name('taixue-oidc.callback');

Route::prefix('user/taixue-account')
    ->middleware('auth')
    ->group(function () {
        Route::get('', 'AccountController@show');
        Route::get('link', 'AccountController@redirectToProvider');
        Route::get('local-password/start', 'AccountController@redirectToLocalPassword');
        Route::get('local-password', 'AccountController@showLocalPassword');
        Route::post('local-password', 'AccountController@storeLocalPassword');
        Route::delete('link', 'AccountController@unlink');
    });

Route::get('admin/taixue-oidc', 'AdminController@show')
    ->middleware(['auth', 'role:admin'])
    ->name('taixue-oidc.admin');
