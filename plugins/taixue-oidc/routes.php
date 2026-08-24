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
        Route::delete('link', 'AccountController@unlink');
    });
