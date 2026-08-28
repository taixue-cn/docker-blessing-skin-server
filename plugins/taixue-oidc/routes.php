<?php

Route::get('auth/taixue', 'AuthController@redirectToProvider')
    ->middleware('guest')
    ->name('taixue-oidc.login');
Route::get('auth/taixue/callback', 'AuthController@callback')
    ->name('taixue-oidc.callback');
