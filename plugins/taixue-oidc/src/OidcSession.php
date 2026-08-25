<?php

namespace Taixue\Oidc;

class OidcSession
{
    public const KEY = 'taixue_oidc_session';

    public static function begin(array $claims, int $uid, ?int $now = null): void
    {
        $now ??= time();
        session()->put(self::KEY, [
            'uid' => $uid,
            'subject' => (string) $claims['sub'],
            'sid' => isset($claims['sid']) && is_string($claims['sid']) && $claims['sid'] !== ''
                ? $claims['sid']
                : null,
            'authenticated_at' => $now,
            'checked_at' => 0,
        ]);
    }
}
