<?php

namespace Taixue\Oidc;

class OidcSession
{
    public const KEY = 'taixue_oidc_session';

    public static function begin(array $claims, int $uid, ?int $now = null): void
    {
        $now ??= time();
        $issuedAt = filter_var($claims['iat'] ?? null, FILTER_VALIDATE_INT);
        $authenticatedAt = $issuedAt !== false && $issuedAt > 0 && $issuedAt <= $now + 30
            ? $issuedAt
            : $now;
        session()->put(self::KEY, [
            'uid' => $uid,
            'subject' => (string) $claims['sub'],
            'sid' => isset($claims['sid']) && is_string($claims['sid']) && $claims['sid'] !== ''
                ? $claims['sid']
                : null,
            // Anchor revocation ordering to the provider token issuance time,
            // not the slightly later local callback time. A logout racing the
            // callback must still invalidate the session created from that token.
            'authenticated_at' => $authenticatedAt,
            'checked_at' => 0,
        ]);
    }
}
