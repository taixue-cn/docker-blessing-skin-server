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

    public static function belongsToUser(mixed $provenance, mixed $authenticatedUid): bool
    {
        if (!is_array($provenance)) {
            return false;
        }
        $sessionUid = filter_var($provenance['uid'] ?? null, FILTER_VALIDATE_INT);
        $currentUid = filter_var($authenticatedUid, FILTER_VALIDATE_INT);
        $subject = $provenance['subject'] ?? null;

        return $sessionUid !== false && $sessionUid > 0 &&
            $currentUid !== false && $currentUid > 0 &&
            $sessionUid === $currentUid &&
            is_string($subject) && preg_match('/^[0-9]{1,20}$/D', $subject) === 1;
    }
}
