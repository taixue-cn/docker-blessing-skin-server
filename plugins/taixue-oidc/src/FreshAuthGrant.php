<?php

namespace Taixue\Oidc;

class FreshAuthGrant
{
    private const SESSION_KEY = 'taixue_oidc_local_password_grant';

    private const TTL_SECONDS = 300;

    public static function issue(int $uid, string $subject): void
    {
        session()->put(self::SESSION_KEY, self::payload($uid, $subject, time()));
    }

    public static function validFor(int $uid, string $subject): bool
    {
        $payload = session()->get(self::SESSION_KEY);

        return is_array($payload) && self::payloadIsValid($payload, $uid, $subject, time());
    }

    public static function consumeFor(int $uid, string $subject): bool
    {
        $payload = session()->pull(self::SESSION_KEY);

        return is_array($payload) && self::payloadIsValid($payload, $uid, $subject, time());
    }

    public static function payload(int $uid, string $subject, int $issuedAt): array
    {
        return [
            'uid' => $uid,
            'subject' => $subject,
            'issued_at' => $issuedAt,
        ];
    }

    public static function payloadIsValid(
        array $payload,
        int $uid,
        string $subject,
        int $now
    ): bool {
        $issuedAt = filter_var($payload['issued_at'] ?? null, FILTER_VALIDATE_INT);
        $storedSubject = $payload['subject'] ?? null;

        return (int) ($payload['uid'] ?? 0) === $uid
            && is_string($storedSubject)
            && hash_equals($storedSubject, $subject)
            && $issuedAt !== false
            && $issuedAt <= $now + 30
            && $now - $issuedAt <= self::TTL_SECONDS;
    }
}
