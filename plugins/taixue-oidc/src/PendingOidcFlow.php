<?php

namespace Taixue\Oidc;

class PendingOidcFlow
{
    private const MAX_AGE_SECONDS = 600;

    public static function validate($value, ?int $now = null): array
    {
        if (!is_array($value)) {
            throw self::expired();
        }

        $now ??= time();
        $createdAt = filter_var($value['created_at'] ?? null, FILTER_VALIDATE_INT);
        if ($createdAt === false || $createdAt <= 0 || $createdAt > $now + 60 ||
            $now - $createdAt > self::MAX_AGE_SECONDS) {
            throw self::expired();
        }

        foreach (['state', 'nonce'] as $field) {
            if (!self::isUrlSafeSecret($value[$field] ?? null, 43, 128)) {
                throw self::expired();
            }
        }
        if (!self::isUrlSafeSecret($value['verifier'] ?? null, 43, 128) ||
            ($value['intent'] ?? null) !== 'login') {
            throw self::expired();
        }

        return [
            'state' => $value['state'],
            'nonce' => $value['nonce'],
            'verifier' => $value['verifier'],
            'intent' => 'login',
            'created_at' => $createdAt,
        ];
    }

    private static function isUrlSafeSecret($value, int $min, int $max): bool
    {
        return is_string($value) && strlen($value) >= $min && strlen($value) <= $max &&
            preg_match('/^[A-Za-z0-9_-]+$/D', $value) === 1;
    }

    private static function expired(): OidcFlowException
    {
        return new OidcFlowException('flow_expired', '登录请求已失效，请重新开始。');
    }
}
