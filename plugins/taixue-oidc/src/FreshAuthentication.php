<?php

namespace Taixue\Oidc;

class FreshAuthentication
{
    private const CLOCK_SKEW_SECONDS = 60;

    public static function assertClaims(array $claims, int $flowCreatedAt, int $now): void
    {
        $authTime = filter_var($claims['auth_time'] ?? null, FILTER_VALIDATE_INT);
        if ($flowCreatedAt <= 0 || $authTime === false ||
            $authTime < $flowCreatedAt - self::CLOCK_SKEW_SECONDS ||
            $authTime > $now + self::CLOCK_SKEW_SECONDS) {
            throw new OidcFlowException(
                'fresh_auth_invalid',
                '太学账号没有提供有效的重新认证证明，请重新输入密码。'
            );
        }
    }
}
