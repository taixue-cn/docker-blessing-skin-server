<?php

namespace Taixue\Oidc;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use RuntimeException;

class IdTokenVerifier
{
    public function verify(
        string $token,
        array $jwks,
        string $issuer,
        string $clientId,
        string $nonce
    ): array {
        JWT::$leeway = 30;
        try {
            $claims = (array) JWT::decode($token, JWK::parseKeySet($jwks, 'RS256'));
        } catch (\Throwable $e) {
            throw new RuntimeException('太学账号身份令牌校验失败。', 0, $e);
        }

        $audience = (array) ($claims['aud'] ?? []);
        if (($claims['iss'] ?? null) !== $issuer || !in_array($clientId, $audience, true)) {
            throw new RuntimeException('太学账号身份令牌的签发方或接收方不正确。');
        }
        if (!isset($claims['sub']) || !is_string($claims['sub']) || $claims['sub'] === '') {
            throw new RuntimeException('太学账号身份令牌缺少用户标识。');
        }
        if (!isset($claims['nonce']) || !hash_equals($nonce, (string) $claims['nonce'])) {
            throw new RuntimeException('太学账号身份令牌 nonce 校验失败。');
        }

        return $claims;
    }
}
