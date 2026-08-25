<?php

namespace Taixue\Oidc;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
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
            throw new OidcFlowException('jwt_decode_failed', '太学账号身份令牌校验失败。', $e);
        }

        $audience = (array) ($claims['aud'] ?? []);
        if (($claims['iss'] ?? null) !== $issuer || !in_array($clientId, $audience, true)) {
            throw new OidcFlowException(
                'issuer_audience_mismatch',
                '太学账号身份令牌的签发方或接收方不正确。'
            );
        }
        $authorizedParty = $claims['azp'] ?? null;
        if ((count($audience) > 1 && !is_string($authorizedParty)) ||
            ($authorizedParty !== null && $authorizedParty !== $clientId)) {
            throw new OidcFlowException(
                'authorized_party_mismatch',
                '太学账号身份令牌的授权客户端不正确。'
            );
        }
        if (!isset($claims['sub']) || !is_string($claims['sub']) || $claims['sub'] === '') {
            throw new OidcFlowException('subject_missing', '太学账号身份令牌缺少用户标识。');
        }
        if (!isset($claims['nonce']) || !hash_equals($nonce, (string) $claims['nonce'])) {
            throw new OidcFlowException('nonce_mismatch', '太学账号身份令牌 nonce 校验失败。');
        }

        return $claims;
    }
}
