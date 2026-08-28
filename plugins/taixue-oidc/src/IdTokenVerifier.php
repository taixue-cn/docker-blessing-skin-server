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

        $rawAudience = $claims['aud'] ?? null;
        if (is_string($rawAudience) && $rawAudience !== '') {
            $audience = [$rawAudience];
        } elseif (is_array($rawAudience) && $rawAudience !== [] &&
            count(array_filter($rawAudience, fn ($value) => !is_string($value) || $value === '')) === 0) {
            $audience = array_values($rawAudience);
        } else {
            throw new OidcFlowException('audience_invalid', '太学账号身份令牌的接收方格式无效。');
        }
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
        if (!isset($claims['sub']) || !is_string($claims['sub']) ||
            preg_match('/^[0-9]{1,20}$/D', $claims['sub']) !== 1) {
            throw new OidcFlowException('subject_missing', '太学账号身份令牌缺少用户标识。');
        }
        if (!isset($claims['iat']) || !is_int($claims['iat']) ||
            !isset($claims['exp']) || !is_int($claims['exp']) ||
            $claims['iat'] <= 0 || $claims['exp'] <= $claims['iat']) {
            throw new OidcFlowException(
                'token_time_invalid',
                '太学账号身份令牌缺少有效的签发或过期时间。'
            );
        }
        if (!isset($claims['nonce']) || !is_string($claims['nonce']) ||
            !hash_equals($nonce, $claims['nonce'])) {
            throw new OidcFlowException('nonce_mismatch', '太学账号身份令牌 nonce 校验失败。');
        }

        return $claims;
    }
}
