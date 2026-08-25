<?php

namespace Taixue\Oidc;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;

class LogoutTokenVerifier
{
    public const EVENT = 'http://schemas.openid.net/event/backchannel-logout';

    public function verify(
        string $token,
        array $jwks,
        string $issuer,
        string $clientId,
        ?int $now = null
    ): array {
        JWT::$leeway = 30;
        try {
            $claims = (array) JWT::decode($token, JWK::parseKeySet($jwks, 'RS256'));
        } catch (\Throwable $e) {
            throw new OidcFlowException('logout_token_decode_failed', '太学账号退出令牌校验失败。', $e);
        }

        $now ??= time();
        $audience = (array) ($claims['aud'] ?? []);
        if (($claims['iss'] ?? null) !== $issuer || !in_array($clientId, $audience, true)) {
            throw new OidcFlowException(
                'logout_token_issuer_audience_mismatch',
                '太学账号退出令牌的签发方或接收方不正确。'
            );
        }
        $authorizedParty = $claims['azp'] ?? null;
        if ((count($audience) > 1 && !is_string($authorizedParty)) ||
            ($authorizedParty !== null && $authorizedParty !== $clientId)) {
            throw new OidcFlowException(
                'logout_token_authorized_party_mismatch',
                '太学账号退出令牌的授权客户端不正确。'
            );
        }

        $issuedAt = filter_var($claims['iat'] ?? null, FILTER_VALIDATE_INT);
        $expiresAt = filter_var($claims['exp'] ?? null, FILTER_VALIDATE_INT);
        if ($issuedAt === false || $expiresAt === false || $issuedAt <= 0 ||
            $expiresAt <= $issuedAt || $issuedAt > $now + 30 || $expiresAt <= $now - 30) {
            throw new OidcFlowException('logout_token_time_invalid', '太学账号退出令牌已失效。');
        }

        $jti = $claims['jti'] ?? null;
        if (!is_string($jti) || $jti === '' || strlen($jti) > 191) {
            throw new OidcFlowException('logout_token_jti_invalid', '太学账号退出令牌缺少有效标识。');
        }

        $subject = $claims['sub'] ?? null;
        $sid = $claims['sid'] ?? null;
        if (($subject !== null && (!is_string($subject) || $subject === '' || strlen($subject) > 191)) ||
            ($sid !== null && (!is_string($sid) || $sid === '' || strlen($sid) > 191)) ||
            ($subject === null && $sid === null)) {
            throw new OidcFlowException('logout_token_target_invalid', '太学账号退出令牌缺少有效会话目标。');
        }

        $events = $claims['events'] ?? null;
        $events = is_object($events) ? (array) $events : $events;
        if (!is_array($events) || !array_key_exists(self::EVENT, $events)) {
            throw new OidcFlowException('logout_token_event_invalid', '太学账号退出令牌事件不正确。');
        }
        $event = $events[self::EVENT];
        if (!is_array($event) && !is_object($event)) {
            throw new OidcFlowException('logout_token_event_invalid', '太学账号退出令牌事件不正确。');
        }
        if (array_key_exists('nonce', $claims)) {
            throw new OidcFlowException('logout_token_nonce_forbidden', '太学账号退出令牌包含禁止字段。');
        }

        return $claims;
    }
}
