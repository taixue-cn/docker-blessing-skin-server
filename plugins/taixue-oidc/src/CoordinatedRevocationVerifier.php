<?php

namespace Taixue\Oidc;

class CoordinatedRevocationVerifier
{
    private const MAX_SKEW_SECONDS = 300;

    public function verify(
        string $subject,
        string $requestId,
        string $timestamp,
        string $signature,
        string $secret,
        ?int $now = null
    ): void {
        $now ??= time();
        if (strlen($secret) < 32) {
            throw new OidcFlowException('coordinated_logout_not_configured', '协调退出尚未配置。');
        }
        if ($subject === '' || strlen($subject) > 191 || !preg_match('/^[A-Za-z0-9._:-]+$/', $subject) ||
            !preg_match('/^[A-Za-z0-9._:-]{8,128}$/', $requestId)) {
            throw new OidcFlowException('coordinated_logout_request_invalid', '协调退出请求不正确。');
        }
        $issuedAt = filter_var($timestamp, FILTER_VALIDATE_INT);
        if ($issuedAt === false || abs($now - $issuedAt) > self::MAX_SKEW_SECONDS) {
            throw new OidcFlowException('coordinated_logout_expired', '协调退出请求已失效。');
        }
        if (!preg_match('/^v1=([a-f0-9]{64})$/', $signature, $matches)) {
            throw new OidcFlowException('coordinated_logout_signature_invalid', '协调退出签名不正确。');
        }
        $expected = hash_hmac('sha256', self::payload($subject, $requestId, $issuedAt), $secret);
        if (!hash_equals($expected, $matches[1])) {
            throw new OidcFlowException('coordinated_logout_signature_invalid', '协调退出签名不正确。');
        }
    }

    public static function payload(string $subject, string $requestId, int $timestamp): string
    {
        return "v1\n{$timestamp}\n{$requestId}\n{$subject}";
    }
}
