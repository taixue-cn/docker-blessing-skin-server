<?php

namespace Taixue\Oidc;

class EndpointFailure
{
    private const OPERATIONAL_REASONS = [
        'client_not_configured',
        'coordinated_logout_not_configured',
        'create_endpoint_disabled',
        'id_token_missing',
        'issuer_invalid',
        'jwks_unavailable',
        'local_account_missing',
        'provisioning_not_configured',
        'provisioning_unavailable',
        'token_exchange_failed',
    ];

    public static function outcome(\Throwable $error): string
    {
        if (!$error instanceof OidcFlowException) {
            return 'FAILED';
        }

        return self::isOperationalReason($error->reason()) ? 'FAILED' : 'REJECTED';
    }

    public static function status(\Throwable $error): int
    {
        return self::outcome($error) === 'FAILED' ? 503 : 400;
    }

    public static function isOperationalReason(string $reason): bool
    {
        return in_array($reason, self::OPERATIONAL_REASONS, true);
    }
}
