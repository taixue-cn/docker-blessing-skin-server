<?php

namespace Taixue\Oidc\Controllers;

use Taixue\Oidc\CoordinatedRevocationVerifier;
use Taixue\Oidc\EndpointFailure;
use Taixue\Oidc\OidcAudit;
use Taixue\Oidc\OidcFlowException;
use Taixue\Oidc\RevocationStore;

class CoordinatedLogoutController
{
    public function __invoke(
        CoordinatedRevocationVerifier $verifier,
        RevocationStore $store,
        OidcAudit $audit
    ) {
        try {
            $contentType = strtolower((string) request()->header('Content-Type', ''));
            if (!str_starts_with($contentType, 'application/json')) {
                throw new OidcFlowException('coordinated_logout_content_type_invalid', '协调退出请求格式不正确。');
            }
            $subject = request('subject');
            $requestId = (string) request()->header('X-Request-ID', '');
            $timestamp = (string) request()->header('X-Taixue-Timestamp', '');
            $signature = (string) request()->header('X-Taixue-Signature', '');
            if (!is_string($subject)) {
                throw new OidcFlowException('coordinated_logout_request_invalid', '协调退出请求不正确。');
            }
            $verifier->verify(
                $subject,
                $requestId,
                $timestamp,
                $signature,
                (string) env('TAIXUE_OIDC_REVOCATION_SECRET', '')
            );
            $store->record(
                'coordinated:'.hash('sha256', $requestId),
                $subject,
                null,
                'COORDINATED_LOGOUT',
                $audit
            );

            return response('', 204)
                ->header('Cache-Control', 'no-store')
                ->header('Pragma', 'no-cache');
        } catch (\Throwable $e) {
            if (!$e instanceof OidcFlowException) {
                report($e);
            }
            $reason = $e instanceof OidcFlowException ? $e->reason() : 'internal_error';
            $outcome = EndpointFailure::outcome($e);
            try {
                $audit->record('COORDINATED_LOGOUT', $outcome, null, null, ['reason' => $reason]);
            } catch (\Throwable $auditError) {
                report($auditError);
            }
            $audit->warn('COORDINATED_LOGOUT', $reason);

            return response('', EndpointFailure::status($e))
                ->header('Cache-Control', 'no-store')
                ->header('Pragma', 'no-cache');
        }
    }
}
