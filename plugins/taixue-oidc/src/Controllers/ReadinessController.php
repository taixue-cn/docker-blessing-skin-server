<?php

namespace Taixue\Oidc\Controllers;

use Illuminate\Support\Facades\Schema;
use Taixue\Oidc\OidcClient;
use Taixue\Oidc\ProvisioningNotifier;
use Taixue\Oidc\UnifiedIdentityBoundary;

class ReadinessController
{
    private const REQUIRED_TABLES = [
        'taixue_oidc_links',
        'taixue_oidc_audit_events',
        'taixue_oidc_revocations',
        'taixue_oidc_provision_requests',
        'taixue_oidc_cardinality_repairs',
        'taixue_oidc_password_sync_requests',
        'taixue_oidc_password_versions',
    ];

    public function __invoke()
    {
        try {
            $autoRegister = filter_var(env('TAIXUE_OIDC_AUTO_REGISTER', false), FILTER_VALIDATE_BOOL);
            $createEnabled = filter_var(
                env('TAIXUE_OIDC_CREATE_ENABLED', false),
                FILTER_VALIDATE_BOOL
            );
            $needsProvisioning = $autoRegister || $createEnabled;
            $provisioningConfigured = !$needsProvisioning || (
                ProvisioningNotifier::endpointIsValid(
                    (string) env('TAIXUE_OIDC_PROVISIONING_URL', '')
                )
                && strlen((string) env('TAIXUE_OIDC_PROVISIONING_SECRET', '')) >= 32
            );
            $createConfigured = !$createEnabled ||
                strlen((string) env('TAIXUE_OIDC_CREATE_SECRET', '')) >= 32;
            $passwordSyncSecret = (string) env('TAIXUE_OIDC_PASSWORD_SYNC_SECRET', '');
            $passwordSyncConfigured = strlen($passwordSyncSecret) >= 32;
            foreach ([
                (string) env('TAIXUE_OIDC_CREATE_SECRET', ''),
                (string) env('TAIXUE_OIDC_PROVISIONING_SECRET', ''),
                (string) env('TAIXUE_OIDC_REVOCATION_SECRET', ''),
            ] as $otherSecret) {
                if ($otherSecret !== '' && hash_equals($otherSecret, $passwordSyncSecret)) {
                    $passwordSyncConfigured = false;
                }
            }
            $unifiedIdentityOnly = filter_var(
                env('TAIXUE_OIDC_UNIFIED_IDENTITY_ONLY', false),
                FILTER_VALIDATE_BOOL
            );
            $automaticRedirect = filter_var(
                env('TAIXUE_OIDC_AUTO_REDIRECT', false),
                FILTER_VALIDATE_BOOL
            );
            $identityModeConfigured = UnifiedIdentityBoundary::configurationIsSafe(
                $unifiedIdentityOnly,
                $automaticRedirect,
                (string) env('TAIXUE_OIDC_ROLLOUT_MODE', 'allowlist'),
                (string) env('TAIXUE_OIDC_ALLOWED_SUBJECTS', '')
            );
            // Validate the complete issuer shape before admitting traffic.
            OidcClient::standardPasswordChangeUrl(
                (string) env('TAIXUE_OIDC_ISSUER', 'https://auth.taixue.cc')
            );
            // The callback must be a fixed client configuration, never a URL
            // reconstructed from the inbound Host header.
            OidcClient::validateRedirectUri(
                (string) env('TAIXUE_OIDC_REDIRECT_URI', '')
            );
            $configured = filter_var(env('TAIXUE_OIDC_ENABLED', false), FILTER_VALIDATE_BOOL)
                && (bool) config('session.secure')
                && trim((string) env('TAIXUE_OIDC_CLIENT_ID', '')) !== ''
                && trim((string) env('TAIXUE_OIDC_CLIENT_SECRET', '')) !== ''
                && strlen((string) env('TAIXUE_OIDC_REVOCATION_SECRET', '')) >= 32
                && $provisioningConfigured
                && $createConfigured
                && $passwordSyncConfigured
                && $identityModeConfigured;

            $schemaReady = true;
            foreach (self::REQUIRED_TABLES as $table) {
                if (!Schema::hasTable($table)) {
                    $schemaReady = false;
                    break;
                }
            }
            $schemaReady = $schemaReady &&
                Schema::hasColumn('taixue_oidc_revocations', 'event_type');

            $status = $configured && $schemaReady ? 204 : 503;
        } catch (\Throwable $error) {
            report($error);
            $status = 503;
        }

        return response('', $status)
            ->header('Cache-Control', 'no-store')
            ->header('Pragma', 'no-cache');
    }
}
