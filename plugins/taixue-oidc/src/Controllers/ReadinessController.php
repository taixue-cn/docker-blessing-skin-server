<?php

namespace Taixue\Oidc\Controllers;

use Illuminate\Support\Facades\Schema;

class ReadinessController
{
    private const REQUIRED_TABLES = [
        'taixue_oidc_links',
        'taixue_oidc_audit_events',
        'taixue_oidc_revocations',
    ];

    public function __invoke()
    {
        try {
            $configured = filter_var(env('TAIXUE_OIDC_ENABLED', false), FILTER_VALIDATE_BOOL)
                && (bool) config('session.secure')
                && trim((string) env('TAIXUE_OIDC_CLIENT_ID', '')) !== ''
                && trim((string) env('TAIXUE_OIDC_CLIENT_SECRET', '')) !== ''
                && strlen((string) env('TAIXUE_OIDC_REVOCATION_SECRET', '')) >= 32;

            $schemaReady = true;
            foreach (self::REQUIRED_TABLES as $table) {
                if (!Schema::hasTable($table)) {
                    $schemaReady = false;
                    break;
                }
            }

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
