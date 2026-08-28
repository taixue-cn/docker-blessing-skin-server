<?php

use Illuminate\Contracts\Console\Kernel;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

$root = dirname(__DIR__, 3);
require $root.'/vendor/autoload.php';
$app = require $root.'/bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();

$boolean = static fn (string $key): bool => filter_var(
    env($key, false),
    FILTER_VALIDATE_BOOL
);
$successful = static function (string $eventType) {
    return DB::table('taixue_oidc_audit_events')
        ->where('event_type', $eventType)
        ->where('outcome', 'SUCCEEDED')
        ->whereNotNull('uid')
        ->whereNotNull('subject');
};
$sessionRevoked = static function (string $source) use ($successful): int {
    return (clone $successful('SESSION_REVOKED'))
        ->where('metadata_json', 'like', '%"source":"'.$source.'"%')
        ->count();
};

$tables = [
    'taixue_oidc_links',
    'taixue_oidc_audit_events',
    'taixue_oidc_revocations',
    'taixue_oidc_provision_requests',
    'taixue_oidc_password_sync_requests',
    'taixue_oidc_password_versions',
    'taixue_oidc_cardinality_repairs',
];
$schemaReady = true;
foreach ($tables as $table) {
    if (!Schema::hasTable($table)) {
        $schemaReady = false;
        break;
    }
}
$schemaReady = $schemaReady &&
    Schema::hasColumn('taixue_oidc_revocations', 'event_type');

$rolloutMode = trim((string) env('TAIXUE_OIDC_ROLLOUT_MODE', 'allowlist'));
$allowedSubjectsEmpty = trim((string) env('TAIXUE_OIDC_ALLOWED_SUBJECTS', '')) === '';
$evidence = [
    'resolved_login' => $successful('LOGIN')->count(),
    'resolved_backchannel_logout' => $successful('BACKCHANNEL_LOGOUT')->count(),
    'resolved_coordinated_logout' => $successful('COORDINATED_LOGOUT')->count(),
    'session_revoked_by_backchannel' => $sessionRevoked('BACKCHANNEL_LOGOUT'),
    'session_revoked_by_coordinated' => $sessionRevoked('COORDINATED_LOGOUT'),
];
$gates = [
    'plugin_enabled' => $boolean('TAIXUE_OIDC_ENABLED'),
    'automatic_redirect' => $boolean('TAIXUE_OIDC_AUTO_REDIRECT'),
    'domain_creation_enabled' => $boolean('TAIXUE_OIDC_CREATE_ENABLED'),
    'rollout_all' => $rolloutMode === 'all',
    'allowlist_empty' => $allowedSubjectsEmpty,
    'schema_ready' => $schemaReady,
    'login_journey_proven' => $evidence['resolved_login'] > 0,
    'backchannel_delivery_proven' => $evidence['resolved_backchannel_logout'] > 0,
    'coordinated_delivery_proven' => $evidence['resolved_coordinated_logout'] > 0,
    'backchannel_session_revocation_proven' => $evidence['session_revoked_by_backchannel'] > 0,
    'coordinated_session_revocation_proven' => $evidence['session_revoked_by_coordinated'] > 0,
];

$report = [
    'safe_to_enable_unified_identity_only' => !in_array(false, $gates, true),
    'unified_identity_only_currently_enabled' => $boolean('TAIXUE_OIDC_UNIFIED_IDENTITY_ONLY'),
    'configuration' => [
        // Account creation is owned by the user service through the signed
        // domain endpoint. Local OIDC callback auto-registration should stay
        // disabled and is diagnostic information, not an acceptance gate.
        'automatic_registration' => $boolean('TAIXUE_OIDC_AUTO_REGISTER'),
    ],
    'gates' => $gates,
    'evidence' => $evidence,
    'checked_at' => gmdate(DATE_ATOM),
];

echo json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES).PHP_EOL;
if (in_array('--require-ready', $argv, true) && !$report['safe_to_enable_unified_identity_only']) {
    exit(2);
}
