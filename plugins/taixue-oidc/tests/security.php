<?php

require __DIR__.'/../vendor/autoload.php';
require_once __DIR__.'/../src/SafeRedirect.php';

use Firebase\JWT\JWT;
use Taixue\Oidc\CoordinatedRevocationVerifier;
use Taixue\Oidc\AuditImpact;
use Taixue\Oidc\EndpointFailure;
use Taixue\Oidc\IdTokenVerifier;
use Taixue\Oidc\LinkConsistency;
use Taixue\Oidc\LogoutTokenVerifier;
use Taixue\Oidc\OidcClient;
use Taixue\Oidc\OidcFlowException;
use Taixue\Oidc\OidcSession;
use Taixue\Oidc\PendingOidcFlow;
use Taixue\Oidc\ProvisioningNotifier;
use Taixue\Oidc\RolloutPolicy;
use Taixue\Oidc\SafeRedirect;
use Taixue\Oidc\UnifiedIdentityBoundary;
use Taixue\Oidc\Controllers\ProvisionAccountController;
use Taixue\Oidc\Controllers\PasswordSyncController;
use Taixue\Oidc\Controllers\CardinalityRepairController;

$oidcClientSource = file_get_contents(__DIR__.'/../src/OidcClient.php');
$authControllerSource = file_get_contents(__DIR__.'/../src/Controllers/AuthController.php');
$bootstrapSource = file_get_contents(__DIR__.'/../bootstrap.php');
$routesSource = file_get_contents(__DIR__.'/../routes.php');
$provisioningSource = file_get_contents(__DIR__.'/../src/ProvisioningNotifier.php');
$accountProvisionerSource = file_get_contents(__DIR__.'/../src/SkinAccountProvisioner.php');
$unlinkedViewSource = file_get_contents(__DIR__.'/../views/unlinked.twig');
$errorViewSource = file_get_contents(__DIR__.'/../views/error.twig');
$provisionAccountControllerSource = file_get_contents(
    __DIR__.'/../src/Controllers/ProvisionAccountController.php'
);
$passwordSyncControllerSource = file_get_contents(
    __DIR__.'/../src/Controllers/PasswordSyncController.php'
);
$cardinalityRepairControllerSource = file_get_contents(
    __DIR__.'/../src/Controllers/CardinalityRepairController.php'
);
$manifest = json_decode(file_get_contents(__DIR__.'/../package.json'), true, 512, JSON_THROW_ON_ERROR);
if (($manifest['version'] ?? null) !== '0.3.22') {
    throw new RuntimeException('OIDC security contracts require the current plugin release');
}

foreach ([
    'https://auth.taixue.cc/api/v1/internal/blessing-skin/provisioning' => true,
    'https://auth.taixue.cc/v1/internal/blessing-skin/provisioning' => false,
    'https://user.service.internal/v1/internal/blessing-skin/provisioning' => true,
    'https://proxy.internal/api/v1/internal/blessing-skin/provisioning' => true,
    'https://user:secret@user.service.internal/v1/internal/blessing-skin/provisioning' => false,
    'https://user.service.internal/v1/internal/blessing-skin/provisioning?debug=1' => false,
    'http://user.service.internal/v1/internal/blessing-skin/provisioning' => false,
] as $endpoint => $expected) {
    if (ProvisioningNotifier::endpointIsValid($endpoint) !== $expected) {
        throw new RuntimeException('Provisioning receipt endpoint validation is unsafe');
    }
}

$flowSecret = rtrim(strtr(base64_encode(str_repeat('x', 32)), '+/', '-_'), '=');
$validFlow = PendingOidcFlow::validate([
    'state' => $flowSecret,
    'nonce' => $flowSecret,
    'verifier' => $flowSecret,
    'intent' => 'login',
    'created_at' => 1000,
], 1001);
if ($validFlow['state'] !== $flowSecret || $validFlow['intent'] !== 'login') {
    throw new RuntimeException('Valid pending OIDC flow was not preserved');
}
foreach ([
    ['state' => [], 'nonce' => $flowSecret, 'verifier' => $flowSecret, 'intent' => 'login', 'created_at' => 1000],
    ['state' => $flowSecret, 'nonce' => $flowSecret, 'verifier' => 'short', 'intent' => 'login', 'created_at' => 1000],
    ['state' => $flowSecret, 'nonce' => $flowSecret, 'verifier' => $flowSecret, 'intent' => 'link', 'created_at' => 1000],
    ['state' => $flowSecret, 'nonce' => $flowSecret, 'verifier' => $flowSecret, 'intent' => 'login', 'created_at' => 1],
] as $invalidFlow) {
    try {
        PendingOidcFlow::validate($invalidFlow, 1001);
        throw new RuntimeException('Expected malformed pending OIDC flow rejection');
    } catch (OidcFlowException $error) {
        if ($error->reason() !== 'flow_expired') {
            throw $error;
        }
    }
}
if (!str_contains($bootstrapSource, "config('session.secure')") ||
    !str_contains($bootstrapSource, 'SESSION_SECURE_COOKIE')) {
    throw new RuntimeException('OIDC must fail closed without Secure session cookies');
}
if (str_contains($routesSource, 'user/taixue-account') ||
    str_contains($routesSource, 'admin/taixue-oidc') ||
    str_contains($routesSource, 'role:admin') ||
    !str_contains($authControllerSource, "if (\$intent !== 'login')") ||
    str_contains($authControllerSource, 'completeLink') ||
    str_contains($authControllerSource, 'completeUnlink') ||
    str_contains($authControllerSource, 'completeLocalPasswordAuthorization') ||
    str_contains($oidcClientSource, 'SENSITIVE_INTENTS') ||
    str_contains($oidcClientSource, "'uid' => \$uid")) {
    throw new RuntimeException('Legacy self-link and role-based migration pages must not remain routable');
}
foreach ([
    __DIR__.'/../src/Controllers/AccountController.php',
    __DIR__.'/../src/Controllers/AdminController.php',
    __DIR__.'/../src/FreshAuthentication.php',
    __DIR__.'/../src/FreshAuthGrant.php',
    __DIR__.'/../views/account.twig',
    __DIR__.'/../views/admin.twig',
    __DIR__.'/../views/local-password.twig',
] as $retiredIdentitySurface) {
    if (file_exists($retiredIdentitySurface)) {
        throw new RuntimeException('Retired local identity surface is still shipped');
    }
}
if (str_contains($accountProvisionerSource, '到账号页面完成绑定') ||
    str_contains($accountProvisionerSource, '请先完成账号关联') ||
    str_contains($unlinkedViewSource, '自行绑定') === false ||
    str_contains($unlinkedViewSource, 'account_settings_url') === false) {
    throw new RuntimeException('Account conflicts must route to unified permissioned repair');
}
if (!str_contains($authControllerSource, 'UnifiedIdentityBoundary::recoveryNavigation(') ||
    !str_contains($errorViewSource, 'retry_url') ||
    !str_contains($errorViewSource, 'local_recovery_url') ||
    str_contains($errorViewSource, "url('/auth/login')")) {
    throw new RuntimeException('Automatic OIDC entry must offer an explicit loop-safe gray-rollout recovery path');
}
$grayRecovery = UnifiedIdentityBoundary::recoveryNavigation(false, 'https://skin.taixue.cc/');
$unifiedRecovery = UnifiedIdentityBoundary::recoveryNavigation(true, 'https://skin.taixue.cc/');
if ($grayRecovery !== [
    'retry_url' => 'https://skin.taixue.cc/auth/taixue',
    'local_recovery_url' => 'https://skin.taixue.cc/auth/login?local=1',
] || $unifiedRecovery !== [
    'retry_url' => 'https://skin.taixue.cc/auth/taixue',
    'local_recovery_url' => null,
]) {
    throw new RuntimeException('Recovery navigation must avoid redirect loops and close local login in unified-only mode');
}
$backchannelControllerSource = file_get_contents(__DIR__.'/../src/Controllers/BackchannelLogoutController.php');
$coordinatedControllerSource = file_get_contents(__DIR__.'/../src/Controllers/CoordinatedLogoutController.php');
$revocationStoreSource = file_get_contents(__DIR__.'/../src/RevocationStore.php');
$sessionGuardSource = file_get_contents(__DIR__.'/../src/OidcSessionGuard.php');
$identityBoundarySource = file_get_contents(__DIR__.'/../src/UnifiedIdentityBoundary.php');
$callbacksSource = file_get_contents(__DIR__.'/../callbacks.php');
$acceptanceAuditSource = file_get_contents(__DIR__.'/../scripts/audit-unified-only-acceptance.php');
foreach ([
    "'auth/taixue/backchannel-logout'",
    "'auth/taixue/coordinated-logout'",
    'BackchannelLogoutController::class',
    'CoordinatedLogoutController::class',
    'pushMiddlewareToGroup',
    'OidcSessionGuard::class',
    'ReadinessController::class',
] as $logoutIntegration) {
    if (!str_contains($bootstrapSource, $logoutIntegration)) {
        throw new RuntimeException('OIDC back-channel logout integration is incomplete');
    }
}
if (!str_contains($bootstrapSource, "'auth/taixue/ready'") ||
    !str_contains($readinessSource = file_get_contents(__DIR__.'/../src/Controllers/ReadinessController.php'),
        "'taixue_oidc_revocations'") ||
    !str_contains($readinessSource, '$needsProvisioning = $autoRegister || $createEnabled') ||
    !str_contains($readinessSource, 'OidcClient::standardPasswordChangeUrl')) {
    throw new RuntimeException('OIDC readiness probe must verify the migration schema without mutating audit data');
}
if (!str_contains($accountProvisionerSource, 'new Events\\PlayerWillBeAdded($playerName)') ||
    !str_contains($accountProvisionerSource, 'new Events\\PlayerWasAdded($player)') ||
    !str_contains($accountProvisionerSource, '$user->players()->count() !== 1') ||
    !str_contains($authControllerSource, '$provisioning->notify(')) {
    throw new RuntimeException('OIDC provisioning must create exactly one player and acknowledge it after commit');
}
if (!str_contains($bootstrapSource, "'auth/taixue/provision-account'") ||
    !str_contains($provisionAccountControllerSource, "TAIXUE_OIDC_CREATE_SECRET") ||
    !str_contains($provisionAccountControllerSource, "taixue_oidc_provision_requests") ||
    !str_contains($provisionAccountControllerSource, '$notifier->notify(')) {
    throw new RuntimeException('Server-to-server skin provisioning must be signed, replay-safe, and acknowledged');
}
if (ProvisionAccountController::payload(
    '8675309',
    ' PlayerOne ',
    'skin-provision:42',
    1_800_000_000
) !== "v1-create\n1800000000\nskin-provision:42\n8675309\nplayerone") {
    throw new RuntimeException('Account creation signature payload must stay compatible with the user service');
}
if (ProvisionAccountController::semanticPayload('8675309', ' PlayerOne ') !==
    ProvisionAccountController::semanticPayload('8675309', 'playerone')) {
    throw new RuntimeException('Account creation replay identity must survive timestamped retries');
}
if (!str_contains($bootstrapSource, "'auth/taixue/sync-password'") ||
    !str_contains($passwordSyncControllerSource, 'taixue_oidc_password_sync_requests') ||
    !str_contains($passwordSyncControllerSource, 'TAIXUE_OIDC_PASSWORD_SYNC_SECRET') ||
    str_contains($passwordSyncControllerSource, 'TAIXUE_OIDC_CREATE_SECRET') ||
    !str_contains($readinessSource, '$passwordSyncConfigured') ||
    !str_contains($passwordSyncControllerSource, "User::where('uid', \$uid)->lockForUpdate()->first()")) {
    throw new RuntimeException('Password synchronization must be signed, binding-checked, and replay-safe');
}
if (!str_contains($bootstrapSource, "'extra:user.player'") ||
    !str_contains($bootstrapSource, "'identityManaged'") ||
    !str_contains($bootstrapSource, "'/settings'")) {
    throw new RuntimeException('Unified player identity must render as managed instead of exposing dead mutation controls');
}
if (PasswordSyncController::payload(
    '8675309', 7, 99, str_repeat('a', 64), 'password:42:99', 1_800_000_000
) !== "v1-password\n1800000000\npassword:42:99\n8675309\n7\n99\n".str_repeat('a', 64)) {
    throw new RuntimeException('Password synchronization signature payload must stay compatible with the user service');
}
if (!str_contains($passwordSyncControllerSource, "User::where('uid', \$uid)->lockForUpdate()->first()") ||
    !str_contains($passwordSyncControllerSource, "hash_equals((string) \$user->password, \$passwordHash)") ||
    !str_contains($passwordSyncControllerSource, '$user->saveOrFail();') ||
    str_contains($passwordSyncControllerSource, '$updated !== 1')) {
    throw new RuntimeException('Password synchronization must treat an identical verifier as idempotent success');
}
if (!str_contains($bootstrapSource, "'auth/taixue/repair-cardinality'") ||
    !str_contains($cardinalityRepairControllerSource, 'taixue_oidc_cardinality_repairs') ||
    !str_contains($cardinalityRepairControllerSource, 'PlayerWillBeAdded') ||
    !str_contains($cardinalityRepairControllerSource, 'PlayerWillBeDeleted') ||
    !str_contains($cardinalityRepairControllerSource, "DB::table('user_closet')->where('user_uid', \$uid)->count()") ||
    !str_contains($readinessSource, "'taixue_oidc_cardinality_repairs'")) {
    throw new RuntimeException('Cardinality repair must be signed, replay-safe, domain-native, and readiness-gated');
}
$repairPayload = [
    'mode' => 'APPLY',
    'uid' => 2324,
    'action' => 'CREATE_PLAYER',
    'expected_revision' => str_repeat('a', 64),
    'canonical_player_id' => null,
    'new_player_name' => 'Qishuang06',
];
if (CardinalityRepairController::payload(
    $repairPayload,
    1_800_000_000,
    'skin-repair:2324'
) !== "v1-cardinality-repair\n1800000000\nskin-repair:2324\nAPPLY\n2324\nCREATE_PLAYER\n".
    str_repeat('a', 64)."\n\nqishuang06") {
    throw new RuntimeException('Cardinality repair signature payload must stay compatible with the user service');
}
foreach (['TAIXUE_OIDC_PROVISIONING_URL', 'TAIXUE_OIDC_PROVISIONING_SECRET'] as $configName) {
    if (!str_contains($provisioningSource, $configName)) {
        throw new RuntimeException('OIDC provisioning receipt configuration is incomplete');
    }
}
if (ProvisioningNotifier::payload(
    '8675309',
    7,
    ' PlayerOne ',
    'oidc-request-123',
    1_800_000_000,
    [
        'player_id' => 70, 'skin_texture_id' => 3, 'cape_texture_id' => 4,
        'player_last_modified' => '2026-08-28 02:00:00',
        'nickname' => 'PlayerOne', 'email' => 'oidc-test@users.invalid',
        'password_hash' => '$SHA$hash', 'authme_realname' => 'PlayerOne',
        'authme_password_hash' => '', 'registered_at' => '2026-08-28 02:00:00',
        'last_signed_at' => '2026-08-27 02:00:00',
    ]
) !== "v2\n1800000000\noidc-request-123\n8675309\n7\nplayerone\n70\n3\n4\n".
    "2026-08-28 02:00:00\nPlayerOne\noidc-test@users.invalid\n\$SHA\$hash\n".
    "PlayerOne\n\n2026-08-28 02:00:00\n2026-08-27 02:00:00") {
    throw new RuntimeException('Provisioning signature payload must stay compatible with the user service');
}
if (ProvisioningNotifier::safeUpstreamCode(' CONFLICT ') !== 'CONFLICT' ||
    ProvisioningNotifier::safeUpstreamCode('provisioning_rejected') !== 'provisioning_rejected' ||
    ProvisioningNotifier::safeUpstreamCode('contains-sensitive message') !== null ||
    ProvisioningNotifier::safeUpstreamCode(str_repeat('a', 65)) !== null) {
    throw new RuntimeException('Provisioning observability must retain only bounded machine error codes');
}
if (EndpointFailure::outcome(new OidcFlowException('logout_token_missing', 'invalid')) !== 'REJECTED' ||
    EndpointFailure::status(new OidcFlowException('logout_token_missing', 'invalid')) !== 400 ||
    EndpointFailure::outcome(new OidcFlowException('flow_expired', 'expired')) !== 'REJECTED' ||
    EndpointFailure::outcome(new OidcFlowException('jwks_unavailable', 'down')) !== 'FAILED' ||
    EndpointFailure::status(new OidcFlowException('create_endpoint_disabled', 'down')) !== 503 ||
    EndpointFailure::status(new OidcFlowException('provisioning_unavailable', 'down')) !== 503 ||
    EndpointFailure::status(new OidcFlowException('token_exchange_failed', 'down')) !== 503 ||
    EndpointFailure::status(new RuntimeException('database unavailable')) !== 503) {
    throw new RuntimeException('OIDC endpoint failures must distinguish rejected input from service outages');
}
$workflowPath = __DIR__.'/../../../.github/workflows/taixue-oidc.yaml';
if (is_file($workflowPath)) {
    $workflowSource = file_get_contents($workflowPath);
    if (str_contains($workflowSource, 'logout_token=invalid') ||
        str_contains($workflowSource, "--data '{}'")) {
        throw new RuntimeException('Production deployment probes must not manufacture security failures');
    }
}
if (!str_contains($backchannelControllerSource, "request('logout_token')") ||
    !str_contains($backchannelControllerSource, "->header('Cache-Control', 'no-store')") ||
    !str_contains($revocationStoreSource, 'insertOrIgnore')) {
    throw new RuntimeException('Back-channel logout must be no-store and replay-safe');
}
foreach (['X-Request-ID', 'X-Taixue-Timestamp', 'X-Taixue-Signature'] as $signedHeader) {
    if (!str_contains($coordinatedControllerSource, $signedHeader)) {
        throw new RuntimeException('Coordinated logout is missing a signed request field');
    }
}
if (!str_contains($sessionGuardSource, 'Auth::logout()') ||
    !str_contains($sessionGuardSource, '$request->session()->invalidate();') ||
    !str_contains($sessionGuardSource, "Schema::hasTable('taixue_oidc_revocations')") ||
    !str_contains($sessionGuardSource, "'SESSION_REVOKED'") ||
    !str_contains($sessionGuardSource, "'revocation_match'") ||
    !str_contains($sessionGuardSource, "'BACKCHANNEL_LOGOUT'") ||
    !str_contains($sessionGuardSource, "'COORDINATED_LOGOUT'") ||
    !str_contains($sessionGuardSource, "'source' => \$source") ||
    !str_contains($sessionGuardSource, "'sid_present'") ||
    !str_contains($sessionGuardSource, "->get(['event_type'])") ||
    str_contains($sessionGuardSource, "->first(['event_type'])") ||
    !str_contains($sessionGuardSource, '$sources[$source] = true') ||
    !str_contains($sessionGuardSource, 'foreach (array_keys($sources) as $source)')) {
    throw new RuntimeException('Revoked OIDC sessions must be invalidated locally');
}
if (!str_contains($callbacksSource, "'event_type', 64") ||
    !str_contains($callbacksSource, "hasColumn('taixue_oidc_revocations', 'event_type')") ||
    !str_contains($readinessSource, "hasColumn('taixue_oidc_revocations', 'event_type')") ||
    !str_contains($revocationStoreSource, "'event_type' => \$eventType")) {
    throw new RuntimeException('Revocation source must be durable and readiness-gated');
}
foreach ([
    'safe_to_enable_unified_identity_only',
    'resolved_backchannel_logout',
    'resolved_coordinated_logout',
    'session_revoked_by_backchannel',
    'session_revoked_by_coordinated',
    "whereNotNull('uid')",
    "whereNotNull('subject')",
    "'--require-ready'",
] as $acceptanceContract) {
    if (!str_contains($acceptanceAuditSource, $acceptanceContract)) {
        throw new RuntimeException('Unified-only acceptance audit is incomplete');
    }
}
if (!preg_match('/\$gates\s*=\s*\[(.*?)\];/s', $acceptanceAuditSource, $acceptanceGates) ||
    str_contains($acceptanceGates[1], 'automatic_registration') ||
    !str_contains($acceptanceAuditSource, "'configuration' => [") ||
    !str_contains($acceptanceAuditSource, "'automatic_registration' => \$boolean('TAIXUE_OIDC_AUTO_REGISTER')")) {
    throw new RuntimeException('Local callback auto-registration must be diagnostic-only because signed domain creation owns provisioning');
}
foreach (['CLIENT_SECRET', 'REVOCATION_SECRET', 'PASSWORD_SYNC_SECRET'] as $forbiddenAcceptanceOutput) {
    if (str_contains($acceptanceAuditSource, $forbiddenAcceptanceOutput)) {
        throw new RuntimeException('Unified-only acceptance audit must not read or emit secrets');
    }
}
foreach (["'logout_token' =>", "'jti' =>", "'sid' =>"] as $forbiddenSessionAuditField) {
    if (str_contains($sessionGuardSource, $forbiddenSessionAuditField)) {
        throw new RuntimeException('Session revocation audit must not persist replay or session material');
    }
}
foreach ([
    'TAIXUE_OIDC_UNIFIED_IDENTITY_ONLY',
    "['password', 'email']",
    "\$action === 'delete'",
    '皮肤站账号固定对应唯一玩家',
    "\$path === 'user/player/bind'",
    "str_starts_with(\$path, 'auth/verify/')",
    "\$path === 'user/email-verification'",
    '邮箱与联系方式由太学统一账号管理',
    "\$request->isMethod('get')",
    "response()->json([",
    '], 403)',
] as $identityBoundary) {
    if (!str_contains($identityBoundarySource, $identityBoundary)) {
        throw new RuntimeException('Unified identity mode must block local identity and player mutations');
    }
}
if (!str_contains($bootstrapSource, "'grid:user.profile'") ||
    !str_contains($bootstrapSource, "'grid:user.index'") ||
    !str_contains($bootstrapSource, "'grid:user.closet'") ||
    !str_contains($bootstrapSource, "'user.widgets.email-verification'") ||
    !str_contains($bootstrapSource, 'protectsCurrentUserIdentity') ||
    !str_contains($bootstrapSource, "'user.widgets.profile.delete-account'") ||
    !str_contains($bootstrapSource, "['can_add_player', 'can_delete_player', 'can_rename_player']") ||
    !str_contains($bootstrapSource, 'UnifiedIdentityBoundary::class')) {
    throw new RuntimeException('Unified identity controls must be installed at both UI and request boundaries');
}
if (!OidcSession::belongsToUser([
    'uid' => 42,
    'subject' => '8675309',
], 42) ||
    OidcSession::belongsToUser(['uid' => 42, 'subject' => '8675309'], 43) ||
    OidcSession::belongsToUser(['uid' => 42, 'subject' => 'not-stable'], 42) ||
    OidcSession::belongsToUser(null, 42)) {
    throw new RuntimeException('OIDC-managed profile boundaries must follow verified session provenance');
}
if (str_contains($oidcClientSource, "request('error')")) {
    throw new RuntimeException('OAuth provider error input must not be reflected to users');
}

$flowRead = strpos($oidcClientSource, "session()->get('taixue_oidc_flow')");
$stateCheck = strpos($oidcClientSource, 'hash_equals($expectedState, $returnedState)');
$flowConsume = strpos($oidcClientSource, "session()->forget('taixue_oidc_flow')", $stateCheck ?: 0);
if ($flowRead === false || $stateCheck === false || $flowConsume === false ||
    !($flowRead < $stateCheck && $stateCheck < $flowConsume) ||
    str_contains($oidcClientSource, "session()->pull('taixue_oidc_flow')")) {
    throw new RuntimeException('OIDC state must be validated before the pending flow is consumed');
}
if (!str_contains($authControllerSource, 'request()->session()->regenerate();')) {
    throw new RuntimeException('OIDC login must rotate the local session identifier');
}
if (!str_contains($authControllerSource, 'EndpointFailure::outcome($e)') ||
    !str_contains($authControllerSource, 'EndpointFailure::status($e)')) {
    throw new RuntimeException('OIDC callbacks must distinguish user rejection from retryable service failure');
}
if (!str_contains($authControllerSource, 'Auth::login($user, false);') ||
    str_contains($authControllerSource, 'Auth::login($user, true);')) {
    throw new RuntimeException('OIDC login must not create an implicit remember-me cookie');
}
if (!str_contains($authControllerSource, '$message = $e instanceof OidcFlowException') ||
    str_contains($authControllerSource, '$message = $e instanceof \\RuntimeException')) {
    throw new RuntimeException('Only bounded OIDC flow errors may be exposed to the browser');
}
if (str_contains($authControllerSource, "'account_state_rejected'")) {
    throw new RuntimeException('OIDC account failures must retain bounded actionable reasons');
}
foreach ([
    '/user/profile' => '/user/profile',
    'https://skin.taixue.cc/user/profile?tab=oauth' => 'https://skin.taixue.cc/user/profile?tab=oauth',
    'https://evil.example/' => 'https://skin.taixue.cc/user',
    '//evil.example/' => 'https://skin.taixue.cc/user',
    '/\\evil.example/' => 'https://skin.taixue.cc/user',
] as $candidate => $expected) {
    if (SafeRedirect::resolve(
        $candidate,
        'https://skin.taixue.cc',
        'https://skin.taixue.cc/user'
    ) !== $expected) {
        throw new RuntimeException('OIDC post-login redirects must stay on the local site');
    }
}
$typedFailure = new OidcFlowException('nonce_mismatch', 'safe message');
if ($typedFailure->reason() !== 'nonce_mismatch' ||
    (new OidcFlowException('../unsafe', 'safe message'))->reason() !== 'invalid_failure_reason') {
    throw new RuntimeException('OIDC failure reason normalization failed');
}
$authControllerSource = file_get_contents(__DIR__.'/../src/Controllers/AuthController.php');
if (!str_contains($authControllerSource, '$e->reason()')) {
    throw new RuntimeException('OIDC callback audit must persist typed failure reasons');
}
if (str_contains($callbacksSource, "dropIfExists('taixue_oidc_links')") ||
    str_contains($callbacksSource, "dropIfExists('taixue_oidc_audit_events')") ||
    str_contains($callbacksSource, "dropIfExists('taixue_oidc_revocations')") ||
    str_contains($callbacksSource, "dropIfExists('taixue_oidc_provision_requests')") ||
    str_contains($callbacksSource, "dropIfExists('taixue_oidc_password_sync_requests')") ||
    str_contains($callbacksSource, "dropIfExists('taixue_oidc_password_versions')")) {
    throw new RuntimeException('Plugin rollback must preserve OIDC migration data');
}

$bootstrapSource = file_get_contents(__DIR__.'/../bootstrap.php');
if (!str_contains($identityBoundarySource, "\$path === 'auth/forgot'") ||
    !str_contains($identityBoundarySource, "str_starts_with(\$path, 'auth/reset/')") ||
    !str_contains($identityBoundarySource, "taixueUrl('/recover')")) {
    throw new RuntimeException(
        'Unified identity mode must delegate password recovery to Taixue'
    );
}
if (str_contains($bootstrapSource, "listen('auth.reset.after'")) {
    throw new RuntimeException('Blessing Skin must not maintain a second authoritative password');
}

if (AuditImpact::label(12345, 'stable-subject') !== '已关联账号' ||
    AuditImpact::label(null, 'stable-subject') !== '已验证太学账号，尚未映射' ||
    AuditImpact::label(null, null) !== '未验证账号（端点流量）') {
    throw new RuntimeException(
        'OIDC operations must distinguish linked-user failures from unverified endpoint traffic'
    );
}

if (OidcClient::scopesFor(false) !== 'openid profile blessing_skin' ||
    OidcClient::scopesFor(true) !== 'openid profile blessing_skin email') {
    throw new RuntimeException(
        'OIDC client must request blessing_skin while limiting email to auto-registration'
    );
}
$rfc7636Verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
if (OidcClient::pkceChallenge($rfc7636Verifier) !==
    'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM') {
    throw new RuntimeException('OIDC PKCE S256 challenge does not match RFC 7636');
}
foreach (['short', str_repeat('a', 129), str_repeat('a', 42).'!'] as $badVerifier) {
    try {
        OidcClient::pkceChallenge($badVerifier);
        throw new RuntimeException('Expected invalid PKCE verifier rejection');
    } catch (OidcFlowException $error) {
        if ($error->reason() !== 'pkce_verifier_invalid') {
            throw $error;
        }
    }
}
$fixedCallback = 'https://skin.taixue.cc/auth/taixue/callback';
if (OidcClient::validateRedirectUri($fixedCallback) !== $fixedCallback ||
    !str_contains($oidcClientSource, "env('TAIXUE_OIDC_REDIRECT_URI', '')") ||
    str_contains($oidcClientSource, "route('taixue-oidc.callback')")) {
    throw new RuntimeException('OIDC callback must use a fixed validated client redirect URI');
}
foreach ([
    '',
    'http://skin.taixue.cc/auth/taixue/callback',
    'https://skin.taixue.cc',
    'https://skin.taixue.cc/auth/taixue/callback?next=https://evil.invalid',
    'https://user:pass@skin.taixue.cc/auth/taixue/callback',
] as $badRedirectUri) {
    try {
        OidcClient::validateRedirectUri($badRedirectUri);
        throw new RuntimeException('Expected invalid OIDC redirect URI rejection');
    } catch (OidcFlowException $error) {
        if ($error->reason() !== 'redirect_uri_invalid') {
            throw $error;
        }
    }
}

if (OidcClient::standardPasswordChangeUrl('https://auth.taixue.cc/') !==
    'https://auth.taixue.cc/.well-known/change-password') {
    throw new RuntimeException('OIDC password change URL must use the configured issuer');
}
if (OidcClient::standardPasswordRecoveryUrl('https://auth.taixue.cc/') !==
    'https://auth.taixue.cc/recover') {
    throw new RuntimeException('OIDC recovery must use the unified account recovery page');
}

$loginHelpSource = file_get_contents(__DIR__.'/../views/login-help.twig');
if (!str_contains($loginHelpSource, 'data-taixue-recovery') ||
    str_contains($loginHelpSource, 'data-local-recovery')) {
    throw new RuntimeException(
        'The plugin must add unified recovery without duplicating Blessing Skin recovery'
    );
}

if (!str_contains($identityBoundarySource, "env('TAIXUE_OIDC_AUTO_REDIRECT', false)") ||
    !str_contains($identityBoundarySource, "redirect()->route('taixue-oidc.login')") ||
    file_exists(__DIR__.'/../views/login-redirect.twig')) {
    throw new RuntimeException('Automatic unified login must use an HTTP redirect and retain the explicit local recovery bypass');
}
if (!UnifiedIdentityBoundary::shouldRedirectToUnifiedLogin('auth/login', 'GET', null, true) ||
    UnifiedIdentityBoundary::shouldRedirectToUnifiedLogin('auth/login', 'GET', '1', true) ||
    UnifiedIdentityBoundary::shouldRedirectToUnifiedLogin('auth/login', 'POST', null, true) ||
    UnifiedIdentityBoundary::shouldRedirectToUnifiedLogin('auth/login', 'GET', null, false) ||
    UnifiedIdentityBoundary::shouldRedirectToUnifiedLogin('auth/forgot', 'GET', null, true)) {
    throw new RuntimeException('Unified-login HTTP redirect decision does not fail closed');
}
if (!UnifiedIdentityBoundary::shouldRedirectToUnifiedLogin('auth/login', 'GET', '1', false, true) ||
    !UnifiedIdentityBoundary::shouldRedirectToUnifiedLogin('auth/login', 'GET', null, false, true) ||
    UnifiedIdentityBoundary::shouldRedirectToUnifiedLogin('auth/login', 'POST', null, false, true) ||
    !str_contains($bootstrapSource, "\$filter->add('can_login'") ||
    !str_contains($bootstrapSource, "'rejectLocalLogin'")) {
    throw new RuntimeException('Unified-only mode must reject both the local login page bypass and direct password submissions');
}
if (!UnifiedIdentityBoundary::configurationIsSafe(false, false, 'bound', '') ||
    !UnifiedIdentityBoundary::configurationIsSafe(true, true, 'all', '') ||
    UnifiedIdentityBoundary::configurationIsSafe(true, false, 'all', '') ||
    UnifiedIdentityBoundary::configurationIsSafe(true, true, 'bound', '') ||
    UnifiedIdentityBoundary::configurationIsSafe(true, true, 'all', '63719050877927426')) {
    throw new RuntimeException('Unified-only readiness must require automatic entry and a complete all rollout');
}
foreach ([
    ['admin/users/7/email', 'PUT'],
    ['api/admin/users/7/password', 'PUT'],
    ['admin/users/7', 'DELETE'],
    ['admin/players/9/name', 'PUT'],
    ['api/admin/players/9/owner', 'PUT'],
    ['api/admin/players/9', 'DELETE'],
] as [$path, $method]) {
    if (!UnifiedIdentityBoundary::isNativeAdminIdentityMutation($path, $method)) {
        throw new RuntimeException('Native role-based identity repair bypass remains open: '.$method.' '.$path);
    }
}
foreach ([
    ['admin/users', 'GET'],
    ['admin/users/7/nickname', 'PUT'],
    ['admin/users/7/score', 'PUT'],
    ['admin/players/9/textures', 'PUT'],
    ['api/players/9/textures', 'DELETE'],
    ['admin/reports/7', 'PUT'],
] as [$path, $method]) {
    if (UnifiedIdentityBoundary::isNativeAdminIdentityMutation($path, $method)) {
        throw new RuntimeException('Operational skin-site action was incorrectly blocked: '.$method.' '.$path);
    }
}
if (!str_contains($bootstrapSource, "pushMiddlewareToGroup('api', UnifiedIdentityBoundary::class)")) {
    throw new RuntimeException('Unified identity boundary must cover Blessing Skin OAuth API mutations');
}
if (!str_contains($bootstrapSource, "'Taixue\\Oidc::login-help'") ||
    strpos($bootstrapSource, "'Taixue\\Oidc::login-help'") >
        strpos($bootstrapSource, "if (!config('session.secure'))")) {
    throw new RuntimeException('Password recovery must survive an OIDC configuration rollback');
}

$coordinatedVerifier = new CoordinatedRevocationVerifier();
$coordinatedSubject = '8675309';
$coordinatedRequestId = 'session-revocation:123456789';
$coordinatedTimestamp = 1_800_000_000;
$coordinatedSecret = '0123456789abcdef0123456789abcdef';
$coordinatedSignature = 'v1='.hash_hmac(
    'sha256',
    CoordinatedRevocationVerifier::payload(
        $coordinatedSubject,
        $coordinatedRequestId,
        $coordinatedTimestamp
    ),
    $coordinatedSecret
);
$coordinatedVerifier->verify(
    $coordinatedSubject,
    $coordinatedRequestId,
    (string) $coordinatedTimestamp,
    $coordinatedSignature,
    $coordinatedSecret,
    $coordinatedTimestamp + 10
);
foreach ([
    ['other-subject', $coordinatedRequestId, (string) $coordinatedTimestamp, $coordinatedSignature, $coordinatedSecret, $coordinatedTimestamp + 10],
    [$coordinatedSubject, 'short', (string) $coordinatedTimestamp, $coordinatedSignature, $coordinatedSecret, $coordinatedTimestamp + 10],
    [$coordinatedSubject, $coordinatedRequestId, (string) $coordinatedTimestamp, $coordinatedSignature, 'too-short', $coordinatedTimestamp + 10],
    [$coordinatedSubject, $coordinatedRequestId, (string) $coordinatedTimestamp, $coordinatedSignature, $coordinatedSecret, $coordinatedTimestamp + 301],
] as $invalidCoordinatedRequest) {
    try {
        $coordinatedVerifier->verify(...$invalidCoordinatedRequest);
        throw new RuntimeException('Expected rejection: invalid coordinated logout request');
    } catch (RuntimeException $e) {
        if ($e->getMessage() === 'Expected rejection: invalid coordinated logout request') {
            throw $e;
        }
    }
}

foreach ([
    'http://auth.taixue.cc',
    'https://attacker.invalid@auth.taixue.cc',
    'https://auth.taixue.cc?next=https://attacker.invalid',
    'https://auth.taixue.cc#attacker',
] as $unsafeIssuer) {
    try {
        OidcClient::standardPasswordChangeUrl($unsafeIssuer);
        throw new RuntimeException('Expected rejection: unsafe OIDC issuer');
    } catch (RuntimeException $e) {
        if ($e->getMessage() === 'Expected rejection: unsafe OIDC issuer') {
            throw $e;
        }
    }
}

$allowlist = new RolloutPolicy('allowlist', '1001, 1002');
if (!$allowlist->allows('1001') || $allowlist->allows('1003')) {
    throw new RuntimeException('OIDC allowlist rollout policy failed');
}
if ((new RolloutPolicy('allowlist', ''))->allows('1001')) {
    throw new RuntimeException('Empty OIDC allowlist must fail closed');
}
if (!(new RolloutPolicy('all', ''))->allows('1001')) {
    throw new RuntimeException('OIDC all rollout mode failed');
}
if ((new RolloutPolicy('invalid', '1001'))->allows('1001')) {
    throw new RuntimeException('Invalid OIDC rollout mode must fail closed');
}
$bound = new RolloutPolicy('bound', '');
if (!$bound->allowsClaims(['sub' => '1003', 'bs_uid' => 42], 'login') ||
    !$bound->allowsClaims(['sub' => '1003', 'bs_uid' => '42'], 'login') ||
    $bound->allowsClaims(['sub' => '1003'], 'login') ||
    $bound->allowsClaims(['sub' => '1003', 'bs_uid' => 0], 'login') ||
    $bound->allowsClaims(['sub' => '1003', 'bs_uid' => 'not-an-id'], 'login') ||
    $bound->allowsClaims(['bs_uid' => 42], 'login')) {
    throw new RuntimeException('Bound-account OIDC rollout policy failed closed');
}
if ($bound->allowsClaims(['sub' => '1003', 'bs_uid' => 42], 'link') ||
    $bound->allowsClaims(['sub' => '1003', 'bs_uid' => 42], 'unlink') ||
    $bound->allowsClaims(['sub' => '1003', 'bs_uid' => 42], 'local_password')) {
    throw new RuntimeException('Rollout policy must reject retired account-management intents');
}
if (strpos($bound->denialMessage(), '尚未关联') === false) {
    throw new RuntimeException('Bound-account rollout must explain the next action');
}

$privateKey = openssl_pkey_new([
    'digest_alg' => 'sha256',
    'private_key_bits' => 2048,
    'private_key_type' => OPENSSL_KEYTYPE_RSA,
]);
openssl_pkey_export($privateKey, $privatePem);
$details = openssl_pkey_get_details($privateKey);
$b64 = fn (string $value) => rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
$jwks = ['keys' => [[
    'kty' => 'RSA',
    'kid' => 'test-key',
    'use' => 'sig',
    'alg' => 'RS256',
    'n' => $b64($details['rsa']['n']),
    'e' => $b64($details['rsa']['e']),
]]];

$issuer = 'https://auth.taixue.cc';
$clientId = 'blessing-skin-test';
$nonce = 'one-time-nonce';
$baseClaims = [
    'iss' => $issuer,
    'aud' => $clientId,
    'sub' => '9223372036854775000',
    'bs_uid' => 12345,
    'nonce' => $nonce,
    'iat' => time(),
    'exp' => time() + 300,
];
$encode = fn (array $claims) => JWT::encode($claims, $privatePem, 'RS256', 'test-key');
$verifier = new IdTokenVerifier();

$assertFails = function (array $claims, string $label) use ($encode, $verifier, $jwks, $issuer, $clientId, $nonce) {
    try {
        $verifier->verify($encode($claims), $jwks, $issuer, $clientId, $nonce);
    } catch (RuntimeException) {
        return;
    }
    throw new RuntimeException("Expected rejection: $label");
};

$verified = $verifier->verify($encode($baseClaims), $jwks, $issuer, $clientId, $nonce);
if ($verified['sub'] !== $baseClaims['sub']) {
    throw new RuntimeException('Valid token subject was not preserved');
}
if ($verified['bs_uid'] !== 12345) {
    throw new RuntimeException('Signed Blessing Skin UID claim was not preserved');
}
$assertFails(array_merge($baseClaims, ['nonce' => 'replayed']), 'nonce mismatch');
$assertFails(array_merge($baseClaims, ['iss' => 'https://attacker.invalid']), 'issuer mismatch');
$assertFails(array_merge($baseClaims, ['aud' => 'another-client']), 'audience mismatch');
$assertFails(array_merge($baseClaims, ['aud' => [$clientId, 'another-client']]), 'multiple audiences without azp');
$assertFails(array_merge($baseClaims, ['aud' => [$clientId, 'another-client'], 'azp' => 'another-client']), 'authorized party mismatch');
$assertFails(array_merge($baseClaims, ['aud' => [$clientId, 123]]), 'non-string audience member');
$assertFails(array_merge($baseClaims, ['aud' => []]), 'empty audience');
$assertFails(array_merge($baseClaims, ['sub' => '']), 'empty subject');
$assertFails(array_merge($baseClaims, ['sub' => 'not-a-stable-id']), 'non-numeric subject');
$assertFails(array_merge($baseClaims, ['sub' => str_repeat('1', 21)]), 'oversized subject');
$assertFails(array_merge($baseClaims, ['nonce' => ['not-a-string']]), 'non-string nonce');
$assertFails(array_merge($baseClaims, ['exp' => time() - 120]), 'expired token');
$withoutIssuedAt = $baseClaims;
unset($withoutIssuedAt['iat']);
$assertFails($withoutIssuedAt, 'missing issued-at time');
$withoutExpiry = $baseClaims;
unset($withoutExpiry['exp']);
$assertFails($withoutExpiry, 'missing expiry time');
$assertFails(array_merge($baseClaims, ['iat' => (string) time()]), 'non-numeric-date issued-at time');
$assertFails(array_merge($baseClaims, ['exp' => (string) (time() + 300)]), 'non-numeric-date expiry time');
$assertFails(array_merge($baseClaims, ['exp' => $baseClaims['iat']]), 'expiry not after issuance');

$multiAudienceClaims = array_merge($baseClaims, [
    'aud' => [$clientId, 'another-client'],
    'azp' => $clientId,
]);
$verifier->verify($encode($multiAudienceClaims), $jwks, $issuer, $clientId, $nonce);

$logoutVerifier = new LogoutTokenVerifier();
$logoutClaims = [
    'iss' => $issuer,
    'aud' => $clientId,
    'sub' => $baseClaims['sub'],
    'sid' => 'provider-session-1',
    'iat' => time(),
    'exp' => time() + 300,
    'jti' => 'logout-request-1',
    'events' => [LogoutTokenVerifier::EVENT => (object) []],
];
$verifiedLogout = $logoutVerifier->verify(
    $encode($logoutClaims),
    $jwks,
    $issuer,
    $clientId
);
if ($verifiedLogout['jti'] !== 'logout-request-1' ||
    $verifiedLogout['sid'] !== 'provider-session-1') {
    throw new RuntimeException('Valid Logout Token target was not preserved');
}

$assertLogoutFails = function (array $claims, string $label) use (
    $encode,
    $logoutVerifier,
    $jwks,
    $issuer,
    $clientId
) {
    try {
        $logoutVerifier->verify($encode($claims), $jwks, $issuer, $clientId);
    } catch (RuntimeException) {
        return;
    }
    throw new RuntimeException("Expected Logout Token rejection: $label");
};
$assertLogoutFails(array_merge($logoutClaims, ['iss' => 'https://attacker.invalid']), 'issuer mismatch');
$assertLogoutFails(array_merge($logoutClaims, ['aud' => 'another-client']), 'audience mismatch');
$assertLogoutFails(array_merge($logoutClaims, ['aud' => [$clientId, 'another-client']]), 'multiple audiences without azp');
$assertLogoutFails(array_merge($logoutClaims, ['aud' => [$clientId, 'another-client'], 'azp' => 'another-client']), 'authorized party mismatch');
$assertLogoutFails(array_merge($logoutClaims, ['exp' => time() - 120]), 'expired token');
$assertLogoutFails(array_merge($logoutClaims, ['iat' => time() + 120]), 'future token');
$assertLogoutFails(array_merge($logoutClaims, ['jti' => '']), 'missing jti');
$assertLogoutFails(array_diff_key($logoutClaims, ['sub' => true, 'sid' => true]), 'missing target');
$assertLogoutFails(array_merge($logoutClaims, ['events' => []]), 'missing logout event');
$assertLogoutFails(array_merge($logoutClaims, ['events' => [LogoutTokenVerifier::EVENT => 'invalid']]), 'invalid logout event');
$assertLogoutFails(array_merge($logoutClaims, ['nonce' => 'forbidden']), 'forbidden nonce');

$subjectOnlyLogout = $logoutClaims;
unset($subjectOnlyLogout['sid']);
$logoutVerifier->verify($encode($subjectOnlyLogout), $jwks, $issuer, $clientId);
$sidOnlyLogout = $logoutClaims;
unset($sidOnlyLogout['sub']);
$logoutVerifier->verify($encode($sidOnlyLogout), $jwks, $issuer, $clientId);
$multiAudienceLogout = array_merge($logoutClaims, [
    'aud' => [$clientId, 'another-client'],
    'azp' => $clientId,
]);
$logoutVerifier->verify($encode($multiAudienceLogout), $jwks, $issuer, $clientId);

LinkConsistency::assertSubjectOwner((object) ['uid' => 12345], 12345);
try {
    LinkConsistency::assertSubjectOwner((object) ['uid' => 54321], 12345);
    throw new RuntimeException('Expected rejection: conflicting signed Blessing Skin UID');
} catch (RuntimeException $e) {
    if ($e->getMessage() === 'Expected rejection: conflicting signed Blessing Skin UID') {
        throw $e;
    }
}

$header = $b64(json_encode(['alg' => 'HS256', 'typ' => 'JWT', 'kid' => 'test-key']));
$payload = $b64(json_encode($baseClaims));
$forged = $header.'.'.$payload.'.'.$b64(hash_hmac('sha256', $header.'.'.$payload, $details['key'], true));
try {
    $verifier->verify($forged, $jwks, $issuer, $clientId, $nonce);
    throw new RuntimeException('Expected rejection: algorithm confusion');
} catch (RuntimeException $e) {
    if ($e->getMessage() === 'Expected rejection: algorithm confusion') {
        throw $e;
    }
}

echo "OIDC token security checks passed\n";
