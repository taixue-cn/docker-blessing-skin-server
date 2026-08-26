<?php

require __DIR__.'/../vendor/autoload.php';
require_once __DIR__.'/../src/SafeRedirect.php';

use Firebase\JWT\JWT;
use Taixue\Oidc\CoordinatedRevocationVerifier;
use Taixue\Oidc\IdTokenVerifier;
use Taixue\Oidc\LinkConsistency;
use Taixue\Oidc\LogoutTokenVerifier;
use Taixue\Oidc\FreshAuthGrant;
use Taixue\Oidc\FreshAuthentication;
use Taixue\Oidc\OidcClient;
use Taixue\Oidc\OidcFlowException;
use Taixue\Oidc\RolloutPolicy;
use Taixue\Oidc\SafeRedirect;

$oidcClientSource = file_get_contents(__DIR__.'/../src/OidcClient.php');
$authControllerSource = file_get_contents(__DIR__.'/../src/Controllers/AuthController.php');
$bootstrapSource = file_get_contents(__DIR__.'/../bootstrap.php');
$adminControllerSource = file_get_contents(__DIR__.'/../src/Controllers/AdminController.php');
$adminViewSource = file_get_contents(__DIR__.'/../views/admin.twig');
if (!str_contains($bootstrapSource, "config('session.secure')") ||
    !str_contains($bootstrapSource, 'SESSION_SECURE_COOKIE')) {
    throw new RuntimeException('OIDC must fail closed without Secure session cookies');
}
$backchannelControllerSource = file_get_contents(__DIR__.'/../src/Controllers/BackchannelLogoutController.php');
$coordinatedControllerSource = file_get_contents(__DIR__.'/../src/Controllers/CoordinatedLogoutController.php');
$revocationStoreSource = file_get_contents(__DIR__.'/../src/RevocationStore.php');
$sessionGuardSource = file_get_contents(__DIR__.'/../src/OidcSessionGuard.php');
foreach ([
    "'auth/taixue/backchannel-logout'",
    "'auth/taixue/coordinated-logout'",
    'BackchannelLogoutController::class',
    'CoordinatedLogoutController::class',
    'pushMiddlewareToGroup',
    'OidcSessionGuard::class',
] as $logoutIntegration) {
    if (!str_contains($bootstrapSource, $logoutIntegration)) {
        throw new RuntimeException('OIDC back-channel logout integration is incomplete');
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
    !str_contains($sessionGuardSource, "Schema::hasTable('taixue_oidc_revocations')")) {
    throw new RuntimeException('Revoked OIDC sessions must be invalidated locally');
}
if (!str_contains($oidcClientSource, "\$parameters['prompt'] = 'login'") ||
    !str_contains($oidcClientSource, "\$parameters['max_age'] = 0") ||
    !str_contains($oidcClientSource, "['unlink', 'local_password']")) {
    throw new RuntimeException('Recovery-boundary changes must require fresh Taixue authentication');
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
$callbacksSource = file_get_contents(__DIR__.'/../callbacks.php');
if (str_contains($callbacksSource, "dropIfExists('taixue_oidc_links')") ||
    str_contains($callbacksSource, "dropIfExists('taixue_oidc_audit_events')") ||
    str_contains($callbacksSource, "dropIfExists('taixue_oidc_revocations')")) {
    throw new RuntimeException('Plugin rollback must preserve OIDC migration data');
}

$bootstrapSource = file_get_contents(__DIR__.'/../bootstrap.php');
if (!str_contains($bootstrapSource, "listen('auth.reset.after'") ||
    !str_contains($bootstrapSource, "'provisioned' => false")) {
    throw new RuntimeException(
        'Blessing Skin password recovery must establish the local fallback credential'
    );
}
if (str_contains($bootstrapSource, "function (\$user, \$password)")) {
    throw new RuntimeException('Password recovery listener must not bind the plaintext password');
}

foreach ([
    "'LOGIN:SUCCEEDED'",
    "'LINK:SUCCEEDED'",
    "'BACKCHANNEL_LOGOUT:SUCCEEDED'",
    "'COORDINATED_LOGOUT:SUCCEEDED'",
    "'readyForExpansion'",
] as $requiredReadinessSignal) {
    if (!str_contains($adminControllerSource, $requiredReadinessSignal)) {
        throw new RuntimeException('OIDC admin readiness gate is missing '.$requiredReadinessSignal);
    }
}
if (!str_contains($adminViewSource, '扩量验收') ||
    !str_contains($adminViewSource, '证据与下一步')) {
    throw new RuntimeException('OIDC admin page must explain rollout blockers and next actions');
}

$routesSource = file_get_contents(__DIR__.'/../routes.php');
$adminControllerSource = file_get_contents(__DIR__.'/../src/Controllers/AdminController.php');
if (!str_contains($routesSource, "middleware(['auth', 'role:admin'])") ||
    !str_contains($routesSource, "admin/taixue-oidc")) {
    throw new RuntimeException('OIDC rollout telemetry must be restricted to skin-site admins');
}
foreach (['TAIXUE_OIDC_CLIENT_SECRET', 'TAIXUE_OIDC_ALLOWED_SUBJECTS'] as $sensitiveConfig) {
    if (str_contains($adminControllerSource, "'$sensitiveConfig' =>") ||
        str_contains($adminControllerSource, "\"$sensitiveConfig\" =>")) {
        throw new RuntimeException('OIDC rollout telemetry must not expose sensitive configuration');
    }
}

if (OidcClient::scopesFor(false) !== 'openid profile blessing_skin' ||
    OidcClient::scopesFor(true) !== 'openid profile blessing_skin email') {
    throw new RuntimeException(
        'OIDC client must request blessing_skin while limiting email to auto-registration'
    );
}

if (OidcClient::standardPasswordChangeUrl('https://auth.taixue.cc/') !==
    'https://auth.taixue.cc/.well-known/change-password') {
    throw new RuntimeException('OIDC password change URL must use the configured issuer');
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

$grant = FreshAuthGrant::payload(12345, 'stable-subject', 1_000);
if (!FreshAuthGrant::payloadIsValid($grant, 12345, 'stable-subject', 1_100) ||
    FreshAuthGrant::payloadIsValid($grant, 54321, 'stable-subject', 1_100) ||
    FreshAuthGrant::payloadIsValid($grant, 12345, 'other-subject', 1_100) ||
    FreshAuthGrant::payloadIsValid($grant, 12345, 'stable-subject', 1_301) ||
    FreshAuthGrant::payloadIsValid($grant, 12345, 'stable-subject', 900)) {
    throw new RuntimeException('Fresh-auth local-password grant binding or expiry failed');
}
FreshAuthentication::assertClaims(['auth_time' => 1_005], 1_000, 1_100);
foreach ([
    [],
    ['auth_time' => 900],
    ['auth_time' => 1_200],
] as $staleClaims) {
    try {
        FreshAuthentication::assertClaims($staleClaims, 1_000, 1_100);
        throw new RuntimeException('Expected rejection: stale fresh-authentication proof');
    } catch (RuntimeException $e) {
        if ($e->getMessage() === 'Expected rejection: stale fresh-authentication proof') {
            throw $e;
        }
    }
}
$accountControllerSource = file_get_contents(__DIR__.'/../src/Controllers/AccountController.php');
foreach ([
    'FreshAuthGrant::consumeFor',
    'lockForUpdate()',
    '$user->changePassword',
    "'LOCAL_PASSWORD_SETUP', 'SUCCEEDED'",
] as $requiredLocalPasswordGate) {
    if (!str_contains($accountControllerSource, $requiredLocalPasswordGate)) {
        throw new RuntimeException('Local-password setup is missing a mandatory security gate');
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
if (!$allowlist->allowsIntent('1003', 'unlink') ||
    !$allowlist->allowsIntent('1003', 'local_password') ||
    $allowlist->allowsIntent('1003', 'login') ||
    $allowlist->allowsIntent('1003', 'link')) {
    throw new RuntimeException('OIDC rollout must preserve recovery without widening login or linking');
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
    !$bound->allowsClaims(['sub' => '1003', 'bs_uid' => '42'], 'link') ||
    $bound->allowsClaims(['sub' => '1003'], 'login') ||
    $bound->allowsClaims(['sub' => '1003', 'bs_uid' => 0], 'login') ||
    $bound->allowsClaims(['sub' => '1003', 'bs_uid' => 'not-an-id'], 'login') ||
    $bound->allowsClaims(['bs_uid' => 42], 'login')) {
    throw new RuntimeException('Bound-account OIDC rollout policy failed closed');
}
if (!$bound->allowsClaims(['sub' => '1003'], 'unlink') ||
    !$bound->allowsClaims(['sub' => '1003'], 'local_password')) {
    throw new RuntimeException('Bound-account rollout must preserve recovery intents');
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
$assertFails(array_merge($baseClaims, ['sub' => '']), 'empty subject');
$assertFails(array_merge($baseClaims, ['exp' => time() - 120]), 'expired token');

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
