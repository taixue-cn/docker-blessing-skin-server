<?php

require __DIR__.'/../vendor/autoload.php';

use Firebase\JWT\JWT;
use Taixue\Oidc\IdTokenVerifier;
use Taixue\Oidc\LinkConsistency;
use Taixue\Oidc\FreshAuthGrant;
use Taixue\Oidc\FreshAuthentication;
use Taixue\Oidc\OidcClient;
use Taixue\Oidc\RolloutPolicy;

$oidcClientSource = file_get_contents(__DIR__.'/../src/OidcClient.php');
if (!str_contains($oidcClientSource, "\$parameters['prompt'] = 'login'") ||
    !str_contains($oidcClientSource, "\$parameters['max_age'] = 0") ||
    !str_contains($oidcClientSource, "['unlink', 'local_password']")) {
    throw new RuntimeException('Recovery-boundary changes must require fresh Taixue authentication');
}
$callbacksSource = file_get_contents(__DIR__.'/../callbacks.php');
if (str_contains($callbacksSource, "dropIfExists('taixue_oidc_links')") ||
    str_contains($callbacksSource, "dropIfExists('taixue_oidc_audit_events')")) {
    throw new RuntimeException('Plugin rollback must preserve OIDC migration data');
}

if (OidcClient::SCOPES !== 'openid profile email blessing_skin') {
    throw new RuntimeException('OIDC client must request the dedicated blessing_skin scope');
}

if (OidcClient::standardPasswordChangeUrl('https://auth.taixue.cc/') !==
    'https://auth.taixue.cc/.well-known/change-password') {
    throw new RuntimeException('OIDC password change URL must use the configured issuer');
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
if ((new RolloutPolicy('allowlist', ''))->allows('1001')) {
    throw new RuntimeException('Empty OIDC allowlist must fail closed');
}
if (!(new RolloutPolicy('all', ''))->allows('1001')) {
    throw new RuntimeException('OIDC all rollout mode failed');
}
if ((new RolloutPolicy('invalid', '1001'))->allows('1001')) {
    throw new RuntimeException('Invalid OIDC rollout mode must fail closed');
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
