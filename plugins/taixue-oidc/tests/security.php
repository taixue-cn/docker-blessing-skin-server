<?php

require __DIR__.'/../vendor/autoload.php';

use Firebase\JWT\JWT;
use Taixue\Oidc\IdTokenVerifier;
use Taixue\Oidc\OidcClient;

if (OidcClient::SCOPES !== 'openid profile email blessing_skin') {
    throw new RuntimeException('OIDC client must request the dedicated blessing_skin scope');
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
$assertFails(array_merge($baseClaims, ['sub' => '']), 'empty subject');
$assertFails(array_merge($baseClaims, ['exp' => time() - 120]), 'expired token');

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
