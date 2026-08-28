<?php

require_once __DIR__.'/../src/RolloutEnvUpdater.php';

use Taixue\Oidc\RolloutEnvUpdater;

$subject = '63719050877927426';
if (RolloutEnvUpdater::parseSubjectArgument('-') !== []) {
    throw new RuntimeException('The CLI empty-list sentinel must remain unambiguous.');
}
if (RolloutEnvUpdater::parseSubjectArgument($subject) !== [$subject]) {
    throw new RuntimeException('Large stable subjects must remain strings during CLI parsing.');
}
$input = "APP_NAME=太学皮肤站\nTAIXUE_OIDC_CLIENT_SECRET=do-not-log-or-change\nTAIXUE_OIDC_ROLLOUT_MODE=allowlist\nTAIXUE_OIDC_ALLOWED_SUBJECTS={$subject}\n";
$bound = RolloutEnvUpdater::update($input, 'allowlist', [$subject], 'bound', []);
if (!str_contains($bound, "APP_NAME=太学皮肤站\n") ||
    !str_contains($bound, "TAIXUE_OIDC_CLIENT_SECRET=do-not-log-or-change\n") ||
    !str_contains($bound, "TAIXUE_OIDC_ROLLOUT_MODE=bound\n") ||
    !str_contains($bound, "TAIXUE_OIDC_ALLOWED_SUBJECTS=\n")) {
    throw new RuntimeException('Bound rollout must preserve UTF-8 and unrelated secrets byte-for-byte.');
}
if (RolloutEnvUpdater::update($bound, 'bound', [], 'bound', []) !== $bound) {
    throw new RuntimeException('Replaying the same rollout policy must be idempotent.');
}
$crlf = str_replace("\n", "\r\n", $input);
$crlfBound = RolloutEnvUpdater::update($crlf, 'allowlist', [$subject], 'bound', []);
if (substr_count($crlfBound, "\r\n") !== substr_count($crlf, "\r\n") ||
    str_contains(str_replace("\r\n", '', $crlfBound), "\n")) {
    throw new RuntimeException('Rollout updates must preserve CRLF line endings.');
}
$callbackUri = 'https://skin.taixue.cc/auth/taixue/callback';
$withCallback = RolloutEnvUpdater::updateRedirectUri($input, null, $callbackUri);
if (!str_contains($withCallback, "TAIXUE_OIDC_REDIRECT_URI={$callbackUri}\n") ||
    !str_contains($withCallback, "APP_NAME=太学皮肤站\n") ||
    !str_contains($withCallback, "TAIXUE_OIDC_CLIENT_SECRET=do-not-log-or-change\n") ||
    RolloutEnvUpdater::updateRedirectUri($withCallback, $callbackUri, $callbackUri) !== $withCallback) {
    throw new RuntimeException('Redirect URI updates must be idempotent and preserve UTF-8 secrets.');
}
$crlfCallback = RolloutEnvUpdater::updateRedirectUri($crlf, null, $callbackUri);
if (str_contains(str_replace("\r\n", '', $crlfCallback), "\n")) {
    throw new RuntimeException('Redirect URI updates must preserve CRLF line endings.');
}

$identityBound = $bound.
    "TAIXUE_OIDC_AUTO_REDIRECT=false\n".
    "TAIXUE_OIDC_UNIFIED_IDENTITY_ONLY=false\n".
    "TAIXUE_OIDC_AUTO_REGISTER=false\n".
    "TAIXUE_OIDC_CREATE_ENABLED=true\n".
    "TAIXUE_OIDC_SHOW_LOGIN_BUTTON=true\n";
$recoveryIdentityMode = [
    'auto_redirect' => false,
    'unified_identity_only' => false,
    'auto_register' => false,
    'create_enabled' => true,
    'show_login_button' => true,
];
$automaticIdentityMode = [
    'auto_redirect' => true,
    'unified_identity_only' => false,
    'auto_register' => false,
    'create_enabled' => true,
    'show_login_button' => false,
];
$automatic = RolloutEnvUpdater::updateIdentityMode(
    $identityBound,
    $recoveryIdentityMode,
    $automaticIdentityMode
);
if (!str_contains($automatic, "TAIXUE_OIDC_AUTO_REDIRECT=true\n") ||
    !str_contains($automatic, "TAIXUE_OIDC_UNIFIED_IDENTITY_ONLY=false\n") ||
    !str_contains($automatic, "TAIXUE_OIDC_SHOW_LOGIN_BUTTON=false\n") ||
    !str_contains($automatic, "TAIXUE_OIDC_CLIENT_SECRET=do-not-log-or-change\n")) {
    throw new RuntimeException('Identity mode update must change only the explicit non-secret gates.');
}
$defaultIdentityMode = [
    'auto_redirect' => false,
    'unified_identity_only' => false,
    'auto_register' => false,
    'create_enabled' => false,
    'show_login_button' => false,
];
$appendedDefaults = RolloutEnvUpdater::updateIdentityMode(
    $bound,
    $defaultIdentityMode,
    $defaultIdentityMode
);
foreach ([
    'TAIXUE_OIDC_AUTO_REDIRECT=false',
    'TAIXUE_OIDC_UNIFIED_IDENTITY_ONLY=false',
    'TAIXUE_OIDC_AUTO_REGISTER=false',
    'TAIXUE_OIDC_CREATE_ENABLED=false',
    'TAIXUE_OIDC_SHOW_LOGIN_BUTTON=false',
] as $appendedDefault) {
    if (substr_count($appendedDefaults, $appendedDefault) !== 1) {
        throw new RuntimeException('Missing identity gates must be materialized from their effective false defaults.');
    }
}
$crlfDefaults = RolloutEnvUpdater::updateIdentityMode(
    $crlfBound,
    $defaultIdentityMode,
    $defaultIdentityMode
);
if (str_contains(str_replace("\r\n", '', $crlfDefaults), "\n")) {
    throw new RuntimeException('Appended identity gates must preserve CRLF line endings.');
}
if (RolloutEnvUpdater::updateIdentityMode(
    $automatic,
    $automaticIdentityMode,
    $automaticIdentityMode
) !== $automatic) {
    throw new RuntimeException('Replaying the same identity mode must be idempotent.');
}

$identityAll = str_replace(
    "TAIXUE_OIDC_ROLLOUT_MODE=bound\n",
    "TAIXUE_OIDC_ROLLOUT_MODE=all\n",
    $automatic
);
$unifiedIdentityMode = $automaticIdentityMode;
$unifiedIdentityMode['unified_identity_only'] = true;
$unified = RolloutEnvUpdater::updateIdentityMode(
    $identityAll,
    $automaticIdentityMode,
    $unifiedIdentityMode
);
if (!str_contains($unified, "TAIXUE_OIDC_UNIFIED_IDENTITY_ONLY=true\n")) {
    throw new RuntimeException('Accepted all rollout must support an audited unified-only transition.');
}

foreach ([
    fn () => RolloutEnvUpdater::update($input, 'bound', [], 'all', []),
    fn () => RolloutEnvUpdater::update($input, 'allowlist', [$subject], 'bound', [$subject]),
    fn () => RolloutEnvUpdater::update($input, 'allowlist', [$subject], 'allowlist', []),
    fn () => RolloutEnvUpdater::parseSubjectArgument('1,1'),
    fn () => RolloutEnvUpdater::parseSubjectArgument('not-an-id'),
    fn () => RolloutEnvUpdater::update("TAIXUE_OIDC_ROLLOUT_MODE=bound\nTAIXUE_OIDC_ALLOWED_SUBJECTS=\n\xff", 'bound', [], 'all', []),
    fn () => RolloutEnvUpdater::updateIdentityMode(
        $identityBound,
        $automaticIdentityMode,
        $unifiedIdentityMode
    ),
    fn () => RolloutEnvUpdater::updateIdentityMode(
        $identityBound,
        $recoveryIdentityMode,
        array_merge($recoveryIdentityMode, ['unified_identity_only' => true])
    ),
    fn () => RolloutEnvUpdater::updateIdentityMode(
        str_replace('TAIXUE_OIDC_AUTO_REDIRECT=false', 'TAIXUE_OIDC_AUTO_REDIRECT=1', $identityBound),
        $recoveryIdentityMode,
        $automaticIdentityMode
    ),
    fn () => RolloutEnvUpdater::updateRedirectUri($input, $callbackUri, $callbackUri),
    fn () => RolloutEnvUpdater::updateRedirectUri($input, null, 'http://skin.taixue.cc/auth/taixue/callback'),
    fn () => RolloutEnvUpdater::updateRedirectUri(
        $input."TAIXUE_OIDC_REDIRECT_URI={$callbackUri}\nTAIXUE_OIDC_REDIRECT_URI={$callbackUri}\n",
        $callbackUri,
        $callbackUri
    ),
] as $invalid) {
    try {
        $invalid();
        throw new RuntimeException('Expected rollout policy rejection.');
    } catch (RuntimeException $error) {
        if ($error->getMessage() === 'Expected rollout policy rejection.') {
            throw $error;
        }
    }
}

$directory = sys_get_temp_dir().'/taixue-rollout-'.bin2hex(random_bytes(8));
if (!mkdir($directory, 0700)) {
    throw new RuntimeException('Unable to create rollout test directory.');
}
$envPath = $directory.'/.env';
$backupPath = $directory.'/before.env';
try {
    file_put_contents($envPath, $input);
    chmod($envPath, 0640);
    $owner = fileowner($envPath);
    $group = filegroup($envPath);
    $dryRun = RolloutEnvUpdater::updateFile(
        $envPath, $backupPath, 'allowlist', [$subject], 'bound', [], false
    );
    if (!$dryRun['changed'] || file_exists($backupPath) || file_get_contents($envPath) !== $input) {
        throw new RuntimeException('Dry-run must not write the environment or backup.');
    }
    $applied = RolloutEnvUpdater::updateFile(
        $envPath, $backupPath, 'allowlist', [$subject], 'bound', [], true
    );
    if (!$applied['changed'] || file_get_contents($envPath) !== $bound ||
        file_get_contents($backupPath) !== $input || (fileperms($backupPath) & 0777) !== 0600 ||
        fileowner($envPath) !== $owner || filegroup($envPath) !== $group) {
        throw new RuntimeException('Applied rollout must atomically update and preserve a private backup.');
    }
    $noopBackup = $directory.'/noop.env';
    $noop = RolloutEnvUpdater::updateFile($envPath, $noopBackup, 'bound', [], 'bound', [], true);
    if ($noop['changed'] || file_exists($noopBackup) || file_get_contents($envPath) !== $bound) {
        throw new RuntimeException('An idempotent apply must not create a backup or rewrite the environment.');
    }
    try {
        RolloutEnvUpdater::updateFile($envPath, $backupPath, 'bound', [], 'all', [], true);
        throw new RuntimeException('An existing backup must prevent a second mutation.');
    } catch (RuntimeException $error) {
        if ($error->getMessage() === 'An existing backup must prevent a second mutation.') {
            throw $error;
        }
    }
    if (file_get_contents($envPath) !== $bound) {
        throw new RuntimeException('A rejected mutation must leave the environment unchanged.');
    }
} finally {
    foreach ([$backupPath, $directory.'/noop.env', $envPath] as $file) {
        if (is_file($file)) {
            unlink($file);
        }
    }
    rmdir($directory);
}

$redirectDirectory = sys_get_temp_dir().'/taixue-redirect-'.bin2hex(random_bytes(8));
if (!mkdir($redirectDirectory, 0700)) {
    throw new RuntimeException('Unable to create redirect URI test directory.');
}
$redirectEnvPath = $redirectDirectory.'/.env';
$redirectBackupPath = $redirectDirectory.'/before.env';
try {
    file_put_contents($redirectEnvPath, $input);
    chmod($redirectEnvPath, 0640);
    $owner = fileowner($redirectEnvPath);
    $group = filegroup($redirectEnvPath);
    $dryRun = RolloutEnvUpdater::updateRedirectUriFile(
        $redirectEnvPath, $redirectBackupPath, null, $callbackUri, false
    );
    if (!$dryRun['changed'] || file_exists($redirectBackupPath) ||
        file_get_contents($redirectEnvPath) !== $input) {
        throw new RuntimeException('Redirect URI dry-run must not write files.');
    }
    $applied = RolloutEnvUpdater::updateRedirectUriFile(
        $redirectEnvPath, $redirectBackupPath, null, $callbackUri, true
    );
    if (!$applied['changed'] || file_get_contents($redirectEnvPath) !== $withCallback ||
        file_get_contents($redirectBackupPath) !== $input ||
        (fileperms($redirectBackupPath) & 0777) !== 0600 ||
        fileowner($redirectEnvPath) !== $owner || filegroup($redirectEnvPath) !== $group) {
        throw new RuntimeException('Redirect URI apply must be atomic and preserve a private backup.');
    }
} finally {
    foreach ([$redirectBackupPath, $redirectEnvPath] as $file) {
        if (is_file($file)) {
            unlink($file);
        }
    }
    rmdir($redirectDirectory);
}

echo "rollout env tests passed\n";
