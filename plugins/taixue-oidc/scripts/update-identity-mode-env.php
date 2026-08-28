#!/usr/bin/env php
<?php

require_once __DIR__.'/../src/RolloutEnvUpdater.php';

use Taixue\Oidc\RolloutEnvUpdater;

$flags = [
    'auto-redirect' => 'auto_redirect',
    'unified-identity-only' => 'unified_identity_only',
    'auto-register' => 'auto_register',
    'create-enabled' => 'create_enabled',
    'show-login-button' => 'show_login_button',
];
$optionNames = ['env:', 'backup:', 'apply'];
foreach (array_keys($flags) as $flag) {
    $optionNames[] = 'expect-'.$flag.':';
    $optionNames[] = 'set-'.$flag.':';
}
$options = getopt('', $optionNames);
if (!isset($options['env']) || !is_string($options['env'])) {
    fwrite(STDERR, "identity-mode-env: --env is required\n");
    exit(2);
}

$parseBoolean = static function (string $name, mixed $value): bool {
    if (!is_string($value) || !in_array(strtolower(trim($value)), ['true', 'false'], true)) {
        throw new InvalidArgumentException('--'.$name.' must be exactly true or false.');
    }

    return strtolower(trim($value)) === 'true';
};

try {
    $expected = [];
    $desired = [];
    foreach ($flags as $option => $field) {
        $expected[$field] = $parseBoolean('expect-'.$option, $options['expect-'.$option] ?? null);
        $desired[$field] = $parseBoolean('set-'.$option, $options['set-'.$option] ?? null);
    }
    $apply = array_key_exists('apply', $options);
    $backup = isset($options['backup']) && is_string($options['backup']) ? $options['backup'] : '';
    $report = RolloutEnvUpdater::updateIdentityModeFile(
        $options['env'],
        $backup,
        $expected,
        $desired,
        $apply
    );
    printf(
        "%s before_sha256=%s after_sha256=%s changed=%s\n",
        $apply ? 'updated' : 'dry-run',
        $report['before_sha256'],
        $report['after_sha256'],
        $report['changed'] ? 'true' : 'false'
    );
} catch (Throwable $error) {
    fwrite(STDERR, 'identity-mode-env: '.$error->getMessage()."\n");
    exit(1);
}
