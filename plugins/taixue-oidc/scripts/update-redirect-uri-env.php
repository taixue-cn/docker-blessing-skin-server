#!/usr/bin/env php
<?php

require_once __DIR__.'/../src/RolloutEnvUpdater.php';

use Taixue\Oidc\RolloutEnvUpdater;

$options = getopt('', [
    'env:',
    'expect:',
    'set:',
    'backup:',
    'apply',
]);
foreach (['env', 'expect', 'set'] as $required) {
    if (!array_key_exists($required, $options) || !is_string($options[$required])) {
        fwrite(STDERR, "redirect-uri-env: --{$required} is required\n");
        exit(2);
    }
}

$expected = trim($options['expect']) === '-' ? null : $options['expect'];
$apply = array_key_exists('apply', $options);
$backup = isset($options['backup']) && is_string($options['backup']) ? $options['backup'] : '';
try {
    $report = RolloutEnvUpdater::updateRedirectUriFile(
        $options['env'],
        $backup,
        $expected,
        $options['set'],
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
    fwrite(STDERR, 'redirect-uri-env: '.$error->getMessage()."\n");
    exit(1);
}
