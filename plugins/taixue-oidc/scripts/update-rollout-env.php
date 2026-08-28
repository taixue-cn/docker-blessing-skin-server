#!/usr/bin/env php
<?php

require_once __DIR__.'/../src/RolloutEnvUpdater.php';

use Taixue\Oidc\RolloutEnvUpdater;

$options = getopt('', [
    'env:',
    'expect-mode:',
    'expect-allowed-subjects:',
    'set-mode:',
    'set-allowed-subjects:',
    'backup:',
    'apply',
]);

foreach (['env', 'expect-mode', 'expect-allowed-subjects', 'set-mode', 'set-allowed-subjects'] as $required) {
    if (!array_key_exists($required, $options) || !is_string($options[$required])) {
        fwrite(STDERR, "rollout-env: --{$required} is required\n");
        exit(2);
    }
}
$apply = array_key_exists('apply', $options);
$backup = isset($options['backup']) && is_string($options['backup']) ? $options['backup'] : '';

try {
    $report = RolloutEnvUpdater::updateFile(
        $options['env'],
        $backup,
        $options['expect-mode'],
        RolloutEnvUpdater::parseSubjectArgument($options['expect-allowed-subjects']),
        $options['set-mode'],
        RolloutEnvUpdater::parseSubjectArgument($options['set-allowed-subjects']),
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
    fwrite(STDERR, 'rollout-env: '.$error->getMessage()."\n");
    exit(1);
}
