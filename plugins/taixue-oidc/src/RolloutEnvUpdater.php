<?php

namespace Taixue\Oidc;

use RuntimeException;

final class RolloutEnvUpdater
{
    private const MODES = ['allowlist', 'bound', 'all'];
    private const IDENTITY_MODE_KEYS = [
        'auto_redirect' => 'TAIXUE_OIDC_AUTO_REDIRECT',
        'unified_identity_only' => 'TAIXUE_OIDC_UNIFIED_IDENTITY_ONLY',
        'auto_register' => 'TAIXUE_OIDC_AUTO_REGISTER',
        'create_enabled' => 'TAIXUE_OIDC_CREATE_ENABLED',
        'show_login_button' => 'TAIXUE_OIDC_SHOW_LOGIN_BUTTON',
    ];

    public static function update(
        string $input,
        string $expectedMode,
        array $expectedSubjects,
        string $desiredMode,
        array $desiredSubjects
    ): string {
        self::requireUtf8($input);
        $expectedMode = self::normalizeMode($expectedMode);
        $desiredMode = self::normalizeMode($desiredMode);
        $expectedSubjects = self::normalizeSubjects($expectedSubjects);
        $desiredSubjects = self::normalizeSubjects($desiredSubjects);
        self::validateDesiredPolicy($desiredMode, $desiredSubjects);

        $currentMode = self::readSingleValue($input, 'TAIXUE_OIDC_ROLLOUT_MODE');
        $currentSubjects = self::normalizeSubjects(self::splitSubjects(
            self::readSingleValue($input, 'TAIXUE_OIDC_ALLOWED_SUBJECTS')
        ));
        if ($currentMode !== $expectedMode || $currentSubjects !== $expectedSubjects) {
            throw new RuntimeException('The rollout policy changed concurrently or does not match the expected value.');
        }

        $updated = self::replaceSingleValue($input, 'TAIXUE_OIDC_ROLLOUT_MODE', $desiredMode);
        $updated = self::replaceSingleValue(
            $updated,
            'TAIXUE_OIDC_ALLOWED_SUBJECTS',
            implode(',', $desiredSubjects)
        );
        self::requireUtf8($updated);

        return $updated;
    }

    public static function updateFile(
        string $envPath,
        string $backupPath,
        string $expectedMode,
        array $expectedSubjects,
        string $desiredMode,
        array $desiredSubjects,
        bool $apply
    ): array {
        return self::updateFileContents(
            $envPath,
            $backupPath,
            $apply,
            fn (string $before): string => self::update(
                $before,
                $expectedMode,
                $expectedSubjects,
                $desiredMode,
                $desiredSubjects
            )
        );
    }

    public static function updateIdentityMode(
        string $input,
        array $expected,
        array $desired
    ): string {
        self::requireUtf8($input);
        $expected = self::normalizeIdentityMode($expected);
        $desired = self::normalizeIdentityMode($desired);
        $current = [];
        foreach (self::IDENTITY_MODE_KEYS as $name => $key) {
            $current[$name] = self::readOptionalBooleanValue($input, $key);
        }
        if ($current !== $expected) {
            throw new RuntimeException('The identity mode changed concurrently or does not match the expected value.');
        }

        $currentRolloutMode = self::normalizeMode(
            self::readSingleValue($input, 'TAIXUE_OIDC_ROLLOUT_MODE')
        );
        $currentSubjects = self::normalizeSubjects(self::splitSubjects(
            self::readSingleValue($input, 'TAIXUE_OIDC_ALLOWED_SUBJECTS')
        ));
        if ($desired['unified_identity_only'] && !$desired['auto_redirect']) {
            throw new RuntimeException('Unified-only mode requires automatic OIDC entry.');
        }
        if ($desired['unified_identity_only'] &&
            ($currentRolloutMode !== 'all' || count($currentSubjects) !== 0)) {
            throw new RuntimeException('Unified-only mode requires an all rollout with an empty subject list.');
        }

        $updated = $input;
        foreach (self::IDENTITY_MODE_KEYS as $name => $key) {
            $updated = self::upsertSingleValue(
                $updated,
                $key,
                $desired[$name] ? 'true' : 'false'
            );
        }
        self::requireUtf8($updated);

        return $updated;
    }

    public static function updateIdentityModeFile(
        string $envPath,
        string $backupPath,
        array $expected,
        array $desired,
        bool $apply
    ): array {
        return self::updateFileContents(
            $envPath,
            $backupPath,
            $apply,
            fn (string $before): string => self::updateIdentityMode(
                $before,
                $expected,
                $desired
            )
        );
    }

    public static function updateRedirectUri(
        string $input,
        ?string $expected,
        string $desired
    ): string {
        self::requireUtf8($input);
        $expected = $expected === null ? null : self::normalizeRedirectUri($expected);
        $desired = self::normalizeRedirectUri($desired);
        $current = self::readOptionalSingleValue($input, 'TAIXUE_OIDC_REDIRECT_URI');
        if ($current !== $expected) {
            throw new RuntimeException(
                'The OIDC redirect URI changed concurrently or does not match the expected value.'
            );
        }

        $updated = self::upsertSingleValue($input, 'TAIXUE_OIDC_REDIRECT_URI', $desired);
        self::requireUtf8($updated);

        return $updated;
    }

    public static function updateRedirectUriFile(
        string $envPath,
        string $backupPath,
        ?string $expected,
        string $desired,
        bool $apply
    ): array {
        return self::updateFileContents(
            $envPath,
            $backupPath,
            $apply,
            fn (string $before): string => self::updateRedirectUri(
                $before,
                $expected,
                $desired
            )
        );
    }

    private static function updateFileContents(
        string $envPath,
        string $backupPath,
        bool $apply,
        callable $transform
    ): array {
        if ($envPath === '' || !is_file($envPath) || is_link($envPath)) {
            throw new RuntimeException('The environment file must be a regular, non-symlink file.');
        }
        $before = file_get_contents($envPath);
        if (!is_string($before)) {
            throw new RuntimeException('Unable to read the environment file.');
        }
        $after = $transform($before);
        $beforeHash = hash('sha256', $before);
        $afterHash = hash('sha256', $after);
        $report = [
            'before_sha256' => $beforeHash,
            'after_sha256' => $afterHash,
            'changed' => !hash_equals($beforeHash, $afterHash),
        ];
        if (!$apply) {
            return $report;
        }
        if (!$report['changed']) {
            return $report;
        }
        if ($backupPath === '' || $backupPath === $envPath) {
            throw new RuntimeException('A distinct backup path is required when applying.');
        }
        self::writeExclusiveBackup($backupPath, $before);

        $directory = dirname($envPath);
        $temporary = tempnam($directory, '.taixue-rollout-');
        if (!is_string($temporary)) {
            throw new RuntimeException('Unable to create an atomic update file.');
        }
        try {
            $mode = fileperms($envPath);
            $owner = fileowner($envPath);
            $group = filegroup($envPath);
            if ($mode === false || $owner === false || $group === false) {
                throw new RuntimeException('Unable to inspect environment file metadata.');
            }
            self::writeFile($temporary, $after);
            if ((fileowner($temporary) !== $owner && !@chown($temporary, $owner)) ||
                (filegroup($temporary) !== $group && !@chgrp($temporary, $group)) ||
                !chmod($temporary, $mode & 0777)) {
                throw new RuntimeException('Unable to preserve environment file permissions.');
            }
            clearstatcache(true, $temporary);
            if (fileowner($temporary) !== $owner || filegroup($temporary) !== $group ||
                (fileperms($temporary) & 0777) !== ($mode & 0777)) {
                throw new RuntimeException('The atomic update file metadata does not match the environment file.');
            }
            $latest = file_get_contents($envPath);
            if (!is_string($latest) || !hash_equals($beforeHash, hash('sha256', $latest))) {
                throw new RuntimeException('The environment file changed after it was inspected.');
            }
            if (!rename($temporary, $envPath)) {
                throw new RuntimeException('Unable to atomically replace the environment file.');
            }
            $temporary = '';
        } finally {
            if ($temporary !== '' && is_file($temporary)) {
                @unlink($temporary);
            }
        }

        return $report;
    }

    private static function normalizeIdentityMode(array $mode): array {
        $normalized = [];
        foreach (self::IDENTITY_MODE_KEYS as $name => $_key) {
            if (!array_key_exists($name, $mode) || !is_bool($mode[$name])) {
                throw new RuntimeException('Identity mode requires an explicit boolean '.$name.'.');
            }
            $normalized[$name] = $mode[$name];
        }
        if (count($mode) !== count(self::IDENTITY_MODE_KEYS)) {
            throw new RuntimeException('Identity mode contains unsupported fields.');
        }

        return $normalized;
    }

    private static function readOptionalBooleanValue(string $input, string $key): bool {
        $pattern = '/^'.preg_quote($key, '/').'=([^\r\n]*)\r?$/m';
        $count = preg_match_all($pattern, $input, $matches);
        if ($count === 0) {
            return false;
        }
        if ($count !== 1) {
            throw new RuntimeException($key.' must appear at most once.');
        }
        $value = strtolower(trim($matches[1][0]));
        if ($value !== 'true' && $value !== 'false') {
            throw new RuntimeException($key.' must be exactly true or false.');
        }

        return $value === 'true';
    }

    private static function readOptionalSingleValue(string $input, string $key): ?string {
        $pattern = '/^'.preg_quote($key, '/').'=([^\r\n]*)\r?$/m';
        $count = preg_match_all($pattern, $input, $matches);
        if ($count === 0) {
            return null;
        }
        if ($count !== 1) {
            throw new RuntimeException($key.' must appear at most once.');
        }

        return trim($matches[1][0]);
    }

    private static function normalizeRedirectUri(string $value): string {
        $value = trim($value);
        $parts = parse_url($value);
        if (!filter_var($value, FILTER_VALIDATE_URL) || !is_array($parts) ||
            strtolower((string) ($parts['scheme'] ?? '')) !== 'https' ||
            ($parts['host'] ?? '') === '' || ($parts['path'] ?? '') === '' ||
            isset($parts['user']) || isset($parts['pass']) ||
            isset($parts['query']) || isset($parts['fragment'])) {
            throw new RuntimeException('The OIDC redirect URI must be an absolute HTTPS URL without credentials, query, or fragment.');
        }

        return $value;
    }

    private static function upsertSingleValue(string $input, string $key, string $value): string {
        $pattern = '/^'.preg_quote($key, '/').'=[^\r\n]*(\r?)$/m';
        $count = preg_match_all($pattern, $input);
        if ($count > 1) {
            throw new RuntimeException($key.' must appear at most once.');
        }
        if ($count === 1) {
            return self::replaceSingleValue($input, $key, $value);
        }

        $lineEnding = str_contains($input, "\r\n") ? "\r\n" : "\n";
        if ($input !== '' && !str_ends_with($input, "\n")) {
            $input .= $lineEnding;
        }

        return $input.$key.'='.$value.$lineEnding;
    }

    public static function parseSubjectArgument(string $value): array
    {
        if (trim($value) === '-') {
            return [];
        }

        return self::normalizeSubjects(self::splitSubjects($value));
    }

    private static function normalizeMode(string $mode): string
    {
        $mode = strtolower(trim($mode));
        if (!in_array($mode, self::MODES, true)) {
            throw new RuntimeException('Rollout mode must be allowlist, bound, or all.');
        }

        return $mode;
    }

    private static function normalizeSubjects(array $subjects): array
    {
        $normalized = [];
        $seen = [];
        foreach ($subjects as $subject) {
            if (!is_string($subject) || preg_match('/^[1-9][0-9]*$/D', trim($subject)) !== 1) {
                throw new RuntimeException('Allowed subjects must be positive decimal Taixue identity IDs.');
            }
            $subject = trim($subject);
            if (isset($seen[$subject])) {
                throw new RuntimeException('Allowed subjects must be unique.');
            }
            $seen[$subject] = true;
            $normalized[] = $subject;
        }

        return $normalized;
    }

    private static function validateDesiredPolicy(string $mode, array $subjects): void
    {
        if ($mode === 'allowlist' && count($subjects) === 0) {
            throw new RuntimeException('Allowlist rollout requires at least one subject.');
        }
        if ($mode !== 'allowlist' && count($subjects) !== 0) {
            throw new RuntimeException('Bound and all rollout modes must not retain an allowlist.');
        }
    }

    private static function splitSubjects(string $value): array
    {
        $value = trim($value);

        return $value === '' ? [] : explode(',', $value);
    }

    private static function readSingleValue(string $input, string $key): string
    {
        $pattern = '/^'.preg_quote($key, '/').'=([^\r\n]*)\r?$/m';
        $count = preg_match_all($pattern, $input, $matches);
        if ($count !== 1) {
            throw new RuntimeException($key.' must appear exactly once.');
        }

        return trim($matches[1][0]);
    }

    private static function replaceSingleValue(string $input, string $key, string $value): string
    {
        $pattern = '/^'.preg_quote($key, '/').'=[^\r\n]*(\r?)$/m';
        $updated = preg_replace_callback(
            $pattern,
            static fn (array $matches): string => $key.'='.$value.$matches[1],
            $input,
            1,
            $count
        );
        if (!is_string($updated) || $count !== 1) {
            throw new RuntimeException('Unable to update '.$key.'.');
        }

        return $updated;
    }

    private static function requireUtf8(string $value): void
    {
        if (preg_match('//u', $value) !== 1) {
            throw new RuntimeException('The environment file is not valid UTF-8.');
        }
    }

    private static function writeExclusiveBackup(string $path, string $value): void
    {
        $handle = @fopen($path, 'x+b');
        if ($handle === false) {
            throw new RuntimeException('The backup path already exists or cannot be created.');
        }
        try {
            if (!chmod($path, 0600)) {
                throw new RuntimeException('Unable to write the policy backup.');
            }
            self::writeHandle($handle, $value);
        } finally {
            fclose($handle);
        }
    }

    private static function writeFile(string $path, string $value): void
    {
        $handle = @fopen($path, 'wb');
        if ($handle === false) {
            throw new RuntimeException('Unable to open the atomic update file.');
        }
        try {
            self::writeHandle($handle, $value);
        } finally {
            fclose($handle);
        }
    }

    private static function writeHandle($handle, string $value): void
    {
        $offset = 0;
        $length = strlen($value);
        while ($offset < $length) {
            $written = fwrite($handle, substr($value, $offset));
            if (!is_int($written) || $written <= 0) {
                throw new RuntimeException('Unable to write the complete rollout policy file.');
            }
            $offset += $written;
        }
        if (!fflush($handle) || (function_exists('fsync') && !fsync($handle))) {
            throw new RuntimeException('Unable to flush the rollout policy file.');
        }
    }
}
