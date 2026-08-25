<?php

namespace Taixue\Oidc;

final class SafeRedirect
{
    public static function resolve($candidate, string $origin, string $fallback): string
    {
        if (!is_string($candidate) || $candidate === '' ||
            str_contains($candidate, '\\') || preg_match('/[\x00-\x1F\x7F]/', $candidate)) {
            return $fallback;
        }
        if (str_starts_with($candidate, '/') && !str_starts_with($candidate, '//')) {
            return $candidate;
        }

        $origin = rtrim($origin, '/');
        if ($candidate === $origin || str_starts_with($candidate, $origin.'/') ||
            str_starts_with($candidate, $origin.'?')) {
            return $candidate;
        }

        return $fallback;
    }
}
