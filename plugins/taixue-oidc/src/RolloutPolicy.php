<?php

namespace Taixue\Oidc;

class RolloutPolicy
{
    private const RECOVERY_INTENTS = ['unlink', 'local_password'];

    private array $allowedSubjects;

    public function __construct(private string $mode, string $allowedSubjects)
    {
        $this->mode = strtolower(trim($mode));
        $values = preg_split('/[\s,]+/', trim($allowedSubjects), -1, PREG_SPLIT_NO_EMPTY);
        $this->allowedSubjects = array_fill_keys($values ?: [], true);
    }

    public static function fromEnvironment(): self
    {
        return new self(
            (string) env('TAIXUE_OIDC_ROLLOUT_MODE', 'allowlist'),
            (string) env('TAIXUE_OIDC_ALLOWED_SUBJECTS', '')
        );
    }

    public function allows(string $subject): bool
    {
        return $this->mode === 'all'
            || ($this->mode === 'allowlist' && isset($this->allowedSubjects[$subject]));
    }

    public function allowsIntent(string $subject, string $intent): bool
    {
        // Rollout controls whether an account may start using OIDC. It must
        // never remove an existing user's recovery path. Sensitive recovery
        // intents still verify the authenticated local UID, signed subject,
        // fresh auth_time and one-time grant in their dedicated handlers.
        return in_array($intent, self::RECOVERY_INTENTS, true)
            || $this->allows($subject);
    }
}
