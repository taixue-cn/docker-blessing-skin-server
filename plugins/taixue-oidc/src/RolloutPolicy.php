<?php

namespace Taixue\Oidc;

class RolloutPolicy
{
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
}
