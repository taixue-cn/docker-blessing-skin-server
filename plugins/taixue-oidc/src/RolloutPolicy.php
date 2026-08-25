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

    public function allowsClaims(array $claims, string $intent): bool
    {
        $subject = $claims['sub'] ?? null;
        if (!is_string($subject) || $subject === '') {
            return false;
        }
        if ($this->allowsIntent($subject, $intent)) {
            return true;
        }
        if ($this->mode !== 'bound') {
            return false;
        }

        // The dedicated blessing_skin scope is resolved by the Taixue identity
        // provider and covered by the ID Token signature. It is therefore a
        // safer gradual-rollout boundary than email or nickname matching.
        return filter_var($claims['bs_uid'] ?? null, FILTER_VALIDATE_INT, [
            'options' => ['min_range' => 1, 'max_range' => 4294967295],
        ]) !== false;
    }

    public function denialMessage(): string
    {
        if ($this->mode === 'bound') {
            return '此太学账号尚未关联现有皮肤站账号，暂时不能使用统一登录。原皮肤站登录和找回密码仍可正常使用。';
        }

        return '太学账号登录正在小范围灰度，此账号暂未开放。原皮肤站登录仍可正常使用。';
    }
}
