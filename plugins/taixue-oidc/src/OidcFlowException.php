<?php

namespace Taixue\Oidc;

use RuntimeException;
use Throwable;

class OidcFlowException extends RuntimeException
{
    public function __construct(
        private string $reason,
        string $message,
        ?Throwable $previous = null
    ) {
        if (!preg_match('/^[a-z][a-z0-9_]{2,63}$/', $reason)) {
            $this->reason = 'invalid_failure_reason';
        }
        parent::__construct($message, 0, $previous);
    }

    public function reason(): string
    {
        return $this->reason;
    }
}
