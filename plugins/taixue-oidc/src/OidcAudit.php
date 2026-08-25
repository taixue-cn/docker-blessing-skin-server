<?php

namespace Taixue\Oidc;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

class OidcAudit
{
    private ?string $requestId = null;

    public function requestId(): string
    {
        if ($this->requestId !== null) {
            return $this->requestId;
        }

        $candidate = (string) request()->header('X-Request-ID', '');
        $this->requestId = preg_match('/^[A-Za-z0-9._:-]{8,64}$/', $candidate)
            ? $candidate
            : (string) Str::uuid();

        return $this->requestId;
    }

    public function record(
        string $eventType,
        string $outcome,
        ?int $uid = null,
        ?string $subject = null,
        array $metadata = []
    ): void {
        DB::table('taixue_oidc_audit_events')->insert([
            'event_type' => Str::limit($eventType, 64, ''),
            'outcome' => Str::limit($outcome, 32, ''),
            'uid' => $uid,
            'subject' => $subject ? Str::limit($subject, 191, '') : null,
            'request_id' => $this->requestId(),
            'inet_addr' => Str::limit((string) request()->ip(), 45, ''),
            'user_agent' => Str::limit((string) request()->userAgent(), 255, ''),
            'metadata_json' => $metadata
                ? json_encode($this->safeMetadata($metadata), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES)
                : null,
            'created_at' => now(),
        ]);
    }

    public function warn(string $eventType, string $reason): void
    {
        logger()->warning('Taixue OIDC request rejected', [
            'request_id' => $this->requestId(),
            'event_type' => Str::limit($eventType, 64, ''),
            'reason' => Str::limit($reason, 64, ''),
        ]);
    }

    private function safeMetadata(array $metadata): array
    {
        $safe = [];
        foreach ($metadata as $key => $value) {
            $key = Str::limit((string) $key, 64, '');
            if (is_bool($value) || is_int($value) || is_float($value) || $value === null) {
                $safe[$key] = $value;
            } elseif (is_string($value)) {
                $safe[$key] = Str::limit($value, 191, '');
            }
        }

        return $safe;
    }
}
