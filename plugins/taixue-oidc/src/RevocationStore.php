<?php

namespace Taixue\Oidc;

use Illuminate\Support\Facades\DB;

class RevocationStore
{
    public function record(
        string $jti,
        ?string $subject,
        ?string $sid,
        string $eventType,
        OidcAudit $audit
    ): void {
        $now = now();
        $retentionMinutes = max(60, (int) config('session.lifetime', 120) + 10);
        DB::transaction(function () use (
            $jti,
            $subject,
            $sid,
            $eventType,
            $audit,
            $now,
            $retentionMinutes
        ) {
            $inserted = DB::table('taixue_oidc_revocations')->insertOrIgnore([
                'jti' => $jti,
                'subject' => $subject,
                'sid' => $sid,
                'revoked_at' => $now,
                'purge_after' => $now->copy()->addMinutes($retentionMinutes),
                'created_at' => $now,
            ]);
            if (!$inserted) {
                return;
            }
            $link = $subject
                ? DB::table('taixue_oidc_links')->where('subject', $subject)->first()
                : null;
            $audit->record($eventType, 'SUCCEEDED', $link ? (int) $link->uid : null, $subject, [
                'sid_present' => $sid !== null,
            ]);
        });
        DB::table('taixue_oidc_revocations')->where('purge_after', '<=', $now)->delete();
    }
}
