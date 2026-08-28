<?php

namespace Taixue\Oidc;

use Closure;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

class OidcSessionGuard
{
    private const CHECK_INTERVAL_SECONDS = 30;

    public function __construct(private OidcAudit $audit)
    {
    }

    public function handle($request, Closure $next)
    {
        $session = $request->session();
        $provenance = $session->get(OidcSession::KEY);
        if (!Auth::check() || !is_array($provenance)) {
            return $next($request);
        }

        $uid = filter_var($provenance['uid'] ?? null, FILTER_VALIDATE_INT);
        $subject = $provenance['subject'] ?? null;
        $authenticatedAt = filter_var($provenance['authenticated_at'] ?? null, FILTER_VALIDATE_INT);
        $checkedAt = filter_var($provenance['checked_at'] ?? 0, FILTER_VALIDATE_INT);
        if (!OidcSession::belongsToUser($provenance, Auth::id()) ||
            $uid === false || $uid <= 0 ||
            !is_string($subject) || $subject === '' || $authenticatedAt === false || $authenticatedAt <= 0) {
            return $this->logout($request);
        }
        $now = time();
        if ($checkedAt !== false && $checkedAt > 0 && $now - $checkedAt < self::CHECK_INTERVAL_SECONDS) {
            return $next($request);
        }
        if (!Schema::hasTable('taixue_oidc_revocations')) {
            logger()->critical('Taixue OIDC session revoked because the revocation schema is missing');

            return $this->logout($request);
        }

        $sid = isset($provenance['sid']) && is_string($provenance['sid']) && $provenance['sid'] !== ''
            ? $provenance['sid']
            : null;
        $authenticatedAtValue = now()->setTimestamp($authenticatedAt);
        $nowValue = now()->setTimestamp($now);
        $revocations = DB::table('taixue_oidc_revocations')
            ->where('revoked_at', '>=', $authenticatedAtValue)
            ->where('purge_after', '>', $nowValue)
            ->where(function ($query) use ($subject, $sid) {
                $query->where(function ($subjectQuery) use ($subject, $sid) {
                    $subjectQuery->where('subject', $subject);
                    if ($sid !== null) {
                        $subjectQuery->where(function ($targetQuery) use ($sid) {
                            $targetQuery->whereNull('sid')->orWhere('sid', $sid);
                        });
                    }
                });
                if ($sid !== null) {
                    $query->orWhere('sid', $sid);
                }
            })
            ->orderByDesc('revoked_at')
            ->get(['event_type']);
        if (!$revocations->isEmpty()) {
            $sources = [];
            foreach ($revocations as $revocation) {
                $source = in_array($revocation->event_type ?? null, [
                    'BACKCHANNEL_LOGOUT',
                    'COORDINATED_LOGOUT',
                ], true) ? $revocation->event_type : 'UNKNOWN';
                $sources[$source] = true;
            }
            // A stored revocation proves only that the provider notification
            // arrived. Record the separate, user-resolved evidence that a live
            // OIDC session actually observed it and was invalidated. A password
            // change can deliver provider and coordinated revocations together,
            // so retain one bounded evidence event for every matching source
            // before invalidating the session once. Never retain a cookie,
            // logout token, jti, or sid value here.
            foreach (array_keys($sources) as $source) {
                try {
                    $this->audit->record('SESSION_REVOKED', 'SUCCEEDED', $uid, $subject, [
                        'reason' => 'revocation_match',
                        'source' => $source,
                        'sid_present' => $sid !== null,
                    ]);
                } catch (\Throwable $auditError) {
                    // Revocation remains fail-closed even when its evidence sink
                    // is unavailable. The critical log makes acceptance fail
                    // without leaving the revoked session alive.
                    report($auditError);
                    logger()->critical('Taixue OIDC session revoked without durable audit evidence');
                }
            }

            return $this->logout($request);
        }

        $provenance['checked_at'] = $now;
        $session->put(OidcSession::KEY, $provenance);

        return $next($request);
    }

    private function logout($request)
    {
        Auth::logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect('/auth/login')->with('error', '太学账号登录状态已失效，请重新登录。');
    }
}
