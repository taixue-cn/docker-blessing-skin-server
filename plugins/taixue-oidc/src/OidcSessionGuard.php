<?php

namespace Taixue\Oidc;

use Closure;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

class OidcSessionGuard
{
    private const CHECK_INTERVAL_SECONDS = 30;

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
        if ($uid === false || $uid <= 0 || (int) Auth::id() !== $uid ||
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
        $revoked = DB::table('taixue_oidc_revocations')
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
            ->exists();
        if ($revoked) {
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
