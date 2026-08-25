<?php

namespace Taixue\Oidc\Controllers;

use Illuminate\Support\Facades\DB;

class AdminController
{
    public function show()
    {
        $links = DB::table('taixue_oidc_links');
        $totalLinks = (int) (clone $links)->count();
        $provisionedLinks = (int) (clone $links)->where('provisioned', true)->count();

        $dayStart = now()->subDay();
        $weekStart = now()->subDays(7);
        $dayEvents = DB::table('taixue_oidc_audit_events')
            ->where('created_at', '>=', $dayStart)
            ->selectRaw('outcome, COUNT(*) AS aggregate')
            ->groupBy('outcome')
            ->pluck('aggregate', 'outcome');
        $weekEvents = DB::table('taixue_oidc_audit_events')
            ->where('created_at', '>=', $weekStart)
            ->selectRaw('event_type, outcome, COUNT(*) AS aggregate')
            ->groupBy('event_type', 'outcome')
            ->orderBy('event_type')
            ->orderBy('outcome')
            ->get();
        $recentFailures = DB::table('taixue_oidc_audit_events')
            ->where('outcome', '<>', 'SUCCEEDED')
            ->orderByDesc('id')
            ->limit(30)
            ->get()
            ->map(function ($event) {
                $metadata = json_decode((string) $event->metadata_json, true);
                $reason = is_array($metadata) && is_string($metadata['reason'] ?? null)
                    ? $metadata['reason']
                    : 'unspecified';

                return (object) [
                    'event_type' => $event->event_type,
                    'outcome' => $event->outcome,
                    'uid' => $event->uid,
                    'request_id' => $event->request_id,
                    'reason' => $reason,
                    'created_at' => $event->created_at,
                ];
            });

        $allowedSubjects = array_filter(array_map(
            'trim',
            explode(',', (string) env('TAIXUE_OIDC_ALLOWED_SUBJECTS', ''))
        ));

        return view('Taixue\Oidc::admin', [
            'totalLinks' => $totalLinks,
            'provisionedLinks' => $provisionedLinks,
            'fallbackReadyLinks' => max(0, $totalLinks - $provisionedLinks),
            'daySucceeded' => (int) ($dayEvents['SUCCEEDED'] ?? 0),
            'dayRejected' => (int) ($dayEvents['REJECTED'] ?? 0),
            'dayFailed' => (int) ($dayEvents['FAILED'] ?? 0),
            'weekEvents' => $weekEvents,
            'recentFailures' => $recentFailures,
            'rolloutMode' => (string) env('TAIXUE_OIDC_ROLLOUT_MODE', 'allowlist'),
            'allowlistCount' => count($allowedSubjects),
            'loginButtonVisible' => filter_var(
                env('TAIXUE_OIDC_SHOW_LOGIN_BUTTON', false),
                FILTER_VALIDATE_BOOL
            ),
            'accountMenuVisible' => filter_var(
                env('TAIXUE_OIDC_SHOW_ACCOUNT_MENU', false),
                FILTER_VALIDATE_BOOL
            ),
            'autoRegister' => filter_var(
                env('TAIXUE_OIDC_AUTO_REGISTER', false),
                FILTER_VALIDATE_BOOL
            ),
            'secureCookie' => (bool) config('session.secure'),
        ]);
    }
}
