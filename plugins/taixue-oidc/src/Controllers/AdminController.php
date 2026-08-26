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
        $weekEventCounts = [];
        foreach ($weekEvents as $event) {
            $weekEventCounts[$event->event_type.':'.$event->outcome] = (int) $event->aggregate;
        }
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
        $rolloutMode = (string) env('TAIXUE_OIDC_ROLLOUT_MODE', 'allowlist');
        $loginButtonVisible = filter_var(
            env('TAIXUE_OIDC_SHOW_LOGIN_BUTTON', false),
            FILTER_VALIDATE_BOOL
        );
        $accountMenuVisible = filter_var(
            env('TAIXUE_OIDC_SHOW_ACCOUNT_MENU', false),
            FILTER_VALIDATE_BOOL
        );
        $autoRegister = filter_var(
            env('TAIXUE_OIDC_AUTO_REGISTER', false),
            FILTER_VALIDATE_BOOL
        );
        $secureCookie = (bool) config('session.secure');
        $successfulLoginOrLink = ($weekEventCounts['LOGIN:SUCCEEDED'] ?? 0)
            + ($weekEventCounts['LINK:SUCCEEDED'] ?? 0);
        // A correctly signed logout for an unknown subject is intentionally
        // accepted and stored, but it proves only endpoint interoperability.
        // Expansion requires evidence that a real linked Blessing Skin account
        // was reached. Keep provider logout and password-change coordination as
        // separate gates so one healthy path cannot conceal the other.
        $linkedRevocations = DB::table('taixue_oidc_audit_events')
            ->where('created_at', '>=', $weekStart)
            ->where('outcome', 'SUCCEEDED')
            ->whereNotNull('uid')
            ->whereIn('event_type', ['BACKCHANNEL_LOGOUT', 'COORDINATED_LOGOUT'])
            ->selectRaw('event_type, COUNT(*) AS aggregate')
            ->groupBy('event_type')
            ->pluck('aggregate', 'event_type');
        $successfulBackchannelLogouts = (int) ($linkedRevocations['BACKCHANNEL_LOGOUT'] ?? 0);
        $successfulCoordinatedLogouts = (int) ($linkedRevocations['COORDINATED_LOGOUT'] ?? 0);
        $rolloutHasAudience = $rolloutMode === 'bound'
            || $rolloutMode === 'all'
            || ($rolloutMode === 'allowlist' && count($allowedSubjects) > 0);

        $readinessChecks = [
            [
                'label' => '安全会话配置',
                'passed' => $secureCookie,
                'detail' => $secureCookie
                    ? '会话 Cookie 仅通过 HTTPS 发送。'
                    : '先启用 Secure Cookie，否则插件会保持关闭。',
            ],
            [
                'label' => '灰度对象',
                'passed' => $rolloutHasAudience,
                'detail' => $rolloutHasAudience
                    ? '当前模式存在可验收的灰度对象。'
                    : '允许名单为空；请先只加入测试账号，不要直接全量开放。',
            ],
            [
                'label' => '真实账号映射',
                'passed' => $totalLinks > 0,
                'detail' => $totalLinks > 0
                    ? "已建立 {$totalLinks} 个稳定 subject 映射。"
                    : '尚无账号完成登录或绑定，请先走通一个真实测试账号。',
            ],
            [
                'label' => '登录或绑定验收',
                'passed' => $successfulLoginOrLink > 0,
                'detail' => $successfulLoginOrLink > 0
                    ? "最近 7 天成功 {$successfulLoginOrLink} 次。"
                    : '最近 7 天没有成功登录或绑定记录。',
            ],
            [
                'label' => '本地回退凭据',
                'passed' => $totalLinks > 0 && $provisionedLinks === 0,
                'detail' => $totalLinks > 0 && $provisionedLinks === 0
                    ? '所有已映射账号都保留了可用的皮肤站本地密码。'
                    : ($totalLinks === 0
                        ? '需先建立账号映射后再验证找回、改密和解绑。'
                        : "仍有 {$provisionedLinks} 个账号需要建立本地备用密码。"),
            ],
            [
                'label' => '单点退出验收',
                'passed' => $successfulBackchannelLogouts > 0,
                'detail' => $successfulBackchannelLogouts > 0
                    ? "最近 7 天有 {$successfulBackchannelLogouts} 次已映射账号完成标准 back-channel logout。"
                    : '尚无已映射账号完成标准 back-channel logout；必须验证退出后皮肤站旧会话失效。',
            ],
            [
                'label' => '改密退出验收',
                'passed' => $successfulCoordinatedLogouts > 0,
                'detail' => $successfulCoordinatedLogouts > 0
                    ? "最近 7 天有 {$successfulCoordinatedLogouts} 次已映射账号完成改密协调退出。"
                    : '尚无已映射账号完成改密协调退出；必须验证修改、找回或重置密码后皮肤站旧会话失效。',
            ],
            [
                'label' => '自动注册保护',
                'passed' => !$autoRegister,
                'detail' => !$autoRegister
                    ? '自动注册保持关闭，当前迁移不会意外创建重复账号。'
                    : '扩量验收前应关闭自动注册，先核对冲突与回滚指标。',
            ],
        ];
        $readyForExpansion = !in_array(false, array_column($readinessChecks, 'passed'), true);

        return view('Taixue\Oidc::admin', [
            'totalLinks' => $totalLinks,
            'provisionedLinks' => $provisionedLinks,
            'fallbackReadyLinks' => max(0, $totalLinks - $provisionedLinks),
            'daySucceeded' => (int) ($dayEvents['SUCCEEDED'] ?? 0),
            'dayRejected' => (int) ($dayEvents['REJECTED'] ?? 0),
            'dayFailed' => (int) ($dayEvents['FAILED'] ?? 0),
            'weekEvents' => $weekEvents,
            'recentFailures' => $recentFailures,
            'rolloutMode' => $rolloutMode,
            'allowlistCount' => count($allowedSubjects),
            'loginButtonVisible' => $loginButtonVisible,
            'accountMenuVisible' => $accountMenuVisible,
            'autoRegister' => $autoRegister,
            'secureCookie' => $secureCookie,
            'readinessChecks' => $readinessChecks,
            'readyForExpansion' => $readyForExpansion,
        ]);
    }
}
