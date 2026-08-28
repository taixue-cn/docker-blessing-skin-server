<?php

namespace Taixue\Oidc;

use Blessing\Rejection;
use Closure;
use Illuminate\Support\Facades\Auth;

class UnifiedIdentityBoundary
{
    public static function enabled(): bool
    {
        return filter_var(
            env('TAIXUE_OIDC_UNIFIED_IDENTITY_ONLY', false),
            FILTER_VALIDATE_BOOL
        );
    }

    public function handle($request, Closure $next)
    {
        $path = trim($request->path(), '/');
        if (self::shouldRedirectToUnifiedLogin(
            $path,
            $request->method(),
            $request->query('local'),
            self::automaticLoginEnabled(),
            self::enabled()
        )) {
            return redirect()->route('taixue-oidc.login');
        }

        // Native role-based administrator routes must never become a second
        // identity-repair authority. Repairs belong to the permissioned Taixue
        // administration flow even while legacy local recovery remains open.
        if (self::isNativeAdminIdentityMutation($path, $request->method())) {
            return response()->json([
                'code' => 1,
                'message' => '账号凭据、账号归属和玩家绑定由太学统一权限系统管理，请前往 auth.taixue.cc/admin?view=subjects 处理。',
            ], 403);
        }

        $protectCurrentIdentity = self::protectsCurrentUserIdentity();
        if (!self::enabled() && !$protectCurrentIdentity) {
            if ($path === 'auth/register' && self::automaticLoginEnabled()) {
                return redirect($this->taixueUrl('/register'));
            }

            return $next($request);
        }

        if ($path === 'auth/register') {
            return redirect($this->taixueUrl('/register'));
        }
        if ($path === 'auth/forgot' || str_starts_with($path, 'auth/reset/')) {
            return redirect($this->taixueUrl('/recover'));
        }
        if ($path === 'auth/bind') {
            return redirect($this->taixueUrl('/settings'));
        }
        if (str_starts_with($path, 'auth/verify/')) {
            return redirect($this->taixueUrl('/settings'));
        }
        if ($path === 'user/email-verification') {
            return response()->json([
                'code' => 1,
                'message' => '邮箱与联系方式由太学统一账号管理，请前往 auth.taixue.cc/settings。',
            ], 403);
        }
        if ($path === 'user/player/bind') {
            if ($request->isMethod('get')) {
                return redirect($this->taixueUrl('/settings'));
            }

            return response()->json([
                'code' => 1,
                'message' => '皮肤站玩家由太学统一账号自动关联；如需修复，请联系有权限的管理员。',
            ], 403);
        }

        return $next($request);
    }

    public static function rejectIdentityMutation(bool $allowed, string $action)
    {
        if (!self::protectsCurrentUserIdentity()) {
            return $allowed;
        }
        if (in_array($action, ['password', 'email'], true)) {
            return new Rejection('密码和联系方式由太学统一账号管理，请前往 auth.taixue.cc/settings。');
        }
        if ($action === 'delete') {
            return new Rejection('统一身份关联的皮肤站账号不能自行删除；如需停用或修复，请联系有权限的管理员。');
        }

        return $allowed;
    }

    public static function rejectLocalLogin($allowed)
    {
        if (!self::enabled()) {
            return $allowed;
        }

        return new Rejection(
            '皮肤站网页登录已由太学统一账号接管，请返回登录页使用统一登录。'
        );
    }

    public static function rejectPlayerMutation(bool $allowed)
    {
        if (!self::protectsCurrentUserIdentity()) {
            return $allowed;
        }

        return new Rejection('皮肤站账号固定对应唯一玩家；如需修复绑定，请联系有权限的管理员。');
    }

    public static function protectsCurrentUserIdentity(): bool
    {
        if (self::enabled()) {
            return true;
        }

        try {
            return OidcSession::belongsToUser(
                session()->get(OidcSession::KEY),
                Auth::id()
            );
        } catch (\Throwable $error) {
            // Console and install contexts may not have an HTTP session. Gray
            // rollout must not accidentally become global unified-only mode.
            return false;
        }
    }

    public static function shouldRedirectToUnifiedLogin(
        string $path,
        string $method,
        mixed $localBypass,
        bool $automaticRedirect,
        bool $unifiedIdentityOnly = false
    ): bool {
        if ($path !== 'auth/login' || strtoupper($method) !== 'GET') {
            return false;
        }

        // During gray rollout, ?local=1 is a data-preserving recovery path.
        // Once unified-only mode is accepted, local credentials are no longer
        // an authentication source and that browser bypass must fail closed.
        return $unifiedIdentityOnly ||
            ($automaticRedirect && $localBypass !== '1');
    }

    public static function configurationIsSafe(
        bool $unifiedIdentityOnly,
        bool $automaticRedirect,
        string $rolloutMode,
        string $allowedSubjects
    ): bool {
        if (!$unifiedIdentityOnly) {
            return true;
        }

        return $automaticRedirect &&
            strtolower(trim($rolloutMode)) === 'all' &&
            trim($allowedSubjects) === '';
    }

    public static function recoveryNavigation(
        bool $unifiedIdentityOnly,
        string $baseUrl
    ): array {
        $baseUrl = rtrim($baseUrl, '/');

        return [
            'retry_url' => $baseUrl.'/auth/taixue',
            'local_recovery_url' => $unifiedIdentityOnly
                ? null
                : $baseUrl.'/auth/login?local=1',
        ];
    }

    public static function isNativeAdminIdentityMutation(
        string $path,
        string $method
    ): bool {
        $path = trim($path, '/');
        $method = strtoupper($method);
        $prefix = '(?:api/)?admin';

        if ($method === 'DELETE') {
            return preg_match('#^'.$prefix.'/users/[^/]+$#', $path) === 1 ||
                preg_match('#^'.$prefix.'/players/[^/]+$#', $path) === 1;
        }
        if ($method !== 'PUT') {
            return false;
        }

        return preg_match(
            '#^'.$prefix.'/users/[^/]+/(?:email|password)$#',
            $path
        ) === 1 || preg_match(
            '#^'.$prefix.'/players/[^/]+/(?:name|owner)$#',
            $path
        ) === 1;
    }

    private static function automaticLoginEnabled(): bool
    {
        return filter_var(
            env('TAIXUE_OIDC_AUTO_REDIRECT', false),
            FILTER_VALIDATE_BOOL
        );
    }

    private function taixueUrl(string $path): string
    {
        $issuer = rtrim((string) env('TAIXUE_OIDC_ISSUER', 'https://auth.taixue.cc'), '/');
        // Reuse the OIDC issuer validator before producing any redirect.
        OidcClient::standardPasswordChangeUrl($issuer);

        return $issuer.$path;
    }
}
