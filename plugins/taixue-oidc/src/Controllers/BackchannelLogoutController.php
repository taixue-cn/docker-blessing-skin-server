<?php

namespace Taixue\Oidc\Controllers;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Taixue\Oidc\LogoutTokenVerifier;
use Taixue\Oidc\OidcAudit;
use Taixue\Oidc\OidcFlowException;

class BackchannelLogoutController
{
    public function __invoke(LogoutTokenVerifier $verifier, OidcAudit $audit)
    {
        try {
            $contentType = strtolower((string) request()->header('Content-Type', ''));
            if (!str_starts_with($contentType, 'application/x-www-form-urlencoded')) {
                throw new OidcFlowException('logout_content_type_invalid', '退出请求格式不正确。');
            }
            $token = request('logout_token');
            if (!is_string($token) || $token === '' || strlen($token) > 16384) {
                throw new OidcFlowException('logout_token_missing', '退出请求缺少有效令牌。');
            }

            $issuer = $this->issuer();
            $clientId = (string) env('TAIXUE_OIDC_CLIENT_ID', '');
            if ($clientId === '') {
                throw new OidcFlowException('client_not_configured', '太学账号登录尚未完成配置。');
            }
            $jwks = Cache::remember('taixue_oidc_jwks', 300, function () use ($issuer) {
                $response = Http::timeout(10)->get($issuer.'/.well-known/jwks.json');
                if (!$response->successful() || !is_array($response->json('keys'))) {
                    throw new OidcFlowException('jwks_unavailable', '无法读取太学账号签名密钥。');
                }

                return $response->json();
            });
            $claims = $verifier->verify($token, $jwks, $issuer, $clientId);
            $subject = isset($claims['sub']) ? (string) $claims['sub'] : null;
            $sid = isset($claims['sid']) ? (string) $claims['sid'] : null;
            $jti = (string) $claims['jti'];

            $now = now();
            $retentionMinutes = max(60, (int) config('session.lifetime', 120) + 10);
            DB::transaction(function () use ($jti, $subject, $sid, $now, $retentionMinutes, $audit) {
                $inserted = DB::table('taixue_oidc_revocations')->insertOrIgnore([
                    'jti' => $jti,
                    'subject' => $subject,
                    'sid' => $sid,
                    'revoked_at' => $now,
                    'purge_after' => $now->copy()->addMinutes($retentionMinutes),
                    'created_at' => $now,
                ]);
                if ($inserted) {
                    $link = $subject
                        ? DB::table('taixue_oidc_links')->where('subject', $subject)->first()
                        : null;
                    $audit->record('BACKCHANNEL_LOGOUT', 'SUCCEEDED', $link ? (int) $link->uid : null, $subject, [
                        'sid_present' => $sid !== null,
                    ]);
                }
            });
            DB::table('taixue_oidc_revocations')->where('purge_after', '<=', $now)->delete();

            return response('', 204)
                ->header('Cache-Control', 'no-store')
                ->header('Pragma', 'no-cache');
        } catch (\Throwable $e) {
            if (!$e instanceof OidcFlowException) {
                report($e);
            }
            $reason = $e instanceof OidcFlowException ? $e->reason() : 'internal_error';
            try {
                $audit->record('BACKCHANNEL_LOGOUT', 'FAILED', null, null, ['reason' => $reason]);
            } catch (\Throwable $auditError) {
                report($auditError);
            }
            $audit->warn('BACKCHANNEL_LOGOUT', $reason);

            return response('', 400)
                ->header('Cache-Control', 'no-store')
                ->header('Pragma', 'no-cache');
        }
    }

    private function issuer(): string
    {
        $issuer = rtrim(trim((string) env('TAIXUE_OIDC_ISSUER', 'https://auth.taixue.cc')), '/');
        $parts = parse_url($issuer);
        if (!is_array($parts) || strtolower((string) ($parts['scheme'] ?? '')) !== 'https' ||
            ($parts['host'] ?? '') === '' || isset($parts['user']) || isset($parts['pass']) ||
            isset($parts['query']) || isset($parts['fragment'])) {
            throw new OidcFlowException('issuer_invalid', '太学账号服务地址配置无效。');
        }

        return $issuer;
    }
}
