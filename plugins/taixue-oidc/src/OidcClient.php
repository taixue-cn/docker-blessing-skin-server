<?php

namespace Taixue\Oidc;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

class OidcClient
{
    public const SCOPES = 'openid profile email blessing_skin';

    private const FLOW_TTL_SECONDS = 600;

    private const SENSITIVE_INTENTS = ['unlink', 'local_password'];

    public function __construct(private IdTokenVerifier $tokenVerifier)
    {
    }

    public function start(string $intent, ?int $uid = null)
    {
        $this->assertConfigured();

        $state = $this->randomUrlSafe(32);
        $nonce = $this->randomUrlSafe(32);
        $verifier = $this->randomUrlSafe(64);
        session()->put('taixue_oidc_flow', [
            'state' => $state,
            'nonce' => $nonce,
            'verifier' => $verifier,
            'intent' => $intent,
            'uid' => $uid,
            'created_at' => time(),
        ]);

        $parameters = [
            'client_id' => $this->clientId(),
            'redirect_uri' => route('taixue-oidc.callback'),
            'response_type' => 'code',
            'scope' => self::SCOPES,
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='),
            'code_challenge_method' => 'S256',
        ];
        if (in_array($intent, self::SENSITIVE_INTENTS, true)) {
            // These actions change the account recovery boundary. A remembered
            // SSO session is insufficient; require fresh Taixue authentication.
            $parameters['prompt'] = 'login';
            $parameters['max_age'] = 0;
        }
        $query = http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);

        return redirect($this->issuer().'/oauth2/auth?'.$query);
    }

    public function complete(): array
    {
        $flow = session()->pull('taixue_oidc_flow');
        if (!is_array($flow) || time() - ($flow['created_at'] ?? 0) > self::FLOW_TTL_SECONDS) {
            throw new OidcFlowException('flow_expired', '登录请求已失效，请重新开始。');
        }
        if (!hash_equals((string) $flow['state'], (string) request('state'))) {
            throw new OidcFlowException('state_mismatch', '登录状态校验失败，请重新开始。');
        }
        if (request()->filled('error')) {
            throw new OidcFlowException('authorization_rejected', '太学账号未完成授权，请重新开始。');
        }
        $code = request('code');
        if (!is_string($code) || $code === '') {
            throw new OidcFlowException('authorization_code_missing', '太学账号没有返回授权码。');
        }

        $response = Http::asForm()
            ->withBasicAuth($this->clientId(), $this->clientSecret())
            ->timeout(10)
            ->post($this->issuer().'/oauth2/token', [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => route('taixue-oidc.callback'),
                'code_verifier' => $flow['verifier'],
            ]);
        if (!$response->successful()) {
            throw new OidcFlowException('token_exchange_failed', '太学账号令牌交换失败，请稍后重试。');
        }

        $idToken = $response->json('id_token');
        if (!is_string($idToken) || $idToken === '') {
            throw new OidcFlowException('id_token_missing', '太学账号没有返回身份令牌。');
        }
        $claims = $this->verifyIdToken($idToken, (string) $flow['nonce']);
        if (in_array($flow['intent'] ?? '', self::SENSITIVE_INTENTS, true)) {
            FreshAuthentication::assertClaims(
                $claims,
                (int) ($flow['created_at'] ?? 0),
                time()
            );
        }

        return ['flow' => $flow, 'claims' => $claims];
    }

    public function passwordChangeUrl(): string
    {
        return self::standardPasswordChangeUrl($this->issuer());
    }

    public static function standardPasswordChangeUrl(string $issuer): string
    {
        return self::normalizeIssuer($issuer).'/.well-known/change-password';
    }

    private function verifyIdToken(string $token, string $nonce): array
    {
        $jwks = Cache::remember('taixue_oidc_jwks', 300, function () {
            $response = Http::timeout(10)->get($this->issuer().'/.well-known/jwks.json');
            if (!$response->successful() || !is_array($response->json('keys'))) {
                throw new OidcFlowException('jwks_unavailable', '无法读取太学账号签名密钥。');
            }

            return $response->json();
        });

        try {
            return $this->tokenVerifier->verify(
                $token,
                $jwks,
                $this->issuer(),
                $this->clientId(),
                $nonce
            );
        } catch (\Throwable $e) {
            Cache::forget('taixue_oidc_jwks');
            if ($e instanceof OidcFlowException) {
                throw $e;
            }
            throw new OidcFlowException(
                'id_token_invalid',
                '太学账号身份令牌校验失败。',
                $e
            );
        }
    }

    private function assertConfigured(): void
    {
        if ($this->clientId() === '' || $this->clientSecret() === '') {
            throw new OidcFlowException('client_not_configured', '太学账号登录尚未完成配置。');
        }
    }

    private function issuer(): string
    {
        return self::normalizeIssuer((string) env('TAIXUE_OIDC_ISSUER', 'https://auth.taixue.cc'));
    }

    private static function normalizeIssuer(string $issuer): string
    {
        $issuer = rtrim(trim($issuer), '/');
        $parts = parse_url($issuer);
        if (!is_array($parts) ||
            strtolower((string) ($parts['scheme'] ?? '')) !== 'https' ||
            ($parts['host'] ?? '') === '' ||
            isset($parts['user']) || isset($parts['pass']) ||
            isset($parts['query']) || isset($parts['fragment'])) {
            throw new OidcFlowException('issuer_invalid', '太学账号服务地址配置无效。');
        }

        return $issuer;
    }

    private function clientId(): string
    {
        return (string) env('TAIXUE_OIDC_CLIENT_ID', '');
    }

    private function clientSecret(): string
    {
        return (string) env('TAIXUE_OIDC_CLIENT_SECRET', '');
    }

    private function randomUrlSafe(int $bytes): string
    {
        return rtrim(strtr(base64_encode(random_bytes($bytes)), '+/', '-_'), '=');
    }
}
