<?php

namespace Taixue\Oidc;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

class OidcClient
{
    public const BASE_SCOPES = 'openid profile blessing_skin';

    public function __construct(private IdTokenVerifier $tokenVerifier)
    {
    }

    public function start()
    {
        $this->assertConfigured();

        $state = $this->randomUrlSafe(32);
        $nonce = $this->randomUrlSafe(32);
        $verifier = $this->randomUrlSafe(64);
        session()->put('taixue_oidc_flow', [
            'state' => $state,
            'nonce' => $nonce,
            'verifier' => $verifier,
            'intent' => 'login',
            'created_at' => time(),
        ]);

        $parameters = [
            'client_id' => $this->clientId(),
            'redirect_uri' => $this->redirectUri(),
            'response_type' => 'code',
            'scope' => self::scopesFor(filter_var(
                env('TAIXUE_OIDC_AUTO_REGISTER', false),
                FILTER_VALIDATE_BOOL
            )),
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => self::pkceChallenge($verifier),
            'code_challenge_method' => 'S256',
        ];
        $query = http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);

        return redirect($this->issuer().'/oauth2/auth?'.$query);
    }

    public function complete(): array
    {
        try {
            $flow = PendingOidcFlow::validate(session()->get('taixue_oidc_flow'));
        } catch (OidcFlowException $error) {
            session()->forget('taixue_oidc_flow');
            throw $error;
        }
        $expectedState = $flow['state'] ?? null;
        $returnedState = request('state');
        if (!is_string($expectedState) || !is_string($returnedState) ||
            !hash_equals($expectedState, $returnedState)) {
            // A forged callback must not consume the legitimate pending flow.
            throw new OidcFlowException('state_mismatch', '登录状态校验失败，请重新开始。');
        }
        // Consume the flow only after state validation and before exchanging
        // the code, so a valid callback is single-use even if token exchange
        // or account reconciliation later fails.
        session()->forget('taixue_oidc_flow');
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
                'redirect_uri' => $this->redirectUri(),
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
        return ['flow' => $flow, 'claims' => $claims];
    }

    public function passwordChangeUrl(): string
    {
        return self::standardPasswordChangeUrl($this->issuer());
    }

    public static function scopesFor(bool $autoRegister): string
    {
        // Existing-account login and linking use only stable identifiers and
        // display profile data. Email is requested only when the explicitly
        // enabled auto-registration path may need to create a local account.
        return self::BASE_SCOPES.($autoRegister ? ' email' : '');
    }

    public static function standardPasswordChangeUrl(string $issuer): string
    {
        return self::normalizeIssuer($issuer).'/.well-known/change-password';
    }

    public static function standardPasswordRecoveryUrl(string $issuer): string
    {
        return self::normalizeIssuer($issuer).'/recover';
    }

    public static function pkceChallenge(string $verifier): string
    {
        if (preg_match('/\A[A-Za-z0-9._~-]{43,128}\z/D', $verifier) !== 1) {
            throw new OidcFlowException('pkce_verifier_invalid', '登录请求的 PKCE 校验参数无效。');
        }

        return rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    }

    public static function validateRedirectUri(string $redirectUri): string
    {
        $redirectUri = trim($redirectUri);
        $parts = parse_url($redirectUri);
        if (!filter_var($redirectUri, FILTER_VALIDATE_URL) || !is_array($parts) ||
            strtolower((string) ($parts['scheme'] ?? '')) !== 'https' ||
            ($parts['host'] ?? '') === '' || ($parts['path'] ?? '') === '' ||
            isset($parts['user']) || isset($parts['pass']) ||
            isset($parts['query']) || isset($parts['fragment'])) {
            throw new OidcFlowException('redirect_uri_invalid', '太学账号回调地址配置无效。');
        }

        return $redirectUri;
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
        $this->redirectUri();
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

    private function redirectUri(): string
    {
        return self::validateRedirectUri((string) env('TAIXUE_OIDC_REDIRECT_URI', ''));
    }

    private function randomUrlSafe(int $bytes): string
    {
        return rtrim(strtr(base64_encode(random_bytes($bytes)), '+/', '-_'), '=');
    }
}
