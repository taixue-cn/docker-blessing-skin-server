<?php

namespace Taixue\Oidc;

use App\Models\Player;
use App\Models\User;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class ProvisioningNotifier
{
    public function notify(string $subject, int $uid, string $playerName, string $requestId): void
    {
        $endpoint = trim((string) env('TAIXUE_OIDC_PROVISIONING_URL', ''));
        $secret = (string) env('TAIXUE_OIDC_PROVISIONING_SECRET', '');
        if (!self::endpointIsValid($endpoint) || strlen($secret) < 32) {
            throw new OidcFlowException('provisioning_not_configured', '皮肤站自动注册回执尚未正确配置。');
        }
        if ($uid <= 0 || $subject === '' || $playerName === '' ||
            !preg_match('/^[A-Za-z0-9._:-]{8,128}$/', $requestId)) {
            throw new OidcFlowException('provisioning_request_invalid', '皮肤站自动注册回执不正确。');
        }

        $user = User::find($uid);
        $players = Player::where('uid', $uid)->limit(2)->get();
        if (!$user || $players->count() !== 1 ||
            strcasecmp((string) $players->first()->name, trim($playerName)) !== 0) {
            throw new OidcFlowException('provisioning_request_invalid', '皮肤站自动注册快照不完整。');
        }
        $player = $players->first();
        $snapshot = self::snapshot($user, $player);

        $timestamp = time();
        $payload = self::payload($subject, $uid, $playerName, $requestId, $timestamp, $snapshot);
        $signature = 'v2='.hash_hmac('sha256', $payload, $secret);
        try {
            $response = Http::asJson()->timeout(10)->withHeaders([
                'X-Request-ID' => $requestId,
                'X-Taixue-Timestamp' => (string) $timestamp,
                'X-Taixue-Signature' => $signature,
            ])->post($endpoint, [
                'receipt_version' => 2,
                'subject' => $subject, 'bs_uid' => $uid, 'player_name' => $playerName,
            ] + $snapshot);
        } catch (\Throwable $e) {
            throw new OidcFlowException('provisioning_unavailable', '太学账号关联暂时不可用，请稍后重试。', $e);
        }
        if (!$response->successful() || !((bool) data_get($response->json(), 'completed', false))) {
            $upstreamCode = self::safeUpstreamCode(data_get($response->json(), 'base.status')) ??
                self::safeUpstreamCode(data_get($response->json(), 'error'));
            Log::warning('Taixue provisioning receipt was rejected', array_filter([
                'request_id' => $requestId,
                'upstream_http_status' => $response->status(),
                'upstream_code' => $upstreamCode,
                'completed' => (bool) data_get($response->json(), 'completed', false),
            ], static fn ($value) => $value !== null));
            throw new OidcFlowException('provisioning_rejected', '太学账号关联未完成，请稍后重试。');
        }
    }

    public static function safeUpstreamCode(mixed $value): ?string
    {
        if (!is_string($value)) {
            return null;
        }
        $value = trim($value);
        if (!preg_match('/^[A-Za-z0-9_]{1,64}$/', $value)) {
            return null;
        }
        return $value;
    }

    public static function endpointIsValid(string $endpoint): bool
    {
        $endpoint = trim($endpoint);
        $parts = parse_url($endpoint);
        if (!is_array($parts) || strtolower((string) ($parts['scheme'] ?? '')) !== 'https' ||
            empty($parts['host']) || isset($parts['user']) || isset($parts['pass']) ||
            isset($parts['query']) || isset($parts['fragment'])) {
            return false;
        }
        $path = rtrim((string) ($parts['path'] ?? ''), '/');
        if (strtolower((string) $parts['host']) === 'auth.taixue.cc') {
            // auth.taixue.cc serves the UI at /v1. User-service traffic must
            // enter through the explicit same-origin /api reverse proxy.
            return $path === '/api/v1/internal/blessing-skin/provisioning';
        }
        return str_ends_with($path, '/v1/internal/blessing-skin/provisioning');
    }

    public static function payload(
        string $subject,
        int $uid,
        string $playerName,
        string $requestId,
        int $timestamp,
        array $snapshot
    ): string {
        return implode("\n", [
            'v2', (string) $timestamp, trim($requestId), trim($subject), (string) $uid,
            strtolower(trim($playerName)), (string) $snapshot['player_id'],
            (string) $snapshot['skin_texture_id'], (string) $snapshot['cape_texture_id'],
            $snapshot['player_last_modified'], $snapshot['nickname'], $snapshot['email'],
            $snapshot['password_hash'], $snapshot['authme_realname'],
            $snapshot['authme_password_hash'], $snapshot['registered_at'],
            $snapshot['last_signed_at'],
        ]);
    }

    public static function snapshot(User $user, Player $player): array
    {
        return [
            'player_id' => (int) $player->pid,
            'skin_texture_id' => (int) $player->tid_skin,
            'cape_texture_id' => (int) $player->tid_cape,
            'player_last_modified' => self::dateString($player->last_modified),
            'nickname' => (string) $user->nickname,
            'email' => (string) $user->email,
            'password_hash' => (string) $user->password,
            'authme_realname' => (string) $user->authme_realname,
            'authme_password_hash' => (string) $user->authme_password,
            'registered_at' => self::dateString($user->register_at),
            'last_signed_at' => self::dateString($user->last_sign_at),
        ];
    }

    private static function dateString($value): string
    {
        if ($value instanceof \DateTimeInterface) {
            return $value->format('Y-m-d H:i:s');
        }
        $value = trim((string) $value);
        $date = \DateTimeImmutable::createFromFormat('Y-m-d H:i:s', $value);
        if (!$date || $date->format('Y-m-d H:i:s') !== $value) {
            throw new OidcFlowException('provisioning_request_invalid', '皮肤站自动注册时间快照无效。');
        }
        return $value;
    }
}
