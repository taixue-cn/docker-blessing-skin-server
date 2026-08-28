<?php

namespace Taixue\Oidc\Controllers;

use App\Events\PlayerWasAdded;
use App\Events\PlayerWasDeleted;
use App\Events\PlayerWillBeAdded;
use App\Events\PlayerWillBeDeleted;
use App\Models\Player;
use App\Models\User;
use App\Rules;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Taixue\Oidc\EndpointFailure;
use Taixue\Oidc\OidcAudit;
use Taixue\Oidc\OidcFlowException;

class CardinalityRepairController
{
    public function __invoke(Request $request, Dispatcher $events, OidcAudit $audit)
    {
        $uid = null;
        try {
            $input = $this->authenticate($request);
            $uid = $input['uid'];
            if ($input['mode'] === 'PREVIEW') {
                return response()->json([
                    'ok' => true,
                    'plan' => $this->preview($input),
                ]);
            }

            $result = $this->apply($input, $events, $audit);
            return response()->json(array_merge(['ok' => true], $result));
        } catch (\Throwable $error) {
            if (!$error instanceof OidcFlowException) {
                report($error);
            }
            $reason = $error instanceof OidcFlowException
                ? $error->reason()
                : 'internal_error';
            try {
                $audit->record('CARDINALITY_REPAIR', EndpointFailure::outcome($error), $uid, null, [
                    'reason' => $reason,
                ]);
            } catch (\Throwable $auditError) {
                report($auditError);
            }
            $audit->warn('CARDINALITY_REPAIR', $reason);

            return response()->json(
                ['ok' => false, 'error' => $reason],
                $this->failureStatus($reason, $error)
            );
        }
    }

    public static function payload(array $input, int $timestamp, string $requestId): string
    {
        return implode("\n", [
            'v1-cardinality-repair',
            (string) $timestamp,
            $requestId,
            $input['mode'],
            (string) $input['uid'],
            $input['action'],
            $input['expected_revision'],
            $input['canonical_player_id'] === null ? '' : (string) $input['canonical_player_id'],
            strtolower($input['new_player_name'] ?? ''),
        ]);
    }

    private function authenticate(Request $request): array
    {
        $mode = strtoupper(trim((string) $request->input('mode', '')));
        $action = strtoupper(trim((string) $request->input('action', '')));
        $uid = (int) $request->input('uid', 0);
        $expectedRevision = trim((string) $request->input('expected_revision', ''));
        $canonicalPlayerId = $request->input('canonical_player_id');
        $canonicalPlayerId = $canonicalPlayerId === null ? null : (int) $canonicalPlayerId;
        $newPlayerName = trim((string) $request->input('new_player_name', ''));
        $newPlayerName = $newPlayerName === '' ? null : $newPlayerName;
        $requestId = trim((string) $request->header('X-Request-ID', ''));
        $timestamp = trim((string) $request->header('X-Taixue-Timestamp', ''));
        $signature = trim((string) $request->header('X-Taixue-Signature', ''));
        $secret = (string) env('TAIXUE_OIDC_CREATE_SECRET', '');
        $skew = max(30, (int) env('TAIXUE_OIDC_CREATE_CLOCK_SKEW_SECONDS', 300));

        if (!in_array($mode, ['PREVIEW', 'APPLY'], true) ||
            !in_array($action, ['KEEP_PLAYER', 'CREATE_PLAYER'], true) ||
            $uid <= 0 ||
            !preg_match('/^[A-Za-z0-9._:-]{8,64}$/', $requestId) ||
            !preg_match('/^[0-9]{10}$/', $timestamp) ||
            strlen($secret) < 32) {
            throw new OidcFlowException('repair_request_invalid', '皮肤站玩家修复请求无效。');
        }
        if ($mode === 'APPLY' && !preg_match('/^[a-f0-9]{64}$/', $expectedRevision)) {
            throw new OidcFlowException('repair_request_invalid', '皮肤站玩家修复证据无效。');
        }
        $timestampValue = (int) $timestamp;
        if (abs(time() - $timestampValue) > $skew) {
            throw new OidcFlowException('repair_request_expired', '皮肤站玩家修复请求已经过期。');
        }
        $input = [
            'mode' => $mode,
            'uid' => $uid,
            'action' => $action,
            'expected_revision' => $expectedRevision,
            'canonical_player_id' => $canonicalPlayerId,
            'new_player_name' => $newPlayerName,
            'request_id' => $requestId,
        ];
        $expected = 'v1='.hash_hmac(
            'sha256',
            self::payload($input, $timestampValue, $requestId),
            $secret
        );
        if (!hash_equals($expected, $signature)) {
            throw new OidcFlowException('repair_signature_invalid', '皮肤站玩家修复请求签名无效。');
        }

        return $input;
    }

    private function preview(array $input): array
    {
        $snapshot = $this->snapshot($input['uid'], false);
        return $this->buildPlan($snapshot, $input);
    }

    private function apply(array $input, Dispatcher $events, OidcAudit $audit): array
    {
        $payloadHash = hash('sha256', self::payload($input, 0, $input['request_id']));

        return DB::transaction(function () use ($input, $events, $audit, $payloadHash) {
            $existing = DB::table('taixue_oidc_cardinality_repairs')
                ->where('request_id', $input['request_id'])
                ->lockForUpdate()
                ->first();
            if ($existing) {
                if (!hash_equals((string) $existing->payload_hash, $payloadHash)) {
                    throw new OidcFlowException(
                        'repair_request_replayed',
                        '皮肤站玩家修复请求标识已被其他决策使用。'
                    );
                }
                return $this->storedResult($existing);
            }

            $snapshot = $this->snapshot($input['uid'], true);
            $plan = $this->buildPlan($snapshot, $input);
            if (!hash_equals($snapshot['revision'], $input['expected_revision'])) {
                throw new OidcFlowException(
                    'repair_evidence_changed',
                    '皮肤站玩家数据已经变化，请刷新证据后重试。'
                );
            }
            $beforeJson = json_encode(
                $snapshot,
                JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
            );
            $user = User::where('uid', $input['uid'])->lockForUpdate()->first();
            if (!$user) {
                throw new OidcFlowException('repair_account_missing', '皮肤站账号不存在。');
            }

            if ($plan['action'] === 'CREATE_PLAYER') {
                $name = $plan['new_player_name'];
                $events->dispatch('player.adding', [$name, $user]);
                event(new PlayerWillBeAdded($name));
                $player = new Player();
                $player->uid = $user->uid;
                $player->name = $name;
                $player->tid_skin = 0;
                $player->tid_cape = 0;
                $player->save();
                $events->dispatch('player.added', [$player, $user]);
                event(new PlayerWasAdded($player));
            } else {
                foreach ($plan['players_removed'] as $removed) {
                    $player = Player::where('uid', $user->uid)
                        ->where('pid', $removed['pid'])
                        ->lockForUpdate()
                        ->first();
                    if (!$player) {
                        throw new OidcFlowException(
                            'repair_evidence_changed',
                            '皮肤站玩家数据已经变化，请刷新证据后重试。'
                        );
                    }
                    $playerName = $player->name;
                    $events->dispatch('player.deleting', [$player, $user]);
                    event(new PlayerWillBeDeleted($player));
                    $player->delete();
                    $events->dispatch('player.deleted', [$player, $user]);
                    event(new PlayerWasDeleted($playerName));
                }
            }

            $after = $this->snapshot($input['uid'], true);
            if ($after['rows'] !== 1) {
                throw new OidcFlowException(
                    'repair_cardinality_invalid',
                    '修复没有产生唯一皮肤站玩家。'
                );
            }
            $afterJson = json_encode(
                $after,
                JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
            );
            $createdAtMs = (int) floor(microtime(true) * 1000);
            DB::table('taixue_oidc_cardinality_repairs')->insert([
                'request_id' => $input['request_id'],
                'payload_hash' => $payloadHash,
                'uid' => $input['uid'],
                'action' => $input['action'],
                'before_json' => $beforeJson,
                'after_json' => $afterJson,
                'created_at_ms' => $createdAtMs,
                'created_at' => now(),
                'updated_at' => now(),
            ]);
            $audit->record('CARDINALITY_REPAIR', 'SUCCEEDED', $input['uid'], null, [
                'action' => $input['action'],
            ]);

            return [
                'request_id' => $input['request_id'],
                'blessing_skin_uid' => $input['uid'],
                'action' => $input['action'],
                'before' => $snapshot,
                'after' => $after,
                'create_time_ms' => $createdAtMs,
            ];
        });
    }

    private function snapshot(int $uid, bool $lock): array
    {
        $userQuery = User::where('uid', $uid);
        if ($lock) {
            $userQuery->lockForUpdate();
        }
        $user = $userQuery->first();
        if (!$user) {
            throw new OidcFlowException('repair_account_missing', '皮肤站账号不存在。');
        }
        $playersQuery = Player::where('uid', $uid)
            ->orderByRaw('LOWER(name), name, pid');
        if ($lock) {
            $playersQuery->lockForUpdate();
        }
        $players = $playersQuery->get()->map(function (Player $player) {
            return [
                'pid' => (int) $player->pid,
                'name' => (string) $player->name,
                'skin_texture_id' => (int) $player->tid_skin,
                'cape_texture_id' => (int) $player->tid_cape,
                'last_modified' => $player->last_modified
                    ? (string) $player->last_modified
                    : '',
            ];
        })->values()->all();
        $snapshot = [
            'kind' => 'SKIN_UID_PLAYER_CARDINALITY',
            'value' => (string) $uid,
            'identities' => 0,
            'rows' => count($players),
            'skin_nickname' => (string) $user->nickname,
            'closet_items' => (int) DB::table('user_closet')->where('user_uid', $uid)->count(),
            'missing_textures' => 0,
            'players' => $players,
            'player_names' => array_map(fn ($player) => $player['name'], $players),
        ];
        $revisionPayload = json_encode(
            $snapshot,
            JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
        );
        $snapshot['revision'] = hash('sha256', $revisionPayload);

        return $snapshot;
    }

    private function buildPlan(array $snapshot, array $input): array
    {
        $plan = [
            'blessing_skin_uid' => $input['uid'],
            'action' => $input['action'],
            'revision' => $snapshot['revision'],
            'players_removed' => [],
            'conflict' => $snapshot,
            'warnings' => [
                'This operation preserves the Blessing Skin UID and user-owned closet/textures.',
                'The immutable before snapshot can be used for a manual rollback.',
            ],
        ];
        if ($input['action'] === 'CREATE_PLAYER') {
            $name = $input['new_player_name'];
            $rule = new Rules\PlayerName();
            $minimum = (int) option('player_name_length_min');
            $maximum = (int) option('player_name_length_max');
            if ($snapshot['rows'] !== 0 || !$name ||
                !$rule->passes('player_name', $name) ||
                mb_strlen($name, 'UTF-8') < $minimum ||
                mb_strlen($name, 'UTF-8') > $maximum) {
                throw new OidcFlowException(
                    'repair_decision_invalid',
                    '新建玩家决策与当前皮肤站账号不匹配。'
                );
            }
            if (Player::whereRaw('LOWER(name) = LOWER(?)', [$name])->exists()) {
                throw new OidcFlowException('player_name_collision', '玩家名已被使用。');
            }
            $plan['new_player_name'] = $name;
            return $plan;
        }

        $canonical = $input['canonical_player_id'];
        if ($snapshot['rows'] < 2 || !$canonical) {
            throw new OidcFlowException(
                'repair_decision_invalid',
                '保留玩家决策与当前皮肤站账号不匹配。'
            );
        }
        $found = false;
        foreach ($snapshot['players'] as $player) {
            if ($player['pid'] === $canonical) {
                $found = true;
            } else {
                $plan['players_removed'][] = $player;
            }
        }
        if (!$found) {
            throw new OidcFlowException('repair_decision_invalid', '保留的玩家不属于该账号。');
        }
        $plan['canonical_player_id'] = $canonical;
        return $plan;
    }

    private function storedResult($row): array
    {
        return [
            'request_id' => (string) $row->request_id,
            'blessing_skin_uid' => (int) $row->uid,
            'action' => (string) $row->action,
            'before' => json_decode((string) $row->before_json, true, 512, JSON_THROW_ON_ERROR),
            'after' => json_decode((string) $row->after_json, true, 512, JSON_THROW_ON_ERROR),
            'create_time_ms' => (int) $row->created_at_ms,
        ];
    }

    private function failureStatus(string $reason, \Throwable $error): int
    {
        if ($reason === 'repair_signature_invalid') {
            return 401;
        }
        if ($reason === 'repair_request_expired') {
            return 408;
        }
        if (in_array($reason, [
            'repair_request_invalid',
            'repair_request_replayed',
            'repair_evidence_changed',
            'repair_decision_invalid',
            'repair_cardinality_invalid',
            'repair_account_missing',
            'player_name_collision',
        ], true)) {
            return 409;
        }
        return EndpointFailure::status($error);
    }
}
