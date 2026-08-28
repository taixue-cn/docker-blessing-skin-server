<?php

namespace Taixue\Oidc;

use App\Events;
use App\Models\Player;
use App\Models\User;
use App\Rules;
use Blessing\Filter;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Vectorface\Whip\Whip;

class SkinAccountProvisioner
{
    public function provision(
        string $subject,
        string $playerName,
        ?string $email,
        ?string $displayName,
        Dispatcher $events,
        OidcAudit $audit
    ) {
        return DB::transaction(function () use (
            $subject,
            $playerName,
            $email,
            $displayName,
            $events,
            $audit
        ) {
            $existing = DB::table('taixue_oidc_links')
                ->where('subject', $subject)
                ->lockForUpdate()
                ->first();
            if ($existing) {
                return $this->assertExistingAccount($existing, $playerName);
            }

            if ($email && User::where('email', $email)->exists()) {
                throw new OidcFlowException(
                    'email_collision',
                    '同邮箱的皮肤站账号已经存在，系统不会据此自动合并身份。请联系有权限的管理员在统一账号系统中核对冲突。'
                );
            }

            $playerName = trim($playerName);
            $playerRule = new Rules\PlayerName();
            $minimum = (int) option('player_name_length_min');
            $maximum = (int) option('player_name_length_max');
            $length = mb_strlen($playerName, 'UTF-8');
            if (!$playerRule->passes('player_name', $playerName) ||
                $length < $minimum || $length > $maximum) {
                throw new OidcFlowException(
                    'player_name_invalid',
                    '太学用户名不符合皮肤站玩家名规则，请联系管理员处理。'
                );
            }
            if (Player::where('name', $playerName)->lockForUpdate()->exists()) {
                throw new OidcFlowException(
                    'player_name_collision',
                    '同名皮肤站玩家已经存在。请联系有权限的管理员在统一账号系统中核对归属。'
                );
            }

            $user = new User();
            $user->email = $email ?: 'oidc-'.hash('sha256', $subject).'@users.invalid';
            $user->nickname = Str::limit($displayName ?: $playerName, 255, '');
            $user->score = option('user_initial_score');
            $user->avatar = 0;
            $password = app('cipher')->hash(Str::random(64), config('secure.salt'));
            $user->password = resolve(Filter::class)->apply('user_password', $password);
            $ip = (new Whip())->getValidIpAddress();
            $user->ip = resolve(Filter::class)->apply('client_ip', $ip);
            $user->permission = User::NORMAL;
            $user->register_at = now();
            $user->last_sign_at = now()->subDay();
            $registration = [
                'email' => $user->email,
                'nickname' => $user->nickname,
                'player_name' => $playerName,
            ];
            $events->dispatch('auth.registration.attempt', [$registration]);
            $events->dispatch('auth.registration.ready', [$registration]);
            $user->save();
            $events->dispatch('auth.registration.completed', [$user]);
            event(new Events\UserRegistered($user));

            // Preserve Blessing Skin's native register-with-player lifecycle,
            // including UUID customization listeners in this deployment.
            $events->dispatch('player.adding', [$playerName, $user]);
            event(new Events\PlayerWillBeAdded($playerName));
            $player = new Player();
            $player->uid = $user->uid;
            $player->name = $playerName;
            $player->tid_skin = 0;
            $player->tid_cape = 0;
            $player->save();
            if ($user->players()->count() !== 1) {
                throw new OidcFlowException(
                    'skin_player_cardinality_invalid',
                    '皮肤站账号没有且仅有一个玩家，注册已取消。'
                );
            }
            $events->dispatch('player.added', [$player, $user]);
            event(new Events\PlayerWasAdded($player));

            DB::table('taixue_oidc_links')->insert([
                'uid' => $user->uid,
                'subject' => $subject,
                'provisioned' => true,
                'created_at' => now(),
                'updated_at' => now(),
            ]);
            $audit->record('REGISTER', 'SUCCEEDED', (int) $user->uid, $subject, [
                'source' => 'taixue_oidc',
            ]);

            return (object) [
                'uid' => $user->uid,
                'subject' => $subject,
                'provisioned' => true,
            ];
        });
    }

    private function assertExistingAccount($link, string $playerName)
    {
        $user = User::find((int) $link->uid);
        if (!$user) {
            throw new OidcFlowException(
                'local_account_missing',
                '绑定的皮肤站账号不存在，请联系管理员修复。'
            );
        }
        $players = $user->players()->limit(2)->get();
        if ($players->count() !== 1 ||
            strcasecmp((string) $players->first()->name, trim($playerName)) !== 0) {
            throw new OidcFlowException(
                'skin_player_cardinality_invalid',
                '皮肤站账号必须恰好关联一个同名玩家，请联系管理员修复。'
            );
        }
        return $link;
    }
}
