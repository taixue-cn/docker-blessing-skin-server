<?php

use App\Events\PluginWasDeleted;
use App\Events\PluginWasEnabled;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return [
    PluginWasEnabled::class => function () {
        if (!Schema::hasTable('taixue_oidc_links')) {
            Schema::create('taixue_oidc_links', function (Blueprint $table) {
                $table->unsignedInteger('uid')->primary();
                $table->string('subject', 191)->unique();
                $table->boolean('provisioned')->default(false);
                $table->timestamps();
            });
        } elseif (!Schema::hasColumn('taixue_oidc_links', 'provisioned')) {
            Schema::table('taixue_oidc_links', function (Blueprint $table) {
                $table->boolean('provisioned')->default(false)->after('subject');
            });
        }
        if (!Schema::hasTable('taixue_oidc_audit_events')) {
            Schema::create('taixue_oidc_audit_events', function (Blueprint $table) {
                $table->bigIncrements('id');
                $table->string('event_type', 64)->index();
                $table->string('outcome', 32);
                $table->unsignedInteger('uid')->nullable()->index();
                $table->string('subject', 191)->nullable()->index();
                $table->string('request_id', 64)->index();
                $table->string('inet_addr', 45)->nullable();
                $table->string('user_agent', 255)->nullable();
                $table->text('metadata_json')->nullable();
                $table->timestamp('created_at')->useCurrent();
            });
        }
        if (!Schema::hasTable('taixue_oidc_revocations')) {
            Schema::create('taixue_oidc_revocations', function (Blueprint $table) {
                $table->bigIncrements('id');
                $table->string('jti', 191)->unique();
                $table->string('subject', 191)->nullable()->index();
                $table->string('sid', 191)->nullable()->index();
                $table->string('event_type', 64)->default('UNKNOWN')->index();
                $table->timestamp('revoked_at')->index();
                $table->timestamp('purge_after')->index();
                $table->timestamp('created_at')->useCurrent();
            });
        } elseif (!Schema::hasColumn('taixue_oidc_revocations', 'event_type')) {
            Schema::table('taixue_oidc_revocations', function (Blueprint $table) {
                $table->string('event_type', 64)->default('UNKNOWN')->index()->after('sid');
            });
        }
        if (!Schema::hasTable('taixue_oidc_provision_requests')) {
            Schema::create('taixue_oidc_provision_requests', function (Blueprint $table) {
                $table->string('request_id', 64)->primary();
                $table->string('payload_hash', 64);
                $table->string('subject', 191)->index();
                $table->unsignedInteger('uid')->nullable()->index();
                $table->timestamps();
            });
        }
        if (!Schema::hasTable('taixue_oidc_password_sync_requests')) {
            Schema::create('taixue_oidc_password_sync_requests', function (Blueprint $table) {
                $table->string('request_id', 64)->primary();
                $table->string('payload_hash', 64);
                $table->string('subject', 191)->index();
                $table->unsignedInteger('uid')->index();
                $table->timestamps();
            });
        }
        if (!Schema::hasTable('taixue_oidc_password_versions')) {
            Schema::create('taixue_oidc_password_versions', function (Blueprint $table) {
                $table->string('subject', 191)->primary();
                $table->unsignedInteger('uid')->index();
                $table->unsignedBigInteger('event_id');
                $table->string('payload_hash', 64);
                $table->timestamps();
            });
        }
        if (!Schema::hasTable('taixue_oidc_cardinality_repairs')) {
            Schema::create('taixue_oidc_cardinality_repairs', function (Blueprint $table) {
                $table->string('request_id', 64)->primary();
                $table->string('payload_hash', 64);
                $table->unsignedInteger('uid')->index();
                $table->string('action', 32);
                $table->longText('before_json');
                $table->longText('after_json');
                $table->unsignedBigInteger('created_at_ms');
                $table->timestamps();
            });
        }
    },
    PluginWasDeleted::class => function () {
        // Account mappings, security audit records, and live revocations are
        // migration/security data, not disposable plugin cache. Preserve them
        // for rollback and reinstall.
    },
];
