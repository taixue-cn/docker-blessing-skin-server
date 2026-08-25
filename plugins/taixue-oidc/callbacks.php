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
    },
    PluginWasDeleted::class => function () {
        // Account mappings and security audit records are migration data, not
        // disposable plugin cache. Preserve both for rollback and reinstall.
    },
];
