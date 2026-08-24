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
    },
    PluginWasDeleted::class => function () {
        Schema::dropIfExists('taixue_oidc_links');
    },
];
