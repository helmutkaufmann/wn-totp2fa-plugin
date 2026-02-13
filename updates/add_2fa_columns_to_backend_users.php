<?php namespace Mercator\Totp2fa\Updates;

use Schema;
use Winter\Storm\Database\Updates\Migration;

/**
 * Adds 2FA columns to backend_users.
 *
 * Columns are added idempotently to support repeated deployments.
 */
class Add2faColumnsToBackendUsers extends Migration
{
    public function up()
    {
        Schema::table('backend_users', function ($table) {
            if (!Schema::hasColumn('backend_users', 'twofa_enabled')) {
                $table->boolean('twofa_enabled')->default(false);
            }
            if (!Schema::hasColumn('backend_users', 'twofa_secret')) {
                $table->text('twofa_secret')->nullable(); // encrypted
            }
            if (!Schema::hasColumn('backend_users', 'twofa_pending_secret')) {
                $table->text('twofa_pending_secret')->nullable(); // encrypted
            }
            if (!Schema::hasColumn('backend_users', 'twofa_recovery_codes')) {
                $table->text('twofa_recovery_codes')->nullable(); // encrypted json
            }
            if (!Schema::hasColumn('backend_users', 'twofa_confirmed_at')) {
                $table->timestamp('twofa_confirmed_at')->nullable();
            }
            // Marker for "show recovery codes once" per generation.
            if (!Schema::hasColumn('backend_users', 'twofa_recovery_generated_at')) {
                $table->timestamp('twofa_recovery_generated_at')->nullable();
            }
            if (!Schema::hasColumn('backend_users', 'twofa_recovery_shown_at')) {
                $table->timestamp('twofa_recovery_shown_at')->nullable();
            }
        });
    }

    public function down()
{
    // Remove columns added by this plugin (idempotent).
    if (!Schema::hasTable('backend_users')) {
        return;
    }

    Schema::table('backend_users', function ($table) {
        $cols = [
            'twofa_enabled',
            'twofa_secret',
            'twofa_pending_secret',
            'twofa_recovery_codes',
            'twofa_confirmed_at',
            'twofa_recovery_generated_at',
            'twofa_recovery_shown_at',
        ];

        foreach ($cols as $col) {
            if (Schema::hasColumn('backend_users', $col)) {
                $table->dropColumn($col);
            }
        }
    });
}

}
