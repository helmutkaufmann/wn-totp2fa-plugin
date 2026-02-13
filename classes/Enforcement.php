<?php namespace Mercator\Totp2fa\Classes;

use Mercator\Totp2fa\Models\Settings;
use Backend\Models\User as BackendUser;

/**
 * Enforcement decisions for backend users.
 */
class Enforcement
{
    public static function requires2faForUser(BackendUser $user): bool
    {
        $mode = (string) Settings::get('require_mode', 'off');

        if ($mode === 'off') return false;
        if ($mode === 'all') return true;

        if ($mode === 'roles') {
            $rolesRaw = (string) Settings::get('require_roles', '');
            $needles = array_values(array_filter(array_map('trim', explode(',', $rolesRaw))));
            if (!$needles) return false;

            try {
                $roles = $user->roles;
                foreach ($roles as $role) {
                    $code = (string) ($role->code ?? '');
                    $name = (string) ($role->name ?? '');
                    foreach ($needles as $n) {
                        if ($n !== '' && (strcasecmp($n, $code) === 0 || strcasecmp($n, $name) === 0)) {
                            return true;
                        }
                    }
                }
            } catch (\Throwable $e) {
                // If role resolution fails, fail closed.
                return true;
            }

            return false;
        }

        return false;
    }

    public static function isVerifiedForSession(BackendUser $user): bool
    {
        return ((int) session('mercator.totp2fa.verified_user_id', 0) === (int) $user->id);
    }
}
