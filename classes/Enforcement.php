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
            $needles = Settings::get('require_roles', '[]');
            // Decode JSON if it's a string
            if (is_string($needles)) {
                $needles = json_decode($needles, true) ?? [];
            }
            // ensure clean array with no empty strings; reindex to get fresh keys
            $needles = array_values(array_filter($needles, function ($v) { return trim((string) $v) !== ''; }));
            if (!$needles) {
                return false;
            }

            \Log::info('TOTP2FA: checking roles for user ' . $user->login . '. Required roles: ' . json_encode($needles));

            try {
                // In WinterCMS, users have a single role (not roles relationship)
                // Access role via role_id and the role attribute
                $userRole = $user->role;
                if (!$userRole) {
                    \Log::info('TOTP2FA: user ' . $user->login . ' has no role assigned.');
                    return false;
                }

                // use the same key generation as getRequireRolesOptions()
                $key = (string) ($userRole->code ?? $userRole->id ?? '');
                $name = (string) ($userRole->name ?? $key);
                
                \Log::info('TOTP2FA: user ' . $user->login . ' has role - code/id: ' . $key . ', name: ' . $name);
                
                if ($key === '') {
                    \Log::info('TOTP2FA: user ' . $user->login . ' role has no valid identifier.');
                    return false;
                }
                
                foreach ($needles as $n) {
                    $nStr = trim((string) $n);
                    if ($nStr !== '' && (strcasecmp($nStr, $key) === 0 || strcasecmp($nStr, $name) === 0)) {
                        \Log::info('TOTP2FA: user ' . $user->login . ' matches required role ' . $nStr);
                        return true;
                    }
                }
                // no matching role found
                \Log::info('TOTP2FA: user ' . $user->login . ' does not match any required role.');
                return false;
            } catch (\Throwable $e) {
                // If role resolution fails, fail open rather than locking every user out.
                // Log the exception so admins can troubleshoot their setup.
                \Log::warning('TOTP2FA: unable to inspect user roles for enforcement: ' . $e->getMessage());
                \Log::warning('TOTP2FA: exception trace: ' . $e->getTraceAsString());
                return false;
            }
        }

        return false;
    }

    public static function isVerifiedForSession(BackendUser $user): bool
    {
        return ((int) session('mercator.totp2fa.verified_user_id', 0) === (int) $user->id);
    }
}
