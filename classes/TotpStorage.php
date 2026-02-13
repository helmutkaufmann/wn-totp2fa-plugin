<?php namespace Mercator\Totp2fa\Classes;

use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Str;

/**
 * Helpers for encrypting/decrypting 2FA secrets and recovery codes.
 */
class TotpStorage
{
    public static function enc(?string $value): ?string
    {
        return $value ? Crypt::encryptString($value) : null;
    }

    public static function dec(?string $value): ?string
    {
        if (!$value) return null;
        try { return Crypt::decryptString($value); } catch (\Throwable $e) { return null; }
    }

    public static function encJson(array $value): string
    {
        return Crypt::encryptString(json_encode(array_values($value)));
    }

    public static function decJson(?string $value): array
    {
        if (!$value) return [];
        try {
            $decoded = json_decode(Crypt::decryptString($value), true);
            return is_array($decoded) ? $decoded : [];
        } catch (\Throwable $e) {
            return [];
        }
    }

    public static function makeRecoveryCodes(int $count = 10): array
    {
        $codes = [];
        for ($i = 0; $i < $count; $i++) {
            $codes[] = Str::upper(Str::random(10) . '-' . Str::random(10));
        }
        return $codes;
    }
}
