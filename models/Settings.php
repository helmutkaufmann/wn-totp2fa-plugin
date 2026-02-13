<?php namespace Mercator\Totp2fa\Models;

use Model;

/**
 * Global enforcement settings for backend 2FA.
 */
class Settings extends Model
{
    public $implement = ['System.Behaviors.SettingsModel'];

    public $settingsCode = 'mercator_totp2fa_settings';
    public $settingsFields = 'fields.yaml';

    public function initSettingsData()
    {
        $this->require_mode = 'off'; // off|all|roles
        $this->require_roles = '';
    }
}
