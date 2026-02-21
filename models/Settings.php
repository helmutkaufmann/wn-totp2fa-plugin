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

    /**
     * Attributes that should be stored as JSON in the settings table.
     *
     * @var array
     */
    public $jsonable = ['require_roles'];

    public function initSettingsData()
    {
        $this->require_mode = 'off'; // off|all|roles
        // store roles as an array of role codes; UI will provide checkboxes
        $this->require_roles = [];
    }

    /**
     * Provide a list of backend roles for the form field options.
     *
     * @return array key=>label pairs where the key is the role code
     */
    public function getRequireRolesOptions(): array
    {
        try {
            // Backend role model is part of the core wintercms installation
            $roles = \Backend\Models\UserRole::all();
            return $roles->mapWithKeys(function ($role) {
                /** @var \Backend\Models\UserRole $role */
                $code = (string) ($role->code ?? $role->id);
                $name = (string) ($role->name ?? $code);
                return [$code => $name];
            })->toArray();
        } catch (\Throwable $_) {
            // In case the backend model isn't available for some reason, fall back to empty list
            return [];
        }
    }

    /**
     * Before the model is saved, make sure roles are stored as an array of codes.
     */
    public function beforeSave()
    {
        if (!is_array($this->require_roles) && is_string($this->require_roles)) {
            $this->require_roles = array_values(array_filter(array_map('trim', explode(',', $this->require_roles))));
        }
    }
}
