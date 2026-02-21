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
     * Get require_roles from attributes, cleaning it up.
     */
    public function getRequireRolesAttribute($value)
    {
        if (is_array($value)) {
            return $value;
        }
        if (is_string($value)) {
            if (substr($value, 0, 1) === '[') {
                $decoded = json_decode($value, true);
                return is_array($decoded) ? $decoded : [];
            }
            return array_values(array_filter(array_map('trim', explode(',', $value))));
        }
        return [];
    }

    /**
     * Set require_roles, ensuring it's cleaned.
     */
    public function setRequireRolesAttribute($value)
    {
        if ($value === null) {
            $this->attributes['require_roles'] = [];
        } elseif (is_string($value)) {
            if (substr($value, 0, 1) === '[') {
                $decoded = json_decode($value, true);
                $this->attributes['require_roles'] = is_array($decoded) ? $decoded : [];
            } else {
                $this->attributes['require_roles'] = array_values(array_filter(array_map('trim', explode(',', $value))));
            }
        } elseif (is_array($value)) {
            $this->attributes['require_roles'] = array_values(array_unique(array_filter(array_map('trim', $value))));
        } else {
            $this->attributes['require_roles'] = [];
        }
    }

    /**
     * Override save to work around the ORM trying to update a non-existent require_roles column.
     * When it fails, manually update just the value column with the correct JSON.
     */
    public function save(?array $options = [], $sessionKey = null)
    {
        try {
            return parent::save($options, $sessionKey);
        } catch (\Exception $e) {
            // The "no such column: require_roles" error occurs because ORM tries to SET require_roles directly.
            // Manually update the value column with all model attributes serialized to JSON.
            if (strpos($e->getMessage(), 'no such column: require_roles') !== false && $this->exists) {
                // Serialize all attributes except standard DB columns
                $valueData = [];
                $excludeKeys = [$this->getKeyName(), 'id', 'created_at', 'updated_at'];
                
                foreach ($this->attributes as $key => $value) {
                    if (!in_array($key, $excludeKeys)) {
                        $valueData[$key] = $value;
                    }
                }
                
                // Manually update the value column with JSON-encoded attributes
                $updated = $this->getConnection()->table($this->getTable())
                    ->where($this->getKeyName(), $this->getKey())
                    ->update(['value' => json_encode($valueData)]);
                
                return $updated > 0;
            }
            throw $e;
        }
    }
}



