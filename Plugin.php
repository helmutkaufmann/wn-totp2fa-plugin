<?php namespace Mercator\Totp2fa;

use System\Classes\PluginBase;
use Backend\Models\User as BackendUser;
use Backend\Facades\Backend;
use Backend\Facades\BackendAuth;
use Event;
use Redirect;

use Mercator\Totp2fa\Classes\Enforcement;
use Mercator\Totp2fa\Controllers\Challenge;

/**
 * Event-based enforcement:
 * - backend.page.beforeDisplay: guards normal backend navigation
 * - backend.ajax.beforeRunHandler: guards AJAX handlers to prevent bypass
 */
class Plugin extends PluginBase
{
    public function pluginDetails()
    {
        return [
            'name'        => 'Backend TOTP 2FA',
            'description' => 'TOTP 2FA for backend users.',
            'author'      => '"Helmut Kaufmann',
            'icon'        => 'icon-lock',
        ];
    }

    public function registerPermissions()
    {
        return [
            'mercator.totp2fa.manage_settings' => [
                'label' => 'Manage TOTP 2FA settings for backend users',
                'tab'   => 'Security',
            ],
        ];
    }

    public function registerSettings()
    {
        return [
            'settings' => [
                'label'       => 'Backend TOTP 2FA',
                'description' => 'Configure time-based one-time password 2FA for backend users.',
                'category'    => 'Security',
                'icon'        => 'icon-lock',
                'class'       => \Mercator\Totp2fa\Models\Settings::class,
                'order'       => 500,
                'keywords'    => '2fa totp mfa security password authenticator',
                'permissions' => ['mercator.totp2fa.manage_settings'],
            ],
        ];
    }

    public function boot()
    {
        Event::listen('backend.page.beforeDisplay', function ($controller, $action, $params) {
            if (!BackendAuth::check()) return null;

            $user = BackendAuth::getUser();
            if (!$user) return null;

            // Always allow the challenge controller to render (avoid redirect loops).
            if ($controller instanceof Challenge) {
                return null;
            }

            // Always allow core backend auth routes.
            $path = trim(request()->path(), '/');
            if (str_starts_with($path, 'backend/auth')) {
                return null;
            }

            $requires = Enforcement::requires2faForUser($user);
            $enabled  = (bool) $user->twofa_enabled;

            // No requirement and not enabled → no enforcement.
            if (!$requires && !$enabled) return null;

            // Always remember where the user wanted to go (for post-2FA redirect).
            session(['mercator.totp2fa.intended' => request()->fullUrl()]);

            // Required but not enrolled → force setup.
            if ($requires && !$enabled) {
                return Redirect::to(Backend::url('mercator/totp2fa/challenge/setup'));
            }

            // Enrolled but not verified for this session → force challenge.
            if (!Enforcement::isVerifiedForSession($user)) {
                return Redirect::to(Backend::url('mercator/totp2fa/challenge'));
            }

            return null;
        });

        Event::listen('backend.ajax.beforeRunHandler', function ($handler) {
            if (!BackendAuth::check()) return null;

            $user = BackendAuth::getUser();
            if (!$user) return null;

            $requires = Enforcement::requires2faForUser($user);
            $enabled  = (bool) $user->twofa_enabled;

            if (!$requires && !$enabled) return null;

            // Allow AJAX for the challenge controller routes.
            $path = trim(request()->path(), '/');
            if (str_contains($path, 'mercator/totp2fa/challenge')) {
                return null;
            }

            if ($requires && !$enabled) {
                abort(403, '2FA setup required');
            }

            if (!Enforcement::isVerifiedForSession($user)) {
                abort(403, '2FA verification required');
            }

            return null;
        });

        // Backend user management: DO NOT display recovery codes here.
        Event::listen('backend.form.extendFields', function ($form) {
            if (!($form->model instanceof BackendUser) || $form->isNested) {
                return;
            }

            $form->addTabFields([
                'twofa_ui' => [
                    'tab'   => 'Security',
                    'label' => 'Two-Factor Authentication',
                    'type'  => 'partial',
                    'path'  => '$/mercator/totp2fa/partials/_twofa_admin.htm',
                ],
            ]);
        });
    }
}
