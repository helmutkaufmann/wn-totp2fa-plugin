<?php namespace Mercator\Totp2fa;

use System\Classes\PluginBase;
use Backend\Models\User as BackendUser;
use Backend\Facades\BackendAuth;
use Event;
use Redirect;

use Mercator\Totp2fa\Classes\EnforceTotpMiddleware;
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
        // Register a global web middleware so TOTP is enforced on every request
        // where a backend user is authenticated — including CMS pages and plugin
        // routes outside the /meradmin URL (e.g. /portfolio-admin).
        app('router')->pushMiddlewareToGroup('web', EnforceTotpMiddleware::class);

        // When a CMS page requires backend login and the user is NOT authenticated,
        // redirect to the backend login page instead of showing a 404.
        Event::listen('cms.page.init', function ($controller /*, $url, $page */) {
            try {
                $page = $controller->getPage();
                if (!$page) return;

                // Check the standard WinterCMS CMS security setting.
                $security = $page->settings['security']
                    ?? $page->viewBag['requiresBackendLogin']
                    ?? $page->viewBag['security']
                    ?? null;

                if ($security !== 'backend') return;

                if (!BackendAuth::check()) {
                    $backendPrefix = trim((string) config('cms.backendUri', 'backend'), '/');
                    $loginUrl     = url($backendPrefix . '/auth/signin');
                    return Redirect::to($loginUrl);
                }
            } catch (\Throwable $e) {
                \Log::error('TOTP2FA cms.page.init guard error: ' . $e->getMessage());
            }
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
