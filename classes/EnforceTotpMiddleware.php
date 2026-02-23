<?php namespace Mercator\Totp2fa\Classes;

use Backend\Facades\BackendAuth;
use Closure;
use Illuminate\Support\Facades\Redirect;
use Illuminate\Support\Facades\Response;
use Illuminate\Support\Facades\Session;

/**
 * Global middleware that enforces TOTP 2FA for any authenticated backend user,
 * regardless of whether the request comes via the /meradmin backend URL or a
 * CMS page / other plugin route that requires backend authentication.
 */
class EnforceTotpMiddleware
{
    /**
     * Return the backend URL prefix (e.g. "meradmin") from config.
     */
    private function backendPrefix(): string
    {
        return trim((string) config('cms.backendUri', 'backend'), '/');
    }

    /**
     * Build a backend URL from a partial path without relying on Backend::url().
     */
    private function backendUrl(string $path): string
    {
        return url($this->backendPrefix() . '/' . ltrim($path, '/'));
    }

    public function handle($request, Closure $next)
    {
        try {
            return $this->enforce($request, $next);
        } catch (\Throwable $e) {
            // If the middleware itself errors, log it and let the request through
            // rather than converting a middleware bug into a 404/500 for the user.
            \Log::error('TOTP2FA EnforceTotpMiddleware error: ' . $e->getMessage(), ['trace' => $e->getTraceAsString()]);
            return $next($request);
        }
    }

    private function enforce($request, Closure $next)
    {
        // Only act when a backend user is authenticated.
        if (!BackendAuth::check()) {
            return $next($request);
        }

        $user = BackendAuth::getUser();
        if (!$user) {
            return $next($request);
        }

        // Never block requests to the challenge controller itself (avoid loops).
        $prefix = $this->backendPrefix();
        $path   = trim($request->path(), '/');

        if (str_starts_with($path, $prefix . '/mercator/totp2fa/challenge')) {
            return $next($request);
        }

        // Allow WinterCMS backend auth routes (login / logout / password reset).
        if (str_starts_with($path, $prefix . '/auth')) {
            return $next($request);
        }

        $requires = Enforcement::requires2faForUser($user);
        $enabled  = (bool) ($user->twofa_enabled ?? false);

        // No requirement and not enrolled → no enforcement.
        if (!$requires && !$enabled) {
            return $next($request);
        }

        // Remember the intended URL so we can redirect back after verification.
        Session::put('mercator.totp2fa.intended', $request->fullUrl());

        // Required but not enrolled → redirect to setup.
        if ($requires && !$enabled) {
            return Redirect::to($this->backendUrl('mercator/totp2fa/challenge/setup'));
        }

        // Enrolled but not yet verified in this session → redirect to challenge.
        if (!Enforcement::isVerifiedForSession($user)) {
            // AJAX: return a 403 with a JSON error instead of a redirect.
            if ($request->ajax() || $request->wantsJson()) {
                return Response::json(['error' => '2FA verification required'], 403);
            }

            return Redirect::to($this->backendUrl('mercator/totp2fa/challenge'));
        }

        return $next($request);
    }
}
