<?php namespace Mercator\Totp2fa\Controllers;

use Backend\Classes\Controller;
use Backend\Facades\Backend;
use Backend\Facades\BackendAuth;
use Backend\Models\User as BackendUser;
use Flash;
use Redirect;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Log;

use Mercator\Totp2fa\Classes\Enforcement;
use Mercator\Totp2fa\Classes\Qr;
use Mercator\Totp2fa\Classes\TotpStorage;

/**
 * Challenge controller (auth layout).
 *
 * Routes:
 * - index(): verify 2FA for this session
 * - setup(): enroll (QR + confirm code)
 * - recovery(): show recovery codes ONCE after enrollment or regeneration
 * - manage(): user self-service (regenerate codes)
 */
class Challenge extends Controller
{
    public $requiredPermissions = [];

    public function __construct()
    {
        parent::__construct();
        $this->layout = 'auth';
    }

    public function index()
    {
        if (!BackendAuth::check()) {
            return Redirect::to(Backend::url('backend/auth/signin'));
        }

        $user = BackendAuth::getUser();
        if (!$user) {
            return Redirect::to(Backend::url('backend/auth/signin'));
        }

        if (!$user->twofa_enabled) {
            return Redirect::to(Backend::url('mercator/totp2fa/challenge/setup'));
        }

        $this->pageTitle = 'Two-Factor Authentication';
        $this->vars['mode'] = 'verify';
        $this->vars['canUseRecovery'] = !empty(TotpStorage::decJson($user->twofa_recovery_codes));
    }

    public function setup()
    {
        if (!BackendAuth::check()) {
            return Redirect::to(Backend::url('backend/auth/signin'));
        }

        $user = BackendAuth::getUser();
        if (!$user) {
            return Redirect::to(Backend::url('backend/auth/signin'));
        }

        if ($user->twofa_enabled) {
            return Redirect::to(Backend::url('mercator/totp2fa/challenge'));
        }

        $google2fa = new \PragmaRX\Google2FA\Google2FA();

        $pendingSecret = TotpStorage::dec($user->twofa_pending_secret);
        if (!$pendingSecret) {
            $pendingSecret = $google2fa->generateSecretKey();
            $user->twofa_pending_secret = TotpStorage::enc($pendingSecret);
            $user->save();
        }

        $qrText = $google2fa->getQRCodeUrl(config('app.name', 'WinterCMS'), $user->email, $pendingSecret);

        $this->pageTitle = 'Set up Two-Factor Authentication';
        $this->vars['mode'] = 'setup';
        $this->vars['requires'] = Enforcement::requires2faForUser($user);
        $this->vars['qrSvg'] = Qr::svg($qrText, 220);
        $this->vars['secret'] = $pendingSecret;
    }

    public function manage()
    {
        if (!BackendAuth::check()) {
            return Redirect::to(Backend::url('backend/auth/signin'));
        }

        $user = BackendAuth::getUser();
        if (!$user) {
            return Redirect::to(Backend::url('backend/auth/signin'));
        }

        // Require enrollment to manage recovery codes.
        if (!$user->twofa_enabled) {
            return Redirect::to(Backend::url('mercator/totp2fa/challenge/setup'));
        }

        // Require session verification before allowing regeneration.
        if (!Enforcement::isVerifiedForSession($user)) {
            session(['mercator.totp2fa.intended' => Backend::url('mercator/totp2fa/challenge/manage')]);
            return Redirect::to(Backend::url('mercator/totp2fa/challenge'));
        }

        $this->pageTitle = 'Manage 2FA';
        $this->vars['mode'] = 'manage';
    }

    public function recovery()
    {
        if (!BackendAuth::check()) {
            return Redirect::to(Backend::url('backend/auth/signin'));
        }

        $user = BackendAuth::getUser();
        if (!$user) {
            return Redirect::to(Backend::url('backend/auth/signin'));
        }

        // Only show recovery codes immediately after creation:
        // onConfirmSetup() / onRegenerateRecovery() sets this as a flash flag.
        if (!(bool) session('mercator.totp2fa.allow_show_recovery', false)) {
            // Prevent redirect loops after acknowledging recovery codes.
// - Ensure the session remains verified.
// - Never allow "intended" redirects back into any challenge route.
session(['mercator.totp2fa.verified_user_id' => (int) $user->id]);

$redirect = session('mercator.totp2fa.post_recovery_redirect') ?: session('mercator.totp2fa.intended');
if (is_string($redirect) && str_contains($redirect, 'totp2fa/challenge')) {
    session()->forget('mercator.totp2fa.post_recovery_redirect');
    session()->forget('mercator.totp2fa.intended');
}

// Clear Laravel's generic intended URL as well.
session()->forget('url.intended');

        return $this->redirectAfter2fa();
        }

        // Safety: only show if they haven't been shown since last generation.
        if ($user->twofa_recovery_generated_at && $user->twofa_recovery_shown_at
            && strtotime($user->twofa_recovery_shown_at) >= strtotime($user->twofa_recovery_generated_at)) {
            return $this->redirectAfter2fa();
        }

        $codes = TotpStorage::decJson($user->twofa_recovery_codes);
        if (empty($codes)) {
            return $this->redirectAfter2fa();
        }

        $this->pageTitle = 'Recovery codes';
        $this->vars['mode'] = 'recovery';
        $this->vars['codes'] = $codes;
    }

    public function onVerify()
    {
        $user = BackendAuth::getUser();
        if (!$user) {
            return Redirect::to(Backend::url('backend/auth/signin'));
        }

        $code = strtoupper(trim(post('code', '')));
        if ($code === '') {
            Flash::error('Enter a code.');
            return Redirect::refresh();
        }

        $key = $this->rateLimitKey($user, 'verify');
        if (RateLimiter::tooManyAttempts($key, 5)) {
            Flash::error('Too many attempts. Please try again later.');
            return Redirect::refresh();
        }

        $secret = TotpStorage::dec($user->twofa_secret);
        $google2fa = new \PragmaRX\Google2FA\Google2FA();

        $validTotp = $secret ? $google2fa->verifyKey($secret, $code) : false;

        if (!$validTotp) {
            $recovery = TotpStorage::decJson($user->twofa_recovery_codes);
            $matchedIndex = null;
            
            // Use constant-time comparison to prevent timing attacks
            foreach ($recovery as $idx => $recoveryCode) {
                if (hash_equals($recoveryCode, $code)) {
                    $matchedIndex = $idx;
                    break;
                }
            }
            
            if ($matchedIndex !== null) {
                unset($recovery[$matchedIndex]);
                $user->twofa_recovery_codes = TotpStorage::encJson(array_values($recovery));
                $user->save();
                $validTotp = true;
                Log::info('Recovery code used successfully', [
                    'user_id' => $user->id,
                    'email' => $user->email,
                    'ip' => request()->ip(),
                ]);
            }
        }

        if (!$validTotp) {
            RateLimiter::hit($key, 300);
            Log::warning('Failed 2FA verification attempt', [
                'user_id' => $user->id,
                'email' => $user->email,
                'ip' => request()->ip(),
                'attempted_code_length' => strlen($code),
            ]);
            Flash::error('Invalid 2FA code.');
            return Redirect::refresh();
        }

        RateLimiter::clear($key);

        session(['mercator.totp2fa.verified_user_id' => (int) $user->id]);

        return $this->redirectAfter2fa();
    }

    public function onConfirmSetup()
    {
        $user = BackendAuth::getUser();
        if (!$user) {
            return Redirect::to(Backend::url('backend/auth/signin'));
        }

        if ($user->twofa_enabled) {
            return Redirect::to(Backend::url('mercator/totp2fa/challenge'));
        }

        $code = strtoupper(trim(post('code', '')));
        if ($code === '') {
            Flash::error('Enter a code.');
            return Redirect::refresh();
        }

        $key = $this->rateLimitKey($user, 'setup');
        if (RateLimiter::tooManyAttempts($key, 5)) {
            Flash::error('Too many attempts. Please try again later.');
            return Redirect::refresh();
        }

        $pending = TotpStorage::dec($user->twofa_pending_secret);
        $google2fa = new \PragmaRX\Google2FA\Google2FA();

        if (!$pending || !$google2fa->verifyKey($pending, $code)) {
            RateLimiter::hit($key, 300);
            Log::warning('Failed 2FA setup confirmation attempt', [
                'user_id' => $user->id,
                'email' => $user->email,
                'ip' => request()->ip(),
                'attempted_code_length' => strlen($code),
            ]);
            Flash::error('Invalid code. Make sure your authenticator app is set up correctly.');
            return Redirect::refresh();
        }

        RateLimiter::clear($key);

        $user->twofa_secret = TotpStorage::enc($pending);
        $user->twofa_pending_secret = null;
        $user->twofa_enabled = true;
        $user->twofa_confirmed_at = now();

        // Create recovery codes and store them encrypted in DB.
        $codes = TotpStorage::makeRecoveryCodes();
        $user->twofa_recovery_codes = TotpStorage::encJson($codes);
        $user->twofa_recovery_generated_at = now();
        $user->twofa_recovery_shown_at = null;

        $user->save();

        Flash::success('2FA enabled.');

        // Mark session as verified and allow one-time recovery code display.
        session(['mercator.totp2fa.verified_user_id' => (int) $user->id]);
        session()->flash('mercator.totp2fa.allow_show_recovery', true);

        return Redirect::to(Backend::url('mercator/totp2fa/challenge/recovery'));
    }

    public function onAcknowledgeRecovery()
    {
        $user = BackendAuth::getUser();
        if (!$user) {
            return Redirect::to(Backend::url('backend/auth/signin'));
        }

        // Mark that codes were shown for this generation.
        $user->twofa_recovery_shown_at = now();
        $user->save();

        // Ensure the session stays verified after enrollment.
        session(['mercator.totp2fa.verified_user_id' => (int) $user->id]);
        return $this->redirectAfter2fa();
    }

    public function onRegenerateRecovery()
    {
        $user = BackendAuth::getUser();
        if (!$user) {
            return Redirect::to(Backend::url('backend/auth/signin'));
        }

        if (!$user->twofa_enabled) {
            return Redirect::to(Backend::url('mercator/totp2fa/challenge/setup'));
        }

        // Require session verification to regenerate.
        if (!Enforcement::isVerifiedForSession($user)) {
            Flash::error('Verify 2FA first.');
            return Redirect::to(Backend::url('mercator/totp2fa/challenge'));
        }

        $codes = TotpStorage::makeRecoveryCodes();
        $user->twofa_recovery_codes = TotpStorage::encJson($codes);
        $user->twofa_recovery_generated_at = now();
        $user->twofa_recovery_shown_at = null;
        $user->save();

        Flash::success('Recovery codes regenerated. Save them now; they will be shown once.');

        session()->flash('mercator.totp2fa.allow_show_recovery', true);

        return Redirect::to(Backend::url('mercator/totp2fa/challenge/recovery'));
    }

    private function redirectAfter2fa()
{
    // Prefer explicit post-recovery redirect, otherwise fall back to last intended backend URL.
    $redirect = session('mercator.totp2fa.post_recovery_redirect') ?: session('mercator.totp2fa.intended');

    session()->forget('mercator.totp2fa.post_recovery_redirect');
    session()->forget('mercator.totp2fa.intended');

    // Never redirect back into the challenge routes (prevents loops).
    if (is_string($redirect) && str_contains($redirect, 'totp2fa/challenge')) {
        $redirect = null;
    }

    // Also clear Laravel's generic intended URL to prevent it from "sticking" to plugin routes.
    session()->forget('url.intended');

    return $redirect ? Redirect::to($redirect) : Redirect::to(Backend::url('backend'));
}

    private function rateLimitKey(BackendUser $user, string $context): string
    {
        $ip = request()->ip() ?: 'noip';
        return 'mercator.totp2fa.' . $context . '.' . $user->id . '.' . sha1($ip);
    }
}
