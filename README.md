# Mercator.Totp2fa

TOTP-based two-factor authentication (2FA) for **Winter CMS backend users**, with **one-time display** of recovery codes.

## Goals (behaviour)

- Backend decides which users **must** enroll (Off / All / Roles).
- If a user must use 2FA but has none:
  - user is forced into **enrollment**
  - recovery codes are shown **once**, immediately after enrollment
- Recovery codes are **never shown** in the backend user management form.
  - Users can regenerate recovery codes themselves
  - New codes are shown **once** immediately after regeneration
- Recovery codes are stored **encrypted** in the database.

## Requirements

- Winter CMS 1.3 (Laravel 12)
- PHP >= 8.2
- Composer:
  - pragmarx/google2fa
  - bacon/bacon-qr-code

## Install

1) Copy to `plugins/mercator/totp2fa`

2) Install dependencies:

```bash
composer require pragmarx/google2fa bacon/bacon-qr-code
```

3) Run plugin migrations:

```bash
php artisan winter:up
```

## Configure enforcement

Backend → Settings → Security → **Backend 2FA (TOTP)**

- Off / All users / Selected roles (comma-separated role codes or names)

## User flow

- If required and not enrolled → `/mercator/totp2fa/challenge/setup`
- If enrolled but not verified this session → `/mercator/totp2fa/challenge`
- After successful enrollment or regeneration → `/mercator/totp2fa/challenge/recovery` (codes shown once)
- Users can regenerate codes at `/mercator/totp2fa/challenge/manage`

## Security notes

- `backend.page.beforeDisplay` and `backend.ajax.beforeRunHandler` are both enforced (prevents AJAX bypass).
- Secrets + recovery codes are encrypted using Laravel `Crypt`.
- Recovery codes are displayed only when a one-time session flag is present, and then require an acknowledgement to mark them as shown.
