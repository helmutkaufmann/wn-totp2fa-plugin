# Mercator.TOTP2FA
Time-based one time password two-factor authentication (TOTP 2FA) for Winter CMS backend users.

## Description
- Backend decides which users **must** enroll (Off / All / Roles).
- If a user must use 2FA but has none, user is forced into **enrollment**. Recovery codes are shown once, immediately after enrollment.
- Users can regenerate recovery codes themselves in the backend. New codes are shown once immediately after regeneration

## Requirements
- Winter CMS 1.3 (Laravel 12)
- PHP >= 8.2
- Composer:
  - pragmarx/google2fa
  - bacon/bacon-qr-code
  - winter/wn-user-plugin

## Installation
Run composer installation
```bash
composer require pragmarx/google2fa bacon/bacon-qr-code
```

Run plugin migrations
```bash
php artisan winter:up
```

Configure enforcement in the backend → Settings → Security → Backend TOTP 2FA
- Off
- All users
- Selected roles (choose from a checkbox list of all backend roles)

> **Note:** if the plugin is unable to determine a user’s roles (for example, if the role relationship is missing), enforcement will now default to **not** requiring 2FA rather than locking everybody out.  A warning is written to the log in that case.

## Additional information
### User flow
- If required and not enrolled → `/mercator/totp2fa/challenge/setup`
- If enrolled but not verified this session → `/mercator/totp2fa/challenge`
- After successful enrollment or regeneration → `/mercator/totp2fa/challenge/recovery` (codes shown once)
- Users can regenerate codes at `/mercator/totp2fa/challenge/manage`

### Security notes
- `backend.page.beforeDisplay` and `backend.ajax.beforeRunHandler` are both enforced (prevents AJAX bypass).
- Secrets + recovery codes are encrypted using Laravel `Crypt`.
- Recovery codes are displayed only when a one-time session flag is present, and then require an acknowledgement to mark them as shown.

# License
MIT

Copyright (C) 2026 Helmut Kaufmann (software@mercator.li)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.