# Security Policy

## Threat Model

This TOTP 2FA plugin is designed to protect Winter CMS backend accounts from unauthorized access. The threat model considers the following scenarios:

### Threats Mitigated

1. **Credential Theft**: Even if an attacker obtains a user's password, they cannot access the account without the second factor (TOTP code or recovery code).

2. **Session Hijacking**: Each session requires 2FA verification, preventing attackers from using stolen session tokens.

3. **Brute Force Attacks**: Rate limiting prevents attackers from attempting multiple TOTP codes to gain access.

4. **Timing Attacks**: Constant-time comparison of recovery codes prevents timing-based side-channel attacks.

5. **Recovery Code Enumeration**: Recovery codes are compared using `hash_equals()` to prevent timing attacks that could leak information about valid codes.

### Threats Outside Scope

1. **Malware on User Device**: If an attacker has compromised the user's device where the authenticator app runs, 2FA provides limited protection.

2. **Social Engineering**: This plugin cannot prevent users from being tricked into providing their TOTP codes to attackers.

3. **Database Compromise with Encryption Key**: If both the database and Laravel encryption keys are compromised, secrets and recovery codes can be decrypted.

## Security Mitigations

### Encryption at Rest

- **TOTP Secrets**: All TOTP secrets are encrypted using Laravel's `Crypt` facade before storage in the database.
- **Recovery Codes**: Recovery codes are JSON-encoded and encrypted before database storage.
- **Pending Secrets**: Temporary secrets during enrollment are also encrypted.

### Constant-Time Comparisons

Recovery codes are verified using PHP's `hash_equals()` function, which performs constant-time string comparison. This prevents timing attacks where an attacker could measure response times to determine if they're getting closer to a valid code.

```php
// Secure: constant-time comparison
foreach ($recovery as $idx => $recoveryCode) {
    if (hash_equals($recoveryCode, $code)) {
        $matchedIndex = $idx;
        break;
    }
}
```

### Rate Limiting

Failed authentication attempts are rate-limited using Laravel's `RateLimiter`:

- **5 attempts** allowed per user/IP combination
- **300 second (5 minute)** lockout after exceeding limit
- Separate rate limits for:
  - 2FA verification (`onVerify`)
  - Initial setup confirmation (`onConfirmSetup`)

### Audit Logging

All failed 2FA verification attempts are logged with the following information:
- User ID and email
- IP address
- Timestamp (automatic)
- Code length (for security analysis without exposing the actual code)

Successful recovery code usage is also logged for audit purposes.

### Input Validation

- **Recovery Code Count**: The `makeRecoveryCodes()` function validates that the count parameter is between 1 and 100 to prevent DoS attacks through excessive code generation.
- **Code Format**: User input is trimmed and uppercased to normalize format before verification.

### CSRF Protection

All forms use Winter CMS's built-in CSRF protection to prevent cross-site request forgery attacks.

### Bypass Prevention

The plugin enforces 2FA through two event listeners:
- `backend.page.beforeDisplay`: Prevents navigation to backend pages without verification
- `backend.ajax.beforeRunHandler`: Prevents AJAX requests without verification

This dual enforcement prevents bypassing 2FA through AJAX requests.

### Session Security

- 2FA verification status is stored in the session and tied to the specific user ID
- Sessions are cleared appropriately after logout
- Redirect loops are prevented through careful session management

### Recovery Code Security

- **One-Time Display**: Recovery codes are shown only once after generation
- **Tracking**: The system tracks when codes were generated and when they were shown
- **Consumption**: Each recovery code can only be used once and is immediately deleted after use
- **Regeneration**: Users can regenerate codes, but must verify their TOTP first

## Best Practices for Deployment

### Required Actions

1. **Use HTTPS**: Always deploy Winter CMS with HTTPS to protect against man-in-the-middle attacks.

2. **Secure Encryption Keys**: Protect your Laravel `APP_KEY` environment variable. If this is compromised, encrypted secrets can be decrypted.

3. **Regular Backups**: Ensure database backups are encrypted and stored securely, as they contain encrypted 2FA secrets.

4. **Monitor Logs**: Regularly review logs for failed 2FA attempts to detect potential attacks.

5. **Keep Dependencies Updated**: Regularly update the plugin and its dependencies to receive security patches.

### Recommended Actions

1. **Enforce for Administrators**: Use the "All users" or "Selected roles" enforcement mode to require 2FA for privileged accounts.

2. **User Education**: Train users to:
   - Keep their authenticator app secure
   - Store recovery codes in a secure location
   - Never share TOTP codes with anyone
   - Report lost devices immediately

3. **Session Timeout**: Configure appropriate session timeouts in Winter CMS to limit the window of opportunity for session hijacking.

4. **IP Allowlisting**: Consider additional IP-based restrictions for administrative access if appropriate for your use case.

5. **Regular Security Audits**: Periodically review 2FA logs and user enrollment status.

## Dependency Security

This plugin depends on:

- **pragmarx/google2fa** (^8.0.2): Implements the TOTP algorithm (RFC 6238)
- **bacon/bacon-qr-code** (^3.0): Generates QR codes for easy authenticator app enrollment

Version constraints are specified to encourage security updates while maintaining compatibility.

### Update Recommendations

Check for updates regularly:

```bash
composer update pragmarx/google2fa bacon/bacon-qr-code
```

Monitor security advisories for these packages:
- [pragmarx/google2fa on Packagist](https://packagist.org/packages/pragmarx/google2fa)
- [bacon/bacon-qr-code on Packagist](https://packagist.org/packages/bacon/bacon-qr-code)

## Vulnerability Reporting

If you discover a security vulnerability in this plugin, please:

1. **Do not** open a public GitHub issue
2. Email the maintainer at: software@mercator.li
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will respond as quickly as possible and work with you to address the issue.

## Security Checklist for Maintainers

When reviewing security-related changes:

- [ ] All user input is properly validated and sanitized
- [ ] Sensitive operations use constant-time comparisons
- [ ] Rate limiting is applied to authentication endpoints
- [ ] Failed attempts are logged with sufficient detail for auditing
- [ ] Secrets are encrypted before storage
- [ ] CSRF protection is maintained
- [ ] Dependencies are kept up to date
- [ ] Changes are tested for timing vulnerabilities
- [ ] Documentation is updated to reflect security changes

## Defense in Depth

This plugin follows the principle of defense in depth by implementing multiple layers of security:

1. **Encryption**: Secrets encrypted at rest
2. **Timing Attack Protection**: Constant-time comparisons
3. **Rate Limiting**: Prevents brute force attacks
4. **Audit Logging**: Enables detection and investigation
5. **Input Validation**: Prevents DoS and injection attacks
6. **Session Security**: Prevents session-based attacks
7. **Bypass Prevention**: Multiple enforcement points

No single security control is perfect, but together they provide robust protection for backend accounts.
