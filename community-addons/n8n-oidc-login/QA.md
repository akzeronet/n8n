# QA and Security Checklist

## 1. Static checks

```bash
npm install
npm run check
npm test
```

Expected: no syntax failures and all transaction-cookie tests pass.

## 2. Runtime compatibility

Build against the exact production n8n image. Startup with `N8N_OIDC_ENABLED=true` must verify:

- the runtime package is actually `n8n`
- `RootLevelController` exists
- `Get` exists
- the shared DI `Container` exists
- `UserRepository` exists
- `AuthIdentityRepository` exists
- `AuthIdentity` exists
- `AuthService` can be located
- `AuthService.issueCookie()` exists

Any missing seam must abort startup. Do not downgrade this to a warning.

## 3. Happy path

1. Existing active n8n user has the same verified email at the IdP.
2. Open `/oidc/login`.
3. Complete IdP authentication.
4. Callback returns 303 to the configured local success path.
5. Browser contains the native n8n auth cookie.
6. `GET /rest/login` succeeds.
7. `AuthIdentity` contains one namespaced OIDC binding.
8. Second login resolves by identity and does not create another row.

## 4. Protocol-negative cases

Every case must fail closed:

- missing transaction cookie
- modified transaction cookie
- expired transaction cookie
- missing state
- state mismatch
- nonce mismatch
- authorization error response from IdP
- wrong issuer
- wrong audience/client ID
- invalid ID-token signature
- expired ID token
- PKCE verifier mismatch
- reused authorization code

No failure page may expose a token, client secret, verifier, nonce, cookie value, or stack trace.

## 5. Account-linking cases

- unlinked identity + matching verified email -> links once
- unlinked identity + unknown email -> deny
- `email_verified=false` -> deny by default
- missing `email_verified` -> deny by default
- disabled n8n user -> deny
- n8n user already linked to a different OIDC identity -> deny
- bound identity after IdP email change -> still resolves by issuer + subject
- `N8N_OIDC_ALLOW_EMAIL_LINKING=false` + unbound identity -> deny

## 6. Group policy

When `N8N_OIDC_ALLOWED_GROUPS` is empty, no group gate is applied.

When it is configured:

- matching array claim -> allow
- no matching value -> deny
- missing groups claim -> deny
- string claim matching exactly -> allow

Test the actual claim shape emitted by Cloudron, Authentik, Keycloak, or the selected IdP.

## 7. MFA

For a user with n8n MFA enabled:

- `MFA_MODE=deny` -> OIDC login denied
- `MFA_MODE=idp-amr` + no accepted `amr`/`acr` -> denied
- `MFA_MODE=idp-amr` + accepted evidence -> allowed and n8n cookie marked MFA-used
- `MFA_MODE=trust-idp` -> allowed only after explicit administrator decision

Also test the instance-wide n8n MFA enforcement setting.

## 8. Concurrency and scale

- two simultaneous first logins for the same identity must converge on one binding
- multiple main nodes must share the same `N8N_OIDC_COOKIE_SECRET`
- callback may land on a different main node than `/oidc/login`
- no in-memory login state is required
- database unique constraint remains authoritative for identity binding

## 9. Reverse proxy

Verify:

- public callback is exactly `N8N_OIDC_BASE_URL + /oidc/callback`
- TLS is terminated safely
- proxy does not cache `/oidc/*`
- no proxy rule strips callback query parameters
- host-header changes cannot alter redirect URI because the addon uses configured base URL

## 10. Upgrade matrix

For each target n8n release:

| Image | Startup seam | Login | Linking | Logout local | Result |
|---|---|---|---|---|---|
| exact production tag | required | required | required | required | pending |
| latest approved patch | required | required | required | required | pending |
| next candidate | required | required | required | required | pending |

Do not claim compatibility with a release that has not passed this matrix.
