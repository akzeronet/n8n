# n8n Community OIDC Login

Experimental community addon that adds **OIDC login** to a self-hosted n8n process without editing n8n core source files.

The addon is intentionally smaller than a full SSO implementation:

- Authorization Code Flow
- PKCE S256
- state + nonce validation
- encrypted, short-lived transaction cookie
- existing n8n users only
- first-login linking by verified email
- persistent identity binding by **issuer + subject**
- optional IdP group allowlist
- n8n disabled-user enforcement
- conservative MFA handling
- native n8n session cookie issuance through n8n's own `AuthService.issueCookie()`
- local n8n login remains available
- no SCIM, JIT provisioning, role sync, or federated logout

## Why this is an addon instead of an n8n community node

n8n community nodes extend workflows and credentials. They do not expose a supported authentication-provider plugin API.

Current n8n backend code does, however, register controllers through shared controller metadata and emits browser sessions through `AuthService`. This addon is preloaded with Node's `--import`, registers its own root-level controller **before n8n activates controllers**, and delegates session creation back to n8n.

No existing n8n source file is patched.

## Important compatibility boundary

This addon uses a **small internal compatibility seam**:

1. `@n8n/decorators.RootLevelController`
2. `@n8n/decorators.Get`
3. `@n8n/di.Container`
4. `@n8n/db` repositories/entities
5. `n8n/dist/auth/auth.service.js` and `AuthService.issueCookie()`

These are runtime-checked. If n8n changes them, startup fails closed when `N8N_OIDC_ENABLED=true`; the addon does not guess, monkey-patch, or manufacture an n8n auth token.

The initial implementation is designed against the n8n 2.40.x backend shape. Test every n8n upgrade before production rollout.

## Security model

The browser is redirected to:

```text
GET /oidc/login
      |
      v
OIDC Provider
      |
      v
GET /oidc/callback
      |
      +-- authorization code + PKCE
      +-- state
      +-- nonce
      +-- issuer/audience/signature/expiry validation by openid-client
      |
      v
issuer + sub -> n8n AuthIdentity
      |
      v
n8n AuthService.issueCookie()
      |
      v
native n8n session
```

The PKCE verifier, nonce, state, expiry, and post-login path live in an AES-256-GCM encrypted HttpOnly transaction cookie. No Redis is required for the login transaction, so the callback remains stateless and works behind multiple main nodes as long as they share the same OIDC configuration and cookie secret.

### First-login account linking

The addon first looks for:

```text
sha256(issuer + NUL + sub)
```

stored in n8n's existing `AuthIdentity` table as a namespaced OIDC provider ID.

If no binding exists, the addon may bind the identity to an **existing** n8n user with the same email, but only when:

- `N8N_OIDC_ALLOW_EMAIL_LINKING=true`
- the email is valid
- `email_verified === true` by default
- the n8n user is not disabled
- the n8n user is not already bound to a different OIDC identity

After the first successful link, subsequent logins resolve by issuer + subject rather than mutable email.

## MFA behavior

`N8N_OIDC_MFA_MODE` controls whether the resulting n8n session is marked as MFA-authenticated.

- `deny`: never treat the IdP authentication as MFA.
- `idp-amr` (default): trust only configured `amr` / `acr` evidence.
- `trust-idp`: explicitly treat every successful IdP login as MFA-authenticated.

Default accepted `amr` values are:

```text
mfa,otp,hwk,swk
```

If the target n8n user already has n8n MFA enabled and the configured OIDC MFA policy is not satisfied, OIDC login is rejected rather than bypassing MFA.

## Build

From this directory:

```bash
docker build \
  --build-arg N8N_IMAGE=n8nio/n8n:2.40.0 \
  -t n8n-community-oidc:2.40.0 .
```

The resulting image inherits the official n8n image and only copies the addon to:

```text
/opt/n8n-community-oidc-login
```

It activates the preload with:

```text
NODE_OPTIONS=--import=/opt/n8n-community-oidc-login/preload.mjs
```

## Required configuration

```env
N8N_OIDC_ENABLED=true
N8N_OIDC_BASE_URL=https://n8n.example.com

N8N_OIDC_DISCOVERY_URL=https://idp.example.com/.well-known/openid-configuration
N8N_OIDC_CLIENT_ID=n8n
N8N_OIDC_CLIENT_SECRET=change-me

# Independent secret used only to encrypt short-lived OIDC transaction cookies.
# Use at least 32 random characters.
N8N_OIDC_COOKIE_SECRET=change-this-to-a-long-random-secret
```

Register this callback URL in the Identity Provider:

```text
https://n8n.example.com/oidc/callback
```

Then start login at:

```text
https://n8n.example.com/oidc/login
```

No editor-ui modification is required.

## Optional configuration

```env
N8N_OIDC_SCOPES=openid,profile,email
N8N_OIDC_PROMPT=

N8N_OIDC_REQUIRE_EMAIL_VERIFIED=true
N8N_OIDC_ALLOW_EMAIL_LINKING=true
N8N_OIDC_EMAIL_CLAIM=email
N8N_OIDC_EMAIL_VERIFIED_CLAIM=email_verified

N8N_OIDC_ALLOWED_GROUPS=
N8N_OIDC_GROUPS_CLAIM=groups

N8N_OIDC_MFA_MODE=idp-amr
N8N_OIDC_MFA_AMR_VALUES=mfa,otp,hwk,swk
N8N_OIDC_MFA_ACR_VALUES=

N8N_OIDC_TRANSACTION_TTL_SECONDS=300
N8N_OIDC_SUCCESS_REDIRECT=/
```

For local HTTP testing only:

```env
N8N_OIDC_ALLOW_INSECURE_HTTP=true
```

Do not enable insecure HTTP in production.

## Cloudron / Authentik / Keycloak

The addon is provider-agnostic. Give it a standards-compliant discovery URL, client ID, client secret, and the callback above.

For providers that expose groups in the ID token or UserInfo response:

```env
N8N_OIDC_ALLOWED_GROUPS=n8n-users
N8N_OIDC_GROUPS_CLAIM=groups
```

When an allowlist is configured and the claim is absent or has no matching value, login is denied.

## What v0.1 deliberately does not do

- No JIT creation of n8n users.
- No role mapping.
- No group-to-project mapping.
- No SCIM.
- No IdP-initiated logout.
- No RP-initiated federated logout.
- No automatic replacement of n8n's existing login form.
- No subpath deployment support yet; `N8N_OIDC_BASE_URL` must be an origin.
- No imports from n8n `.ee` OIDC implementation.

The direct login endpoint is intentional for the first version. A UI button can be added later without changing the authentication core.

## Upgrade rule

Before upgrading n8n:

1. build the addon on the target n8n image,
2. run the runtime compatibility smoke test,
3. execute the QA cases in `QA.md`,
4. only then promote the image.

If the compatibility seam changes, update the adapter rather than patching n8n core.

## License

The addon source in this directory is MIT licensed. n8n itself remains governed by its own license and is not redistributed under the addon's license.
