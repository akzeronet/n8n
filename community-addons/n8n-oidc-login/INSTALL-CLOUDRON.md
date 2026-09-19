# Cloudron install — n8n Community OIDC Login v0.4.1

Target validated during development: Cloudron n8n package root `/app/code`, n8n 2.39.7.

## Files

Extract this directory to:

```text
/app/data/n8n-oidc-login
```

Do not modify `/app/code`.

## Activation

Append the relevant values from `cloudron-env.example` to:

```text
/app/data/env.sh
```

Cloudron activation uses n8n's native `EXTERNAL_HOOK_FILES` mechanism:

```bash
export EXTERNAL_HOOK_FILES="${EXTERNAL_HOOK_FILES:+${EXTERNAL_HOOK_FILES}:}/app/data/n8n-oidc-login/cloudron-hook.cjs"
```

Do not use `NODE_OPTIONS` for the Cloudron installation.

## Group authorization

Example:

```bash
export N8N_OIDC_SCOPES="openid,profile,email,groups"
export N8N_OIDC_ALLOWED_GROUPS="n8n-users"
export N8N_OIDC_GROUPS_CLAIM="groups"
export N8N_OIDC_GROUP_MATCH="any"
export N8N_OIDC_STRICT_GROUPS_CLAIM=true
```

When an allowlist is configured, group validation is fail-closed and is evaluated on every login.

## Identity

Permanent identity is `issuer + sub`. Email is only allowed as an optional first-link bootstrap when
`N8N_OIDC_ALLOW_EMAIL_LINKING=true`.

For a hardened production deployment, pre-linking/provisioning can later replace email bootstrap and then:

```bash
export N8N_OIDC_ALLOW_EMAIL_LINKING=false
```

## Smoke checks

```bash
cd /app/data/n8n-oidc-login
node --check cloudron-hook.cjs
for f in preload.mjs lib/*.mjs test/*.mjs; do node --check "$f" || exit 1; done
node --test test/*.test.mjs
```

Then restart the Cloudron app and test:

```text
https://YOUR-N8N-DOMAIN/oidc/login
```
