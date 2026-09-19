import assert from 'node:assert/strict';
import test from 'node:test';

import { loadConfig } from '../lib/config.mjs';

function baseEnv() {
  return {
    N8N_OIDC_ENABLED: 'true',
    N8N_OIDC_BASE_URL: 'https://n8n.example.com',
    N8N_OIDC_DISCOVERY_URL: 'https://idp.example.com/.well-known/openid-configuration',
    N8N_OIDC_EXPECTED_ISSUER: 'https://idp.example.com/openid',
    N8N_OIDC_CLIENT_ID: 'n8n',
    N8N_OIDC_CLIENT_SECRET: 'secret',
    N8N_OIDC_COOKIE_SECRET: 'x'.repeat(64),
  };
}

test('group allowlist auto-requests groups scope', () => {
  const config = loadConfig({
    ...baseEnv(),
    N8N_OIDC_ALLOWED_GROUPS: 'n8n-users',
    N8N_OIDC_SCOPES: 'openid,profile,email',
  });

  assert.equal(config.groupMatch, 'any');
  assert.equal(config.strictGroupsClaim, true);
  assert.deepEqual(config.allowedGroups, ['n8n-users']);
  assert.ok(config.scopes.includes('groups'));
});

test('supports all-group matching mode', () => {
  const config = loadConfig({
    ...baseEnv(),
    N8N_OIDC_ALLOWED_GROUPS: 'staff,n8n-users',
    N8N_OIDC_GROUP_MATCH: 'all',
  });

  assert.equal(config.groupMatch, 'all');
});

test('rejects invalid group matching mode', () => {
  assert.throws(
    () =>
      loadConfig({
        ...baseEnv(),
        N8N_OIDC_ALLOWED_GROUPS: 'n8n-users',
        N8N_OIDC_GROUP_MATCH: 'xor',
      }),
    /N8N_OIDC_GROUP_MATCH/,
  );
});
