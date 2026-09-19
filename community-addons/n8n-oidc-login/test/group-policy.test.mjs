import assert from 'node:assert/strict';
import test from 'node:test';

import { assertGroupAccess, normalizeGroupsClaim } from '../lib/identity.mjs';

const baseConfig = {
  allowedGroups: ['n8n-users'],
  groupsClaim: 'groups',
  groupMatch: 'any',
  strictGroupsClaim: true,
};

test('strict groups claim accepts an array of strings', () => {
  assert.deepEqual(normalizeGroupsClaim(['staff', 'n8n-users'], true), ['staff', 'n8n-users']);
});

test('strict groups claim rejects missing, string, and mixed claims', () => {
  assert.throws(() => normalizeGroupsClaim(undefined, true));
  assert.throws(() => normalizeGroupsClaim('n8n-users', true));
  assert.throws(() => normalizeGroupsClaim(['n8n-users', 42], true));
});

test('any mode allows one matching group', () => {
  assert.doesNotThrow(() =>
    assertGroupAccess(
      { groups: ['staff', 'n8n-users'] },
      baseConfig,
    ),
  );
});

test('any mode denies no matching groups', () => {
  assert.throws(() =>
    assertGroupAccess(
      { groups: ['staff'] },
      baseConfig,
    ),
  );
});

test('all mode requires every configured group', () => {
  const config = {
    ...baseConfig,
    allowedGroups: ['staff', 'n8n-users'],
    groupMatch: 'all',
  };

  assert.doesNotThrow(() => assertGroupAccess({ groups: ['staff', 'n8n-users'] }, config));
  assert.throws(() => assertGroupAccess({ groups: ['n8n-users'] }, config));
});
