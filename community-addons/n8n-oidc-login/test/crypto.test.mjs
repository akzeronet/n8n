import assert from 'node:assert/strict';
import test from 'node:test';

import { createTransactionCrypto, providerIdFor } from '../lib/crypto.mjs';

test('transaction cookie round-trips and rejects tampering', () => {
  const crypto = createTransactionCrypto('x'.repeat(64));
  const payload = {
    state: 'state',
    nonce: 'nonce',
    verifier: 'verifier',
    exp: Math.floor(Date.now() / 1000) + 60,
  };

  const token = crypto.seal(payload);
  assert.deepEqual(crypto.open(token), payload);

  const tampered = token.slice(0, -1) + (token.endsWith('A') ? 'B' : 'A');
  assert.throws(() => crypto.open(tampered));
});

test('transaction cookie rejects expiry', () => {
  const crypto = createTransactionCrypto('y'.repeat(64));
  const token = crypto.seal({
    exp: Math.floor(Date.now() / 1000) - 1,
  });

  assert.throws(() => crypto.open(token), /expired/i);
});

test('provider identity is stable and issuer-qualified', () => {
  const a = providerIdFor('https://idp-a.example', '123');
  const b = providerIdFor('https://idp-a.example', '123');
  const c = providerIdFor('https://idp-b.example', '123');

  assert.equal(a, b);
  assert.notEqual(a, c);
  assert.match(a, /^community-oidc:/);
});
