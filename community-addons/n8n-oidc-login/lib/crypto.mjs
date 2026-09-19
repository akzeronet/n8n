import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from 'node:crypto';

const VERSION = 'v1';

function deriveKey(secret) {
  return createHash('sha256').update(secret, 'utf8').digest();
}

function b64url(input) {
  return Buffer.from(input).toString('base64url');
}

function fromB64url(input) {
  return Buffer.from(input, 'base64url');
}

export function createTransactionCrypto(secret) {
  const key = deriveKey(secret);

  function seal(payload) {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(Buffer.from(VERSION, 'utf8'));

    const plaintext = Buffer.from(JSON.stringify(payload), 'utf8');
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();

    return [VERSION, b64url(iv), b64url(tag), b64url(ciphertext)].join('.');
  }

  function open(token) {
    if (typeof token !== 'string') throw new Error('Missing OIDC transaction cookie');

    const [version, ivRaw, tagRaw, ciphertextRaw, extra] = token.split('.');
    if (extra !== undefined || version !== VERSION || !ivRaw || !tagRaw || !ciphertextRaw) {
      throw new Error('Invalid OIDC transaction cookie format');
    }

    const decipher = createDecipheriv('aes-256-gcm', key, fromB64url(ivRaw));
    decipher.setAAD(Buffer.from(VERSION, 'utf8'));
    decipher.setAuthTag(fromB64url(tagRaw));

    const plaintext = Buffer.concat([
      decipher.update(fromB64url(ciphertextRaw)),
      decipher.final(),
    ]);

    const payload = JSON.parse(plaintext.toString('utf8'));
    if (!payload || typeof payload !== 'object') throw new Error('Invalid OIDC transaction payload');

    if (!Number.isFinite(payload.exp) || payload.exp <= Math.floor(Date.now() / 1000)) {
      throw new Error('OIDC transaction expired');
    }

    return payload;
  }

  return { seal, open };
}

export function providerIdFor(issuer, subject) {
  const digest = createHash('sha256')
    .update(String(issuer), 'utf8')
    .update('\0', 'utf8')
    .update(String(subject), 'utf8')
    .digest('base64url');

  return `community-oidc:${digest}`;
}
