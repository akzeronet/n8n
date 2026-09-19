import { randomUUID } from 'node:crypto';

import { createTransactionCrypto } from './crypto.mjs';
import { OidcAccessError, resolveExistingN8nUser } from './identity.mjs';

const PREFIX = '[n8n-community-oidc]';
const TRANSACTION_COOKIE = 'n8n-community-oidc-tx';

function safeReturnPath(value, fallback) {
  if (typeof value !== 'string') return fallback;
  if (
    !value.startsWith('/') ||
    value.startsWith('//') ||
    value.includes('\\') ||
    /[\u0000-\u001F\u007F]/.test(value) ||
    value.length > 2048
  ) {
    return fallback;
  }
  if (value.startsWith('/oidc')) return fallback;
  return value;
}

function publicFailure(res, statusCode, reference) {
  res
    .status(statusCode)
    .set('Cache-Control', 'no-store')
    .type('html')
    .send(
      `<!doctype html><html><head><meta charset="utf-8"><title>OIDC login failed</title></head><body><h1>OIDC login failed</h1><p>The login request could not be completed.</p><p>Reference: <code>${reference}</code></p></body></html>`,
    );
}

function clearTransactionCookie(res, config) {
  res.clearCookie(TRANSACTION_COOKIE, {
    httpOnly: true,
    secure: config.cookieSecure,
    sameSite: 'lax',
    path: '/oidc',
  });
}

function applyMethodDecorator(decorator, klass, methodName) {
  const descriptor = Object.getOwnPropertyDescriptor(klass.prototype, methodName);
  decorator(klass.prototype, methodName, descriptor);
}

function logFailure(stage, reference, error, debugLog) {
  const safe = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
  process.stderr.write(`${PREFIX} ${stage} failed [${reference}] ${safe}\n`);

  if (debugLog && error instanceof Error && error.stack) {
    process.stderr.write(`${PREFIX} debug [${reference}] ${error.stack}\n`);
  }
}

export function registerOidcController({ runtime, config, oidcClient }) {
  const transactionCrypto = createTransactionCrypto(config.cookieSecret);

  class CommunityOidcController {
    async login(req, res) {
      const reference = randomUUID();

      try {
        const returnTo = safeReturnPath(req.query?.returnTo, config.successRedirect);
        const { authorizationUrl, transaction } = await oidcClient.begin();

        const now = Math.floor(Date.now() / 1000);
        const sealed = transactionCrypto.seal({
          ...transaction,
          returnTo,
          iat: now,
          exp: now + config.transactionTtlSeconds,
        });

        res.cookie(TRANSACTION_COOKIE, sealed, {
          httpOnly: true,
          secure: config.cookieSecure,
          sameSite: 'lax',
          path: '/oidc',
          maxAge: config.transactionTtlSeconds * 1000,
        });

        res.set('Cache-Control', 'no-store');
        res.redirect(302, authorizationUrl.href);
      } catch (error) {
        logFailure('login initiation', reference, error, config.debugLog);
        publicFailure(res, 500, reference);
      }
    }

    async callback(req, res) {
      const reference = randomUUID();

      try {
        const sealed = req.cookies?.[TRANSACTION_COOKIE];
        const transaction = transactionCrypto.open(sealed);

        clearTransactionCookie(res, config);

        const state = typeof req.query?.state === 'string' ? req.query.state : '';
        if (!state || state !== transaction.state) {
          throw new OidcAccessError('OIDC state mismatch', 401);
        }

        const queryIndex = req.originalUrl.indexOf('?');
        const queryString = queryIndex >= 0 ? req.originalUrl.slice(queryIndex + 1) : '';

        const oidcResult = await oidcClient.finish(queryString, transaction);
        const resolved = await resolveExistingN8nUser({
          runtime,
          config,
          oidcResult,
        });

        const authService = runtime.Container.get(runtime.AuthService);
        authService.issueCookie(res, resolved.user, resolved.usedMfa, undefined);

        process.stdout.write(
          `${PREFIX} login succeeded userId=${resolved.user.id} linkedNow=${resolved.linkedNow}\n`,
        );

        const destination = new URL(transaction.returnTo, `${config.baseUrl}/`);
        if (destination.origin !== config.baseUrl) {
          throw new OidcAccessError('Unsafe post-login redirect', 400);
        }

        res.set('Cache-Control', 'no-store');
        res.redirect(303, destination.href);
      } catch (error) {
        clearTransactionCookie(res, config);

        const statusCode =
          error instanceof OidcAccessError && Number.isInteger(error.statusCode)
            ? error.statusCode
            : 401;

        logFailure('callback', reference, error, config.debugLog);
        publicFailure(res, statusCode, reference);
      }
    }
  }

  applyMethodDecorator(
    runtime.Get('/login', {
      skipAuth: true,
      usesTemplates: true,
      ipRateLimit: { limit: 60, windowMs: 5 * 60 * 1000 },
    }),
    CommunityOidcController,
    'login',
  );

  applyMethodDecorator(
    runtime.Get('/callback', {
      skipAuth: true,
      usesTemplates: true,
      ipRateLimit: { limit: 120, windowMs: 5 * 60 * 1000 },
    }),
    CommunityOidcController,
    'callback',
  );

  runtime.RootLevelController('/oidc')(CommunityOidcController);

  return CommunityOidcController;
}
