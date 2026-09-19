const TRUE_VALUES = new Set(['1', 'true', 'yes', 'on']);
const FALSE_VALUES = new Set(['0', 'false', 'no', 'off']);

function parseBoolean(env, name, defaultValue) {
  const raw = env[name];
  if (raw === undefined || raw === '') return defaultValue;
  const value = raw.trim().toLowerCase();
  if (TRUE_VALUES.has(value)) return true;
  if (FALSE_VALUES.has(value)) return false;
  throw new Error(`${name} must be one of true/false, 1/0, yes/no, on/off`);
}

function parseEnum(env, name, defaultValue, allowed) {
  const value = (env[name] || defaultValue).trim().toLowerCase();
  if (!allowed.includes(value)) {
    throw new Error(`${name} must be one of ${allowed.join(', ')}`);
  }
  return value;
}

function required(env, name) {
  const value = env[name]?.trim();
  if (!value) throw new Error(`${name} is required when N8N_OIDC_ENABLED=true`);
  return value;
}

function csv(value) {
  if (!value) return [];
  return [...new Set(value.split(',').map((item) => item.trim()).filter(Boolean))];
}

function boundedInteger(env, name, defaultValue, min, max) {
  const raw = env[name];
  if (raw === undefined || raw === '') return defaultValue;
  const value = Number.parseInt(raw, 10);
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new Error(`${name} must be an integer between ${min} and ${max}`);
  }
  return value;
}

function normalizeHttpsUrl(raw, name, allowInsecureHttp) {
  const url = new URL(raw);
  if (!['https:', 'http:'].includes(url.protocol)) {
    throw new Error(`${name} must use http or https`);
  }
  if (url.protocol !== 'https:' && !allowInsecureHttp) {
    throw new Error(`${name} must use https unless N8N_OIDC_ALLOW_INSECURE_HTTP=true`);
  }
  if (url.username || url.password) {
    throw new Error(`${name} must not contain URL credentials`);
  }
  url.hash = '';
  return url;
}

function normalizeBaseUrl(raw, allowInsecureHttp) {
  const url = normalizeHttpsUrl(raw, 'N8N_OIDC_BASE_URL', allowInsecureHttp);
  if (url.search || (url.pathname !== '/' && url.pathname !== '')) {
    throw new Error('N8N_OIDC_BASE_URL must be an origin only, for example https://n8n.example.com');
  }
  return url.origin;
}

function normalizeIssuer(raw, allowInsecureHttp) {
  if (!raw?.trim()) return undefined;
  const url = normalizeHttpsUrl(raw.trim(), 'N8N_OIDC_EXPECTED_ISSUER', allowInsecureHttp);
  if (url.search) throw new Error('N8N_OIDC_EXPECTED_ISSUER must not contain a query string');
  return url.href.replace(/\/$/, '');
}

function normalizeSuccessPath(raw) {
  const value = raw?.trim() || '/';
  if (
    !value.startsWith('/') ||
    value.startsWith('//') ||
    value.includes('\\') ||
    /[\u0000-\u001F\u007F]/.test(value)
  ) {
    throw new Error('N8N_OIDC_SUCCESS_REDIRECT must be a safe local absolute path beginning with /');
  }
  return value;
}

export function loadConfig(env = process.env) {
  const enabled = parseBoolean(env, 'N8N_OIDC_ENABLED', false);
  if (!enabled) return { enabled: false };

  const allowInsecureHttp = parseBoolean(env, 'N8N_OIDC_ALLOW_INSECURE_HTTP', false);
  const baseUrl = normalizeBaseUrl(required(env, 'N8N_OIDC_BASE_URL'), allowInsecureHttp);
  const discoveryUrl = normalizeHttpsUrl(
    required(env, 'N8N_OIDC_DISCOVERY_URL'),
    'N8N_OIDC_DISCOVERY_URL',
    allowInsecureHttp,
  ).href;

  const expectedIssuer = normalizeIssuer(env.N8N_OIDC_EXPECTED_ISSUER, allowInsecureHttp);

  const cookieSecret = required(env, 'N8N_OIDC_COOKIE_SECRET');
  if (cookieSecret.length < 32) {
    throw new Error('N8N_OIDC_COOKIE_SECRET must contain at least 32 characters');
  }

  const groupsClaim = env.N8N_OIDC_GROUPS_CLAIM?.trim() || 'groups';
  const allowedGroups = csv(env.N8N_OIDC_ALLOWED_GROUPS);
  const groupMatch = parseEnum(env, 'N8N_OIDC_GROUP_MATCH', 'any', ['any', 'all']);
  const strictGroupsClaim = parseBoolean(env, 'N8N_OIDC_STRICT_GROUPS_CLAIM', true);

  const scopes = csv(env.N8N_OIDC_SCOPES || 'openid,profile,email');
  if (!scopes.includes('openid')) scopes.unshift('openid');

  // Cloudron and many other providers expose the standard-named groups claim only
  // when the groups scope is requested. Auto-request it when the group gate is enabled.
  if (allowedGroups.length > 0 && groupsClaim === 'groups' && !scopes.includes('groups')) {
    scopes.push('groups');
  }

  const mfaMode = parseEnum(env, 'N8N_OIDC_MFA_MODE', 'idp-amr', [
    'deny',
    'idp-amr',
    'trust-idp',
  ]);

  const transactionTtlSeconds = boundedInteger(
    env,
    'N8N_OIDC_TRANSACTION_TTL_SECONDS',
    300,
    60,
    600,
  );

  return Object.freeze({
    enabled: true,
    n8nRoot: env.N8N_OIDC_N8N_ROOT?.trim() || undefined,
    baseUrl,
    redirectUri: `${baseUrl}/oidc/callback`,
    successRedirect: normalizeSuccessPath(env.N8N_OIDC_SUCCESS_REDIRECT),
    discoveryUrl,
    expectedIssuer,
    clientId: required(env, 'N8N_OIDC_CLIENT_ID'),
    clientSecret: required(env, 'N8N_OIDC_CLIENT_SECRET'),
    cookieSecret,
    cookieSecure: new URL(baseUrl).protocol === 'https:',
    transactionTtlSeconds,
    scopes,
    prompt: env.N8N_OIDC_PROMPT?.trim() || undefined,
    debugLog: parseBoolean(env, 'N8N_OIDC_DEBUG', false),
    requireEmailVerified: parseBoolean(env, 'N8N_OIDC_REQUIRE_EMAIL_VERIFIED', true),
    allowEmailLinking: parseBoolean(env, 'N8N_OIDC_ALLOW_EMAIL_LINKING', true),
    emailClaim: env.N8N_OIDC_EMAIL_CLAIM?.trim() || 'email',
    emailVerifiedClaim: env.N8N_OIDC_EMAIL_VERIFIED_CLAIM?.trim() || 'email_verified',
    groupsClaim,
    allowedGroups,
    groupMatch,
    strictGroupsClaim,
    mfaMode,
    mfaAmrValues: csv(env.N8N_OIDC_MFA_AMR_VALUES || 'mfa,otp,hwk,swk'),
    mfaAcrValues: csv(env.N8N_OIDC_MFA_ACR_VALUES),
  });
}
