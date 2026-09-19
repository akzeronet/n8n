import { providerIdFor } from './crypto.mjs';

export class OidcAccessError extends Error {
  constructor(message, statusCode = 403) {
    super(message);
    this.name = 'OidcAccessError';
    this.statusCode = statusCode;
  }
}

function claim(claims, name) {
  return claims?.[name];
}

function normalizeStringArray(value) {
  if (Array.isArray(value)) return value.map(String).map((v) => v.trim()).filter(Boolean);
  if (typeof value === 'string' && value.trim()) return [value.trim()];
  return [];
}

export function normalizeGroupsClaim(value, strict = true) {
  if (value === undefined || value === null) {
    throw new OidcAccessError('OIDC groups claim is missing');
  }

  if (Array.isArray(value)) {
    if (strict && value.some((entry) => typeof entry !== 'string')) {
      throw new OidcAccessError('OIDC groups claim has an invalid format');
    }

    const groups = value
      .filter((entry) => typeof entry === 'string')
      .map((entry) => entry.trim())
      .filter(Boolean);

    if (groups.length === 0) {
      throw new OidcAccessError('OIDC groups claim is empty');
    }

    return [...new Set(groups)];
  }

  if (!strict && typeof value === 'string' && value.trim()) {
    return [value.trim()];
  }

  throw new OidcAccessError('OIDC groups claim has an invalid format');
}

export function assertGroupAccess(claims, config) {
  if (config.allowedGroups.length === 0) return;

  const groups = new Set(
    normalizeGroupsClaim(claim(claims, config.groupsClaim), config.strictGroupsClaim),
  );

  const allowed =
    config.groupMatch === 'all'
      ? config.allowedGroups.every((group) => groups.has(group))
      : config.allowedGroups.some((group) => groups.has(group));

  if (!allowed) {
    throw new OidcAccessError('OIDC account is not a member of the required group set');
  }
}

function idpMfaSatisfied(claims, config) {
  if (config.mfaMode === 'trust-idp') return true;
  if (config.mfaMode === 'deny') return false;

  const amr = new Set(normalizeStringArray(claims.amr).map((v) => v.toLowerCase()));
  if (config.mfaAmrValues.some((value) => amr.has(value.toLowerCase()))) return true;

  const acr = typeof claims.acr === 'string' ? claims.acr : '';
  if (acr && config.mfaAcrValues.includes(acr)) return true;

  return false;
}

async function findIdentity(identityRepository, providerId) {
  return await identityRepository.findOne({
    where: { providerId, providerType: 'oidc' },
    relations: {
      user: {
        role: true,
        authIdentities: true,
      },
    },
  });
}

function assertUsableUser(user) {
  if (!user) throw new OidcAccessError('OIDC identity is not linked to an n8n user');
  if (user.disabled) throw new OidcAccessError('This n8n user is disabled');
  if (!user.role) throw new OidcAccessError('This n8n user does not have a role');
}

function assertMfaPolicy(user, claims, config) {
  const satisfied = idpMfaSatisfied(claims, config);

  if (user.mfaEnabled && !satisfied) {
    throw new OidcAccessError(
      'This n8n user requires MFA, but the OIDC response did not satisfy the configured MFA policy',
    );
  }

  return satisfied;
}

export async function resolveExistingN8nUser({ runtime, config, oidcResult }) {
  const claims = oidcResult.claims ?? {};
  const issuer = String(claims.iss || oidcResult.issuer || '');
  const subject = String(claims.sub || '');

  if (!issuer || !subject) {
    throw new OidcAccessError('OIDC identity is missing issuer or subject', 401);
  }

  if (config.expectedIssuer && issuer !== config.expectedIssuer) {
    throw new OidcAccessError('OIDC issuer does not match the configured issuer', 401);
  }

  // Group authorization is evaluated on EVERY login, including already-linked users.
  // Removing a user from the allowed IdP group therefore revokes future OIDC logins.
  assertGroupAccess(claims, config);

  const providerId = providerIdFor(issuer, subject);
  const identityRepository = runtime.Container.get(runtime.AuthIdentityRepository);
  const userRepository = runtime.Container.get(runtime.UserRepository);

  let identity = await findIdentity(identityRepository, providerId);

  if (identity?.user) {
    assertUsableUser(identity.user);
    const usedMfa = assertMfaPolicy(identity.user, claims, config);
    return {
      user: identity.user,
      linkedNow: false,
      usedMfa,
      providerId,
    };
  }

  if (!config.allowEmailLinking) {
    throw new OidcAccessError(
      'OIDC identity is not pre-linked and email linking is disabled',
    );
  }

  const rawEmail = claim(claims, config.emailClaim);
  const email = typeof rawEmail === 'string' ? rawEmail.trim().toLowerCase() : '';

  if (!email || (typeof runtime.isValidEmail === 'function' && !runtime.isValidEmail(email))) {
    throw new OidcAccessError('OIDC account did not provide a valid email address');
  }

  if (config.requireEmailVerified) {
    const verified = claim(claims, config.emailVerifiedClaim);
    if (verified !== true) {
      throw new OidcAccessError('OIDC email address is not verified');
    }
  }

  const user = await userRepository.findOne({
    where: { email },
    relations: ['role', 'authIdentities'],
  });

  assertUsableUser(user);

  // Never re-link an n8n account automatically if it already has a different OIDC
  // identity. This blocks "same email, different subject" account claiming.
  const conflictingOidcIdentity = user.authIdentities?.find(
    (candidate) =>
      candidate.providerType === 'oidc' &&
      candidate.providerId !== providerId,
  );

  if (conflictingOidcIdentity) {
    throw new OidcAccessError('This n8n user is already linked to another OIDC identity');
  }

  // Validate all access policy before persisting a first-login identity binding.
  const usedMfa = assertMfaPolicy(user, claims, config);

  const newIdentity = runtime.AuthIdentity.create(user, providerId, 'oidc');

  try {
    await identityRepository.save(newIdentity, { transaction: false });
  } catch (error) {
    // Concurrent first logins converge on the database unique constraint.
    const unique =
      typeof runtime.isUniqueConstraintError === 'function' &&
      runtime.isUniqueConstraintError(error);

    if (!unique) throw error;

    identity = await findIdentity(identityRepository, providerId);
    if (!identity?.user || identity.user.id !== user.id) throw error;
  }

  return {
    user,
    linkedNow: true,
    usedMfa,
    providerId,
  };
}
