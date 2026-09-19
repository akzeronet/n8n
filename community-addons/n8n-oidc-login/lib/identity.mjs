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

function assertGroupAccess(claims, config) {
  if (config.allowedGroups.length === 0) return;

  const groups = new Set(normalizeStringArray(claim(claims, config.groupsClaim)));
  const allowed = config.allowedGroups.some((group) => groups.has(group));

  if (!allowed) {
    throw new OidcAccessError('OIDC account is not a member of an allowed group');
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

  if (!issuer || !subject) throw new OidcAccessError('OIDC identity is missing issuer or subject', 401);

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
      'OIDC identity is not linked and N8N_OIDC_ALLOW_EMAIL_LINKING=false',
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

  const conflictingOidcIdentity = user.authIdentities?.find(
    (candidate) =>
      candidate.providerType === 'oidc' &&
      candidate.providerId !== providerId,
  );

  if (conflictingOidcIdentity) {
    throw new OidcAccessError('This n8n user is already linked to another OIDC identity');
  }

  // Validate access policy before persisting a first-login identity binding.
  // A rejected MFA policy must not mutate the n8n account.
  const usedMfa = assertMfaPolicy(user, claims, config);

  const newIdentity = runtime.AuthIdentity.create(user, providerId, 'oidc');

  try {
    await identityRepository.save(newIdentity, { transaction: false });
  } catch (error) {
    // A concurrent first login may win the unique constraint race. Re-read the canonical link.
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
