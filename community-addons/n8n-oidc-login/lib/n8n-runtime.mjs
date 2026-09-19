import { access, readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

async function importResolved(runtimeRequire, specifier) {
  const resolved = runtimeRequire.resolve(specifier);
  return await import(pathToFileURL(resolved).href);
}

async function firstExisting(paths) {
  for (const candidate of paths) {
    try {
      await access(candidate);
      return candidate;
    } catch {
      // try next candidate
    }
  }
  return undefined;
}

function assertFunction(value, name) {
  if (typeof value !== 'function') {
    throw new Error(`Unsupported n8n runtime: missing ${name}`);
  }
}

export async function loadN8nRuntime(n8nRoot) {
  const packageJsonPath = path.join(n8nRoot, 'package.json');
  const packageJson = JSON.parse(await readFile(packageJsonPath, 'utf8'));

  if (packageJson.name !== 'n8n') {
    throw new Error(`N8N_OIDC_N8N_ROOT does not point to the n8n package: ${n8nRoot}`);
  }

  const runtimeRequire = createRequire(packageJsonPath);

  // Load n8n's own copy before registering decorators so DI/metadata singletons are shared.
  try {
    await importResolved(runtimeRequire, 'reflect-metadata');
  } catch {
    // Newer n8n runtimes may initialize reflection elsewhere; controller has no typed constructor deps.
  }

  const [decorators, di, db] = await Promise.all([
    importResolved(runtimeRequire, '@n8n/decorators'),
    importResolved(runtimeRequire, '@n8n/di'),
    importResolved(runtimeRequire, '@n8n/db'),
  ]);

  assertFunction(decorators.RootLevelController, '@n8n/decorators.RootLevelController');
  assertFunction(decorators.Get, '@n8n/decorators.Get');
  assertFunction(di.Container?.get, '@n8n/di.Container.get');
  assertFunction(db.UserRepository, '@n8n/db.UserRepository');
  assertFunction(db.AuthIdentityRepository, '@n8n/db.AuthIdentityRepository');
  assertFunction(db.AuthIdentity, '@n8n/db.AuthIdentity');

  const authServicePath = await firstExisting([
    path.join(n8nRoot, 'dist', 'auth', 'auth.service.js'),
    path.join(n8nRoot, 'dist', 'src', 'auth', 'auth.service.js'),
  ]);

  if (!authServicePath) {
    throw new Error('Unsupported n8n runtime: AuthService implementation could not be located');
  }

  const { AuthService } = await import(pathToFileURL(authServicePath).href);
  assertFunction(AuthService, 'n8n AuthService');

  if (typeof AuthService.prototype?.issueCookie !== 'function') {
    throw new Error('Unsupported n8n runtime: AuthService.issueCookie() is unavailable');
  }

  return Object.freeze({
    version: String(packageJson.version || 'unknown'),
    n8nRoot,
    RootLevelController: decorators.RootLevelController,
    Get: decorators.Get,
    Container: di.Container,
    UserRepository: db.UserRepository,
    AuthIdentityRepository: db.AuthIdentityRepository,
    AuthIdentity: db.AuthIdentity,
    isValidEmail: db.isValidEmail,
    isUniqueConstraintError: db.isUniqueConstraintError,
    AuthService,
  });
}
