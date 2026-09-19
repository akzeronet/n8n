import { access, readFile, readdir } from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const DIRECT_ROOTS = [
  '/app/code',
  '/app/code/node_modules/n8n',
  '/usr/local/lib/node_modules/n8n',
];

async function exists(candidate) {
  try {
    await access(candidate);
    return true;
  } catch {
    return false;
  }
}

async function isN8nPackageRoot(candidate) {
  try {
    const pkg = JSON.parse(await readFile(path.join(candidate, 'package.json'), 'utf8'));
    return pkg?.name === 'n8n';
  } catch {
    return false;
  }
}

async function findCloudronPnpmRoot() {
  const store = '/app/code/node_modules/.pnpm';
  if (!(await exists(store))) return undefined;

  const entries = await readdir(store, { withFileTypes: true });
  for (const entry of entries) {
    if (!entry.isDirectory() || !entry.name.startsWith('n8n@')) continue;
    const candidate = path.join(store, entry.name, 'node_modules', 'n8n');
    if (await isN8nPackageRoot(candidate)) return candidate;
  }
  return undefined;
}

async function detectN8nRoot(explicitRoot) {
  const candidates = explicitRoot ? [explicitRoot, ...DIRECT_ROOTS] : DIRECT_ROOTS;

  for (const candidate of [...new Set(candidates)]) {
    if (await isN8nPackageRoot(candidate)) return candidate;
  }

  const pnpmRoot = await findCloudronPnpmRoot();
  if (pnpmRoot) return pnpmRoot;

  throw new Error(
    'Unable to locate the n8n package root. Checked /app/code, direct node_modules paths, ' +
      'the Cloudron pnpm store, and N8N_OIDC_N8N_ROOT when supplied.',
  );
}

async function importResolved(runtimeRequire, specifier) {
  const resolved = runtimeRequire.resolve(specifier);
  return await import(pathToFileURL(resolved).href);
}

async function firstExisting(paths) {
  for (const candidate of paths) {
    if (await exists(candidate)) return candidate;
  }
  return undefined;
}

function assertFunction(value, name) {
  if (typeof value !== 'function') {
    throw new Error(`Unsupported n8n runtime: missing ${name}`);
  }
}

export async function loadN8nRuntime(explicitRoot) {
  const n8nRoot = await detectN8nRoot(explicitRoot);
  const packageJsonPath = path.join(n8nRoot, 'package.json');
  const packageJson = JSON.parse(await readFile(packageJsonPath, 'utf8'));

  if (packageJson.name !== 'n8n') {
    throw new Error(`Detected path does not point to the n8n package: ${n8nRoot}`);
  }

  const runtimeRequire = createRequire(packageJsonPath);

  try {
    await importResolved(runtimeRequire, 'reflect-metadata');
  } catch {
    // Reflection metadata may already be initialized by n8n.
  }

  const [decorators, di, db, openidClient] = await Promise.all([
    importResolved(runtimeRequire, '@n8n/decorators'),
    importResolved(runtimeRequire, '@n8n/di'),
    importResolved(runtimeRequire, '@n8n/db'),
    importResolved(runtimeRequire, 'openid-client'),
  ]);

  assertFunction(decorators.RootLevelController, '@n8n/decorators.RootLevelController');
  assertFunction(decorators.Get, '@n8n/decorators.Get');
  assertFunction(di.Container?.get, '@n8n/di.Container.get');
  assertFunction(db.UserRepository, '@n8n/db.UserRepository');
  assertFunction(db.AuthIdentityRepository, '@n8n/db.AuthIdentityRepository');
  assertFunction(db.AuthIdentity, '@n8n/db.AuthIdentity');
  assertFunction(openidClient.discovery, 'openid-client.discovery');
  assertFunction(openidClient.authorizationCodeGrant, 'openid-client.authorizationCodeGrant');

  const authServicePath = await firstExisting([
    path.join(n8nRoot, 'dist', 'auth', 'auth.service.js'),
    path.join(n8nRoot, 'dist', 'src', 'auth', 'auth.service.js'),
  ]);

  if (!authServicePath) {
    throw new Error(
      `Unsupported n8n runtime ${packageJson.version}: AuthService could not be located under ${n8nRoot}/dist`,
    );
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
    openidClient,
  });
}
