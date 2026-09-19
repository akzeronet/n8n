import { loadConfig } from './lib/config.mjs';
import { registerOidcController } from './lib/controller.mjs';
import { N8nCommunityOidcClient } from './lib/oidc-client.mjs';
import { loadN8nRuntime } from './lib/n8n-runtime.mjs';

const PREFIX = '[n8n-community-oidc]';
const config = loadConfig(process.env);

if (config.enabled) {
  try {
    const runtime = await loadN8nRuntime(config.n8nRoot);
    const oidcClient = new N8nCommunityOidcClient(config, runtime.openidClient);

    registerOidcController({ runtime, config, oidcClient });

    process.stdout.write(
      `${PREFIX} enabled for n8n ${runtime.version} at ${runtime.n8nRoot}; login endpoint: ${config.baseUrl}/oidc/login\n`,
    );
  } catch (error) {
    const message = error instanceof Error ? error.stack ?? error.message : String(error);
    process.stderr.write(`${PREFIX} startup failed; refusing to start with OIDC enabled. ${message}\n`);
    throw error;
  }
}
