'use strict';

let loaded = false;

module.exports = {
  frontend: {
    settings: [
      async function loadCommunityOidcAddon() {
        if (loaded || process.env.N8N_OIDC_ENABLED !== 'true') return;
        loaded = true;
        await import('./preload.mjs');
      },
    ],
  },
};
