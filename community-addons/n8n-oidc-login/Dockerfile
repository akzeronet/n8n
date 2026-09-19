ARG N8N_IMAGE=n8nio/n8n:2.40.0
FROM ${N8N_IMAGE}

USER root
COPY --chown=node:node . /opt/n8n-community-oidc-login
ENV NODE_OPTIONS="--import=/opt/n8n-community-oidc-login/preload.mjs"
USER node
