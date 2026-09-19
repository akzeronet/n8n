ARG N8N_IMAGE=n8nio/n8n:2.40.0
ARG NODE_IMAGE=node:26-alpine

FROM ${NODE_IMAGE} AS addon
WORKDIR /opt/addon

COPY package.json ./
RUN npm install --omit=dev --ignore-scripts \
    && npm cache clean --force

COPY preload.mjs ./
COPY lib ./lib
COPY test ./test
COPY README.md QA.md LICENSE ./

FROM ${N8N_IMAGE}

USER root
COPY --from=addon --chown=node:node /opt/addon /opt/n8n-community-oidc-login

ENV NODE_OPTIONS="--import=/opt/n8n-community-oidc-login/preload.mjs"

USER node
