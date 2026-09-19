export class N8nCommunityOidcClient {
  #configurationPromise;

  constructor(config, openidClient) {
    this.config = config;
    this.oidc = openidClient;
  }

  async configuration() {
    if (!this.#configurationPromise) {
      this.#configurationPromise = this.oidc
        .discovery(
          new URL(this.config.discoveryUrl),
          this.config.clientId,
          this.config.clientSecret,
        )
        .then((configuration) => {
          const issuer = configuration.serverMetadata().issuer;
          if (!issuer) throw new Error('OIDC discovery response did not contain an issuer');

          if (this.config.expectedIssuer && issuer !== this.config.expectedIssuer) {
            throw new Error('OIDC discovery issuer does not match N8N_OIDC_EXPECTED_ISSUER');
          }

          return configuration;
        });
    }

    return await this.#configurationPromise;
  }

  async begin() {
    const configuration = await this.configuration();
    const verifier = this.oidc.randomPKCECodeVerifier();
    const challenge = await this.oidc.calculatePKCECodeChallenge(verifier);
    const nonce = this.oidc.randomNonce();
    const state = this.oidc.randomState();

    const parameters = {
      redirect_uri: this.config.redirectUri,
      scope: this.config.scopes.join(' '),
      code_challenge: challenge,
      code_challenge_method: 'S256',
      nonce,
      state,
    };

    if (this.config.prompt) parameters.prompt = this.config.prompt;

    return {
      authorizationUrl: this.oidc.buildAuthorizationUrl(configuration, parameters),
      transaction: { verifier, nonce, state },
    };
  }

  async finish(queryString, transaction) {
    const configuration = await this.configuration();
    const currentUrl = new URL(this.config.redirectUri);
    currentUrl.search = queryString.startsWith('?') ? queryString : `?${queryString}`;

    const tokens = await this.oidc.authorizationCodeGrant(configuration, currentUrl, {
      pkceCodeVerifier: transaction.verifier,
      expectedNonce: transaction.nonce,
      expectedState: transaction.state,
      idTokenExpected: true,
    });

    const idTokenClaims = tokens.claims();
    if (!idTokenClaims?.sub) {
      throw new Error('OIDC ID token did not contain a subject');
    }

    const metadata = configuration.serverMetadata();
    if (!metadata.issuer || idTokenClaims.iss !== metadata.issuer) {
      throw new Error('OIDC ID token issuer does not match discovery metadata');
    }

    if (this.config.expectedIssuer && idTokenClaims.iss !== this.config.expectedIssuer) {
      throw new Error('OIDC ID token issuer does not match N8N_OIDC_EXPECTED_ISSUER');
    }

    let userInfo = {};
    if (tokens.access_token && metadata.userinfo_endpoint) {
      userInfo = await this.oidc.fetchUserInfo(
        configuration,
        tokens.access_token,
        idTokenClaims.sub,
      );

      if (userInfo?.sub && userInfo.sub !== idTokenClaims.sub) {
        throw new Error('OIDC UserInfo subject does not match ID token subject');
      }
    }

    return {
      issuer: metadata.issuer,
      claims: {
        ...idTokenClaims,
        ...userInfo,
        // Immutable identity claims always come from the validated ID token / metadata.
        sub: idTokenClaims.sub,
        iss: idTokenClaims.iss,
      },
    };
  }
}
