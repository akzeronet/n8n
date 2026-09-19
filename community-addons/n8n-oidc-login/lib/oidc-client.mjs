import * as oidc from 'openid-client';

export class N8nCommunityOidcClient {
  #configurationPromise;

  constructor(config) {
    this.config = config;
  }

  async configuration() {
    if (!this.#configurationPromise) {
      this.#configurationPromise = oidc.discovery(
        new URL(this.config.discoveryUrl),
        this.config.clientId,
        this.config.clientSecret,
      ).then((configuration) => {
        const issuer = configuration.serverMetadata().issuer;
        if (!issuer) throw new Error('OIDC discovery response did not contain an issuer');
        return configuration;
      });
    }

    return await this.#configurationPromise;
  }

  async begin() {
    const configuration = await this.configuration();

    const verifier = oidc.randomPKCECodeVerifier();
    const challenge = await oidc.calculatePKCECodeChallenge(verifier);
    const nonce = oidc.randomNonce();
    const state = oidc.randomState();

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
      authorizationUrl: oidc.buildAuthorizationUrl(configuration, parameters),
      transaction: { verifier, nonce, state },
    };
  }

  async finish(queryString, transaction) {
    const configuration = await this.configuration();

    const currentUrl = new URL(this.config.redirectUri);
    currentUrl.search = queryString.startsWith('?') ? queryString : `?${queryString}`;

    const tokens = await oidc.authorizationCodeGrant(configuration, currentUrl, {
      pkceCodeVerifier: transaction.verifier,
      expectedNonce: transaction.nonce,
      expectedState: transaction.state,
      idTokenExpected: true,
    });

    const idTokenClaims = tokens.claims();
    if (!idTokenClaims?.sub) {
      throw new Error('OIDC ID token did not contain a subject');
    }

    let userInfo = {};
    const metadata = configuration.serverMetadata();

    if (tokens.access_token && metadata.userinfo_endpoint) {
      userInfo = await oidc.fetchUserInfo(
        configuration,
        tokens.access_token,
        idTokenClaims.sub,
      );
    }

    return {
      issuer: metadata.issuer,
      claims: {
        ...idTokenClaims,
        ...userInfo,
        sub: idTokenClaims.sub,
        iss: idTokenClaims.iss ?? metadata.issuer,
      },
    };
  }
}
