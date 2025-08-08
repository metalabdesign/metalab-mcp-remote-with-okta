
const crypto = require('crypto');
const os = require('os');

/**
 * Creates an authentication strategy based on the provided configuration.
 * @param {Object} config - The configuration object.
 * @returns {AuthStrategy} The authentication strategy.
 */
function createAuthStrategy(config) {
  return new OktaAuthStrategy(config);
}

/**
 * Base class for authentication strategies.
 */
class AuthStrategy {
  constructor(config) {
    this.config = config;
  }

  getAuthUrl() {
    throw new Error('getAuthUrl() must be implemented by subclasses');
  }

  async exchangeForJWT(accessToken) {
    throw new Error('exchangeForJWT() must be implemented by subclasses');
  }
}

/**
 * Okta authentication strategy.
 */
class OktaAuthStrategy extends AuthStrategy {
  constructor(config) {
    super(config);
    this.clientId = this.config.clientId;
    this.scope = this.config.scope || 'openid profile email';
    this.redirectUri = this.config.redirectUri || 'http://localhost:8080/callback';
    this.oktaDomain = this.config.oktaDomain;
  }

  getAuthUrl(state) {
    const authParams = new URLSearchParams({
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      scope: this.scope,
      response_type: 'code',
      state,
      nonce: crypto.randomBytes(16).toString('hex'),
    });
    return `https://${this.oktaDomain}/oauth2/v1/authorize?${authParams.toString()}`;
  }

  async exchangeForJWT(accessToken) {
    // For Okta, the access token can be used directly as a bearer token
    // if the resource server is configured to validate Okta tokens.
    // If a different JWT is required, this is where the exchange would happen.
    this.config.output('✅ Using Okta access token as JWT');
    return accessToken;
  }
}

module.exports = { createAuthStrategy }; 