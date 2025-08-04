
const crypto = require('crypto');
const http = require('http');
const { spawn } = require('child_process');
const os = require('os');

/**
 * Creates an authentication strategy based on the provided configuration.
 * @param {Object} config - The configuration object.
 * @returns {AuthStrategy} The authentication strategy.
 */
function createAuthStrategy(config) {
  if (config.authProvider === 'okta') {
    return new OktaAuthStrategy(config);
  }
  return new ImsAuthStrategy(config);
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
 * Adobe IMS authentication strategy.
 */
class ImsAuthStrategy extends AuthStrategy {
  constructor(config) {
    super(config);
    this.imsEnvironment = this.config.imsEnvironment || 'prod';
    this.clientId = this.config.clientId;
    this.scope = this.config.scope || 'AdobeID,openid';
    this.redirectUri = this.config.redirectUri || 'http://localhost:8080/callback';
  }

  getEnvironmentInfo() {
    const envs = {
      prod: { name: 'Production', url: 'https://ims-na1.adobelogin.com/ims/authorize/v2' },
      stage: { name: 'Stage', url: 'https://ims-na1-stg1.adobelogin.com/ims/authorize/v2' },
      dev: { name: 'Development', url: 'https://ims-na1-dev.adobelogin.com/ims/authorize/v2' },
    };
    return envs[this.imsEnvironment.toLowerCase()] || envs.prod;
  }

  getAuthUrl(state) {
    const authParams = new URLSearchParams({
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      scope: this.scope,
      response_type: 'token',
      state,
      response_mode: 'fragment',
    });
    return `${this.getEnvironmentInfo().url}?${authParams.toString()}`;
  }

  async exchangeForJWT(accessToken, attempt = 1) {
    const jwtUrl = `${this.config.getApiRootUrl()}/auth/login`;
    const maxRetries = 3;

    try {
      this.config.output(`🔄 Exchanging for JWT (${attempt}/${maxRetries})...`);
      const response = await fetch(jwtUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': `mcp-remote-with-okta/1.2.0`,
        },
        body: JSON.stringify({ accessToken }),
      });

      if (!response.ok) {
        throw new Error(`JWT exchange failed (${response.status})`);
      }

      const jwtResponse = await response.json();
      const jwtToken = jwtResponse.token || jwtResponse.jwt;

      if (!jwtToken) {
        throw new Error('No JWT token in response');
      }

      this.config.output('✅ JWT token obtained');
      return jwtToken;
    } catch (error) {
      if (attempt < maxRetries) {
        const delay = 2 ** (attempt - 1) * 1000;
        this.config.output(`⏳ Retrying in ${delay}ms...`);
        await new Promise((resolve) => setTimeout(resolve, delay));
        return this.exchangeForJWT(accessToken, attempt + 1);
      }
      throw error;
    }
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