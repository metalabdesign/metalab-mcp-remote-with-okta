const { OktaAuthStrategy } = require('../src/index');
const dotenv = require('dotenv');
dotenv.config();

describe('Authentication Strategies', () => {

  describe('OktaAuthStrategy', () => {
    let strategy;
    const mockConfig = {
      oktaDomain: 'test.okta.com',
      clientId: 'test-okta-client',
      scope: 'openid profile',
      redirectUri: 'http://localhost:8080/callback',
      getApiRootUrl: () => 'https://api.test.com',
      output: () => {},
    };

    beforeEach(() => {
      strategy = new OktaAuthStrategy(mockConfig);
    });

    it('should create a valid Okta auth URL', () => {
      const state = 'test-state-456';
      const authUrl = new URL(strategy.getAuthUrl(state));
      expect(authUrl.origin).toBe('https://test.okta.com');
      expect(authUrl.pathname).toBe('/oauth2/v1/authorize');
      expect(authUrl.searchParams.get('client_id')).toBe(mockConfig.clientId);
      expect(authUrl.searchParams.get('state')).toBe(state);
    });

    it('should return the access token directly for JWT exchange', async () => {
      const jwt = await strategy.exchangeForJWT('okta-access-token');
      expect(jwt).toBe('okta-access-token');
    });
  });
});