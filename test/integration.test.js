const { createAuthStrategy } = require('../auth-strategy');

describe('Authentication Strategies', () => {
  describe('ImsAuthStrategy', () => {
    let strategy;
    const mockConfig = {
      imsEnvironment: 'prod',
      clientId: 'test-ims-client',
      scope: 'AdobeID,openid',
      redirectUri: 'http://localhost:8080/callback',
      getApiRootUrl: () => 'https://api.test.com',
      output: () => {},
    };

    beforeEach(() => {
      strategy = createAuthStrategy({ authProvider: 'adobe', ...mockConfig });
    });

    it('should create a valid Adobe IMS auth URL', () => {
      const state = 'test-state-123';
      const authUrl = new URL(strategy.getAuthUrl(state));
      expect(authUrl.origin).toBe('https://ims-na1.adobelogin.com');
      expect(authUrl.pathname).toBe('/ims/authorize/v2');
      expect(authUrl.searchParams.get('client_id')).toBe(mockConfig.clientId);
      expect(authUrl.searchParams.get('state')).toBe(state);
    });

    it('should exchange an access token for a JWT', async () => {
        global.fetch = jest.fn().mockResolvedValue({
            ok: true,
            json: jest.fn().mockResolvedValue({ token: 'mock-jwt-from-ims' }),
        });
        const jwt = await strategy.exchangeForJWT('test-access-token');
        expect(jwt).toBe('mock-jwt-from-ims');
        expect(global.fetch).toHaveBeenCalledWith('https://api.test.com/auth/login', expect.any(Object));
    });

    it('should retry JWT exchange on failure and then throw', async () => {
        global.fetch = jest.fn()
            .mockResolvedValueOnce({ ok: false, status: 500 })
            .mockResolvedValueOnce({ ok: false, status: 500 })
            .mockResolvedValueOnce({ ok: false, status: 500 });

        await expect(strategy.exchangeForJWT('test-access-token')).rejects.toThrow('JWT exchange failed (500)');
        expect(global.fetch).toHaveBeenCalledTimes(3);
    });
  });

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
      strategy = createAuthStrategy({ authProvider: 'okta', ...mockConfig });
    });

    it('should create a valid Okta auth URL', () => {
        const state = 'test-state-456';
        const authUrl = new URL(strategy.getAuthUrl(state));
        expect(authUrl.origin).toBe('https://test.okta.com');
        expect(authUrl.pathname).toBe('/oauth2/default/v1/authorize');
        expect(authUrl.searchParams.get('client_id')).toBe(mockConfig.clientId);
        expect(authUrl.searchParams.get('state')).toBe(state);
    });

    it('should return the access token directly for JWT exchange', async () => {
        const jwt = await strategy.exchangeForJWT('okta-access-token');
        expect(jwt).toBe('okta-access-token');
    });
  });
}); 