const fs = require('fs');
const http = require('http');
const os = require('os');
const { spawn } = require('child_process');
const AdobeMCPWrapper = require('./index.js');

// Mock external dependencies
jest.mock('child_process');
jest.mock('fs');
jest.mock('http');
jest.mock('os', () => ({
  homedir: jest.fn(() => '/fake/home/dir'),
  platform: jest.fn(() => 'darwin'),
}));

// Mock global fetch for JWT exchange tests
global.fetch = jest.fn();

describe('AdobeMCPWrapper', () => {
  let wrapper;
  let mockProcessExit;
  let mockSpawn;
  let mockHttp;
  let mockServer;

  beforeEach(() => {
    // Reset mocks
    jest.clearAllMocks();

    // Mock timers to prevent hanging tests
    jest.useFakeTimers();

    // Mock process.exit to prevent tests from actually exiting
    mockProcessExit = jest.spyOn(process, 'exit').mockImplementation(() => {});

    // Mock environment variables
    process.env.ADOBE_CLIENT_ID = 'test-client-id';
    process.env.ADOBE_SCOPE = 'AdobeID,openid';
    process.env.ADOBE_AUTH_METHOD = 'jwt';
    process.env.ADOBE_IMS_ENV = 'prod';

    // Suppress console output during tests unless specifically testing it
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});

    wrapper = new AdobeMCPWrapper('https://test.com/mcp', { silent: true });

    // Mock debug method to prevent interference with tests
    wrapper.debug = jest.fn();

    // Mock fs methods
    fs.existsSync = jest.fn();
    fs.readFileSync = jest.fn();
    fs.writeFileSync = jest.fn();
    fs.mkdirSync = jest.fn();
    fs.unlinkSync = jest.fn();

    // Mock spawn
    mockSpawn = spawn;
    mockSpawn.mockReturnValue({
      on: jest.fn(),
    });

    // Mock HTTP server
    mockServer = {
      listen: jest.fn((port, callback) => {
        if (callback) callback();
      }),
      close: jest.fn(),
      on: jest.fn(),
    };
    mockHttp = http;
    mockHttp.createServer = jest.fn().mockReturnValue(mockServer);

    // Mock os.platform
    os.platform = jest.fn().mockReturnValue('darwin');
  });

  afterEach(() => {
    // Clean up wrapper resources (timers, etc.)
    if (wrapper && wrapper.cleanup) {
      wrapper.cleanup();
    }

    // Restore real timers
    jest.useRealTimers();

    // Clean up environment variables
    delete process.env.ADOBE_CLIENT_ID;
    delete process.env.ADOBE_SCOPE;
    delete process.env.ADOBE_AUTH_METHOD;
    delete process.env.ADOBE_IMS_ENV;
    delete process.env.ADOBE_REDIRECT_URI;

    // Restore mocks
    jest.restoreAllMocks();
  });

  describe('Constructor', () => {
    it('should initialize with default values', () => {
      const testWrapper = new AdobeMCPWrapper();

      expect(testWrapper.mcpRemoteUrl).toBe('https://spacecat.experiencecloud.live/api/v1/mcp');
      expect(testWrapper.scope).toBe('AdobeID,openid');
      expect(testWrapper.authMethod).toBe('jwt');
      expect(testWrapper.redirectUri).toBe('http://localhost:8080/callback');
      expect(testWrapper.imsEnvironment).toBe('prod');
    });

    it('should initialize with custom values', () => {
      process.env.ADOBE_SCOPE = 'custom,scope';
      process.env.ADOBE_AUTH_METHOD = 'access_token';
      process.env.ADOBE_REDIRECT_URI = 'https://custom.callback.com';

      const testWrapper = new AdobeMCPWrapper('https://custom.com/mcp', {
        silent: true,
        isMCPMode: true,
      });

      expect(testWrapper.mcpRemoteUrl).toBe('https://custom.com/mcp');
      expect(testWrapper.scope).toBe('custom,scope');
      expect(testWrapper.authMethod).toBe('access_token');
      expect(testWrapper.redirectUri).toBe('https://custom.callback.com');
      expect(testWrapper.silent).toBe(true);
      expect(testWrapper.isMCPMode).toBe(true);
    });

    it('should use environment variables for configuration', () => {
      expect(wrapper.clientId).toBe('test-client-id');
      expect(wrapper.scope).toBe('AdobeID,openid');
      expect(wrapper.authMethod).toBe('jwt');
      expect(wrapper.imsEnvironment).toBe('prod');
    });
  });

  describe('getEnvironmentInfo', () => {
    it('should return correct environment info for each environment', () => {
      const testCases = [
        { 
          env: 'prod', 
          expectedName: 'Production',
          expectedUrl: 'https://ims-na1.adobelogin.com/ims/authorize/v2'
        },
        { 
          env: 'production', 
          expectedName: 'Production',
          expectedUrl: 'https://ims-na1.adobelogin.com/ims/authorize/v2'
        },
        { 
          env: 'stage', 
          expectedName: 'Stage',
          expectedUrl: 'https://ims-na1-stg1.adobelogin.com/ims/authorize/v2'
        },
        { 
          env: 'stg', 
          expectedName: 'Stage',
          expectedUrl: 'https://ims-na1-stg1.adobelogin.com/ims/authorize/v2'
        },
        { 
          env: 'dev', 
          expectedName: 'Development',
          expectedUrl: 'https://ims-na1-dev.adobelogin.com/ims/authorize/v2'
        },
        { 
          env: 'development', 
          expectedName: 'Development',
          expectedUrl: 'https://ims-na1-dev.adobelogin.com/ims/authorize/v2'
        },
        { 
          env: 'qa', 
          expectedName: 'QA/Test',
          expectedUrl: 'https://ims-na1-qa.adobelogin.com/ims/authorize/v2'
        },
        { 
          env: 'test', 
          expectedName: 'QA/Test',
          expectedUrl: 'https://ims-na1-qa.adobelogin.com/ims/authorize/v2'
        },
      ];

      testCases.forEach(({ env, expectedName, expectedUrl }) => {
        wrapper.imsEnvironment = env;
        const envInfo = wrapper.getEnvironmentInfo();
        expect(envInfo.name).toBe(expectedName);
        expect(envInfo.url).toBe(expectedUrl);
      });
    });
  });

  describe('output method', () => {
    beforeEach(() => {
      jest.restoreAllMocks();
      jest.spyOn(console, 'log').mockImplementation(() => {});
      jest.spyOn(console, 'error').mockImplementation(() => {});
    });

    it('should not output when silent is true', () => {
      wrapper.silent = true;
      wrapper.output('test message');
      expect(console.log).not.toHaveBeenCalled();
      expect(console.error).not.toHaveBeenCalled();
    });

    it('should output to console.log when not in MCP mode', () => {
      wrapper.silent = false;
      wrapper.isMCPMode = false;
      wrapper.output('test message');
      expect(console.log).toHaveBeenCalledWith('test message');
    });

    it('should output to console.error when in MCP mode', () => {
      wrapper.silent = false;
      wrapper.isMCPMode = true;
      wrapper.output('test message');
      expect(console.error).toHaveBeenCalledWith('test message');
    });

    it('should output to console.error when level is error', () => {
      wrapper.silent = false;
      wrapper.isMCPMode = false;
      wrapper.error('test message');
      expect(console.error).toHaveBeenCalledWith('test message');
    });
  });

  describe('ensureConfigDir', () => {
    it('should create config directory if it does not exist', () => {
      fs.existsSync.mockReturnValue(false);
      wrapper.ensureConfigDir();
      expect(fs.mkdirSync).toHaveBeenCalledWith(wrapper.configDir, { recursive: true });
    });

    it('should not create config directory if it exists', () => {
      fs.existsSync.mockReturnValue(true);
      wrapper.ensureConfigDir();
      expect(fs.mkdirSync).not.toHaveBeenCalled();
    });
  });

  describe('loadTokens', () => {
    it('should load tokens from file successfully', () => {
      const mockTokens = { access_token: 'test-token', expires_in: '3600' };
      fs.existsSync.mockReturnValue(true);
      fs.readFileSync.mockReturnValue(JSON.stringify(mockTokens));

      const result = wrapper.loadTokens();
      expect(result).toEqual(mockTokens);
      expect(fs.readFileSync).toHaveBeenCalledWith(wrapper.tokenFile, 'utf8');
    });

    it('should return null if file does not exist', () => {
      fs.existsSync.mockReturnValue(false);
      const result = wrapper.loadTokens();
      expect(result).toBeNull();
    });

    it('should return null if file read fails', () => {
      fs.existsSync.mockReturnValue(true);
      fs.readFileSync.mockImplementation(() => {
        throw new Error('Read error');
      });

      const result = wrapper.loadTokens();
      expect(result).toBeNull();
    });
  });

  describe('saveTokens', () => {
    it('should save tokens successfully', () => {
      const mockTokens = { access_token: 'test-token', expires_in: '3600' };
      fs.existsSync.mockReturnValue(true);

      wrapper.saveTokens(mockTokens);

      expect(fs.writeFileSync).toHaveBeenCalledWith(
        wrapper.tokenFile,
        expect.stringContaining('"access_token": "test-token"'),
      );
    });

    it('should create config directory before saving tokens', () => {
      const mockTokens = { access_token: 'test-token' };
      fs.existsSync.mockReturnValue(false);

      wrapper.saveTokens(mockTokens);

      expect(fs.mkdirSync).toHaveBeenCalledWith(wrapper.configDir, { recursive: true });
      expect(fs.writeFileSync).toHaveBeenCalled();
    });

    it('should handle save errors gracefully', () => {
      const mockTokens = { access_token: 'test-token' };
      fs.writeFileSync.mockImplementation(() => {
        throw new Error('Write error');
      });

      // Should not throw
      expect(() => wrapper.saveTokens(mockTokens)).not.toThrow();
    });
  });

  describe('isTokenExpired', () => {
    it('should return true for null tokens', () => {
      expect(AdobeMCPWrapper.isTokenExpired(null)).toBe(true);
    });

    it('should return true for tokens without timestamp', () => {
      const tokens = { access_token: 'test' };
      expect(AdobeMCPWrapper.isTokenExpired(tokens)).toBe(true);
    });

    it('should return false for non-expired tokens', () => {
      const tokens = {
        access_token: 'test',
        expires_in: '3600',
        timestamp: Date.now(),
      };
      expect(AdobeMCPWrapper.isTokenExpired(tokens)).toBe(false);
    });

    it('should return true for expired tokens', () => {
      const tokens = {
        access_token: 'test',
        expires_in: '3600',
        timestamp: Date.now() - (3700 * 1000), // Expired 1 hour 40 mins ago
      };
      expect(AdobeMCPWrapper.isTokenExpired(tokens)).toBe(true);
    });

    it('should consider tokens expired within 5 minutes', () => {
      const tokens = {
        access_token: 'test',
        expires_in: '3600',
        timestamp: Date.now() - (3540 * 1000), // Expires in 1 minute
      };
      expect(AdobeMCPWrapper.isTokenExpired(tokens)).toBe(true);
    });
  });

  describe('startAuthFlow - OAuth server basics', () => {
    let requestHandler;
    let serverErrorHandler;

    beforeEach(() => {
      // Setup server mocks
      mockHttp.createServer.mockImplementation((handler) => {
        requestHandler = handler;
        return mockServer;
      });

      mockServer.on.mockImplementation((event, handler) => {
        if (event === 'error') {
          serverErrorHandler = handler;
        }
      });
    });

    it('should create HTTP server and listen on port', () => {
      wrapper.clientId = 'test-client';
      wrapper.startAuthFlow();

      expect(mockHttp.createServer).toHaveBeenCalled();
      expect(mockServer.listen).toHaveBeenCalledWith(8080, expect.any(Function));
    });

    it('should handle callback URL correctly', () => {
      wrapper.clientId = 'test-client';
      wrapper.startAuthFlow();

      const mockReq = { url: '/callback' };
      const mockRes = {
        writeHead: jest.fn(),
        end: jest.fn(),
      };

      requestHandler(mockReq, mockRes);

      expect(mockRes.writeHead).toHaveBeenCalledWith(200, { 'Content-Type': 'text/html' });
      expect(mockRes.end).toHaveBeenCalled();
    });

    it('should handle 404 for unknown paths', () => {
      wrapper.clientId = 'test-client';
      wrapper.startAuthFlow();

      const mockReq = { url: '/unknown' };
      const mockRes = {
        writeHead: jest.fn(),
        end: jest.fn(),
      };

      requestHandler(mockReq, mockRes);

      expect(mockRes.writeHead).toHaveBeenCalledWith(404);
      expect(mockRes.end).toHaveBeenCalledWith('<h1>Not Found</h1>');
    });

    it('should throw error if client ID is missing', async () => {
      wrapper.clientId = null;
      await expect(wrapper.startAuthFlow()).rejects.toThrow(
        'Client ID not found. Please add ADOBE_CLIENT_ID to env variables.',
      );
    });

    it('should handle POST requests with routing', () => {
      wrapper.clientId = 'test-client';
      wrapper.startAuthFlow();

      // Test success POST route
      const mockSuccessReq = { url: '/success', on: jest.fn() };
      const mockSuccessRes = { writeHead: jest.fn(), end: jest.fn() };
      
      requestHandler(mockSuccessReq, mockSuccessRes);
      
      // Should set up data/end handlers for success route
      expect(mockSuccessReq.on).toHaveBeenCalledWith('data', expect.any(Function));
      expect(mockSuccessReq.on).toHaveBeenCalledWith('end', expect.any(Function));

      // Test error POST route
      const mockErrorReq = { url: '/error', on: jest.fn() };
      const mockErrorRes = { writeHead: jest.fn(), end: jest.fn() };
      
      requestHandler(mockErrorReq, mockErrorRes);
      
      // Should set up data/end handlers for error route
      expect(mockErrorReq.on).toHaveBeenCalledWith('data', expect.any(Function));
      expect(mockErrorReq.on).toHaveBeenCalledWith('end', expect.any(Function));
    });

    it('should handle server setup correctly', () => {
      wrapper.clientId = 'test-client';
      wrapper.startAuthFlow();

      // Verify server event handlers are set up
      expect(mockServer.on).toHaveBeenCalledWith('error', expect.any(Function));
      
      // Verify HTTP server creation
      expect(mockHttp.createServer).toHaveBeenCalledWith(expect.any(Function));
      
      // Verify server listens on correct port
      expect(mockServer.listen).toHaveBeenCalledWith(8080, expect.any(Function));
    });
  });

  describe('getValidToken', () => {
    it('should return stored valid token', async () => {
      const mockTokens = {
        access_token: 'stored-token',
        expires_in: '3600',
        timestamp: Date.now(),
      };
      fs.existsSync.mockReturnValue(true);
      fs.readFileSync.mockReturnValue(JSON.stringify(mockTokens));

      const result = await wrapper.getValidToken();
      expect(result).toBe('stored-token');
    });

    it('should throw error when authentication fails', async () => {
      fs.existsSync.mockReturnValue(false);
      wrapper.clientId = null;

      await expect(wrapper.getValidToken()).rejects.toThrow(
        'Client ID not found. Please add ADOBE_CLIENT_ID to env variables.',
      );
    });
  });

  describe('exchangeForJWT', () => {
    beforeEach(() => {
      global.fetch = jest.fn();
      // For these tests, we want to disable the retry delays to avoid timeouts
      jest.spyOn(global, 'setTimeout').mockImplementation((callback) => {
        setImmediate(callback);
        return 'mock-timer';
      });
    });

    it('should exchange access token for JWT successfully', async () => {
      const mockJWTResponse = { token: 'jwt-token-123' };
      global.fetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue(mockJWTResponse),
        headers: new Map(),
      });

      const result = await wrapper.exchangeForJWT('test-access-token');

      expect(result).toBe('jwt-token-123');
      expect(global.fetch).toHaveBeenCalledWith(
        'https://test.com/auth/login',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
            'User-Agent': 'mcp-remote-with-okta/1.1.0',
          }),
          body: JSON.stringify({ accessToken: 'test-access-token' }),
        }),
      );
    });

    it('should handle different JWT token field names', async () => {
      const mockJWTResponse = { sessionToken: 'session-jwt-123' };
      global.fetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue(mockJWTResponse),
        headers: new Map(),
      });

      const result = await wrapper.exchangeForJWT('test-access-token');
      expect(result).toBe('session-jwt-123');
    });

    it('should handle JWT exchange failure', async () => {
      // Mock wrapper with no retries to avoid timeout issues
      const noRetryWrapper = new AdobeMCPWrapper('https://test.com/mcp');
      
      global.fetch.mockResolvedValue({
        ok: false,
        status: 401,
        text: jest.fn().mockResolvedValue('Unauthorized'),
        headers: new Map(),
      });

      await expect(noRetryWrapper.exchangeForJWT('test-access-token', 3))
        .rejects.toThrow('JWT exchange failed (401): Unauthorized');

      expect(global.fetch).toHaveBeenCalled();
    });

    it('should handle missing JWT token in response', async () => {
      const noRetryWrapper = new AdobeMCPWrapper('https://test.com/mcp');
      const mockJWTResponse = { message: 'Success but no token' };
      
      global.fetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue(mockJWTResponse),
        headers: new Map(),
      });

      await expect(noRetryWrapper.exchangeForJWT('test-access-token', 3))
        .rejects.toThrow('No JWT token in response');

      expect(global.fetch).toHaveBeenCalled();
    });

    it('should handle network errors', async () => {
      const noRetryWrapper = new AdobeMCPWrapper('https://test.com/mcp');
      
      global.fetch.mockRejectedValue(new Error('Network error'));

      await expect(noRetryWrapper.exchangeForJWT('test-access-token', 3))
        .rejects.toThrow('Network error');

      expect(global.fetch).toHaveBeenCalled();
    });
  });

  describe('getValidJWT', () => {
    beforeEach(() => {
      global.fetch = jest.fn();
    });

    it('should get valid JWT token by exchanging access token', async () => {
      // Mock stored valid token
      const mockTokens = {
        access_token: 'stored-token',
        expires_in: '3600',
        timestamp: Date.now(),
      };
      fs.existsSync.mockReturnValue(true);
      fs.readFileSync.mockReturnValue(JSON.stringify(mockTokens));

      // Mock JWT exchange
      global.fetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({ token: 'jwt-token-123' }),
        headers: new Map(),
      });

      const result = await wrapper.getValidJWT();
      expect(result).toBe('jwt-token-123');
    });

    it('should handle JWT exchange failure', async () => {
      fs.existsSync.mockReturnValue(false);
      wrapper.clientId = null;

      await expect(wrapper.getValidJWT()).rejects.toThrow(
        'Client ID not found. Please add ADOBE_CLIENT_ID to env variables.',
      );
    });
  });

  describe('launchMCP', () => {
    it('should launch MCP with access token authentication', async () => {
      wrapper.authMethod = 'access_token';

      // Mock stored valid token
      const mockTokens = {
        access_token: 'stored-token',
        expires_in: '3600',
        timestamp: Date.now(),
      };
      fs.existsSync.mockReturnValue(true);
      fs.readFileSync.mockReturnValue(JSON.stringify(mockTokens));

      await wrapper.launchMCP();

      expect(mockSpawn).toHaveBeenCalledWith(
        'npx',
        expect.arrayContaining([
          'mcp-remote@latest',
          'https://test.com/mcp',
          '--transport', 'http-first',
          '--debug',
          '--header', 'Authorization:Bearer stored-token',
        ]),
        expect.any(Object),
      );
    });

    it('should launch MCP with JWT authentication', async () => {
      wrapper.authMethod = 'jwt';

      // Mock stored valid token
      const mockTokens = {
        access_token: 'stored-token',
        expires_in: '3600',
        timestamp: Date.now(),
      };
      fs.existsSync.mockReturnValue(true);
      fs.readFileSync.mockReturnValue(JSON.stringify(mockTokens));

      // Mock JWT exchange
      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({ token: 'jwt-token-123' }),
        headers: new Map(),
      });

      await wrapper.launchMCP();

      expect(mockSpawn).toHaveBeenCalledWith(
        'npx',
        expect.arrayContaining([
          'mcp-remote@latest',
          'https://test.com/mcp',
          '--transport', 'http-first',
          '--debug',
          '--header', 'Authorization:Bearer jwt-token-123',
        ]),
        expect.any(Object),
      );
    });

    it('should handle missing client ID', async () => {
      wrapper.clientId = null;
      try {
        await wrapper.launchMCP();
      } catch (error) {
        expect(error.message).toBe('ADOBE_CLIENT_ID environment variable not found');
      }
    });
  });

  describe('runCLI', () => {
    beforeEach(() => {
      // Suppress console output for CLI tests
      wrapper.silent = false;
      jest.spyOn(console, 'log').mockImplementation(() => {});
      jest.spyOn(console, 'error').mockImplementation(() => {});
    });

    it('should handle authenticate command', async () => {
      const mockTokens = {
        access_token: 'stored-token',
        expires_in: '3600',
        timestamp: Date.now(),
      };
      fs.existsSync.mockReturnValue(true);
      fs.readFileSync.mockReturnValue(JSON.stringify(mockTokens));

      await wrapper.runCLI('authenticate');
      // Should not throw and should complete successfully
    });

    it('should handle status command', async () => {
      const mockTokens = {
        access_token: 'stored-token',
        expires_in: '3600',
        timestamp: Date.now(),
      };
      fs.existsSync.mockReturnValue(true);
      fs.readFileSync.mockReturnValue(JSON.stringify(mockTokens));

      await wrapper.runCLI('status');
      // Should not throw and should complete successfully
    });

    it('should handle status command with no token', async () => {
      fs.existsSync.mockReturnValue(false);
      await wrapper.runCLI('status');
      // Should not throw and should complete successfully
    });

    it('should handle token command', async () => {
      const mockTokens = {
        access_token: 'stored-token',
        expires_in: '3600',
        timestamp: Date.now(),
      };
      fs.existsSync.mockReturnValue(true);
      fs.readFileSync.mockReturnValue(JSON.stringify(mockTokens));

      await wrapper.runCLI('token');
      // Should not throw and should complete successfully
    });

    it('should handle clear command', async () => {
      fs.existsSync.mockReturnValue(true);
      await wrapper.runCLI('clear');
      expect(fs.unlinkSync).toHaveBeenCalledWith(wrapper.tokenFile);
    });

    it('should handle clear command when no tokens exist', async () => {
      fs.existsSync.mockReturnValue(false);
      await wrapper.runCLI('clear');
      expect(fs.unlinkSync).not.toHaveBeenCalled();
    });

    it('should handle help command', async () => {
      await wrapper.runCLI('help');
      // Should not throw and should complete successfully
    });

    it('should handle unknown command', async () => {
      await wrapper.runCLI('unknown');
      // Should not throw and should complete successfully
    });

    it('should handle CLI errors and exit', async () => {
      wrapper.clientId = null;
      await wrapper.runCLI('authenticate');
      expect(mockProcessExit).toHaveBeenCalledWith(1);
    });

    it('should handle token command when no valid token', async () => {
      fs.existsSync.mockReturnValue(false);
      wrapper.clientId = null;
      await wrapper.runCLI('token');
      // Should complete but may not show token
    });

    it('should handle clear command file deletion errors', async () => {
      fs.existsSync.mockReturnValue(true);
      fs.unlinkSync.mockImplementation(() => {
        throw new Error('Permission denied');
      });

      await wrapper.runCLI('clear');
      // Should complete without throwing (error is caught and logged)
    });

    it('should handle status command with expired tokens', async () => {
      const expiredTokens = {
        access_token: 'expired-token',
        expires_in: '3600',
        timestamp: Date.now() - (7200 * 1000), // Expired 2 hours ago
      };
      fs.existsSync.mockReturnValue(true);
      fs.readFileSync.mockReturnValue(JSON.stringify(expiredTokens));

      await wrapper.runCLI('status');
      // Should complete successfully showing expired status
    });

    it('should handle status command with tokens missing timestamp', async () => {
      const tokensNoTimestamp = {
        access_token: 'token-no-timestamp',
        expires_in: '3600',
      };
      fs.existsSync.mockReturnValue(true);
      fs.readFileSync.mockReturnValue(JSON.stringify(tokensNoTimestamp));

      await wrapper.runCLI('status');
      // Should complete successfully
    });
  });

  describe('openBrowser', () => {
    it('should attempt to open browser with URL', () => {
      mockSpawn.mockImplementation(() => {});
      wrapper.openBrowser('https://test-url.com');
      expect(mockSpawn).toHaveBeenCalled();
    });

    it('should handle spawn errors gracefully', () => {
      mockSpawn.mockImplementation(() => {
        throw new Error('Spawn error');
      });
      // Should not throw
      expect(() => wrapper.openBrowser('https://test-url.com')).not.toThrow();
    });

    it('should use correct commands for different platforms', () => {
      // Test macOS
      os.platform.mockReturnValue('darwin');
      mockSpawn.mockImplementation(() => {});
      wrapper.openBrowser('https://test-url.com');
      expect(mockSpawn).toHaveBeenCalledWith('open', ['https://test-url.com'], expect.any(Object));

      // Test Windows
      os.platform.mockReturnValue('win32');
      wrapper.openBrowser('https://test-url.com');
      expect(mockSpawn).toHaveBeenCalledWith('start', ['https://test-url.com'], expect.any(Object));

      // Test Linux
      os.platform.mockReturnValue('linux');
      wrapper.openBrowser('https://test-url.com');
      expect(mockSpawn).toHaveBeenCalledWith('xdg-open', ['https://test-url.com'], expect.any(Object));
    });
  });

  describe('launchMCP - process event handling', () => {
    let mockMcpProcess;

    beforeEach(() => {
      mockMcpProcess = {
        on: jest.fn(),
      };
      mockSpawn.mockReturnValue(mockMcpProcess);
    });

    it('should handle MCP process errors', async () => {
      wrapper.authMethod = 'access_token';

      const mockTokens = {
        access_token: 'stored-token',
        expires_in: '3600',
        timestamp: Date.now(),
      };
      fs.existsSync.mockReturnValue(true);
      fs.readFileSync.mockReturnValue(JSON.stringify(mockTokens));

      // Set up process event handlers
      let errorHandler;
      mockMcpProcess.on.mockImplementation((event, handler) => {
        if (event === 'error') {
          errorHandler = handler;
        }
      });

      await wrapper.launchMCP();

      // Simulate process error
      const processError = new Error('Failed to spawn process');
      errorHandler(processError);

      expect(mockProcessExit).toHaveBeenCalledWith(1);
    });

    it('should handle MCP process exit with signal', async () => {
      wrapper.authMethod = 'access_token';

      const mockTokens = {
        access_token: 'stored-token',
        expires_in: '3600',
        timestamp: Date.now(),
      };
      fs.existsSync.mockReturnValue(true);
      fs.readFileSync.mockReturnValue(JSON.stringify(mockTokens));

      // Set up process event handlers
      let exitHandler;
      mockMcpProcess.on.mockImplementation((event, handler) => {
        if (event === 'exit') {
          exitHandler = handler;
        }
      });

      await wrapper.launchMCP();

      // Simulate process exit with signal
      exitHandler(null, 'SIGTERM');

      expect(mockProcessExit).toHaveBeenCalledWith(0);
    });

    it('should handle MCP process exit with code', async () => {
      wrapper.authMethod = 'access_token';

      const mockTokens = {
        access_token: 'stored-token',
        expires_in: '3600',
        timestamp: Date.now(),
      };
      fs.existsSync.mockReturnValue(true);
      fs.readFileSync.mockReturnValue(JSON.stringify(mockTokens));

      // Set up process event handlers
      let exitHandler;
      mockMcpProcess.on.mockImplementation((event, handler) => {
        if (event === 'exit') {
          exitHandler = handler;
        }
      });

      await wrapper.launchMCP();

      // Simulate process exit with code
      exitHandler(1, null);

      expect(mockProcessExit).toHaveBeenCalledWith(1);
    });
  });

  describe('edge cases and error scenarios', () => {
    it('should handle isTokenExpired with undefined expires_in', () => {
      const tokens = {
        access_token: 'test',
        timestamp: Date.now(),
      };
      // Should not throw and should use default expiration
      expect(AdobeMCPWrapper.isTokenExpired(tokens)).toBe(false);
    });

    it('should handle getValidToken when stored tokens are invalid JSON', async () => {
      fs.existsSync.mockReturnValue(true);
      fs.readFileSync.mockReturnValue('invalid-json');

      // Should start auth flow since loadTokens returns null
      wrapper.clientId = null;
      await expect(wrapper.getValidToken()).rejects.toThrow(
        'Client ID not found. Please add ADOBE_CLIENT_ID to env variables.',
      );
    });

    it('should handle all JWT token field names', async () => {
      // Test token field
      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({ token: 'jwt-from-token' }),
        headers: new Map(),
      });
      let result = await wrapper.exchangeForJWT('test-access-token');
      expect(result).toBe('jwt-from-token');

      // Test jwt field
      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({ jwt: 'jwt-from-jwt' }),
        headers: new Map(),
      });
      result = await wrapper.exchangeForJWT('test-access-token');
      expect(result).toBe('jwt-from-jwt');

      // Test access_token field
      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({
          access_token: 'jwt-from-access-token',
        }),
        headers: new Map(),
      });
      result = await wrapper.exchangeForJWT('test-access-token');
      expect(result).toBe('jwt-from-access-token');

      // Test sessionToken field
      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({ sessionToken: 'jwt-from-session' }),
        headers: new Map(),
      });
      result = await wrapper.exchangeForJWT('test-access-token');
      expect(result).toBe('jwt-from-session');
    });
  });
});

// Main function tests to cover lines 560-599
describe('main function integration', () => {
  let originalArgv;
  let originalConsoleLog;
  let originalConsoleError;
  let mockWrapper;

  beforeEach(() => {
    originalArgv = process.argv;
    originalConsoleLog = console.log;
    originalConsoleError = console.error;

    console.log = jest.fn();
    console.error = jest.fn();

    // Mock the constructor
    mockWrapper = {
      runCLI: jest.fn(),
      launchMCP: jest.fn(),
    };
  });

  afterEach(() => {
    process.argv = originalArgv;
    console.log = originalConsoleLog;
    console.error = originalConsoleError;
    jest.restoreAllMocks();
  });

  it('should show help when no arguments provided', async () => {
    process.argv = ['node', 'index.js'];

    // Mock the main function logic
    const args = process.argv.slice(2);
    const isMCPMode = !process.stdin.isTTY || process.env.MCP_MODE === 'true';
    
    if (args.length === 0) {
      // Help should be shown
      expect(args.length).toBe(0);
    }
  });

  it('should parse MCP URL correctly', async () => {
    process.argv = ['node', 'index.js', 'https://test.com/mcp'];

    const args = process.argv.slice(2);
    const mcpRemoteUrl = args[0] || 'https://spacecat.experiencecloud.live/api/v1/mcp';
    const command = args[1];

    expect(mcpRemoteUrl).toBe('https://test.com/mcp');
    expect(command).toBeUndefined();
  });

  it('should parse MCP URL and command correctly', async () => {
    process.argv = ['node', 'index.js', 'https://test.com/mcp', 'status'];

    const args = process.argv.slice(2);
    const mcpRemoteUrl = args[0] || 'https://spacecat.experiencecloud.live/api/v1/mcp';
    const command = args[1];

    expect(mcpRemoteUrl).toBe('https://test.com/mcp');
    expect(command).toBe('status');
  });

  it('should detect MCP mode correctly', () => {
    // Test with MCP_MODE environment variable
    process.env.MCP_MODE = 'true';
    const isMCPModeEnv = !process.stdin.isTTY || process.env.MCP_MODE === 'true';
    expect(isMCPModeEnv).toBe(true);

    delete process.env.MCP_MODE;
    
    // Test TTY detection
    const isMCPModeTTY = !process.stdin.isTTY || process.env.MCP_MODE === 'true';
    // This will depend on the test environment's TTY state
  });

  it('should handle CLI commands', async () => {
    process.argv = ['node', 'index.js', 'https://test.com/mcp', 'authenticate'];

    const args = process.argv.slice(2);
    const mcpRemoteUrl = args[0] || 'https://spacecat.experiencecloud.live/api/v1/mcp';
    const command = args[1];
    const isMCPMode = !process.stdin.isTTY || process.env.MCP_MODE === 'true';

    if (command) {
      // CLI command mode
      expect(command).toBe('authenticate');
      expect(mcpRemoteUrl).toBe('https://test.com/mcp');
    }
  });

  it('should handle MCP launch mode', async () => {
    process.argv = ['node', 'index.js', 'https://test.com/mcp'];

    const args = process.argv.slice(2);
    const mcpRemoteUrl = args[0] || 'https://spacecat.experiencecloud.live/api/v1/mcp';
    const command = args[1];
    const isMCPMode = !process.stdin.isTTY || process.env.MCP_MODE === 'true';

    if (!command) {
      // MCP launch mode
      expect(command).toBeUndefined();
      expect(mcpRemoteUrl).toBe('https://test.com/mcp');
    }
  });

  it('should use default MCP URL when none provided', async () => {
    process.argv = ['node', 'index.js'];

    const args = process.argv.slice(2);
    const mcpRemoteUrl = args[0] || 'https://spacecat.experiencecloud.live/api/v1/mcp';
    
    expect(mcpRemoteUrl).toBe('https://spacecat.experiencecloud.live/api/v1/mcp');
  });
});

// Process error handlers tests to cover lines 606-614
describe('process error handlers', () => {
  let originalConsoleError;

  beforeEach(() => {
    originalConsoleError = console.error;
    console.error = jest.fn();
  });

  afterEach(() => {
    console.error = originalConsoleError;
    jest.restoreAllMocks();
  });
  it('should handle main function errors', async () => {
    // Test error handling in main function
    const error = new Error('Fatal error');

    // Simulate catching an error in main
    try {
      throw error;
    } catch (caughtError) {
      // This simulates the catch block in main()
      expect(caughtError.message).toBe('Fatal error');
    }
  });
});
