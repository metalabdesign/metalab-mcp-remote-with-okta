const fs = require('fs');
const os = require('os');
const { spawn } = require('child_process');
const AuthMCPWrapper = require('../src/index');
const dotenv = require('dotenv');
dotenv.config();

// Mock external dependencies
jest.mock('fs');
jest.mock('http');
jest.mock('os');
jest.mock('child_process');

// Mock global fetch
global.fetch = jest.fn();

describe('AuthMCPWrapper', () => {
  let wrapper;
  const mcpRemoteUrl = 'https://test.mcp.com/mcp';
  const originalDate = global.Date;

  // Function to mock the Date object
  const mockDateNow = (date) => {
    const mockDate = new originalDate(date);
    global.Date = class extends originalDate {
      constructor() {
        super();
        return mockDate;
      }
      static now() {
        return mockDate.getTime();
      }
    };
  };

  beforeEach(() => {
    // Reset environment variables
    Object.keys(process.env).forEach(key => {
      if (key.startsWith('OKTA_') || ['AUTH_PROVIDER', 'DEBUG_MODE', 'AUTH_METHOD'].includes(key)) {
        delete process.env[key];
      }
    });

    // Reset mocks
    jest.clearAllMocks();
    mockDateNow('2025-01-01T00:00:00.000Z');

    os.homedir.mockReturnValue('/fake/home');
    os.platform.mockReturnValue('darwin');
    fs.mkdirSync.mockImplementation(() => { });
    fs.existsSync.mockReturnValue(false); // Default to no token file
    spawn.mockReturnValue({ on: jest.fn() });
  });

  afterEach(() => {
    global.Date = originalDate; // Restore original Date object
    if (wrapper) {
      wrapper.cleanup();
    }
  });

  describe('Constructor and Configuration', () => {
    it('should use Okta provider when configured', () => {
      process.env.OKTA_CLIENT_ID = 'okta-id';
      process.env.OKTA_DOMAIN = 'okta.domain';
      wrapper = new AuthMCPWrapper(mcpRemoteUrl);
      expect(wrapper.authProvider).toBe('okta');
      expect(wrapper.clientId).toBe('okta-id');
      expect(wrapper.tokenFile).toBe('/fake/home/.metalab/okta-token.json');
    });
  });

  describe('Token Management', () => {
    beforeEach(() => {
      wrapper = new AuthMCPWrapper(mcpRemoteUrl, { silent: true });
    });

    it('should save tokens with the correct timestamp', () => {
      const mockTokens = { access_token: '123', expires_in: 3600 };
      wrapper.saveTokens(mockTokens);
      const expectedData = JSON.stringify(
        { ...mockTokens, timestamp: Date.now() },
        null,
        2
      );
      expect(fs.writeFileSync).toHaveBeenCalledWith(wrapper.tokenFile, expectedData);
    });

    it('should correctly identify an expired token', () => {
      mockDateNow('2025-01-01T01:00:00.000Z');
      const expiredToken = {
        timestamp: new originalDate('2025-01-01T00:00:00.000Z').getTime(),
        expires_in: 3500 // Expires in less than an hour
      };
      // Expiration time is less than the buffer
      expect(AuthMCPWrapper.isTokenExpired(expiredToken)).toBe(true);
    });

    it('should correctly identify a valid token', () => {
      mockDateNow('2025-01-01T00:00:01.000Z');
      const validToken = {
        timestamp: new originalDate('2025-01-01T00:00:00.000Z').getTime(),
        expires_in: 3600 // Expires in an hour
      };
      expect(AuthMCPWrapper.isTokenExpired(validToken)).toBe(false);
    });
  });

  describe('CLI Commands', () => {
    beforeEach(() => {
      wrapper = new AuthMCPWrapper(mcpRemoteUrl, { silent: true });
      jest.spyOn(wrapper, 'getValidToken').mockResolvedValue('valid-token');
    });

    it('runCLI("status") shows valid for a good token', async () => {
      const outputSpy = jest.spyOn(wrapper, 'output').mockImplementation(() => { });
      fs.existsSync.mockReturnValue(true);
      fs.readFileSync.mockReturnValue(JSON.stringify({
        timestamp: Date.now(),
        expires_in: 3600
      }));

      await wrapper.runCLI('status');
      expect(outputSpy).toHaveBeenCalledWith(expect.stringContaining('Token Status: ✅ Valid'));
    });

    it('runCLI("status") shows expired for a bad token', async () => {
      const outputSpy = jest.spyOn(wrapper, 'output').mockImplementation(() => { });
      fs.existsSync.mockReturnValue(true);
      fs.readFileSync.mockReturnValue(JSON.stringify({
        timestamp: new originalDate('2024-01-01T00:00:00.000Z').getTime(),
        expires_in: 3600
      }));

      await wrapper.runCLI('status');
      expect(outputSpy).toHaveBeenCalledWith(expect.stringContaining('Token Status: ❌ Expired'));
    });
  });
});

describe('Additional index.js Logic', () => {
  const mcpRemoteUrl = 'https://test.mcp.com/mcp';
  let wrapper;

  afterEach(() => {
    if (wrapper) {
      wrapper.cleanup();
    }
  });

  beforeEach(() => {
    jest.clearAllMocks();
    jest.spyOn(console, 'error').mockImplementation(() => { });
  });

  it('getApiRootUrl should remove /mcp suffix', () => {
    wrapper = new AuthMCPWrapper('https://test.com/api/mcp');
    expect(wrapper.getApiRootUrl()).toBe('https://test.com/api');
  });

  it('getApiRootUrl should return original url if no /mcp suffix', () => {
    wrapper = new AuthMCPWrapper('https://test.com/api');
    expect(wrapper.getApiRootUrl()).toBe('https://test.com/api');
  });

  it('validateConfiguration should fail if okta domain is missing for okta provider', () => {
    const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => { });
    wrapper = new AuthMCPWrapper(mcpRemoteUrl);
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('OKTA_DOMAIN is required'));
    errorSpy.mockRestore();
  });

  it('getValidToken should return a stored, valid token without fetching', async () => {
    wrapper = new AuthMCPWrapper(mcpRemoteUrl, { silent: true });
    const mockTokens = {
      access_token: 'valid-stored-token',

      timestamp: Date.now(),
      expires_in: 3600
    };
    jest.spyOn(wrapper, 'loadTokens').mockReturnValue(mockTokens);
    const startAuthFlowSpy = jest.spyOn(wrapper, 'startAuthFlow');

    const token = await wrapper.getValidToken();

    expect(token).toBe('valid-stored-token');
    expect(wrapper.loadTokens).toHaveBeenCalled();
    expect(startAuthFlowSpy).not.toHaveBeenCalled();
  });

  it('getValidToken should start auth flow if token is expired', async () => {
    wrapper = new AuthMCPWrapper(mcpRemoteUrl, { silent: true });
    const mockTokens = {
      access_token: 'expired-token',

      timestamp: new Date('2020-01-01').getTime(), expires_in: 3600
    };
    jest.spyOn(wrapper, 'loadTokens').mockReturnValue(mockTokens);
    // This is the key fix: We need to mock the refresh function itself
    const refreshTokenSpy = jest.spyOn(wrapper, 'refreshTokenIfNeeded').mockResolvedValue(true);

    // Have loadTokens return a new token after the refresh
    jest.spyOn(wrapper, 'loadTokens')
      .mockReturnValueOnce(mockTokens) // First call returns expired
      .mockReturnValueOnce({ access_token: 'new-token' }); // Second call returns new

    const token = await wrapper.getValidToken();

    expect(token).toBe('new-token');
    expect(refreshTokenSpy).toHaveBeenCalled();
  });

  it('healthCheck should return true on success', async () => {
    wrapper = new AuthMCPWrapper(mcpRemoteUrl, { silent: true });
    global.fetch = jest.fn().mockResolvedValue({ ok: true });
    const result = await wrapper.healthCheck();
    expect(result).toBe(true);
  });

  it('runCLI("help") should display help text', async () => {
    wrapper = new AuthMCPWrapper(mcpRemoteUrl, { silent: true });
    const outputSpy = jest.spyOn(wrapper, 'output').mockImplementation(() => { });
    await wrapper.runCLI('help');
    expect(outputSpy).toHaveBeenCalledWith(expect.stringContaining('Available commands:'));
  });

  it('runCLI("debug") should display debug information', async () => {
    wrapper = new AuthMCPWrapper(mcpRemoteUrl, { silent: true });
    const outputSpy = jest.spyOn(wrapper, 'output').mockImplementation(() => { });
    fs.existsSync.mockReturnValue(true);
    fs.readFileSync.mockReturnValue(JSON.stringify({
      access_token: 'debug-token',
      expires_in: 3600,
      timestamp: Date.now()
    }));
    await wrapper.runCLI('debug');
    expect(outputSpy).toHaveBeenCalledWith(expect.stringContaining('Debug Information:'));
    expect(outputSpy).toHaveBeenCalledWith(expect.stringContaining('Token Status: ✅ Valid'));
  });
});

describe('Main function', () => {
  let originalArgv;

  beforeEach(() => {
    originalArgv = process.argv;
    jest.spyOn(console, 'log').mockImplementation(() => { });
    jest.spyOn(console, 'error').mockImplementation(() => { });
  });

  afterEach(() => {
    process.argv = originalArgv;
    jest.restoreAllMocks();
  });

  it('should show help if no arguments are provided', async () => {
    const { main } = require('../src/index');
    process.argv = ['node', 'index.js'];
    await main();
    expect(console.log).
      toHaveBeenCalledWith(
        expect.stringContaining('Usage: npx mcp-remote-with-okta')
      );
  });

  it('should call runCLI when a command is provided', async () => {
    const { main } = require('../src/index');
    const runCLISpy = jest.spyOn(AuthMCPWrapper.prototype, 'runCLI').mockResolvedValue();
    process.argv = ['node', 'index.js', 'https://some.url/mcp', 'status'];
    await main();
    expect(runCLISpy).toHaveBeenCalledWith('status');
  });

  it('should call launchMCP when no command is provided', async () => {
    const { main } = require('../src/index');
    const launchMCPSpy = jest.spyOn(AuthMCPWrapper.prototype, 'launchMCP').mockResolvedValue();
    process.argv = ['node', 'index.js', 'https://some.url/mcp'];
    await main();
    expect(launchMCPSpy).toHaveBeenCalled();
  });
});

describe('Error Handling and Edge Cases', () => {
  const mcpRemoteUrl = 'https://test.mcp.com/mcp';
  let wrapper;

  beforeEach(() => {
    jest.clearAllMocks();
    process.env.ADOBE_CLIENT_ID = 'test-id';
    wrapper = new AuthMCPWrapper(mcpRemoteUrl, { silent: false });
    jest.spyOn(console, 'log').mockImplementation(() => { });
    jest.spyOn(console, 'error').mockImplementation(() => { });
  });

  afterEach(() => {
    if (wrapper) wrapper.cleanup();
    jest.restoreAllMocks();
  });

  it('log should use console.error when in MCPMode', () => {
    wrapper.isMCPMode = true;
    wrapper.log('test message');
    expect(console.error).toHaveBeenCalledWith('test message');
  });

  it('debug should not log when debugMode is false', () => {
    wrapper.debugMode = false;
    wrapper.debug('test debug message');
    expect(console.log).not.toHaveBeenCalled();
  });

  it('loadTokens should handle invalid JSON gracefully', () => {
    fs.existsSync.mockReturnValue(true);
    fs.readFileSync.mockReturnValue('invalid json');
    const tokens = wrapper.loadTokens();
    expect(tokens).toBeNull();
  });

  it('saveTokens should handle write errors gracefully', () => {
    fs.writeFileSync.mockImplementation(() => { throw new Error('write error'); });
    wrapper.saveTokens({ access_token: '123' });
    expect(console.error).toHaveBeenCalledWith(expect.stringContaining('Failed to save tokens'));
  });

  it('openBrowser should use correct command for win32', () => {
    os.platform.mockReturnValue('win32');
    wrapper.openBrowser('url');
    expect(spawn).toHaveBeenCalledWith('start', ['url'], expect.any(Object));
  });

  it('handleCallback should reject on state mismatch', () => {
    const reject = jest.fn();
    const handlers = {};
    const req = {
      on: (event, cb) => { handlers[event] = cb; }
    };
    const res = { writeHead: jest.fn(), end: jest.fn() };
    const server = { close: jest.fn() };

    wrapper.handleCallback(req, res, 'correct-state', jest.fn(), reject, server);

    handlers.data(JSON.stringify({ state: 'wrong-state' }));
    handlers.end();

    expect(reject).toHaveBeenCalledWith(new Error('Invalid state parameter'));
  });

  it('healthCheck should return false on fetch error', async () => {
    global.fetch = jest.fn().mockRejectedValue(new Error('Network error'));
    const result = await wrapper.healthCheck();
    expect(result).toBe(false);
  });
});
