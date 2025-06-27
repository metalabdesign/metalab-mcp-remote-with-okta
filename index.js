#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const http = require('http');
const os = require('os');
const crypto = require('crypto');
const { spawn } = require('child_process');

/**
 * Adobe Authentication and MCP Wrapper
 * Handles Adobe IMS OAuth implicit flow with token management and auto-refresh
 */
class AdobeMCPWrapper {
  constructor(mcpRemoteUrl, options = {}) {
    this.configDir = path.join(os.homedir(), '.cursor');
    this.tokenFile = path.join(this.configDir, 'adobe-tokens.json');

    // Configuration
    this.clientId = process.env.ADOBE_CLIENT_ID;
    this.scope = process.env.ADOBE_SCOPE || 'AdobeID,openid';
    this.authMethod = process.env.ADOBE_AUTH_METHOD || 'jwt';
    this.imsEnvironment = process.env.ADOBE_IMS_ENV || 'prod';
    this.redirectUri = process.env.ADOBE_REDIRECT_URI || 'http://localhost:8080/callback';

    // Debug and auto-refresh
    this.debugMode = process.env.ADOBE_DEBUG === 'true'
      || process.env.DEBUG === 'adobe'
      || process.env.DEBUG === '*';
    this.autoRefresh = process.env.ADOBE_AUTO_REFRESH !== 'false';
    this.refreshThresholdMinutes = parseInt(process.env.ADOBE_REFRESH_THRESHOLD, 10) || 10;

    // MCP configuration
    this.mcpRemoteUrl = mcpRemoteUrl || 'https://spacecat.experiencecloud.live/api/v1/mcp';
    this.mcpArgs = [
      'npx',
      'mcp-remote@latest',
      this.mcpRemoteUrl,
      '--transport',
      'http-first',
      '--debug',
    ];

    // Options
    this.silent = options.silent || false;
    this.isMCPMode = options.isMCPMode || false;
    this.refreshTimer = null;

    this.validateConfiguration();
    this.debug(`Configuration loaded: ${this.getEnvironmentInfo().name} environment`);
  }

  /**
   * Environment configuration - consolidated from multiple methods
   */
  getEnvironmentInfo() {
    const envs = {
      prod: { name: 'Production', url: 'https://ims-na1.adobelogin.com/ims/authorize/v2' },
      production: {
        name: 'Production',
        url: 'https://ims-na1.adobelogin.com/ims/authorize/v2',
      },
      stage: { name: 'Stage', url: 'https://ims-na1-stg1.adobelogin.com/ims/authorize/v2' },
      stg: { name: 'Stage', url: 'https://ims-na1-stg1.adobelogin.com/ims/authorize/v2' },
      dev: {
        name: 'Development',
        url: 'https://ims-na1-dev.adobelogin.com/ims/authorize/v2',
      },
      development: {
        name: 'Development',
        url: 'https://ims-na1-dev.adobelogin.com/ims/authorize/v2',
      },
      qa: { name: 'QA/Test', url: 'https://ims-na1-qa.adobelogin.com/ims/authorize/v2' },
      test: { name: 'QA/Test', url: 'https://ims-na1-qa.adobelogin.com/ims/authorize/v2' },
    };
    return envs[this.imsEnvironment.toLowerCase()] || envs.prod;
  }

  /**
   * Gets the API root URL by removing the trailing '/mcp' segment.
   * @returns {String} The root URL for API calls.
   */
  getApiRootUrl() {
    if (this.mcpRemoteUrl.endsWith('/mcp')) {
      return this.mcpRemoteUrl.slice(0, -4);
    }
    return this.mcpRemoteUrl;
  }

  /**
   * Unified output method - consolidates debug() and output()
   */
  log(message, level = 'info') {
    if (this.silent) return;

    const isDebug = level === 'debug';
    if (isDebug && !this.debugMode) return;

    const prefix = isDebug ? `[${new Date().toISOString()}] [DEBUG]` : '';
    const output = isDebug ? `${prefix} ${message}` : message;

    if (this.isMCPMode || level === 'error') {
      console.error(output);
    } else {
      console.log(output);
    }
  }

  debug(message) {
    this.log(message, 'debug');
  }

  output(message) {
    this.log(message, 'info');
  }

  error(message) {
    this.log(message, 'error');
  }

  /**
   * Simplified configuration validation
   */
  validateConfiguration() {
    const errors = [];
    if (!this.clientId) errors.push('ADOBE_CLIENT_ID is required');
    if (this.authMethod && !['jwt', 'access_token'].includes(this.authMethod)) {
      errors.push('ADOBE_AUTH_METHOD must be "jwt" or "access_token"');
    }

    if (errors.length > 0) {
      this.error('❌ Configuration errors:');
      errors.forEach((error) => this.error(`   ${error}`));
      this.error('💡 Check your environment variables');
    }
  }

  ensureConfigDir() {
    if (!fs.existsSync(this.configDir)) {
      fs.mkdirSync(this.configDir, { recursive: true });
    }
  }

  /**
   * Token management - simplified
   */
  loadTokens() {
    try {
      if (fs.existsSync(this.tokenFile)) {
        const tokens = JSON.parse(fs.readFileSync(this.tokenFile, 'utf8'));
        this.debug(`Tokens loaded, expired: ${AdobeMCPWrapper.isTokenExpired(tokens)}`);
        return tokens;
      }
    } catch (error) {
      this.debug(`Token loading failed: ${error.message}`);
    }
    return null;
  }

  saveTokens(tokens) {
    this.ensureConfigDir();
    try {
      const tokenData = { ...tokens, timestamp: Date.now() };
      fs.writeFileSync(this.tokenFile, JSON.stringify(tokenData, null, 2));
      this.output('✅ Tokens saved successfully');
      if (this.autoRefresh) this.scheduleAutoRefresh(tokenData);
    } catch (error) {
      this.error(`❌ Failed to save tokens: ${error.message}`);
    }
  }

  scheduleAutoRefresh(tokens) {
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = null;
    }

    const expiresIn = parseInt(tokens.expires_in, 10) || 3600;
    const refreshThresholdMs = this.refreshThresholdMinutes * 60 * 1000;
    const timeUntilRefresh = (tokens.timestamp + (expiresIn * 1000))
      - refreshThresholdMs - Date.now();

    if (timeUntilRefresh > 0) {
      this.debug(`Auto-refresh scheduled in ${Math.round(timeUntilRefresh / 1000)}s`);
      this.refreshTimer = setTimeout(async () => {
        try {
          await this.refreshTokenIfNeeded();
        } catch (error) {
          this.error('⚠️ Auto-refresh failed, manual re-authentication may be required');
        }
      }, timeUntilRefresh);
    }
  }

  async refreshTokenIfNeeded() {
    const tokens = this.loadTokens();
    if (!tokens || AdobeMCPWrapper.isTokenExpired(tokens)) {
      const newTokens = await this.startAuthFlow();
      this.saveTokens(newTokens);
      return true;
    }
    return false;
  }

  cleanup() {
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = null;
      this.debug('Auto-refresh timer cleared');
    }
  }

  static isTokenExpired(tokens) {
    if (!tokens || !tokens.timestamp) return true;
    const expiresIn = parseInt(tokens.expires_in, 10) || 3600;
    const expirationTime = tokens.timestamp + (expiresIn * 1000);
    return (expirationTime - Date.now()) < (5 * 60 * 1000); // 5 min buffer
  }

  static handleError(req, res, reject, server) {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
    });
    req.on('end', () => {
      try {
        const data = JSON.parse(body);
        res.writeHead(400);
        res.end('Error received');
        server.close();
        reject(new Error(`Authentication error: ${data.error_description || data.error}`));
      } catch (error) {
        res.writeHead(500);
        res.end('Parse error');
        server.close();
        reject(new Error('Parse error'));
      }
    });
  }

  /**
   * OAuth flow - simplified HTML and server logic
   */
  async startAuthFlow() {
    if (!this.clientId) {
      throw new Error('Client ID not found. Please add ADOBE_CLIENT_ID to env variables.');
    }

    const state = crypto.randomBytes(16).toString('hex');
    const authParams = new URLSearchParams({
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      scope: this.scope,
      response_type: 'token',
      state,
      response_mode: 'fragment',
    });

    const authUrl = `${this.getEnvironmentInfo().url}?${authParams.toString()}`;
    this.output(`🚀 Starting Adobe OAuth (${this.getEnvironmentInfo().name})...`);
    this.openBrowser(authUrl);

    return new Promise((resolve, reject) => {
      const server = http.createServer((req, res) => {
        const url = new URL(req.url, 'http://localhost:8080');

        if (url.pathname === '/callback') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(`<!DOCTYPE html><html><head><title>Adobe Auth</title></head><body>
            <h1>Processing...</h1><p id="status">Reading response...</p>
            <script>
              const fragment = window.location.hash.substring(1);
              const params = new URLSearchParams(fragment);
              const token = params.get('access_token');
              const error = params.get('error');
              if (error) {
                const errorDesc = params.get('error_description') || error;
                document.getElementById('status').innerHTML =
                  '<h2 style="color:red">Error: ' + errorDesc + '</h2>';
                fetch('/error', {
                  method:'POST',
                  headers:{'Content-Type':'application/json'},
                  body:JSON.stringify({error: errorDesc})
                });
              } else if (token) {
                document.getElementById('status').innerHTML =
                  '<h2 style="color:green">Success! You can close this tab.</h2>';
                fetch('/success', {
                  method:'POST',
                  headers:{'Content-Type':'application/json'},
                  body:JSON.stringify({
                    access_token:token,
                    expires_in:params.get('expires_in'),
                    state:params.get('state'),
                  })
                });
              }
            </script></body></html>`);
        } else if (url.pathname === '/success') {
          this.handleCallback(req, res, state, resolve, reject, server);
        } else if (url.pathname === '/error') {
          AdobeMCPWrapper.handleError(req, res, reject, server);
        } else {
          res.writeHead(404);
          res.end('<h1>Not Found</h1>');
        }
      });

      server.listen(8080, () => this.output('🔗 Waiting for callback on localhost:8080'));
      server.on('error', (err) => reject(new Error(`Server error: ${err.message}`)));
    });
  }

  handleCallback(req, res, state, resolve, reject, server) {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
    });
    req.on('end', () => {
      try {
        const data = JSON.parse(body);
        if (data.state !== state) {
          res.writeHead(400);
          res.end('Invalid state');
          server.close();
          reject(new Error('Invalid state parameter'));
          return;
        }

        const tokens = {
          access_token: data.access_token,
          expires_in: data.expires_in || '3600',
          token_type: 'Bearer',
        };

        res.writeHead(200);
        res.end('OK');
        server.close();
        this.output('🎉 Successfully obtained access token!');
        resolve(tokens);
      } catch (error) {
        res.writeHead(500);
        res.end('Parse error');
        server.close();
        reject(new Error(`Parse error: ${error.message}`));
      }
    });
  }

  openBrowser(url) {
    const commands = { darwin: 'open', win32: 'start' };
    const command = commands[os.platform()] || 'xdg-open';
    try {
      spawn(command, [url], { detached: true, stdio: 'ignore' });
    } catch (error) {
      this.output(`Unable to open browser. Please visit: ${url}`);
    }
  }

  /**
   * Token retrieval - simplified
   */
  async getValidToken() {
    this.debug('🔍 Getting valid access token...');
    const storedTokens = this.loadTokens();

    if (storedTokens && !AdobeMCPWrapper.isTokenExpired(storedTokens)) {
      this.debug('✅ Using stored valid token');
      this.debug(`Token expires in: ${storedTokens.expires_in}s`);
      if (storedTokens.timestamp) {
        const expiresAt = new Date(
          storedTokens.timestamp + parseInt(storedTokens.expires_in, 10) * 1000,
        );
        this.debug(`Token expires at: ${expiresAt.toISOString()}`);
      }
      if (this.autoRefresh && !this.refreshTimer) {
        this.scheduleAutoRefresh(storedTokens);
      }
      return storedTokens.access_token;
    }

    this.debug('⚠️ No valid stored token found');

    // Try auto-refresh first if enabled
    if (this.autoRefresh && storedTokens) {
      this.debug('🔄 Attempting auto-refresh...');
      try {
        const refreshed = await this.refreshTokenIfNeeded();
        if (refreshed) {
          this.debug('✅ Auto-refresh successful');
          return this.loadTokens().access_token;
        }
      } catch (error) {
        this.debug(`❌ Auto-refresh failed: ${error.message}`);
      }
    }

    // Start new auth flow
    this.debug('🚀 Starting new authentication flow...');
    const tokens = await this.startAuthFlow();
    this.saveTokens(tokens);
    this.debug('✅ New tokens obtained and saved');
    return tokens.access_token;
  }

  /**
   * JWT exchange - simplified with retry logic
   */
  async exchangeForJWT(accessToken, attempt = 1) {
    const jwtUrl = `${this.getApiRootUrl()}/auth/login`;
    const maxRetries = 3;

    try {
      this.output(`🔄 Exchanging for JWT (${attempt}/${maxRetries})...`);
      this.debug(`JWT URL: ${jwtUrl}`);
      this.debug(`Access Token (first 20 chars): ${accessToken.substring(0, 20)}...`);
      this.debug(`Access Token length: ${accessToken.length}`);

      const requestBody = { accessToken };
      this.debug(`Request body: ${JSON.stringify(requestBody)}`);

      const response = await fetch(jwtUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'mcp-remote-with-okta/1.1.0',
        },
        body: JSON.stringify(requestBody),
      });

      this.debug(`Response status: ${response.status}`);
      if (response.headers && typeof response.headers.entries === 'function') {
        const responseHeaders = Object.fromEntries(response.headers.entries());
        this.debug(`Response headers: ${JSON.stringify(responseHeaders)}`);
      }

      if (!response.ok) {
        const errorBody = await response.text();
        this.debug(`Error response body: ${errorBody}`);
        // Enhanced error message with more context
        const errorMsg = `JWT exchange failed (${response.status}): ${errorBody}`;
        this.debug(`Full error: ${errorMsg}`);
        throw new Error(errorMsg);
      }

      const jwtResponse = await response.json();
      this.debug(`JWT response keys: ${Object.keys(jwtResponse).join(', ')}`);
      const jwtToken = jwtResponse.token
        || jwtResponse.jwt
        || jwtResponse.access_token
        || jwtResponse.sessionToken;

      if (!jwtToken) {
        this.debug(`JWT response: ${JSON.stringify(jwtResponse)}`);
        throw new Error('No JWT token in response');
      }

      this.debug(`JWT token (first 20 chars): ${jwtToken.substring(0, 20)}...`);
      this.output('✅ JWT token obtained');
      return jwtToken;
    } catch (error) {
      this.debug(`JWT exchange error: ${error.message}`);
      this.debug(`Error stack: ${error.stack}`);
      if (attempt < maxRetries) {
        const delay = 2 ** (attempt - 1) * 1000;
        this.output(`⏳ Retrying in ${delay}ms...`);
        return new Promise((resolve, reject) => {
          setTimeout(() => {
            this.exchangeForJWT(accessToken, attempt + 1).then(resolve).catch(reject);
          }, delay);
        });
      }
      throw error;
    }
  }

  async healthCheck() {
    try {
      const healthUrl = `${this.getApiRootUrl()}/health`;
      const headers = { 'User-Agent': 'mcp-remote-with-okta/1.1.0' };
      const response = await fetch(healthUrl, { method: 'HEAD', headers });
      const isHealthy = response.ok;
      this.output(isHealthy ? '✅ MCP server is healthy' : '⚠️ MCP server health check failed');
      return isHealthy;
    } catch (error) {
      this.output(`⚠️ Health check failed: ${error.message}`);
      return false;
    }
  }

  async getValidJWT() {
    const accessToken = await this.getValidToken();
    return this.exchangeForJWT(accessToken);
  }

  /**
   * MCP launch - simplified
   */
  async launchMCP() {
    this.output(`🔐 Adobe MCP Wrapper starting (${this.getEnvironmentInfo().name})...`);

    if (!this.clientId) {
      throw new Error('ADOBE_CLIENT_ID environment variable not found');
    }

    let authToken;
    if (this.authMethod === 'access_token') {
      this.output('🔑 Using access token authentication...');
      authToken = await this.getValidToken();
    } else {
      this.output('🔄 Using JWT authentication...');
      authToken = await this.getValidJWT();
    }

    this.output('🚀 Launching MCP remote...');

    const mcpProcess = spawn(this.mcpArgs[0], [
      ...this.mcpArgs.slice(1),
      '--header', `Authorization:Bearer ${authToken}`,
    ], { stdio: 'inherit', env: process.env });

    mcpProcess.on('error', (error) => {
      this.error(`❌ Failed to start MCP: ${error.message}`);
      process.exit(1);
    });

    mcpProcess.on('exit', (code, signal) => {
      this.output(signal ? `🛑 Terminated by ${signal}` : `🏁 Exited with code ${code}`);
      process.exit(code || 0);
    });
  }

  /**
   * CLI interface - simplified
   */
  async runCLI(command) {
    this.output('🔐 Adobe Experience Cloud Authentication CLI\n');

    const commands = {
      authenticate: async () => {
        const token = await this.getValidToken();
        this.output(`\n🎉 Authentication completed!\n🔑 Token: ${token.substring(0, 20)}...`);
      },
      status: () => {
        this.output(`🌐 Environment: ${this.getEnvironmentInfo().name}`);
        const tokens = this.loadTokens();
        if (tokens) {
          const isExpired = AdobeMCPWrapper.isTokenExpired(tokens);
          this.output(`📊 Token Status: ${isExpired ? '❌ Expired' : '✅ Valid'}`);
          if (tokens.timestamp) {
            const expiresIn = parseInt(tokens.expires_in, 10) || 3600;
            const expiration = new Date(tokens.timestamp + (expiresIn * 1000));
            this.output(`⏰ Expires: ${expiration.toLocaleString()}`);
          }
        } else {
          this.output('📊 Token Status: ❌ No tokens found');
        }
      },
      token: async () => {
        try {
          const token = await this.getValidToken();
          this.output(`\n🔑 Current Token: ${token}`);
        } catch (error) {
          this.output('❌ No valid token available');
        }
      },
      clear: () => {
        try {
          if (fs.existsSync(this.tokenFile)) {
            fs.unlinkSync(this.tokenFile);
            this.output('🗑️ Tokens cleared');
          } else {
            this.output('ℹ️ No stored tokens to clear');
          }
        } catch (error) {
          this.output(`❌ Error clearing tokens: ${error.message}`);
        }
      },
      help: () => {
        this.output(`
Available commands:
  authenticate - Authenticate and get token
  status       - Check token status
  token        - Display current token
  clear        - Clear stored tokens
  debug        - Debug authentication and JWT exchange
  help         - Show this help
        `);
      },
      debug: async () => {
        this.output('🔍 Debug Information:');
        this.output(`🌐 Environment: ${this.getEnvironmentInfo().name}`);
        this.output(`🔗 MCP URL: ${this.mcpRemoteUrl}`);
        const clientId = this.clientId ? `${this.clientId.substring(0, 10)}...` : 'Not set';
        this.output(`🔑 Client ID: ${clientId}`);
        this.output(`🎯 Auth Method: ${this.authMethod}`);
        const tokens = this.loadTokens();
        if (tokens) {
          const isExpired = AdobeMCPWrapper.isTokenExpired(tokens);
          this.output(`📊 Token Status: ${isExpired ? '❌ Expired' : '✅ Valid'}`);
          this.output(`🔐 Access Token (first 20): ${tokens.access_token.substring(0, 20)}...`);
          this.output(`⏰ Expires In: ${tokens.expires_in}s`);
          if (tokens.timestamp) {
            const expiresAt = new Date(
              tokens.timestamp + (parseInt(tokens.expires_in, 10) * 1000),
            );
            this.output(`📅 Expires At: ${expiresAt.toLocaleString()}`);
          }
          // Test JWT exchange
          this.output('\n🧪 Testing JWT Exchange...');
          try {
            const jwt = await this.exchangeForJWT(tokens.access_token);
            this.output(`✅ JWT Exchange Success: ${jwt.substring(0, 20)}...`);
          } catch (error) {
            this.output(`❌ JWT Exchange Failed: ${error.message}`);
          }
        } else {
          this.output('📊 Token Status: ❌ No tokens found');
        }
      },
    };

    try {
      const handler = commands[command];
      if (handler) {
        await handler();
      } else {
        this.output('Unknown command. Use "help" for available commands.');
      }
    } catch (error) {
      this.error(`❌ Error: ${error.message}`);
      process.exit(1);
    }
  }
}

// Main function - simplified
async function main() {
  const args = process.argv.slice(2);
  const isMCPMode = !process.stdin.isTTY || process.env.MCP_MODE === 'true';

  if (args.length === 0) {
    console.log(`
Adobe MCP Remote Wrapper v1.1.0

Usage: npx mcp-remote-with-okta <mcp-url> [command]

Commands: authenticate, status, token, clear, debug, help

Environment Variables:
  ADOBE_CLIENT_ID          - Adobe IMS Client ID (required)
  ADOBE_SCOPE              - OAuth scope (default: AdobeID,openid)
  ADOBE_AUTH_METHOD        - jwt or access_token (default: jwt)
  ADOBE_IMS_ENV            - prod, stage, dev (default: prod)
  ADOBE_DEBUG              - Enable debug mode (default: false)
  ADOBE_AUTO_REFRESH       - Enable auto-refresh (default: true)
  ADOBE_REFRESH_THRESHOLD  - Refresh threshold in minutes (default: 10)

Examples:
  npx mcp-remote-with-okta https://my-server.com/mcp
  ADOBE_DEBUG=true npx mcp-remote-with-okta https://my-server.com/mcp status
    `);
    return;
  }

  const wrapper = new AdobeMCPWrapper(args[0], { isMCPMode });

  // Cleanup handlers
  const cleanup = () => {
    wrapper.cleanup();
    process.exit(0);
  };
  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);
  process.on('exit', cleanup);

  try {
    if (args[1]) {
      await wrapper.runCLI(args[1]);
    } else {
      await wrapper.launchMCP();
    }
  } catch (error) {
    console.error('Error:', error.message);
    wrapper.cleanup();
    process.exit(1);
  }
}

// Error handling
process.on('unhandledRejection', (reason) => {
  console.error('Unhandled Rejection:', reason);
  process.exit(1);
});

if (require.main === module) {
  main().catch((error) => {
    console.error('Fatal error:', error.message);
    process.exit(1);
  });
}

module.exports = AdobeMCPWrapper;
module.exports.main = main;
