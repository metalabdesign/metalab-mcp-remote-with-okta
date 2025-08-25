#!/usr/bin/env node
/* eslint-disable max-len */
const fs = require('fs');
const path = require('path');
const http = require('http');
const os = require('os');
const crypto = require('crypto');
const { spawn, exec } = require('child_process');
const net = require('net');

async function isPortTaken(port, host = '0.0.0.0') {
  return new Promise((resolve) => {
    const tester = net
      .createServer()
      .once('error', (err) => {
        if (err.code === 'EADDRINUSE') {
          resolve(true);
        } else {
          resolve(false); // Some other error
        }
      })
      .once('listening', () => {
        tester.close();
        resolve(false);
      })
      .listen(port, host);
  });
}

class OktaAuthStrategy {
  constructor(config) {
    this.config = config;
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
    this.config.output('✅ Using Okta access token as JWT');
    return accessToken;
  }
}

/**
 * Generic Authentication and MCP Wrapper
 * Handles OAuth implicit flow with token management and auto-refresh
 */
class AuthMCPWrapper {
  constructor(mcpRemoteUrl, options = {}) {
    this.configDir = path.join(os.homedir(), '.metalab');
    this.tokenFile = path.join(this.configDir, 'okta-token.json');
    this.loginLockFile = path.join(this.configDir, 'okta-login.lock');

    // Configuration
    this.clientId = process.env.OKTA_CLIENT_ID;
    this.scope = process.env.OKTA_SCOPE || 'openid profile email';
    this.oktaDomain = process.env.OKTA_DOMAIN;
    this.mcpTokenUri = process.env.MCP_TOKEN_URI || 'http://localhost:8000/token';

    // Debug and auto-refresh
    this.debugMode = process.env.DEBUG_MODE === 'true';
    this.autoRefresh = process.env.AUTO_REFRESH !== 'false';
    this.refreshThresholdMinutes = parseInt(process.env.REFRESH_THRESHOLD, 10) || 10;

    // MCP configuration
    this.mcpRemoteUrl = mcpRemoteUrl;
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

    this.authStrategy = new OktaAuthStrategy(this);

    this.validateConfiguration();
    this.debug(`Okta Domain: ${this.oktaDomain}`);
    this.debug(`Client ID: ${this.clientId}`);
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
   * Unified output method
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
   * Validates configuration based on the selected auth provider
   */
  validateConfiguration() {
    const errors = [];
    if (!this.clientId) {
      errors.push('OKTA_CLIENT_ID is required');
    }

    if (!this.oktaDomain) {
      errors.push('OKTA_DOMAIN is required');
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
   * Token management
   */
  loadTokens() {
    try {
      if (fs.existsSync(this.tokenFile)) {
        const tokens = JSON.parse(fs.readFileSync(this.tokenFile, 'utf8'));
        this.debug(`Tokens loaded, expired: ${AuthMCPWrapper.isTokenExpired(tokens)}`);
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
    if (!tokens || AuthMCPWrapper.isTokenExpired(tokens)) {
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

  // ---- Cross-process lock helpers ----
  _lockPath() {
    return this.loginLockFile;
  }

  /**
   * Returns true if the login lock file is fresh (i.e. within the maxAgeMs time range).
   * @param {number} maxAgeMs - The maximum age of the lock file in milliseconds.
   * @returns {boolean} true if the lock file is fresh, false otherwise.
   */
  _lockFresh(maxAgeMs = 5_000) {
    try {
      if (!fs.existsSync(this._lockPath())) return false;
      const stat = fs.statSync(this._lockPath());
      return Date.now() - stat.mtimeMs < maxAgeMs;
    } catch {
      return false;
    }
  }

  /**
   * Write the current timestamp to the lock file. This is used to prevent concurrent login flows.
   * Ignores any errors that occur while writing the lock file.
   */
  _writeLock() {
    try {
      this.ensureConfigDir();
      fs.writeFileSync(this._lockPath(), String(Date.now()));
    } catch {
      // ignore
    }
  }

  _clearLock() {
    try {
      if (fs.existsSync(this._lockPath())) fs.unlinkSync(this._lockPath());
    } catch {
      // ignore
    }
  }

  /**
   * OAuth flow
   */
  async startAuthFlow() {
    if (!this.clientId) {
      throw new Error('Client ID not found. Please set OKTA_CLIENT_ID.');
    }

    const state = crypto.randomBytes(16).toString('hex');
    const authUrl = this.authStrategy.getAuthUrl(state);

    if (this._lockFresh()) {
      return new Promise((res) => {
        res(null);
      });
    }

    this.output('🚀 Starting Okta OAuth flow...');

    this.openBrowser(authUrl);
    this._writeLock();

    const taken = await isPortTaken(8080);

    if (taken) {
      return new Promise((res) => {
        res(null);
      });
    }

    return new Promise((resolve, reject) => {
      const server = http.createServer((req, res) => {
        const url = new URL(req.url, 'http://localhost:8080');

        if (url.pathname === '/callback') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(`<!DOCTYPE html><html><head><title>Auth Callback</title></head><body>
            <h1>Processing...</h1><p id="status">Reading response...</p>
            <script>
              const urlParams = new URLSearchParams(window.location.search);
              const code = urlParams.get('code');
              const error = urlParams.get('error');

              if (error) {
                const errorDesc = urlParams.get('error_description') || error;
                document.getElementById('status').innerHTML =
                  '<h2 style="color:red">Error: ' + errorDesc + '</h2>';
                fetch('/error', {
                  method:'POST',
                  headers:{'Content-Type':'application/json'},
                  body:JSON.stringify({error: errorDesc})
                });
              } else if (code) {
                document.getElementById('status').innerHTML = 'Exchanging code for JWT token...';

                // First, fetch JWT token from localhost:3000/token
                fetch(\`${this.mcpTokenUri}?code=\${code}\`, {
                  method: 'GET',
                  headers: {
                    'Content-Type': 'application/json'
                  }
                })
                .then(response => {
                  if (!response.ok) {
                    throw new Error('Failed to retrieve JWT token: ' + response.statusText);
                  }
                  return response.json();
                })
                .then(data => {
                  document.getElementById('status').innerHTML = 'JWT token retrieved, completing authentication...';
                  console.log(data);
                  // Then POST to /success with the JWT token
                  return fetch('/success', {
                    method:'POST',
                    headers:{'Content-Type':'application/json'},
                    body:JSON.stringify({
                      ...data,
                      state: urlParams.get('state'),
                    })
                  });
                })
                .then(() => {
                  document.getElementById('status').innerHTML =
                    '<h2 style="color:green">Success! You can close this tab.</h2>';
                })
                .catch(error => {
                  console.error('Error:', error);
                  document.getElementById('status').innerHTML =
                    '<h2 style="color:red">Error: ' + error.message + '</h2>';
                  fetch('/error', {
                    method:'POST',
                    headers:{'Content-Type':'application/json'},
                    body:JSON.stringify({error: error.message})
                  });
                });
              } else {
                document.getElementById('status').innerHTML =
                  '<h2 style="color:red">Error: No authorization code received</h2>';
              }
            </script></body></html>`);
        } else if (url.pathname === '/success') {
          this.handleCallback(req, res, state, resolve, reject, server);
        } else if (url.pathname === '/error') {
          AuthMCPWrapper.handleError(req, res, reject, server);
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
    this.debug('Calling success callback');
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
    });
    req.on('end', () => {
      try {
        const data = JSON.parse(body);
        this.debug(`new Debug: ${body}`);
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
   * Token retrieval
   */
  async getValidToken() {
    this.debug('🔍 Getting valid access token...');
    const storedTokens = this.loadTokens();

    if (storedTokens && !AuthMCPWrapper.isTokenExpired(storedTokens)) {
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
    this.debug('✅ New tokens obtained and saved');

    if (tokens) {
      this.saveTokens(tokens);
      return tokens.access_token;
    }

    return null;
  }

  /**
   * JWT exchange
   */
  async exchangeForJWT(accessToken) {
    return this.authStrategy.exchangeForJWT(accessToken);
  }

  async healthCheck() {
    try {
      const healthUrl = `${this.getApiRootUrl()}/health`;
      const headers = { 'User-Agent': 'mcp-remote-with-okta/1.2.0' };
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
   * MCP launch
   */
  async launchMCP() {
    this.output('🔐 Okta MCP Wrapper starting...');

    if (!this.clientId) {
      throw new Error('OKTA_CLIENT_ID environment variable not found');
    }

    const authToken = await this.getValidToken();

    if (!authToken) {
      throw new Error('Waiting for authentication');
    }

    this.output('🚀 Launching MCP remote...');

    const mcpProcess = spawn(this.mcpArgs[0], [
      ...this.mcpArgs.slice(1),
      '--header', `Authorization: Bearer ${authToken}`,
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
   * CLI interface
   */
  async runCLI(command) {
    this.output('🔐 Okta Authentication CLI\n');

    const commands = {
      authenticate: async () => {
        const token = await this.getValidToken();
        this.output(`\n🎉 Authentication completed!\n🔑 Token: ${token.substring(0, 20)}...`);
      },
      status: () => {
        const tokens = this.loadTokens();
        if (tokens) {
          const isExpired = AuthMCPWrapper.isTokenExpired(tokens);
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
        this.output(`🔗 MCP URL: ${this.mcpRemoteUrl}`);
        const clientId = this.clientId ? `${this.clientId.substring(0, 10)}...` : 'Not set';
        this.output(`🔑 Client ID: ${clientId}`);
        const tokens = this.loadTokens();
        if (tokens) {
          const isExpired = AuthMCPWrapper.isTokenExpired(tokens);
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

// Main function
async function main() {
  const args = process.argv.slice(2);
  const isMCPMode = !process.stdin.isTTY || process.env.MCP_MODE === 'true';

  const mcpRemoteUri = args[0] || process.env.MCP_REMOTE_URI;

  if (args.includes('--help') || !mcpRemoteUri || !mcpRemoteUri.endsWith('/mcp')) {
    console.log(`
MCP Remote Wrapper v1.2.0

Usage: npx mcp-remote-with-okta <mcp-url> [command]

Commands: authenticate, status, token, clear, debug, help

Environment Variables:
  OKTA_CLIENT_ID           - Okta Client ID (required for okta)
  OKTA_DOMAIN              - Okta domain (e.g., dev-12345.okta.com)
  OKTA_SCOPE               - OAuth scope for Okta

  --- General ---
  AUTH_METHOD              - jwt or access_token (default: jwt)
  DEBUG_MODE               - Enable debug mode (default: false)
  AUTO_REFRESH             - Enable auto-refresh (default: true)
  REFRESH_THRESHOLD        - Refresh threshold in minutes (default: 10)
    `);
    return;
  }


  const wrapper = new AuthMCPWrapper(mcpRemoteUri, { isMCPMode });

  const cleanup = () => {
    wrapper.cleanup();
    process.exit(0);
  };
  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);
  process.on('exit', cleanup);

  try {
    if (process.env.NODE_ENV !== 'test') {
      // Attempt to ensure port 8080 is free
      await kill();
    }

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

module.exports = AuthMCPWrapper;
module.exports.main = main;
module.exports.OktaAuthStrategy = OktaAuthStrategy;

// ----- Process management helpers -----
function run(cmd) {
  return new Promise((resolve, reject) => {
    exec(cmd,
      { windowsHide: true, maxBuffer: 1024 * 1024 },
      (err, stdout, stderr) => {
        if (err || stderr) return reject(new Error(stderr || err.message));
        resolve(stdout);
      });
  });
}

async function getProcessIdsUnix(port) {
  try {
    const out = await run(`lsof -nP -i :${port} -t`);
    return out
      .split(/\r?\n/)
      .map(s => s.trim())
      .filter(Boolean)
      .map(Number)
      .filter(n => !Number.isNaN(n));
  } catch {
    return [];
  }
}

async function getProcessIdsWindows(port) {
  try {
    const out = await run(`netstat -ano | findstr :${port}`);
    const lines = out.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    const pids = new Set();

    for (const line of lines) {
      const cols = line.split(/\s+/);
      if (cols.length < 4) continue;

      const proto = (cols[0] || '').toUpperCase();
      const local = cols[1] || '';
      const foreign = cols[2] || '';
      const pidStr = cols[cols.length - 1] || '';

      const isPortMatch =
        local.endsWith(`:${port}`) || foreign.endsWith(`:${port}`);

      if ((proto === 'TCP' || proto === 'UDP') && isPortMatch) {
        const pid = Number(pidStr);

        if (!Number.isNaN(pid)) {
          pids.add(pid);
        }
      }
    }

    return [...pids];
  } catch {
    return [];
  }
}

async function getPids(port) {
  if (os.platform() === "win32") {
    return getProcessIdsWindows(port);
  }

  return getProcessIdsUnix(port);
}

function sleep(ms) {
  return new Promise(res => {
    setTimeout(res, ms);
  });
}

async function killProcessIds(pids, opts = { force: false }) {
  const selfPid = process.pid;
  const unique = [...new Set(pids)].filter(pid => pid && pid !== selfPid);

  if (unique.length === 0) {
    // No processes found on port
    return;
  }

  if (!opts.force) {
    for (const pid of unique) {
      try {
        process.kill(pid, "SIGTERM");
      } catch (e) {
        // Could not SIGTERM PID
      }
    }

    // Wait a moment for graceful shutdown
    await sleep(1500);
  }

  // Check which are still alive
  const stillAlive = unique.filter(pid => {
    try {
      process.kill(pid, 0);
      return true;
    } catch {
      return false;
    }
  });

  if (stillAlive.length === 0) {
    // All processes exited gracefully
    return;
  }

  // Hard kill remaining
  if (os.platform() === "win32") {
    for (const pid of stillAlive) {
      try {
        await run(`taskkill /F /PID ${pid}`);
      } catch (e) {
        // Failed to force-kill PID
      }
    }
  } else {
    for (const pid of stillAlive) {
      try {
        process.kill(pid, "SIGKILL");
      } catch (e) {
        // Failed to SIGKILL PID
      }
    }
  }
}

async function kill() {
  try {
    const pids = await getPids(8080);
    await killProcessIds(pids, { force: false });
  } catch (e) {
    console.error(`❌ Error: ${e.message}`);
    process.exit(1);
  }
}
