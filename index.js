#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const { URL } = require('url');
const { spawn } = require('child_process');
const os = require('os');
const crypto = require('crypto');

/**
 * Adobe Authentication and MCP Wrapper
 *
 * This script handles Adobe IMS authentication and launches the MCP remote server
 * with proper authentication headers. It can be used directly as an MCP server
 * command or run standalone for authentication management.
 */
class AdobeMCPWrapper {
  constructor(mcpRemoteUrl, options = {}) {
    this.configDir = path.join(os.homedir(), '.cursor');
    this.tokenFile = path.join(this.configDir, 'adobe-tokens.json');

    // Adobe IMS configuration using environment variables
    this.clientId = process.env.ADOBE_CLIENT_ID;
    this.clientSecret = process.env.ADOBE_CLIENT_SECRET;
    this.scope = process.env.ADOBE_SCOPE || 'AdobeID,openid';
    this.redirectUri = 'http://localhost:8080/callback';

    this.authUrl = 'https://ims-na1.adobelogin.com/ims/authorize/v2';
    this.tokenUrl = 'https://ims-na1.adobelogin.com/ims/token/v3';

    // MCP configuration
    this.mcpRemoteUrl = mcpRemoteUrl;
    this.mcpArgs = [
      'npx', 'mcp-remote@latest',
      this.mcpRemoteUrl,
      '--transport', 'http-first',
      '--debug',
    ];

    // Silent mode for MCP integration
    this.silent = options.silent || false;
    this.isMCPMode = options.isMCPMode || false;
  }

  // Output method that respects silent mode and routes to stderr in MCP mode
  output(message, forceStderr = false) {
    if (this.silent) return;

    if (this.isMCPMode || forceStderr) {
      console.error(message);
    } else {
      console.log(message);
    }
  }

  // Ensure config directory exists
  ensureConfigDir() {
    if (!fs.existsSync(this.configDir)) {
      fs.mkdirSync(this.configDir, { recursive: true });
    }
  }

  // Generate PKCE challenge
  static generatePKCE() {
    const codeVerifier = crypto.randomBytes(32).toString('base64url');
    const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
    return { codeVerifier, codeChallenge };
  }

  // Load stored tokens
  loadTokens() {
    try {
      if (fs.existsSync(this.tokenFile)) {
        const data = fs.readFileSync(this.tokenFile, 'utf8');
        return JSON.parse(data);
      }
    } catch (error) {
      this.output(`Failed to load stored tokens: ${error.message}`, true);
    }
    return null;
  }

  // Save tokens
  saveTokens(tokens) {
    this.ensureConfigDir();
    try {
      fs.writeFileSync(this.tokenFile, JSON.stringify({
        ...tokens,
        timestamp: Date.now(),
      }, null, 2));
      this.output('✅ Tokens saved successfully', true);
    } catch (error) {
      this.output(`❌ Failed to save tokens: ${error.message}`, true);
    }
  }

  // Check if token is expired
  static isTokenExpired(tokens) {
    if (!tokens || !tokens.timestamp) return true;

    const expiresIn = parseInt(tokens.expires_in, 10) || 86400; // Default 24 hours
    const expirationTime = tokens.timestamp + (expiresIn * 1000);
    const now = Date.now();

    // Consider token expired if it expires within the next 5 minutes
    return (expirationTime - now) < (5 * 60 * 1000);
  }

  // Start OAuth flow
  async startAuthFlow() {
    if (!this.clientId) {
      throw new Error('Client ID not found. Please add ADOBE_CLIENT_ID to your MCP config environment variables.');
    }

    if (!this.clientSecret) {
      throw new Error('Client secret not found. Please add ADOBE_CLIENT_SECRET to your MCP config environment variables.');
    }

    const { codeVerifier, codeChallenge } = AdobeMCPWrapper.generatePKCE();
    const state = crypto.randomBytes(16).toString('hex');

    const authParams = new URLSearchParams({
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      scope: this.scope,
      response_type: 'code',
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      state,
      response_mode: 'query',
    });

    const authUrlWithParams = `${this.authUrl}?${authParams.toString()}`;

    this.output('🚀 Starting Adobe authentication flow...', true);
    this.output('📱 Opening browser for authentication...', true);

    // Open browser
    this.openBrowser(authUrlWithParams);

    // Start local server to handle callback
    return new Promise((resolve, reject) => {
      const server = http.createServer(async (req, res) => {
        const url = new URL(req.url, 'http://localhost:8080');

        if (url.pathname === '/callback') {
          const code = url.searchParams.get('code');
          const returnedState = url.searchParams.get('state');
          const error = url.searchParams.get('error');

          if (error) {
            res.writeHead(400, { 'Content-Type': 'text/html' });
            res.end(`<h1>Authentication Error</h1><p>${error}</p>`);
            server.close();
            reject(new Error(`Authentication error: ${error}`));
            return;
          }

          if (returnedState !== state) {
            res.writeHead(400, { 'Content-Type': 'text/html' });
            res.end('<h1>Authentication Error</h1><p>Invalid state parameter</p>');
            server.close();
            reject(new Error('Invalid state parameter'));
            return;
          }

          if (code) {
            try {
              const tokens = await this.exchangeCodeForToken(code, codeVerifier);

              res.writeHead(200, { 'Content-Type': 'text/html' });
              res.end(`
                <h1>Authentication Successful!</h1>
                <p>You can now close this tab and return to your terminal.</p>
                <script>setTimeout(() => window.close(), 3000);</script>
              `);

              server.close();
              resolve(tokens);
            } catch (tokenError) {
              res.writeHead(500, { 'Content-Type': 'text/html' });
              res.end(`<h1>Token Exchange Error</h1><p>${tokenError.message}</p>`);
              server.close();
              reject(tokenError);
            }
          }
        } else {
          res.writeHead(404, { 'Content-Type': 'text/html' });
          res.end('<h1>Not Found</h1>');
        }
      });

      server.listen(8080, () => {
        this.output('🔗 Waiting for authentication callback on http://localhost:8080', true);
      });

      server.on('error', (serverError) => {
        reject(new Error(`Server error: ${serverError.message}`));
      });
    });
  }

  // Exchange authorization code for tokens
  async exchangeCodeForToken(code, codeVerifier) {
    const tokenData = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: this.clientId,
      client_secret: this.clientSecret,
      code,
      redirect_uri: this.redirectUri,
      code_verifier: codeVerifier,
    });

    return new Promise((resolve, reject) => {
      const postData = tokenData.toString();

      const options = {
        hostname: 'ims-na1.adobelogin.com',
        port: 443,
        path: '/ims/token/v3',
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(postData),
        },
      };

      const req = https.request(options, (res) => {
        let data = '';

        res.on('data', (chunk) => {
          data += chunk;
        });

        res.on('end', () => {
          try {
            const response = JSON.parse(data);

            if (res.statusCode === 200) {
              this.output('🎉 Successfully obtained access token!', true);
              resolve(response);
            } else {
              reject(new Error(`Token exchange failed: ${response.error_description || response.error || 'Unknown error'}`));
            }
          } catch (parseError) {
            reject(new Error(`Failed to parse token response: ${parseError.message}`));
          }
        });
      });

      req.on('error', (requestError) => {
        reject(new Error(`Request failed: ${requestError.message}`));
      });

      req.write(postData);
      req.end();
    });
  }

  // Open browser (cross-platform)
  openBrowser(url) {
    const platform = os.platform();
    let command;

    switch (platform) {
      case 'darwin':
        command = 'open';
        break;
      case 'win32':
        command = 'start';
        break;
      default:
        command = 'xdg-open';
    }

    try {
      spawn(command, [url], { detached: true, stdio: 'ignore' });
    } catch (error) {
      this.output(`Unable to open browser automatically. Please visit: ${url}`, true);
    }
  }

  // Get valid access token
  async getValidToken() {
    const storedTokens = this.loadTokens();

    if (storedTokens && !AdobeMCPWrapper.isTokenExpired(storedTokens)) {
      this.output('✅ Using valid stored token', true);
      return storedTokens.access_token;
    }

    this.output('🔄 Token expired or not found, initiating authentication...', true);

    try {
      const tokens = await this.startAuthFlow();
      this.saveTokens(tokens);
      return tokens.access_token;
    } catch (error) {
      this.output(`❌ Authentication failed: ${error.message}`, true);
      throw error;
    }
  }

  // Launch MCP remote with authentication
  async launchMCP() {
    try {
      this.output('🔐 Adobe MCP Wrapper starting...', true);
      // Check if required environment variables are available
      if (!this.clientId) {
        throw new Error('ADOBE_CLIENT_ID environment variable not found. Please check your MCP configuration.');
      }

      if (!this.clientSecret) {
        throw new Error('ADOBE_CLIENT_SECRET environment variable not found. Please check your MCP configuration.');
      }

      // Get valid access token
      const accessToken = await this.getValidToken();

      this.output('🚀 Launching MCP remote with authentication...', true);

      // Prepare command with authentication header
      const command = this.mcpArgs[0];
      const args = [
        ...this.mcpArgs.slice(1),
        '--header', `Authorization:Bearer ${accessToken}`,
      ];

      // Launch MCP remote process
      const mcpProcess = spawn(command, args, {
        stdio: 'inherit',
        env: {
          ...process.env,
          // Pass through any additional environment variables
        },
      });

      // Handle process events
      mcpProcess.on('error', (error) => {
        this.output(`❌ Failed to start MCP remote: ${error.message}`, true);
        process.exit(1);
      });

      mcpProcess.on('exit', (code, signal) => {
        if (signal) {
          this.output(`🛑 MCP remote terminated by signal: ${signal}`, true);
        } else {
          this.output(`🏁 MCP remote exited with code: ${code}`, true);
        }
        process.exit(code || 0);
      });
    } catch (error) {
      this.output(`❌ Error: ${error.message}`, true);
      process.exit(1);
    }
  }

  // CLI interface for standalone usage
  async runCLI(command) {
    this.output('🔐 Adobe Experience Cloud Authentication CLI\n');

    try {
      switch (command) {
        case 'authenticate': {
          const token = await this.getValidToken();
          this.output('\n🎉 Authentication completed successfully!');
          this.output(`🔑 Access Token: ${token.substring(0, 20)}...`);
          break;
        }

        case 'status': {
          const tokens = this.loadTokens();
          if (tokens) {
            const isExpired = AdobeMCPWrapper.isTokenExpired(tokens);
            this.output(`📊 Token Status: ${isExpired ? '❌ Expired' : '✅ Valid'}`);
            if (tokens.timestamp) {
              const expiresIn = parseInt(tokens.expires_in, 10) || 86400;
              const expirationTime = new Date(tokens.timestamp + (expiresIn * 1000));
              this.output(`⏰ Expires at: ${expirationTime.toLocaleString()}`);
            }
          } else {
            this.output('📊 Token Status: ❌ No token found');
          }
          break;
        }

        case 'token': {
          const validToken = await this.getValidToken();
          this.output(`🔑 Access Token: ${validToken}`);
          break;
        }

        case 'clear':
          if (fs.existsSync(this.tokenFile)) {
            fs.unlinkSync(this.tokenFile);
            this.output('🗑️ Stored tokens cleared');
          } else {
            this.output('ℹ️ No stored tokens to clear');
          }
          break;

        case 'mcp':
          // Launch in MCP mode
          this.isMCPMode = true;
          this.silent = true;
          await this.launchMCP();
          break;

        case 'help':
        default:
          this.output('📚 Available commands:');
          this.output('  authenticate - Authenticate and get token');
          this.output('  status       - Check token status');
          this.output('  token        - Display current valid token');
          this.output('  clear        - Clear stored tokens');
          this.output('  mcp          - Launch MCP remote with authentication');
          this.output('  help         - Show this help message');
          this.output('\n🔧 Usage:');
          this.output('  npx mcp-remote-with-okta <mcp-url> <command>');
          this.output('  npx mcp-remote-with-okta <mcp-url>  # Launch as MCP server');
          this.output('\n🔑 Environment Variables:');
          this.output('  ADOBE_CLIENT_ID     - Required: Client ID for Adobe IMS');
          this.output('  ADOBE_CLIENT_SECRET - Required: Client secret for Adobe IMS');
          this.output('  ADOBE_SCOPE         - Optional: OAuth scope (default: AdobeID,openid)');
          this.output('\n💡 Example MCP config:');
          this.output('  {');
          this.output('    "mcpServers": {');
          this.output('      "my-mcp-server": {');
          this.output('        "command": "node",');
          this.output('        "args": [');
          this.output('          "/path/to/mcp-adobe-auth-wrapper.js",');
          this.output('          "https://your-mcp-server.com/mcp"');
          this.output('        ],');
          this.output('        "env": {');
          this.output('          "ADOBE_CLIENT_ID": "your_client_id_here",');
          this.output('          "ADOBE_CLIENT_SECRET": "your_client_secret_here",');
          this.output('          "ADOBE_SCOPE": "AdobeID,openid"  // Optional: defaults to AdobeID,openid');
          this.output('        }');
          this.output('      }');
          this.output('    }');
          this.output('  }');
      }
    } catch (error) {
      this.output(`\n❌ Error: ${error.message}`, true);
      process.exit(1);
    }
  }
}

// Main execution logic
async function main() {
  const args = process.argv.slice(2);

  // First argument is always the MCP URL
  const mcpUrl = args[0];
  const command = args[1];

  // Check if we're being called as an MCP server (has URL but no command)
  const isDirectMCPCall = mcpUrl && !command;

  const wrapper = new AdobeMCPWrapper(mcpUrl, {
    silent: isDirectMCPCall,
    isMCPMode: isDirectMCPCall,
  });

  if (isDirectMCPCall) {
    // Called directly as MCP server - launch with authentication
    await wrapper.launchMCP();
  } else if (mcpUrl && command) {
    // Called with CLI commands
    await wrapper.runCLI(command);
  } else {
    // No URL provided or invalid usage
    console.log('Usage:');
    console.log('  npx mcp-remote-with-okta <mcp-url> <command>');
    console.log('  npx mcp-remote-with-okta <mcp-url>  # Launch as MCP server');
    console.log('');
    console.log('Commands: authenticate, status, token, clear, mcp, help');
    process.exit(1);
  }
}

// Run if called directly
if (require.main === module) {
  main().catch((error) => {
    console.error(`Fatal error: ${error.message}`);
    process.exit(1);
  });
}

module.exports = AdobeMCPWrapper;

