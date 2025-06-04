#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const http = require('http');
const { URL } = require('url');
const { spawn } = require('child_process');
const os = require('os');
const crypto = require('crypto');

/**
 * Adobe Authentication and MCP Wrapper
 *
 * This script handles Adobe IMS authentication using implicit grant flow
 * and launches the MCP remote server with proper authentication headers.
 * It can be used directly as an MCP server command or run standalone for authentication management.
 */
class AdobeMCPWrapper {
  constructor(mcpRemoteUrl, options = {}) {
    this.configDir = path.join(os.homedir(), '.cursor');
    this.tokenFile = path.join(this.configDir, 'adobe-tokens.json');

    // Adobe IMS configuration using environment variables
    this.clientId = process.env.ADOBE_CLIENT_ID;
    this.scope = process.env.ADOBE_SCOPE || 'AdobeID,openid';
    this.redirectUri = 'http://localhost:8080/callback';

    this.authUrl = 'https://ims-na1.adobelogin.com/ims/authorize/v2';

    // MCP configuration
    this.mcpRemoteUrl = mcpRemoteUrl || 'https://spacecat.experiencecloud.live/api/v1/mcp';
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

    const expiresIn = parseInt(tokens.expires_in, 10) || 3600; // Default 1 hour for implicit flow
    const expirationTime = tokens.timestamp + (expiresIn * 1000);
    const now = Date.now();

    // Consider token expired if it expires within the next 5 minutes
    return (expirationTime - now) < (5 * 60 * 1000);
  }

  // Start OAuth implicit flow
  async startAuthFlow() {
    if (!this.clientId) {
      throw new Error('Client ID not found. Please add ADOBE_CLIENT_ID to your MCP config environment variables.');
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

    const authUrlWithParams = `${this.authUrl}?${authParams.toString()}`;

    this.output('🚀 Starting Adobe implicit grant authentication flow...', true);
    this.output('📱 Opening browser for user authentication...', true);

    // Open browser
    this.openBrowser(authUrlWithParams);

    // Start local server to handle callback
    return new Promise((resolve, reject) => {
      const server = http.createServer(async (req, res) => {
        const url = new URL(req.url, 'http://localhost:8080');

        if (url.pathname === '/callback') {
          // For implicit flow, we need to serve HTML that can read the fragment
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(`
            <!DOCTYPE html>
            <html>
            <head>
              <title>Adobe Authentication</title>
            </head>
            <body>
              <h1>Processing Authentication...</h1>
              <p id="status">Reading authentication response...</p>
              <script>
                function parseFragment() {
                  const fragment = window.location.hash.substring(1);
                  const params = new URLSearchParams(fragment);
                  
                  const accessToken = params.get('access_token');
                  const expiresIn = params.get('expires_in');
                  const state = params.get('state');
                  const error = params.get('error');
                  const errorDescription = params.get('error_description');
                  
                  if (error) {
                    document.getElementById('status').innerHTML = 
                      '<h2 style="color: red;">Authentication Error</h2><p>' + 
                      (errorDescription || error) + '</p>';
                    
                    // Send error to server
                    fetch('/error', {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({ error: error, error_description: errorDescription })
                    });
                    return;
                  }
                  
                  if (accessToken) {
                    document.getElementById('status').innerHTML = 
                      '<h2 style="color: green;">Authentication Successful!</h2>' +
                      '<p>You can now close this tab and return to your terminal.</p>';
                    
                    // Send success to server
                    fetch('/success', {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({ 
                        access_token: accessToken, 
                        expires_in: expiresIn,
                        state: state
                      })
                    }).then(() => {
                      setTimeout(() => window.close(), 3000);
                    });
                  } else {
                    document.getElementById('status').innerHTML = 
                      '<h2 style="color: red;">Authentication Error</h2>' +
                      '<p>No access token received</p>';
                  }
                }
                
                // Parse fragment when page loads
                parseFragment();
              </script>
            </body>
            </html>
          `);
        } else if (url.pathname === '/success') {
          // Handle success callback from JavaScript
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

              this.output('🎉 Successfully obtained access token via implicit flow!', true);
              resolve(tokens);
            } catch (parseError) {
              res.writeHead(500);
              res.end('Parse error');
              server.close();
              reject(new Error(`Failed to parse response: ${parseError.message}`));
            }
          });
        } else if (url.pathname === '/error') {
          // Handle error callback from JavaScript
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
            } catch (parseError) {
              res.writeHead(500);
              res.end('Parse error');
              server.close();
              reject(new Error('Failed to parse error response'));
            }
          });
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
      this.output('🔐 Adobe MCP Wrapper (Implicit Flow) starting...', true);
      // Check if required environment variables are available
      if (!this.clientId) {
        throw new Error('ADOBE_CLIENT_ID environment variable not found. Please check your MCP configuration.');
      }

      // Get valid access token
      const accessToken = await this.getValidToken();

      this.output('🚀 Launching MCP remote with implicit grant authentication...', true);

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
    this.output('🔐 Adobe Experience Cloud User Authentication CLI (Implicit Flow)\n');

    try {
      switch (command) {
        case 'authenticate': {
          const token = await this.getValidToken();
          this.output('\n🎉 User authentication completed successfully!');
          this.output(`🔑 Access Token: ${token.substring(0, 20)}...`);
          break;
        }

        case 'status': {
          const tokens = this.loadTokens();
          if (tokens) {
            const isExpired = AdobeMCPWrapper.isTokenExpired(tokens);
            this.output(`📊 Token Status: ${isExpired ? '❌ Expired' : '✅ Valid'}`);
            if (tokens.timestamp) {
              const expiresIn = parseInt(tokens.expires_in, 10) || 3600;
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
          this.output('  authenticate - Authenticate user and get token');
          this.output('  status       - Check token status');
          this.output('  token        - Display current valid token');
          this.output('  clear        - Clear stored tokens');
          this.output('  mcp          - Launch MCP remote with authentication');
          this.output('  help         - Show this help message');
          this.output('\n🔧 Usage:');
          this.output('  npx mcp-remote-with-okta <mcp-url> <command>');
          this.output('  npx mcp-remote-with-okta <mcp-url>  # Launch as MCP server');
          this.output('\n🔑 Environment Variables:');
          this.output('  ADOBE_CLIENT_ID     - Required: Client ID for Adobe IMS (Implicit Grant)');
          this.output('  ADOBE_SCOPE         - Optional: OAuth scope (default: AdobeID,openid)');
          this.output('\n💡 Example MCP config (Implicit Grant):');
          this.output('  {');
          this.output('    "mcpServers": {');
          this.output('      "my-mcp-server": {');
          this.output('        "command": "npx",');
          this.output('        "args": [');
          this.output('          "mcp-remote-with-okta",');
          this.output('          "https://your-mcp-server.com/mcp"');
          this.output('        ],');
          this.output('        "env": {');
          this.output('          "ADOBE_CLIENT_ID": "your_client_id_here",');
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
