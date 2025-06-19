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
    this.authMethod = process.env.ADOBE_AUTH_METHOD || 'jwt'; // 'jwt' or 'access_token'
    this.imsEnvironment = process.env.ADOBE_IMS_ENV || 'prod'; // 'prod' or 'stage'
    this.redirectUri = 'http://localhost:8080/callback';

    // Set IMS auth URL based on environment
    this.authUrl = this.getImsAuthUrl();

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

  // Get IMS auth URL based on environment
  getImsAuthUrl() {
    switch (this.imsEnvironment.toLowerCase()) {
    case 'stage':
    case 'stg':
      return 'https://ims-na1-stg1.adobelogin.com/ims/authorize/v2';
    case 'dev':
    case 'development':
      return 'https://ims-na1-dev.adobelogin.com/ims/authorize/v2';
    case 'qa':
    case 'test':
      return 'https://ims-na1-qa.adobelogin.com/ims/authorize/v2';
    case 'prod':
    case 'production':
    default:
      return 'https://ims-na1.adobelogin.com/ims/authorize/v2';
    }
  }

  // Get IMS environment display name
  getImsEnvironmentName() {
    switch (this.imsEnvironment.toLowerCase()) {
    case 'stage':
    case 'stg':
      return 'Stage';
    case 'dev':
    case 'development':
      return 'Development';
    case 'qa':
    case 'test':
      return 'QA/Test';
    case 'prod':
    case 'production':
    default:
      return 'Production';
    }
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

  // Check if JWT token is expired
  static isJWTExpired(tokens) {
    if (!tokens || !tokens.jwt_token || !tokens.jwt_timestamp) return true;

    const jwtExpiresIn = parseInt(tokens.jwt_expires_in, 10) || 3600; // Default 1 hour
    const jwtExpirationTime = tokens.jwt_timestamp + (jwtExpiresIn * 1000);
    const now = Date.now();

    // Consider JWT token expired if it expires within the next 5 minutes
    return (jwtExpirationTime - now) < (5 * 60 * 1000);
  }

  // Exchange access token for JWT token
  async exchangeForJWT(accessToken) {
    return new Promise((resolve, reject) => {
      try {
        // Extract base URL from mcpRemoteUrl
        const mcpUrl = new URL(this.mcpRemoteUrl);
        const jwtEndpoint = `${mcpUrl.origin}/api/v1/auth/login`;

        this.output('🔄 Exchanging access token for JWT...', true);
        this.output(`📍 JWT endpoint: ${jwtEndpoint}`, true);
        this.output(`🔑 Access token (first 20 chars): ${accessToken.substring(0, 20)}...`, true);

        // Decode and display JWT payload for debugging
        try {
          const [header, payload] = accessToken.split('.');
          const decodedHeader = JSON.parse(Buffer.from(header, 'base64').toString());
          const decodedPayload = JSON.parse(Buffer.from(payload, 'base64').toString());

          this.output(`🔍 Token header: ${JSON.stringify(decodedHeader)}`, true);
          this.output(`🔍 Token payload (client_id): ${decodedPayload.client_id}`, true);
          this.output(`🔍 Token payload (scope): ${decodedPayload.scope}`, true);
          const createdAt = decodedPayload.created_at * 1000;
          const expiresIn = parseInt(decodedPayload.expires_in, 10) * 1000;
          const expirationDate = new Date(createdAt + expiresIn);
          this.output(`🔍 Token payload (expires): ${expirationDate.toISOString()}`, true);
        } catch (decodeError) {
          this.output(`⚠️ Could not decode token for debugging: ${decodeError.message}`, true);
        }

        const url = new URL(jwtEndpoint);
        const postData = JSON.stringify({
          accessToken,
        });

        const options = {
          hostname: url.hostname,
          port: url.port || (url.protocol === 'https:' ? 443 : 80),
          path: url.pathname,
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(postData),
            'User-Agent': 'mcp-remote-with-okta/1.0.0',
          },
        };

        this.output(`📤 Making request to: ${options.hostname}${options.path}`, true);
        this.output(`📤 Request headers: ${JSON.stringify(options.headers, null, 2)}`, true);
        this.output(`📤 Request body length: ${postData.length}`, true);

        const req = https.request(options, (res) => {
          let data = '';
          res.on('data', (chunk) => {
            data += chunk;
          });
          res.on('end', () => {
            try {
              this.output(`📥 JWT exchange response status: ${res.statusCode}`, true);
              this.output(`📥 JWT exchange response headers: ${JSON.stringify(res.headers)}`, true);
              this.output(`📥 JWT exchange response body: ${data}`, true);

              // Log invocation ID for server-side debugging
              if (res.headers['x-invocation-id']) {
                const invocationId = res.headers['x-invocation-id'];
                const message = `🔍 Server invocation ID: ${invocationId}`;
                this.output(message, true);
              }

              if (res.statusCode !== 200) {
                reject(new Error(`JWT exchange failed with status ${res.statusCode}: ${data}`));
                return;
              }

              const jwtData = JSON.parse(data);

              if (!jwtData.token && !jwtData.jwt && !jwtData.access_token
                && !jwtData.sessionToken) {
                const fields = Object.keys(jwtData).join(', ');
                this.output(`❌ No JWT token found in response. Available fields: ${fields}`, true);
                reject(new Error('No JWT token found in response'));
                return;
              }

              this.output('✅ Successfully exchanged access token for JWT', true);
              // Use whichever field contains the JWT token
              const jwtToken = jwtData.sessionToken || jwtData.token
                               || jwtData.jwt || jwtData.access_token;

              resolve(jwtToken);
            } catch (parseError) {
              this.output(`❌ Failed to parse JWT response: ${parseError.message}`, true);
              reject(new Error(`Failed to parse JWT response: ${parseError.message}`));
            }
          });
        });

        req.on('error', (error) => {
          this.output(`❌ JWT exchange request failed: ${error.message}`, true);
          reject(new Error(`JWT exchange request failed: ${error.message}`));
        });

        req.write(postData);
        req.end();
      } catch (error) {
        this.output(`❌ JWT exchange failed: ${error.message}`, true);
        reject(new Error(`JWT exchange failed: ${error.message}`));
      }
    });
  }

  // Test JWT exchange with different formats
  async testJWTExchange(accessToken, format) {
    return new Promise((resolve, reject) => {
      try {
        const mcpUrl = new URL(this.mcpRemoteUrl);
        const jwtEndpoint = `${mcpUrl.origin}/api/v1/auth/login`;
        const url = new URL(jwtEndpoint);

        let postData; let
          options;

        if (format === 'header') {
          // Test with Authorization header
          postData = JSON.stringify({});
          options = {
            hostname: url.hostname,
            port: url.port || (url.protocol === 'https:' ? 443 : 80),
            path: url.pathname,
            method: 'POST',
            headers: {
              Authorization: `Bearer ${accessToken}`,
              'Content-Type': 'application/json',
              'Content-Length': Buffer.byteLength(postData),
            },
          };
        } else if (format === 'access_token') {
          // Test with access_token field name
          postData = JSON.stringify({
            access_token: accessToken,
          });
          options = {
            hostname: url.hostname,
            port: url.port || (url.protocol === 'https:' ? 443 : 80),
            path: url.pathname,
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Content-Length': Buffer.byteLength(postData),
            },
          };
        } else if (format === 'extra_headers') {
          // Test with additional headers
          postData = JSON.stringify({});
          options = {
            hostname: url.hostname,
            port: url.port || (url.protocol === 'https:' ? 443 : 80),
            path: url.pathname,
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Content-Length': Buffer.byteLength(postData),
              'User-Agent': 'mcp-remote-with-okta/1.0.0',
            },
          };
        }

        const req = https.request(options, (res) => {
          let data = '';
          res.on('data', (chunk) => {
            data += chunk;
          });
          res.on('end', () => {
            this.output(`Response status: ${res.statusCode}`, true);
            this.output(`Response body: ${data}`, true);
            if (res.headers['x-invocation-id']) {
              this.output(`Invocation ID: ${res.headers['x-invocation-id']}`, true);
            }

            if (res.statusCode === 200) {
              this.output(`✅ ${format} format worked!`, true);
              resolve(data);
            } else {
              reject(new Error(`${format} format failed with status ${res.statusCode}: ${data}`));
            }
          });
        });

        req.on('error', (error) => {
          reject(new Error(`Request failed: ${error.message}`));
        });

        req.write(postData);
        req.end();
      } catch (error) {
        reject(new Error(`Test failed: ${error.message}`));
      }
    });
  }

  // Start OAuth implicit flow
  async startAuthFlow() {
    if (!this.clientId) {
      // eslint-disable-next-line max-len
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

    const envName = this.getImsEnvironmentName();
    this.output(`🚀 Starting Adobe implicit grant authentication flow (${envName})...`, true);
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

  // Get valid JWT token (exchanges access token for JWT if needed)
  async getValidJWT() {
    try {
      // First check if we have a valid cached JWT token
      const storedTokens = this.loadTokens();

      if (storedTokens && !AdobeMCPWrapper.isJWTExpired(storedTokens)) {
        this.output('✅ Using valid stored JWT token', true);
        return storedTokens.jwt_token;
      }

      this.output('🔄 JWT token expired or not found, exchanging access token...', true);

      // Get the access token
      const accessToken = await this.getValidToken();

      // Exchange it for a JWT
      const jwtToken = await this.exchangeForJWT(accessToken);

      // Save the JWT token along with existing tokens
      const tokensToSave = {
        ...(storedTokens || {}),
        jwt_token: jwtToken,
        jwt_timestamp: Date.now(),
        jwt_expires_in: '3600', // Default to 1 hour, could be extracted from JWT if needed
      };

      this.saveTokens(tokensToSave);

      return jwtToken;
    } catch (error) {
      this.output(`❌ Failed to get JWT token: ${error.message}`, true);
      throw error;
    }
  }

  // Launch MCP remote with authentication
  async launchMCP() {
    try {
      const envName = this.getImsEnvironmentName();
      this.output(`🔐 Adobe MCP Wrapper (Implicit Flow) starting (${envName})...`, true);
      // Check if required environment variables are available
      if (!this.clientId) {
      // eslint-disable-next-line max-len
        throw new Error('ADOBE_CLIENT_ID environment variable not found. Please check your MCP configuration.');
      }

      let authToken;
      if (this.authMethod === 'access_token') {
        this.output('🔑 Using direct access token authentication...', true);
        authToken = await this.getValidToken();
        this.output('✅ Got access token for direct authentication', true);
      } else {
        this.output('🔄 Using JWT exchange authentication...', true);
        // Get valid JWT token (this will handle access token exchange)
        authToken = await this.getValidJWT();
        this.output('✅ Got JWT token for authentication', true);
      }

      this.output('🚀 Launching MCP remote with authentication...', true);

      // Prepare command with authentication header
      const command = this.mcpArgs[0];
      const args = [
        ...this.mcpArgs.slice(1),
        '--header', `Authorization:Bearer ${authToken}`,
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
        this.output(`🌐 IMS Environment: ${this.getImsEnvironmentName()}`);
        const tokens = this.loadTokens();
        if (tokens) {
          const isExpired = AdobeMCPWrapper.isTokenExpired(tokens);
          this.output(`📊 Access Token Status: ${isExpired ? '❌ Expired' : '✅ Valid'}`);
          if (tokens.timestamp) {
            const expiresIn = parseInt(tokens.expires_in, 10) || 3600;
            const expirationTime = new Date(tokens.timestamp + (expiresIn * 1000));
            this.output(`⏰ Access Token Expires at: ${expirationTime.toLocaleString()}`);
          }

          // Show JWT token status if available
          if (tokens.jwt_token) {
            const isJWTExpired = AdobeMCPWrapper.isJWTExpired(tokens);
            this.output(`📊 JWT Token Status: ${isJWTExpired ? '❌ Expired' : '✅ Valid'}`);
            if (tokens.jwt_timestamp) {
              const jwtExpiresIn = parseInt(tokens.jwt_expires_in, 10) || 3600;
              const jwtExpirationTime = new Date(tokens.jwt_timestamp + (jwtExpiresIn * 1000));
              this.output(`⏰ JWT Token Expires at: ${jwtExpirationTime.toLocaleString()}`);
            }
          } else {
            this.output('📊 JWT Token Status: ❌ No JWT token cached');
          }
        } else {
          this.output('📊 Token Status: ❌ No tokens found');
        }
        break;
      }

      case 'token': {
        const validToken = await this.getValidToken();
        this.output(`🔑 Access Token: ${validToken.substring(0, 20)}...`);
        break;
      }

      case 'jwt': {
        const jwtToken = await this.getValidJWT();
        this.output(`🔑 JWT Token: ${jwtToken.substring(0, 20)}...`);
        break;
      }

      case 'auth-type': {
        this.output(`🔧 Current authentication type: ${this.authMethod}`);
        this.output('Available types:');
        this.output('  - jwt: Exchange access token for JWT (default)');
        this.output('  - access_token: Use access token directly');
        this.output('\nTo change: Set ADOBE_AUTH_METHOD environment variable');
        break;
      }

      case 'test-auth': {
        this.output(`🧪 Testing current authentication type: ${this.authMethod}\n`);

        if (this.authMethod === 'access_token') {
          this.output('Testing direct access token...');
          try {
            const accessToken = await this.getValidToken();
            this.output(`✅ Got access token: ${accessToken.substring(0, 20)}...`);
          } catch (error) {
            this.output(`❌ Access token test failed: ${error.message}`);
          }
        } else {
          this.output('Testing JWT exchange...');
          try {
            const jwtToken = await this.getValidJWT();
            this.output(`✅ Got JWT token: ${jwtToken.substring(0, 20)}...`);
          } catch (error) {
            this.output(`❌ JWT test failed: ${error.message}`);
          }
        }
        break;
      }

      case 'test-jwt': {
        const accessToken = await this.getValidToken();
        this.output('🧪 Testing different JWT exchange formats...\n');

        // Test 1: Current format
        this.output('Test 1: Current format (accessToken in body)');
        try {
          await this.exchangeForJWT(accessToken);
        } catch (error) {
          this.output(`❌ Test 1 failed: ${error.message}\n`);
        }

        // Test 2: Try with Authorization header instead
        this.output('Test 2: Access token in Authorization header');
        try {
          await this.testJWTExchange(accessToken, 'header');
        } catch (error) {
          this.output(`❌ Test 2 failed: ${error.message}\n`);
        }

        // Test 3: Try with different field name
        this.output('Test 3: Different field name (access_token)');
        try {
          await this.testJWTExchange(accessToken, 'access_token');
        } catch (error) {
          this.output(`❌ Test 3 failed: ${error.message}\n`);
        }

        // Test 4: Try with additional headers
        this.output('Test 4: With additional headers');
        try {
          await this.testJWTExchange(accessToken, 'extra_headers');
        } catch (error) {
          this.output(`❌ Test 4 failed: ${error.message}\n`);
        }

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

      case 'clear-jwt': {
        const tokens = this.loadTokens();
        if (tokens && tokens.jwt_token) {
          // Remove JWT-related fields while keeping access token
          const {
            jwt_token: jwtToken,
            jwt_timestamp: jwtTimestamp,
            jwt_expires_in: jwtExpiresIn,
            ...remainingTokens
          } = tokens;
          this.saveTokens(remainingTokens);
          this.output('🗑️ JWT token cleared (access token preserved)');
        } else {
          this.output('ℹ️ No JWT token to clear');
        }
        break;
      }

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
        this.output('  jwt          - Display current valid JWT token');
        this.output('  auth-type    - Show current authentication type');
        this.output('  test-auth    - Test current authentication method');
        this.output('  test-jwt     - Test different JWT exchange formats');
        this.output('  clear        - Clear stored tokens');
        this.output('  clear-jwt    - Clear JWT token (keep access token)');
        this.output('  mcp          - Launch MCP remote with authentication');
        this.output('  help         - Show this help message');
        this.output('\n🔧 Usage:');
        this.output('  npx mcp-remote-with-okta <mcp-url> <command>');
        this.output('  npx mcp-remote-with-okta <mcp-url>  # Launch as MCP server');
        this.output('\n🔑 Environment Variables:');
        this.output('  ADOBE_CLIENT_ID     - Required: Client ID for Adobe IMS (Implicit Grant)');
        this.output('  ADOBE_SCOPE         - Optional: OAuth scope (default: AdobeID,openid)');
        this.output('  ADOBE_AUTH_METHOD   - Optional: Authentication type (default: jwt)');
        this.output('                        Values: jwt, access_token');
        this.output('\n💡 Example MCP config (JWT Authentication):');
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
        // eslint-disable-next-line max-len
        this.output('          "ADOBE_SCOPE": "AdobeID,openid",  // Optional: defaults to AdobeID,openid');
        this.output('          "ADOBE_AUTH_METHOD": "jwt"  // Optional: defaults to jwt');
        this.output('        }');
        this.output('      }');
        this.output('    }');
        this.output('  }');
        this.output('\n💡 Example MCP config (Direct Access Token):');
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
        this.output('          "ADOBE_AUTH_METHOD": "access_token"');
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
    console.log('Commands: authenticate, jwt, mcp, status, token, auth-type,');
    console.log('          test-auth, test-jwt, clear, clear-jwt, help');
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
