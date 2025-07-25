# MCP Remote with Adobe and Okta Authentication

A wrapper for `mcp-remote` that handles Adobe IMS or Okta authentication using OAuth implicit flow, providing seamless authentication for protected MCP servers.

## Features

- 🔐 **Multi-Provider OAuth**: Implements Adobe's and Okta's OAuth implicit flow for secure user authentication.
- 🔄 **Token Management**: Automatic token storage, validation, and expiration handling.
- 🖥️ **Cross-Platform**: Works on macOS, Windows, and Linux.
- 🚀 **Zero Maintenance**: Set it once, never worry about tokens again.
- 🔧 **Configurable**: Support for multiple environments, scopes, and authentication methods.
- 🔒 **Secure Storage**: Tokens stored securely in user's home directory.
- 🎯 **Production Ready**: Robust error handling for both Adobe and Okta.

## Installation

### Via npx (Recommended)

```bash
npx mcp-remote-with-okta <mcp-url>
```

### Global Installation

```bash
npm install -g mcp-remote-with-okta
mcp-remote-with-okta <mcp-url>
```

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `AUTH_PROVIDER` | Optional | `adobe` | Authentication provider (`adobe` or `okta`) |
| `ADOBE_CLIENT_ID` | ✅ If `AUTH_PROVIDER` is `adobe` | - | Client ID for Adobe IMS |
| `ADOBE_SCOPE` | Optional | `AdobeID,openid` | OAuth scope for Adobe IMS |
| `ADOBE_IMS_ENV` | Optional | `prod` | IMS environment (`prod`, `stage`, `dev`) |
| `OKTA_CLIENT_ID` | ✅ If `AUTH_PROVIDER` is `okta` | - | Client ID for Okta |
| `OKTA_DOMAIN` | ✅ If `AUTH_PROVIDER` is `okta` | - | Your Okta domain (e.g., `dev-12345.okta.com`) |
| `OKTA_SCOPE` | Optional | `openid profile email` | OAuth scope for Okta |
| `REDIRECT_URI` | Optional | `http://localhost:8080/callback` | OAuth redirect URI |
| `AUTH_METHOD` | Optional | `jwt` | Authentication method (`jwt` or `access_token`) |
| `DEBUG_MODE` | Optional | `false` | Enable debug mode for troubleshooting |
| `AUTO_REFRESH` | Optional | `true` | Enable automatic token refresh |
| `REFRESH_THRESHOLD` | Optional | `10` | Auto-refresh threshold in minutes |

### MCP Configuration

#### For Adobe

```json
{
  "mcpServers": {
    "my-mcp-server": {
      "command": "npx",
      "args": [
        "mcp-remote-with-okta",
        "https://your-mcp-server.com/mcp"
      ],
      "env": {
        "AUTH_PROVIDER": "adobe",
        "ADOBE_CLIENT_ID": "your_client_id_here",
        "ADOBE_IMS_ENV": "prod"
      }
    }
  }
}
```

#### For Okta

```json
{
  "mcpServers": {
    "my-mcp-server": {
      "command": "npx",
      "args": [
        "mcp-remote-with-okta",
        "https://your-mcp-server.com/mcp"
      ],
      "env": {
        "AUTH_PROVIDER": "okta",
        "OKTA_CLIENT_ID": "your_okta_client_id",
        "OKTA_DOMAIN": "your_okta_domain.okta.com"
      }
    }
  }
}
```

## Usage

### As MCP Server (Primary Use Case)

The script automatically detects the configured authentication provider and handles user authentication transparently.

**For Adobe:**
```bash
export AUTH_PROVIDER=adobe
export ADOBE_CLIENT_ID=your_client_id
npx mcp-remote-with-okta https://my.mcp-server.com/mcp
```

**For Okta:**
```bash
export AUTH_PROVIDER=okta
export OKTA_CLIENT_ID=your_client_id
export OKTA_DOMAIN=your.okta.domain
npx mcp-remote-with-okta https://my.mcp-server.com/mcp
```

### CLI Commands

The package also provides CLI commands for token management:

```bash
# Authenticate user and get token
npx mcp-remote-with-okta <mcp-url> authenticate

# Check token status
npx mcp-remote-with-okta <mcp-url> status

# Display current token
npx mcp-remote-with-okta <mcp-url> token

# Clear stored tokens
npx mcp-remote-with-okta <mcp-url> clear

# Show help
npx mcp-remote-with-okta <mcp-url> help
```

## How It Works

This wrapper implements the OAuth implicit flow for authentication:

1.  **OAuth Setup**: Configures OAuth parameters for the selected provider (Adobe or Okta).
2.  **Browser Authentication**: Opens browser for secure user authentication.
3.  **Token Capture**: Local HTTP server captures OAuth callback with tokens.
4.  **Token Storage**: Securely stores tokens with expiration tracking.
5.  **JWT Exchange**: Optional JWT token exchange for servers requiring JWT authentication.
6.  **MCP Launch**: Launches `mcp-remote` with `Authorization: Bearer <token>` header.

## Authentication Flow

The package implements a complete OAuth implicit flow:

```
1. Generate OAuth URL → Auth Server (Adobe IMS or Okta)
2. Open Browser → User Authentication
3. Capture Callback → Local HTTP Server  
4. Extract Tokens → From URL Fragment
5. Store Tokens → Secure Local Storage
6. Launch MCP → With Auth Header
```

## Environments

The library supports multiple Adobe IMS environments. For Okta, the domain is configured directly via `OKTA_DOMAIN`.

- **Production** (`prod`) - Default Adobe production environment
- **Stage** (`stage`, `stg`) - Adobe staging environment for testing
- **Development** (`dev`, `development`) - Adobe development environment

```bash
export ADOBE_IMS_ENV="stage"  # Use Adobe staging environment
```

## Troubleshooting

### Common Issues

**"Client ID not found"**
```bash
# Ensure ADOBE_CLIENT_ID or OKTA_CLIENT_ID is set for your chosen AUTH_PROVIDER
```

**"Authentication failed"**
```bash
# Check that your Developer Console project (Adobe or Okta) is properly configured
# Verify the client ID is correct for the target environment
```

**"OAuth state parameter invalid"**
```bash
# This usually indicates a callback security issue
# Clear tokens and try again
npx mcp-remote-with-okta <url> clear
```

**"Token validation failed"**
```bash
# Clear stored tokens and re-authenticate
npx mcp-remote-with-okta <url> clear
npx mcp-remote-with-okta <url> authenticate
```

**"Auto-refresh failed"**
```bash
# Check debug logs to see the specific error
export DEBUG_MODE=true
npx mcp-remote-with-okta <url> status

# Disable auto-refresh if causing issues
export AUTO_REFRESH=false
```

**"Client error for command A system error occurred (spawn npx ENOENT)"**
```bash
# If you encounter this error when using npx in MCP configuration,
# this often happens when the Node.js/npm environment isn't properly 
set up

# Solution: Create an npx wrapper script
cat > ~/.cursor/npx-wrapper.sh << 'SCRIPT'
#!/bin/bash

# Source nvm to get the correct node version
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"

# Use your preferred node version (adjust as needed)
nvm use 22.0.0 >/dev/null 2>&1

# Execute npx with all passed arguments
exec npx "$@"
SCRIPT

# Make the script executable
chmod +x ~/.cursor/npx-wrapper.sh

# Update your ~/.cursor/mcp.json to use the wrapper instead of npx:
{
  "mcpServers": {
    "your-server": {
      "command": "/Users/your-username/.cursor/npx-wrapper.sh",
      "args": [
        "mcp-remote-with-okta",
        "https://your-mcp-server.com/mcp"
      ],
      "env": {
        "AUTH_PROVIDER": "adobe",
        "ADOBE_CLIENT_ID": "your_client_id_here"
      }
    }
  }
}
```

### Debug Mode

For detailed troubleshooting, enable debug mode:

```bash
# Enable debug logging for the selected provider
export DEBUG_MODE=true
export AUTH_PROVIDER=okta # or 'adobe'
npx mcp-remote-with-okta <url> status

# Or use standard DEBUG variable
export DEBUG=okta # or 'adobe'
npx mcp-remote-with-okta <url> authenticate
```

Debug mode shows:
- Configuration validation results
- Token expiration times and validity
- OAuth flow step-by-step progress
- Auto-refresh timer scheduling
- Network request details
- Error stack traces

### Manual Diagnostics

For debugging authentication issues:

```bash
# Check authentication status with debug info
export DEBUG_MODE=true
npx mcp-remote-with-okta <url> status

# View current token details
npx mcp-remote-with-okta <url> token

# Test authentication flow with full logging
export DEBUG_MODE=true
npx mcp-remote-with-okta <url> authenticate

# Clear tokens and start fresh
npx mcp-remote-with-okta <url> clear
```

## Architecture

This package is built with:

- **OAuth Implicit Flow** - For client-side applications
- **Multi-Provider Support** - Adobe IMS and Okta
- **Auto-refresh** - Background token refresh with configurable timing
- **Debug Mode** - Comprehensive logging for troubleshooting
- **[mcp-remote](https://www.npmjs.com/package/mcp-remote)** - MCP remote server client
- **Node.js 18+** - Modern JavaScript runtime
- **Native HTTP Server** - For OAuth callback handling

The implementation provides robust error handling, automatic token management, and follows OAuth security best practices.

- **Process cleanup**: Timers are properly cleaned up on exit

### Auto-Refresh

The wrapper automatically refreshes tokens before they expire to ensure uninterrupted service:

```bash
# Enable auto-refresh (default: true)
export AUTO_REFRESH=true

# Set refresh threshold to 5 minutes before expiration
export REFRESH_THRESHOLD=5

# Disable auto-refresh
export AUTO_REFRESH=false
```

Auto-refresh features:
- **Background refresh**: Tokens are refreshed automatically before expiration
- **Configurable threshold**: Set how many minutes before expiration to trigger refresh
- **Graceful fallback**: If auto-refresh fails, manual authentication is triggered
- **Process cleanup**: Timers are properly cleaned up on exit

## Contributing

Contributions are welcomed! Please ensure all tests pass and maintain code coverage above 75%.

```bash
npm test              # Run tests
npm run test:coverage # Run tests with coverage
npm run lint          # Check code style
```

## License

This project is licensed under the MIT License. See LICENSE for more information.
