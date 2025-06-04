# MCP Remote with Okta/Adobe IMS Authentication

A wrapper for `mcp-remote` that handles Adobe IMS/Okta OAuth authentication automatically, eliminating the need for manual token management.

## Features

- 🔐 **Automatic OAuth Authentication**: Handles Adobe IMS OAuth flow with PKCE security
- 🔄 **Token Management**: Automatically refreshes expired tokens (24-hour lifetime)
- 🖥️ **Cross-Platform**: Works on macOS, Windows, and Linux
- 🚀 **Zero Maintenance**: Set it once, never worry about tokens again
- 🔧 **Configurable**: Support for custom client IDs, scopes, and MCP URLs
- 📱 **Browser Integration**: Opens browser automatically for authentication
- 🔒 **Secure Storage**: Tokens stored securely in `~/.cursor/`

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
| `ADOBE_CLIENT_ID` | ✅ Required | - | Client ID for Adobe IMS |
| `ADOBE_CLIENT_SECRET` | ✅ Required | - | Client secret for Adobe IMS |
| `ADOBE_SCOPE` | Optional | `AdobeID,openid` | OAuth scope for Adobe IMS |

### MCP Configuration

Add to your `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "aem_sites_optimizer": {
      "command": "npx",
      "args": [
        "mcp-remote-with-okta",
        "https://your-mcp-server.com/api/v1/mcp"
      ],
      "env": {
        "ADOBE_CLIENT_ID": "your_client_id_here",
        "ADOBE_CLIENT_SECRET": "your_client_secret_here"
      }
    }
  }
}
```

## Usage

### As MCP Server (Primary Use Case)

The script automatically detects when called as an MCP server and handles authentication transparently:

```bash
npx mcp-remote-with-okta https://spacecat.experiencecloud.live/api/v1/mcp
```

### CLI Commands

The package also provides CLI commands for token management:

```bash
# Authenticate and get token
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

1. **Token Check**: Script checks for valid stored tokens in `~/.cursor/adobe-tokens.json`
2. **Authentication**: If no valid token exists, launches OAuth flow:
   - Opens browser to Adobe IMS login
   - Starts local server on `localhost:8080` for callback
   - Exchanges authorization code for access token using PKCE
3. **Token Storage**: Securely stores tokens with expiration tracking
4. **MCP Launch**: Launches `mcp-remote` with `Authorization: Bearer <token>` header
5. **Auto-Refresh**: Automatically refreshes tokens when they expire

## Authentication Flow

The package uses OAuth 2.0 Authorization Code flow with PKCE (Proof Key for Code Exchange) for security:

```
1. User → Browser → Adobe IMS Login
2. Adobe IMS → Callback → localhost:8080
3. Script → Exchange Code → Access Token
4. Script → Store Token → ~/.cursor/
5. Script → Launch MCP → With Auth Header
```

## Troubleshooting

### Common Issues

**"Client ID not found"**
```bash
# Ensure ADOBE_CLIENT_ID is set in your MCP config
```

**"Client secret not found"**
```bash
# Ensure ADOBE_CLIENT_SECRET is set in your MCP config
```

**"Port 8080 in use"**
```bash
# The redirect URI is hardcoded to localhost:8080
# Ensure no other service is using this port during authentication
```

**"Browser doesn't open"**
```bash
# Manually visit the authentication URL that appears in the terminal
```

### Debug Mode

The underlying `mcp-remote` runs in debug mode by default. Logs are written to `~/.mcp-auth/`.

### Token Management

```bash
# Check if tokens are valid
npx mcp-remote-with-okta <url> status

# Force re-authentication
npx mcp-remote-with-okta <url> clear
npx mcp-remote-with-okta <url> authenticate
```

## Security Notes

- Tokens are stored locally in `~/.cursor/adobe-tokens.json`
- Uses PKCE for additional OAuth security
- Tokens expire after 24 hours and are automatically refreshed
- Client secrets should be kept secure and not committed to version control

## Adobe IMS Setup

To use this package, you need:

1. An Adobe Developer Console project
2. OAuth Server-to-Server credentials configured
3. Redirect URI set to `http://localhost:8080/callback`
4. Appropriate scopes enabled (typically `AdobeID,openid`)

## Requirements

- Node.js 18.0.0 or higher
- Internet connection for authentication
- Browser for OAuth flow

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Changelog

### v1.0.0
- Initial release
- Adobe IMS OAuth authentication
- Automatic token management
- Cross-platform support
- MCP integration 