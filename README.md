# MCP Remote with Okta Authentication

This is a fork of [mcp-remote-with-okta](https://github.com/adobe-rnd/mcp-remote-with-okta) with our own configurations

A wrapper for `mcp-remote` that handles Okta authentication using OAuth implicit flow, providing seamless authentication for protected MCP servers.

It grants access to MCP servers by proxying the authentication process to Okta, by storing the tokens on user `~/.metalab` directory.

## Features

- 🔐 **Okta OAuth**: Implements Okta's OAuth implicit flow for secure user authentication.
- 🔄 **Token Management**: Automatic token storage, validation, and expiration handling.
- 🖥️ **Cross-Platform**: Works on macOS, Windows, and Linux.
- 🚀 **Zero Maintenance**: Set it once, never worry about tokens again.
- 🔧 **Configurable**: Support for multiple environments, scopes, and authentication methods.
- 🔒 **Secure Storage**: Tokens stored securely in user's home directory.
- 🎯 **Production Ready**: Robust error handling for Okta.

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OKTA_CLIENT_ID` | ✅ | - | Client ID for Okta |
| `OKTA_DOMAIN` | ✅ | - | Your Okta domain (e.g., `dev-12345.okta.com`) |
| `OKTA_SCOPE` | Optional | `openid profile email` | OAuth scope for Okta |
| `MCP_TOKEN_URI` | Optional | `http://localhost:8080/token` | MCP token URL |
| `DEBUG_MODE` | Optional | `false` | Enable debug mode for troubleshooting |
| `AUTO_REFRESH` | Optional | `true` | Enable automatic token refresh |
| `REFRESH_THRESHOLD` | Optional | `10` | Auto-refresh threshold in minutes |

## Instalation

### Auto installation

Run the following command on your terminal, then reopen Windsurf or refresh the MCP config

```bash
mkdir ~/.metalab;
curl -L https://github.com/metalabdesign/metalab-mcp-remote-with-okta/releases/latest/download/metalab-mcp-remote-with-okta.js -o ~/.metalab/metalab-mcp-remote-with-okta.js
curl -fsSL https://raw.githubusercontent.com/metalabdesign/metalab-mcp-remote-with-okta/main/install.js | node
```

### Manual installation

Download the latest [mcp-remote-with-okta.js](https://github.com/metalabdesign/metalab-mcp-remote-with-okta/releases/latest/download/metalab-mcp-remote-with-okta.js) release from [releases](https://github.com/metalabdesign/metalab-mcp-remote-with-okta/releases) and save it to a location of your choice

Add the following to your mcp config

```json
{
  "mcpServers": {
    "metalab": {
      "command": "node",
      "args": [
        "<PATH_SAVED>/metalab-mcp-remote-with-okta.js"
      ],
    }
  }
}
```

## Development

run `npm run build` and then add the following to your mcp config

```json
{
  "mcpServers": {
    "metalab": {
      "command": "node",
      "args": [
        "<REPO_PATH>/dist/index.js",
      ]
    }
  }
}
```


## Okta Configuration

Ensure your Okta application is configured correctly:

1. **Grant Types**: Enable "Authorization Code"
2. **App Type**: Use "OIDC Web Application"
3. **MCP Token URIs**: Add your token generation URL (e.g., `http://localhost:8080/token`)
4. **Scopes**: Ensure requested scopes are allowed

## Troubleshooting

If you encounter `access_denied` errors or "The requested feature is not enabled" messages:

1. Verify your Okta app settings match the requirements above
2. Check that all URIs are correctly registered in Okta
3. Ensure your Okta domain and client credentials are correct
4. For free Okta Developer orgs, use the default authorization server

## Project Structure

```
src/
  auth-strategy.js  # Authentication strategy
  index.js          # Main server application
package.json         # Node.js dependencies and scripts
.env.example         # Environment configuration template
README.md           # This file
```
