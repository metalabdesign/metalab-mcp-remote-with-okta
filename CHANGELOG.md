# Changelog

## [1.2.0] - 2024-08-01

### Added
- **Okta Authentication**: Added support for Okta as an authentication provider.
- **Multi-Provider Architecture**: Refactored the authentication logic to support multiple providers.
- `AUTH_PROVIDER` environment variable to select between `adobe` and `okta`.

### Changed
- Renamed `AdobeMCPWrapper` to `AuthMCPWrapper` to reflect its more generic role.
- Updated `README.md` with instructions for configuring and using both Adobe and Okta.
- Consolidated environment variables for a more consistent configuration experience.

## [1.1.0] - 2024-07-31

### Added
- **Auto-refresh**: Implemented automatic token refresh to prevent session expiration.
- **Debug Mode**: Added a debug mode for easier troubleshooting.
- `ADOBE_AUTO_REFRESH` and `ADOBE_REFRESH_THRESHOLD` environment variables.

### Changed
- Improved error handling and reporting.
- Simplified the OAuth callback server.

## [1.0.0] - 2024-07-30

- Initial release of the `mcp-remote-with-okta` package.
- Adobe IMS authentication using OAuth implicit flow.
- Secure token storage in the user's home directory.
- CLI commands for token management (`authenticate`, `status`, `token`, `clear`). 