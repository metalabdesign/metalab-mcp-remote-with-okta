const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');

/**
 * Build script for local-auth-proxy-nodejs
 * This script:
 * 1. Creates a dist directory
 * 2. Copies source files to dist
 * 3. Injects environment variables into the bundle
 * 4. Makes the main file executable
 */

const srcDir = path.join(__dirname, 'src');
const distDir = path.join(__dirname, 'dist');
const envPath = path.join(__dirname, '.env');

// Ensure dist directory exists
if (fs.existsSync(distDir)) {
  fs.rmSync(distDir, { recursive: true });
}
fs.mkdirSync(distDir, { recursive: true });

if(!fs.existsSync(envPath)) {
  console.error('❌ .env file not found');
  process.exit(1);
}

const envs = dotenv.parse(fs.readFileSync(envPath));

const injectableEnvs = [
  'OKTA_CLIENT_ID',
  'OKTA_DOMAIN',
  'MCP_TOKEN_URI',
  'MCP_REMOTE_URI',
];

// Function to inject environment variables into code
function injectEnvVars(content) {
  // Replace process.env references with actual values or fallbacks
  let modifiedContent = content;

  // Add environment variable injection at the top of the file
  const envInjection = `
// Environment variables injected at build time
const ENV_DEFAULTS = ${JSON.stringify({
    ...injectableEnvs.reduce((acc, key) => {
      acc[key] = envs[key];
      return acc;
    }, {}),
  }, null, 2)};

// Override with actual environment variables if available
Object.keys(ENV_DEFAULTS).forEach(key => {
  if (process.env[key] === undefined) {
    process.env[key] = ENV_DEFAULTS[key];
  }
});
`;

  // Insert after the shebang line if it exists
  if (modifiedContent.startsWith('#!/usr/bin/env node')) {
    const lines = modifiedContent.split('\n');
    lines.splice(1, 0, envInjection);
    modifiedContent = lines.join('\n');
  } else {
    modifiedContent = envInjection + modifiedContent;
  }

  return modifiedContent;
}

// Copy and process source files
function copyFile(srcPath, destPath) {
  const content = fs.readFileSync(srcPath, 'utf8');
  let processedContent = content;

  // Only inject env vars into the main index.js file
  if (path.basename(srcPath) === 'index.js') {
    processedContent = injectEnvVars(content);
  }

  fs.writeFileSync(destPath, processedContent);

  // Make executable if it's the main file
  if (path.basename(srcPath) === 'index.js') {
    fs.chmodSync(destPath, '755');
  }
}

// Recursively copy source files
function copyDirectory(src, dest) {
  if (!fs.existsSync(dest)) {
    fs.mkdirSync(dest, { recursive: true });
  }

  const entries = fs.readdirSync(src, { withFileTypes: true });

  for (const entry of entries) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);

    if (entry.isDirectory()) {
      copyDirectory(srcPath, destPath);
    } else {
      copyFile(srcPath, destPath);
    }
  }
}

// Build process
console.log('🔨 Building local-auth-proxy-nodejs...');

try {
  // Copy source files to dist
  copyDirectory(srcDir, distDir);

  console.log('✅ Build completed successfully!');
  console.log(`📦 Output directory: ${distDir}`);
  console.log('🚀 Ready for publishing!');

} catch (error) {
  console.error('❌ Build failed:', error.message);
  process.exit(1);
}
