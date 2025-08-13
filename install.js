#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const os = require('os');

const filePath = path.join(os.homedir(), '.codeium', 'windsurf', 'mcp_config.json');
const dirPath = path.dirname(filePath);

// Ensure directory exists
fs.mkdirSync(dirPath, { recursive: true });

// Load or initialize JSON
let data = {};
if (fs.existsSync(filePath)) {
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    data = JSON.parse(raw);
  } catch (err) {
    console.error(`Error: existing JSON in ${filePath} is invalid.`);
    process.exit(1);
  }
}

// Ensure mcpServer exists
if (!data.mcpServer || typeof data.mcpServer !== 'object') {
  data.mcpServer = {};
}

// Add/update "metalab"
data.mcpServer.metalab = {
  command: 'node',
  args: ['~/.metalab/metalab-mcp-remote-with-okta.js']
};

// Save file with pretty formatting
fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');

console.log(`✅ Done: updated ${filePath}`);