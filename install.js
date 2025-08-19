const fs = require('fs');
const path = require('path');
const os = require('os');
const { modify, applyEdits } = require('jsonc-parser');

const filePath = path.join(os.homedir(), '.codeium', 'windsurf', 'mcp_config.json');
const dirPath = path.dirname(filePath);

// Ensure directory exists
fs.mkdirSync(dirPath, { recursive: true });

// Read original text (JSONC allowed)
let raw = '{}\n';
if (fs.existsSync(filePath)) {
  try {
    raw = fs.readFileSync(filePath, 'utf8');
  } catch (err) {
    console.error(`Error: existing JSON in ${filePath} is invalid.`);
    process.exit(1);
  }
}

// The value we want to set at path mcpServers.metalab
const value = {
  command: path.join(os.homedir(), '.nvm', 'versions', 'node', 'v22.18.0', 'bin', 'node'),
  args: [path.join(os.homedir(), '.metalab', 'metalab-mcp-remote-with-okta.js')],
};

// Compute minimal edits that create parents if missing and set/replace the value
const edits = modify(
  raw,
  ['mcpServers', 'metalab'],
  value,
  {
    formattingOptions: { insertSpaces: true, tabSize: 2, eol: '\n' },
  }
);

// Apply edits to the original text
const updated = applyEdits(raw, edits);

// Write back — comments and unrelated formatting remain intact
fs.writeFileSync(filePath, updated, 'utf8');

console.log(`✅ Done: updated ${filePath}`);
