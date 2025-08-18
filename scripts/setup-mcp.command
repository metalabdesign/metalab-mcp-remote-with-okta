#!/bin/bash
TOTAL_STEPS=9
STEP=0
NODE_VERSION="22.18.0"
NPM_VERSION="10.9.3"

step() {
    ((STEP++))
    local label="$1"; shift
    local cmd="$*"

    echo ""
    echo "Step $STEP/$TOTAL_STEPS: $label"
    eval "$cmd"
    local status=$?
    if [ $status -ne 0 ]; then
        echo ""
        echo "Step $STEP/$TOTAL_STEPS: $label failed ❌ (exit $status)"
        echo ""
        sleep 3
        exit $status
    fi
    sleep 2
}

step "Download and install nvm" \
'
if [ -s "$HOME/.nvm/nvm.sh" ]; then
  echo -e "✅ nvm already installed"
else
  echo -e "⬇️  Installing nvm via curl..."
  curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash
fi
'

step "Ensure nvm lines in ~/.zshrc" \
    '
    ZSHRC="$HOME/.zshrc"
    touch "$ZSHRC"
    NVM_LINES="export NVM_DIR=\"\$HOME/.nvm\"
[ -s \"\$NVM_DIR/nvm.sh\" ] && \. \"\$NVM_DIR/nvm.sh\"  # This loads nvm
[ -s \"\$NVM_DIR/bash_completion\" ] && \. \"\$NVM_DIR/bash_completion\"  # This loads nvm bash_completion"
    if ! grep -Fxq "export NVM_DIR=\"\$HOME/.nvm\"" "$ZSHRC"; then
        echo -e "\n# Added by script based on official curl script to enable nvm\n$NVM_LINES" >> "$ZSHRC"
        echo "✅ nvm lines added to $ZSHRC"
    else
        echo -e "✅ nvm lines already exist in $ZSHRC"
    fi
    '

step "Load nvm into current shell" \
    ". \"$HOME/.nvm/nvm.sh\""
echo -e "✅ nvm loaded"

step "Install Node.js $NODE_VERSION" \
"
if [ \"\$(nvm version $NODE_VERSION)\" = \"N/A\" ]; then
  echo -e \"⬇️  Installing Node.js $NODE_VERSION...\"
  nvm install $NODE_VERSION
else
  echo -e \"✅ Node.js $NODE_VERSION already installed via nvm.\"
fi
"

step "Set Node.js $NODE_VERSION as default" \
"
resolved=\$(nvm version default 2>/dev/null || true)
if [ \"\$resolved\" = \"v$NODE_VERSION\" ]; then
    echo -e \"✅ Default nvm alias already points to \$resolved.\"
else
    echo -e \"⬇️  Setting Node.js $NODE_VERSION as default...\"
    nvm alias default $NODE_VERSION
fi
"

step "Ensure npm $NPM_VERSION is installed" \
"
current_npm=\$(npm -v 2>/dev/null || echo 'none')
if [ \"\$current_npm\" = \"$NPM_VERSION\" ]; then
    echo -e \"✅ npm \$current_npm already matches required version $NPM_VERSION.\"
else
    echo -e \"⬇️  Installing npm@$NPM_VERSION...\"
    npm install -g npm@$NPM_VERSION
fi
"

step "Ensure ~/.metalab directory exists" \
    "mkdir -p \"$HOME/.metalab\""
echo -e "✅ ~/.metalab directory exists"

step "Download Metalab MCP (Okta) script" \
    "curl -L https://github.com/metalabdesign/metalab-mcp-remote-with-okta/releases/latest/download/metalab-mcp-remote-with-okta.js -o \"$HOME/.metalab/metalab-mcp-remote-with-okta.js\""
echo -e "✅ Metalab MCP (Okta) script downloaded"

step "Run Metalab installer" \
    "curl -fsSL https://raw.githubusercontent.com/metalabdesign/metalab-mcp-remote-with-okta/main/install.js | node"

echo ""
echo -e "🎉 All $TOTAL_STEPS steps completed successfully — closing..."
sleep 5
osascript -e 'tell application "Terminal" to close front window' &
exit 0