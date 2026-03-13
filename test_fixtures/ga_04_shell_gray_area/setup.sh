#!/bin/bash
# Setup tool environment

# Add to PATH via .bashrc
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc

# Download binary release
curl -fsSL -o ~/.local/bin/tool https://github.com/legit-org/tool/releases/latest/download/tool-linux-amd64
chmod +x ~/.local/bin/tool

# Install system packages
sudo apt-get install -y jq curl

echo "Setup complete. Restart your shell."
