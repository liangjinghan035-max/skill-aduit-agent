#!/bin/bash
set -e

SKILL_DIR="$HOME/.claude/skills/seo"

echo "Installing SEO skill..."

# Create directories
mkdir -p "$SKILL_DIR"
mkdir -p "$SKILL_DIR/references"

# Copy files
cp -r skills/* "$SKILL_DIR/"
cp -r agents/* "$HOME/.claude/agents/" 2>/dev/null || true

# Make scripts executable
chmod +x scripts/*.py 2>/dev/null || true

echo "SEO skill installed to $SKILL_DIR"
echo "Restart Claude Code to activate."
