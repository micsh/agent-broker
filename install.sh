#!/usr/bin/env bash
# agent-broker installer for Linux/macOS
# Usage: curl -fsSL https://raw.githubusercontent.com/micsh/agent-broker/main/install.sh | bash
#   or:  ./install.sh [install-dir]

set -euo pipefail

INSTALL_DIR="${1:-$HOME/.agent-broker/bin}"
REPO="micsh/agent-broker"

echo "🔌 Installing agent-broker..."

# Detect platform
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS-$ARCH" in
    Linux-x86_64)   SUFFIX="linux-x64" ;;
    Darwin-arm64)   SUFFIX="macos-arm64" ;;
    Darwin-x86_64)  SUFFIX="macos-x64" ;;
    *)
        echo "❌ Unsupported platform: $OS-$ARCH"
        echo "   Build from source: cargo build --release"
        exit 1
        ;;
esac

# Get latest release URL
BASE="https://github.com/$REPO/releases/latest/download"
echo "   Downloading from $BASE..."

mkdir -p "$INSTALL_DIR"

for BIN in agent-broker broker-mcp; do
    URL="$BASE/$BIN-$SUFFIX"
    DEST="$INSTALL_DIR/$BIN"
    curl -fsSL "$URL" -o "$DEST"
    chmod +x "$DEST"
    echo "   ✅ $BIN → $DEST"
done

echo ""
echo "✅ Installed to $INSTALL_DIR"
echo ""
echo "   Start the broker:  $INSTALL_DIR/agent-broker"
echo "   MCP server:        $INSTALL_DIR/broker-mcp"
