#!/bin/sh
# Tuora Installer Script
# Usage: curl -fsSL https://get.runtuora.com/install.sh | sh

set -e

# Configuration
REPO="tuora/tuora"
# User-level installation only (no sudo required)
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${VERSION:-latest}"

# Detect OS and Architecture
detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)
    
    case "$OS" in
        linux)
            case "$ARCH" in
                x86_64) PLATFORM="x86_64-unknown-linux-musl" ;;
                aarch64|arm64) PLATFORM="aarch64-unknown-linux-musl" ;;
                *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
            esac
            ;;
        darwin)
            case "$ARCH" in
                x86_64) PLATFORM="x86_64-apple-darwin" ;;
                arm64) PLATFORM="aarch64-apple-darwin" ;;
                *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
            esac
            ;;
        *)
            echo "Unsupported OS: $OS"
            exit 1
            ;;
    esac
}

# Download binary
download() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- "$1"
    else
        echo "Error: curl or wget is required"
        exit 1
    fi
}

# Main installation
main() {
    echo "Installing Tuora..."
    
    detect_platform
    echo "Detected platform: $PLATFORM"
    
    # Determine download URL
    if [ "$VERSION" = "latest" ]; then
        DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/tuora-${PLATFORM}"
    else
        DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/tuora-${PLATFORM}"
    fi
    
    echo "Downloading from: $DOWNLOAD_URL"
    
    # Create temp directory
    TMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TMP_DIR"' EXIT
    
    # Download binary
    download "$DOWNLOAD_URL" > "$TMP_DIR/tuora"
    
    # Verify binary
    if ! file "$TMP_DIR/tuora" | grep -q "executable"; then
        echo "Error: Downloaded file is not a valid executable"
        exit 1
    fi
    
    # Make executable
    chmod +x "$TMP_DIR/tuora"
    
    # Ensure install directory exists
    if [ ! -d "$INSTALL_DIR" ]; then
        echo "Creating $INSTALL_DIR..."
        mkdir -p "$INSTALL_DIR"
    fi
    
    # Install
    echo "Installing to $INSTALL_DIR/tuora"
    mv "$TMP_DIR/tuora" "$INSTALL_DIR/tuora"
    
    # Verify binary exists
    if [ -f "$INSTALL_DIR/tuora" ]; then
        VERSION_INSTALLED=$("$INSTALL_DIR/tuora" --version 2>/dev/null || echo "unknown")
        echo ""
        echo "✓ Tuora installed successfully!"
        echo "  Version: $VERSION_INSTALLED"
        echo "  Location: $INSTALL_DIR/tuora"
        echo ""
        
        # Check if install dir is in PATH
        case ":$PATH:" in
            *":$INSTALL_DIR:"*)
                echo "Get started:"
                echo "  tuora init          # Configure your API key"
                echo "  tuora watch         # Scan and watch current directory"
                ;;
            *)
                echo "⚠️  $INSTALL_DIR is not in your PATH"
                echo ""
                echo "Add to your shell profile:"
                echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
                echo ""
                echo "Then run:"
                echo "  tuora init          # Configure your API key"
                echo "  tuora watch         # Scan and watch current directory"
                ;;
        esac
    else
        echo "Error: Installation failed. Could not write to $INSTALL_DIR"
        exit 1
    fi
}

# Run main function
main
