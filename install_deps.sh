#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$SCRIPT_DIR/bin"

mkdir -p "$BIN_DIR"
export PATH="$BIN_DIR:$PATH"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

if [ "$ARCH" = "x86_64" ]; then
    ARCH_ALT="amd64"
elif [ "$ARCH" = "arm64" ] || [ "$ARCH" = "aarch64" ]; then
    ARCH_ALT="arm64"
else
    ARCH_ALT="$ARCH"
fi

echo "============================================="
echo "  Multi-Tool Scanner — Dependency Installer"
echo "  OS: $OS | Arch: $ARCH"
echo "============================================="
echo ""

# --------------------------------------------------
# 1. Gitleaks
# --------------------------------------------------
if command -v gitleaks &> /dev/null; then
    echo "[✓] Gitleaks is already installed: $(command -v gitleaks)"
else
    echo "[+] Installing Gitleaks to $BIN_DIR ..."
    GITLEAKS_VERSION="8.18.2"
    if [ "$OS" = "darwin" ]; then
        GL_OS="darwin"
    else
        GL_OS="linux"
    fi
    # Gitleaks uses x64 not amd64
    GL_ARCH="$ARCH_ALT"
    if [ "$GL_ARCH" = "amd64" ]; then GL_ARCH="x64"; fi
    GL_URL="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${GL_OS}_${GL_ARCH}.tar.gz"
    curl -sSL "$GL_URL" -o /tmp/gitleaks.tar.gz
    tar -xzf /tmp/gitleaks.tar.gz -C /tmp gitleaks
    mv /tmp/gitleaks "$BIN_DIR/"
    chmod +x "$BIN_DIR/gitleaks"
    rm -f /tmp/gitleaks.tar.gz
    echo "    Installed gitleaks v${GITLEAKS_VERSION}"
fi

# --------------------------------------------------
# 2. Trufflehog
# --------------------------------------------------
if command -v trufflehog &> /dev/null; then
    echo "[✓] Trufflehog is already installed: $(command -v trufflehog)"
else
    echo "[+] Installing Trufflehog to $BIN_DIR ..."
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b "$BIN_DIR"
    echo "    Installed trufflehog"
fi

# --------------------------------------------------
# 3. Detect Secrets (Python package — installed via requirements.txt)
# --------------------------------------------------
if command -v detect-secrets &> /dev/null; then
    echo "[✓] Detect Secrets is already installed: $(command -v detect-secrets)"
else
    echo "[i] Detect Secrets will be installed via pip (requirements.txt)"
fi

# --------------------------------------------------
# 4. Titus (replaces Noseyparker)
# --------------------------------------------------
if command -v titus &> /dev/null; then
    echo "[✓] Titus is already installed: $(command -v titus)"
else
    echo "[+] Installing Titus to $BIN_DIR ..."
    TITUS_VERSION="1.1.14"
    TITUS_FILE="titus-${OS}-${ARCH_ALT}"
    TITUS_URL="https://github.com/praetorian-inc/titus/releases/download/v${TITUS_VERSION}/${TITUS_FILE}"
    curl -sSL "$TITUS_URL" -o "$BIN_DIR/titus"
    chmod +x "$BIN_DIR/titus"
    echo "    Installed titus v${TITUS_VERSION}"
fi

# --------------------------------------------------
# 5. Python dependencies
# --------------------------------------------------
echo ""
echo "[+] Installing Python requirements ..."
pip install -r "$SCRIPT_DIR/requirements.txt"

echo ""
echo "============================================="
echo "  All dependencies ready!"
echo "  Local binaries: $BIN_DIR"
echo "============================================="
