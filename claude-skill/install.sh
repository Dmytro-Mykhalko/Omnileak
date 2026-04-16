#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OMNILEAK_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SKILL_SRC="$SCRIPT_DIR/scan-secrets.md"
SKILL_SUB_DIR="$SCRIPT_DIR/scan-secrets"
COMMANDS_DIR="$HOME/.claude/commands"
SKILL_DST="$COMMANDS_DIR/scan-secrets.md"
SKILL_SUB_DST="$COMMANDS_DIR/scan-secrets"
SHELL_RC=""

# Detect shell config file — check the user's login shell ($SHELL),
# not the interpreter running this script (always bash due to shebang).
detect_shell_rc() {
    case "$(basename "$SHELL" 2>/dev/null)" in
        zsh)  echo "$HOME/.zshrc" ;;
        bash) echo "$HOME/.bashrc" ;;
        fish) echo "$HOME/.config/fish/config.fish" ;;
        *)    echo "" ;;
    esac
}

SHELL_RC="$(detect_shell_rc)"

echo "============================================="
echo "  Omnileak — Claude Code Skill Installer"
echo "============================================="
echo ""
echo "  Omnileak path:  $OMNILEAK_DIR"
echo "  Skill source:   $SKILL_SRC"
echo "  Install target: $SKILL_DST"
if [ -n "$SHELL_RC" ]; then
    echo "  Shell config:   $SHELL_RC"
fi
echo ""

# 1. Verify skill file exists
if [ ! -f "$SKILL_SRC" ]; then
    echo "[ERROR] Skill file not found: $SKILL_SRC"
    exit 1
fi

# 2. Create commands directory
mkdir -p "$COMMANDS_DIR"

# 3. Copy skill files (main + sub-directory)
cp "$SKILL_SRC" "$SKILL_DST"
echo "[+] Installed skill to $SKILL_DST"

if [ -d "$SKILL_SUB_DIR" ]; then
    mkdir -p "$SKILL_SUB_DST"
    cp "$SKILL_SUB_DIR"/*.md "$SKILL_SUB_DST/"
    echo "[+] Installed sub-files to $SKILL_SUB_DST/"
fi

# 4. Set OMNILEAK_HOME environment variable
if [ -z "$SHELL_RC" ]; then
    echo "[!] Could not detect shell config file."
    echo "    Add this manually to your shell profile:"
    echo "    export OMNILEAK_HOME=\"$OMNILEAK_DIR\""
elif grep -q "OMNILEAK_HOME" "$SHELL_RC" 2>/dev/null; then
    echo "[i] OMNILEAK_HOME already set in $SHELL_RC"
else
    # fish uses a different syntax
    if [[ "$SHELL_RC" == *"fish"* ]]; then
        mkdir -p "$(dirname "$SHELL_RC")"
        echo "" >> "$SHELL_RC"
        echo "# Omnileak — secrets scanner for Claude Code" >> "$SHELL_RC"
        echo "set -gx OMNILEAK_HOME \"$OMNILEAK_DIR\"" >> "$SHELL_RC"
    else
        echo "" >> "$SHELL_RC"
        echo "# Omnileak — secrets scanner for Claude Code" >> "$SHELL_RC"
        echo "export OMNILEAK_HOME=\"$OMNILEAK_DIR\"" >> "$SHELL_RC"
    fi
    echo "[+] Added OMNILEAK_HOME=$OMNILEAK_DIR to $SHELL_RC"
fi

echo ""
echo "============================================="
echo "  Done!"
echo ""
echo "  Usage:  Open Claude Code and type:"
echo "    /scan-secrets                                — scan cwd"
echo "    /scan-secrets --repo ~/Projects/app          — scan a specific repo"
echo "    /scan-secrets --repo ~/Projects/app --out /tmp/out"
echo ""
if [ -n "$SHELL_RC" ]; then
    echo "  If this is a fresh install, restart your"
    echo "  terminal or run:  source $SHELL_RC"
else
    echo "  If this is a fresh install, restart your"
    echo "  terminal after setting OMNILEAK_HOME."
fi
echo "============================================="
