#!/usr/bin/env bash
set -euo pipefail

if [ ! -t 0 ]; then
  exec </dev/tty
fi

REPO_URL="https://github.com/Ogglord/opn-mcp.git"
INSTALL_DIR="$PWD/opn-mcp"

# ── colours ───────────────────────────────────────────────────────────────────
red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
bold()  { printf '\033[1m%s\033[0m\n' "$*"; }
die()   { red "Error: $*"; exit 1; }

# ── dependency check ──────────────────────────────────────────────────────────
command -v git &>/dev/null || die "git is required but not installed"
command -v uv  &>/dev/null || die "uv is required but not installed — see https://docs.astral.sh/uv/getting-started/installation/"

# ── detect if running via curl | bash (not inside cloned repo) ────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-"."}")" 2>/dev/null && pwd || echo "")"
if [ ! -f "$SCRIPT_DIR/pyproject.toml" ]; then
  # Running via curl | bash — need to clone first
  bold "This will:"
  echo "  1. Clone opn-mcp into $INSTALL_DIR"
  echo "  2. Install Python dependencies via uv"
  echo "  3. Write .mcp.json (Claude Code) and opencode.json (OpenCode) into $INSTALL_DIR"
  echo ""
  printf "Continue? [Y/n] "
  read -r answer
  case "${answer:-Y}" in
    [Yy]*) ;;
    *) echo "Aborted."; exit 0 ;;
  esac

  git clone "$REPO_URL" "$INSTALL_DIR"
  cd "$INSTALL_DIR"
  SCRIPT_DIR="$INSTALL_DIR"
else
  cd "$SCRIPT_DIR"
  INSTALL_DIR="$SCRIPT_DIR"
  bold "This will:"
  echo "  1. Install Python dependencies via uv"
  echo "  2. Write .mcp.json (Claude Code) and opencode.json (OpenCode) into $INSTALL_DIR"
  echo ""
  printf "Continue? [Y/n] "
  read -r answer
  case "${answer:-Y}" in
    [Yy]*) ;;
    *) echo "Aborted."; exit 0 ;;
  esac
fi

# ── install deps ──────────────────────────────────────────────────────────────
bold "Installing Python dependencies..."
uv sync

# ── prompt for credentials ────────────────────────────────────────────────────
bold "\nOPNsense connection details"
read -rp "  OPN_HOSTS (comma-separated, e.g. http://10.10.10.1): " OPN_HOSTS
read -rp "  OPN_KEY: " OPN_KEY
read -rsp "  OPN_SECRET: " OPN_SECRET; echo
read -rp "  OPN_SSH_KEY (path to SSH private key, or leave blank for agent): " OPN_SSH_KEY
read -rsp "  NTOPNG_PASSWORD (or leave blank): " NTOPNG_PASSWORD; echo

# ── Claude Code (.mcp.json) ───────────────────────────────────────────────────
bold "\nWriting Claude Code config → $INSTALL_DIR/.mcp.json"
cat > "$INSTALL_DIR/.mcp.json" <<EOF
{
  "mcpServers": {
    "opnsense": {
      "type": "stdio",
      "command": "uv",
      "args": ["--directory", "$INSTALL_DIR", "run", "opn-mcp"],
      "env": {
        "MCP_ENV": "prod",
        "OPN_HOSTS": "$OPN_HOSTS",
        "OPN_KEY": "$OPN_KEY",
        "OPN_SECRET": "$OPN_SECRET",
        "OPN_SSH_KEY": "$OPN_SSH_KEY",
        "NTOPNG_PASSWORD": "$NTOPNG_PASSWORD"
      }
    }
  }
}
EOF
green "  ✓ .mcp.json written"

# ── OpenCode (opencode.json) ──────────────────────────────────────────────────
bold "Writing OpenCode config → $INSTALL_DIR/opencode.json"
cat > "$INSTALL_DIR/opencode.json" <<EOF
{
  "\$schema": "https://opencode.ai/config.json",
  "mcp": {
    "opnsense": {
      "type": "local",
      "command": ["uv", "--directory", "$INSTALL_DIR", "run", "opn-mcp"],
      "environment": {
        "MCP_ENV": "prod",
        "OPN_HOSTS": "$OPN_HOSTS",
        "OPN_KEY": "$OPN_KEY",
        "OPN_SECRET": "$OPN_SECRET",
        "OPN_SSH_KEY": "$OPN_SSH_KEY",
        "NTOPNG_PASSWORD": "$NTOPNG_PASSWORD"
      }
    }
  }
}
EOF
green "  ✓ opencode.json written"

# ── verify ────────────────────────────────────────────────────────────────────
bold "\nVerifying MCP server starts..."
if echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}' \
    | OPN_HOSTS="$OPN_HOSTS" OPN_KEY="$OPN_KEY" OPN_SECRET="$OPN_SECRET" \
      uv --directory "$INSTALL_DIR" run opn-mcp 2>/dev/null | grep -q '"result"'; then
  green "  ✓ MCP server responds"
else
  red "  ✗ MCP server did not respond — check credentials and OPNsense connectivity"
fi

bold "\nDone. Open Claude Code or OpenCode from $INSTALL_DIR to load the MCP server."
