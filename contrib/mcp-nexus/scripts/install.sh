#!/usr/bin/env bash
# MCP Nexus — Quick Install Script
# Usage: curl -sSL https://raw.githubusercontent.com/farukalpay/mcp-nexus/main/scripts/install.sh | bash

set -euo pipefail

GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}  MCP Nexus — Remote Server Management via MCP  ${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo

# Check Python version
PYTHON=$(command -v python3 || true)
if [ -z "$PYTHON" ]; then
    echo -e "${RED}Error: Python 3.10+ is required${NC}"
    exit 1
fi

PY_VERSION=$($PYTHON -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$($PYTHON -c "import sys; print(sys.version_info.major)")
PY_MINOR=$($PYTHON -c "import sys; print(sys.version_info.minor)")

if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]; }; then
    echo -e "${RED}Error: Python 3.10+ required (found $PY_VERSION)${NC}"
    exit 1
fi
echo -e "${GREEN}✓${NC} Python $PY_VERSION"

# Install layout
INSTALL_DIR="${MCP_NEXUS_DIR:-$HOME/mcp-nexus}"
PIP_SPEC="${MCP_NEXUS_PIP_SPEC:-git+https://github.com/farukalpay/mcp-nexus.git}"
INIT_ARGS="${MCP_NEXUS_INIT_ARGS:-}"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"
echo "Using install directory: $INSTALL_DIR"

# Virtual environment
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    $PYTHON -m venv .venv
fi

source .venv/bin/activate
echo -e "${GREEN}✓${NC} Virtual environment"

# Package install
python -m pip install -U pip >/dev/null
python -m pip install -U "$PIP_SPEC"
echo -e "${GREEN}✓${NC} Installed package from $PIP_SPEC"

# Scaffold setup
if [ ! -f ".env" ]; then
    # shellcheck disable=SC2086
    mcp-nexus init "$INSTALL_DIR" $INIT_ARGS
    echo -e "${GREEN}✓${NC} Runtime scaffold generated"
else
    echo -e "${GREEN}✓${NC} .env exists"
fi

echo
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  Installation complete!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo
echo "  Quick start:"
echo "    cd $INSTALL_DIR"
echo "    source .venv/bin/activate"
echo "    nano .env                        # Set your server credentials"
echo "    mcp-nexus serve                  # Start MCP server"
echo
echo "  Health check:"
echo "    mcp-nexus health"
echo
