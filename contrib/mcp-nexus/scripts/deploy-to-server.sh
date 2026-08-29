#!/usr/bin/env bash
# Deploy MCP Nexus to a remote server as a systemd service.
# This script is meant to be run from the mcp-nexus project root.
#
# Usage: ./scripts/deploy-to-server.sh <SSH_HOST> [SSH_USER] [SSH_PORT]
#
# Example: ./scripts/deploy-to-server.sh 149.102.155.77 root 22

set -euo pipefail

if [ -f ".env" ]; then
    set -a
    # shellcheck disable=SC1091
    source .env
    set +a
fi

HOST="${1:-${NEXUS_SSH_HOST:-}}"
USER="${2:-${NEXUS_SSH_USER:-root}}"
PORT="${3:-${NEXUS_SSH_PORT:-22}}"
REMOTE_DIR="${NEXUS_DEPLOY_REMOTE_DIR:-/root/mcp-nexus}"

if [ -z "$HOST" ]; then
    echo "Usage: deploy-to-server.sh <SSH_HOST> [SSH_USER] [SSH_PORT]" >&2
    echo "Or set NEXUS_SSH_HOST in .env" >&2
    exit 1
fi

SSH_OPTS=(-o StrictHostKeyChecking=no -p "$PORT")
if [ -n "${NEXUS_SSH_KEY_PATH:-}" ]; then
    SSH_OPTS+=(-i "$NEXUS_SSH_KEY_PATH")
fi

SSH=(ssh "${SSH_OPTS[@]}" "$USER@$HOST")
SCP=(scp -o StrictHostKeyChecking=no -P "$PORT")
if [ -n "${NEXUS_SSH_KEY_PATH:-}" ]; then
    SCP+=(-i "$NEXUS_SSH_KEY_PATH")
fi

echo "━━━ Deploying MCP Nexus to $USER@$HOST:$PORT ━━━"

CURRENT_BIND_HOST="$("${SSH[@]}" "systemctl cat mcp-nexus --no-pager 2>/dev/null | sed -n 's/.*--host \\([^ ]*\\).*/\\1/p' | tail -n1" || true)"
CURRENT_BIND_PORT="$("${SSH[@]}" "systemctl cat mcp-nexus --no-pager 2>/dev/null | sed -n 's/.*--port \\([0-9][0-9]*\\).*/\\1/p' | tail -n1" || true)"
BIND_HOST="${NEXUS_DEPLOY_BIND_HOST:-${CURRENT_BIND_HOST:-127.0.0.1}}"
BIND_PORT="${NEXUS_DEPLOY_BIND_PORT:-${CURRENT_BIND_PORT:-${NEXUS_PORT:-8766}}}"
TOOL_ALIAS_BASE="${NEXUS_TOOL_ALIAS_BASE:-/mcp-nexus}"

# 1. Create remote directory
"${SSH[@]}" "mkdir -p $REMOTE_DIR"

# 2. Sync code (excluding .env, .git, __pycache__)
rsync -avz --delete \
    --exclude='.env' \
    --exclude='.git' \
    --exclude='.mcp-nexus' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='.venv' \
    --exclude='node_modules' \
    --exclude='.DS_Store' \
    --exclude='._*' \
    --exclude='.pytest_cache' \
    --exclude='.mypy_cache' \
    --exclude='.ruff_cache' \
    --exclude='*.egg-info' \
    -e "ssh ${NEXUS_SSH_KEY_PATH:+-i $NEXUS_SSH_KEY_PATH }-o StrictHostKeyChecking=no -p $PORT" \
    ./ "$USER@$HOST:$REMOTE_DIR/"

echo "✓ Code synced"

# 3. Setup venv & install
"${SSH[@]}" "cd $REMOTE_DIR && python3 -m venv .venv && .venv/bin/pip install -q -e ."
echo "✓ Dependencies installed"

if [ -z "${NEXUS_PUBLIC_BASE_URL:-}" ]; then
    echo "⚠ NEXUS_PUBLIC_BASE_URL is not set. ChatGPT Connect / OAuth discovery routes will not be externally advertised."
fi

# 4. Copy .env if it exists locally and not on remote
if [ -f ".env" ]; then
    "${SSH[@]}" "test -f $REMOTE_DIR/.env" 2>/dev/null || "${SCP[@]}" .env "$USER@$HOST:$REMOTE_DIR/.env"
fi

# 5. Create systemd service
"${SSH[@]}" "cat > /etc/systemd/system/mcp-nexus.service << 'UNIT'
[Unit]
Description=MCP Nexus — Remote Server Management via MCP
After=network.target
Wants=network-online.target
StartLimitBurst=10
StartLimitIntervalSec=120

[Service]
Type=simple
User=root
WorkingDirectory=$REMOTE_DIR
ExecStart=$REMOTE_DIR/.venv/bin/python -m mcp_nexus serve --host $BIND_HOST --port $BIND_PORT
Restart=always
RestartSec=3
OOMScoreAdjust=-500
LimitNOFILE=65535
StandardOutput=journal
StandardError=journal
EnvironmentFile=$REMOTE_DIR/.env

[Install]
WantedBy=multi-user.target
UNIT"

echo "✓ Systemd service created"

# 6. Add nginx location block (if nginx exists)
"${SSH[@]}" "if command -v nginx &>/dev/null; then
    # Surface the latest proxy snippet when the public config is missing any required Nexus routes.
    if ! grep -q 'mcp/nexus' /etc/nginx/sites-enabled/* 2>/dev/null || \
       ! grep -q '${TOOL_ALIAS_BASE#"/"}' /etc/nginx/sites-enabled/* 2>/dev/null || \
       ! grep -q 'tool-registry/nexus' /etc/nginx/sites-enabled/* 2>/dev/null || \
       ! grep -q '/.well-known/nexus-tool-registry' /etc/nginx/sites-enabled/* 2>/dev/null; then
        echo '
    # MCP Nexus
    location /mcp/nexus {
        proxy_pass http://127.0.0.1:$BIND_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \"upgrade\";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
        proxy_buffering off;
    }

    # Legacy MCP path compatibility
    location /mcp {
        proxy_pass http://127.0.0.1:$BIND_PORT/mcp/nexus;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \"upgrade\";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
        proxy_buffering off;
    }

    # Stable HTTP tool-alias surface from the Nexus registry (optional caller fallback).
    location ${TOOL_ALIAS_BASE} {
        proxy_pass http://127.0.0.1:$BIND_PORT;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
        proxy_buffering off;
    }

    location /health/nexus {
        proxy_pass http://127.0.0.1:$BIND_PORT/health;
        proxy_read_timeout 5s;
    }

    location /ready/nexus {
        proxy_pass http://127.0.0.1:$BIND_PORT/ready;
        proxy_read_timeout 5s;
    }

    location /version/nexus {
        proxy_pass http://127.0.0.1:$BIND_PORT/version;
        proxy_read_timeout 5s;
    }

    location /info/nexus {
        proxy_pass http://127.0.0.1:$BIND_PORT/info;
        proxy_read_timeout 5s;
    }

    location /tool-registry {
        proxy_pass http://127.0.0.1:$BIND_PORT/tool-registry;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 5s;
    }

    location /tool-registry/nexus {
        proxy_pass http://127.0.0.1:$BIND_PORT/tool-registry/nexus;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 5s;
    }

    location = /.well-known/nexus-tool-registry {
        proxy_pass http://127.0.0.1:$BIND_PORT/.well-known/nexus-tool-registry;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 5s;
    }

    location = /.well-known/oauth-authorization-server {
        proxy_pass http://127.0.0.1:$BIND_PORT/.well-known/oauth-authorization-server;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location /.well-known/oauth-protected-resource/ {
        proxy_pass http://127.0.0.1:$BIND_PORT/.well-known/oauth-protected-resource/;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location = /authorize {
        proxy_pass http://127.0.0.1:$BIND_PORT/authorize;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location = /token {
        proxy_pass http://127.0.0.1:$BIND_PORT/token;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location = /register {
        proxy_pass http://127.0.0.1:$BIND_PORT/register;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location = /oauth/consent {
        proxy_pass http://127.0.0.1:$BIND_PORT/oauth/consent;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location = /oauth/token {
        proxy_pass http://127.0.0.1:$BIND_PORT/oauth/token;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 10s;
    }' >> /tmp/nexus_nginx_snippet.txt
        echo '→ Nginx snippet saved to /tmp/nexus_nginx_snippet.txt'
        echo '  Add it inside the server {} block of your nginx config'
    fi
fi"

# 7. Enable and start
"${SSH[@]}" "systemctl daemon-reload && systemctl enable mcp-nexus && systemctl restart mcp-nexus"
echo "✓ Service started"

# 8. Verify
sleep 2
"${SSH[@]}" "systemctl is-active mcp-nexus && echo '✓ MCP Nexus is running' || echo '✗ Service failed to start'"

echo
echo "━━━ Deployment complete ━━━"
echo "  MCP endpoint: https://your-domain.com/mcp/nexus"
echo "  Health check: https://your-domain.com/health/nexus"
echo "  Logs: ssh $USER@$HOST journalctl -u mcp-nexus -f"
echo "  Important: if another frontend app owns the same public origin, proxy /.well-known, /authorize,"
echo "             /token, /register, /oauth/consent, and /mcp/nexus to MCP Nexus on that same origin."
