#!/usr/bin/env bash
# scripts/tpot_setup.sh
# Full T-Pot CE installation script for AWS EC2 (Ubuntu 22.04 LTS).
#
# This script is uploaded to S3 by the CI pipeline and downloaded/executed
# by user_data.sh at instance launch.
#
# What this script does:
#   1. Install system prerequisites and Docker
#   2. Clone T-Pot CE and install it in HIVE (standalone) mode
#   3. Restrict T-Pot nginx to localhost via docker-compose.override.yml
#   4. Install and configure oauth2-proxy for SAML-compatible SSO via
#      Microsoft Entra ID OIDC, listening on port 443
#   5. Configure sysctl / kernel parameters recommended by T-Pot
#   6. Enable and start all services

set -euo pipefail

LOG="/var/log/tpot-setup.log"
exec > >(tee -a "$LOG") 2>&1

# ---------------------------------------------------------------------------
# Configuration — sourced from environment variables set by user_data.sh
# ---------------------------------------------------------------------------
TPOT_HOSTNAME="${TPOT_HOSTNAME:-tpot}"
TPOT_WEB_USER="${TPOT_WEB_USER:-admin}"
TPOT_WEB_PASSWORD="${TPOT_WEB_PASSWORD:?TPOT_WEB_PASSWORD is required}"
TPOT_FQDN="${TPOT_FQDN:?TPOT_FQDN is required}"

AZURE_TENANT_ID="${AZURE_TENANT_ID:?AZURE_TENANT_ID is required}"
AZURE_CLIENT_ID="${AZURE_CLIENT_ID:?AZURE_CLIENT_ID is required}"
AZURE_CLIENT_SECRET="${AZURE_CLIENT_SECRET:?AZURE_CLIENT_SECRET is required}"
OAUTH2_COOKIE_SECRET="${OAUTH2_COOKIE_SECRET:?OAUTH2_COOKIE_SECRET is required}"

TPOT_REPO="https://github.com/telekom-security/tpotce"
TPOT_INSTALL_DIR="/home/tsec/tpotce"

OAUTH2_PROXY_VERSION="7.6.0"
OAUTH2_PROXY_BIN="/usr/local/bin/oauth2-proxy"
OAUTH2_PROXY_CONF_DIR="/etc/oauth2-proxy"

log() { echo "[$(date -u +%FT%TZ)] $*"; }

# ---------------------------------------------------------------------------
# 1. System prerequisites
# ---------------------------------------------------------------------------
log "=== Phase 1: System prerequisites ==="

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get upgrade -y --no-install-recommends
apt-get install -y --no-install-recommends \
  git \
  curl \
  wget \
  vim \
  htop \
  net-tools \
  dnsutils \
  jq \
  apache2-utils \
  openssl \
  iptables-persistent \
  python3 \
  python3-pip \
  ca-certificates \
  gnupg \
  lsb-release

log "System prerequisites installed"

# ---------------------------------------------------------------------------
# 2. Kernel / sysctl tuning recommended by T-Pot
# ---------------------------------------------------------------------------
log "=== Phase 2: Kernel tuning ==="

cat > /etc/sysctl.d/99-tpot.conf << 'SYSCTL'
# Recommended by T-Pot CE for honeypot workloads
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
net.core.somaxconn=65535
net.ipv4.tcp_max_syn_backlog=65535
fs.file-max=1048576
vm.max_map_count=262144
SYSCTL

sysctl --system
log "Kernel parameters applied"

# ---------------------------------------------------------------------------
# 3. Docker installation
# ---------------------------------------------------------------------------
log "=== Phase 3: Docker ==="

if ! command -v docker &>/dev/null; then
  curl -fsSL https://get.docker.com | sh
fi

systemctl enable docker
systemctl start docker

# Verify Docker Compose v2 (ships with Docker Desktop / Compose plugin)
docker compose version || {
  log "Docker Compose v2 not found; installing plugin..."
  COMPOSE_VERSION="2.24.5"
  mkdir -p /usr/local/lib/docker/cli-plugins
  curl -fsSL \
    "https://github.com/docker/compose/releases/download/v${COMPOSE_VERSION}/docker-compose-linux-x86_64" \
    -o /usr/local/lib/docker/cli-plugins/docker-compose
  chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
}

log "Docker $(docker --version)"
log "Docker Compose $(docker compose version)"

# ---------------------------------------------------------------------------
# 4. Create T-Pot user (tsec) — mirrors the T-Pot installer's convention
# ---------------------------------------------------------------------------
log "=== Phase 4: Create tsec user ==="

if ! id tsec &>/dev/null; then
  useradd -m -s /bin/bash -G docker,sudo tsec
  log "User 'tsec' created"
else
  usermod -aG docker tsec 2>/dev/null || true
  log "User 'tsec' already exists"
fi

# ---------------------------------------------------------------------------
# 5. Clone and install T-Pot CE
# ---------------------------------------------------------------------------
log "=== Phase 5: Clone T-Pot CE ==="

if [ ! -d "$TPOT_INSTALL_DIR" ]; then
  git clone --depth 1 "$TPOT_REPO" "$TPOT_INSTALL_DIR"
  chown -R tsec:tsec "$TPOT_INSTALL_DIR"
else
  log "T-Pot directory already exists at $TPOT_INSTALL_DIR; skipping clone"
fi

log "=== Phase 5b: Run T-Pot installer (HIVE/standalone mode) ==="

# The T-Pot installer accepts:
#   -s  suppress confirmations (non-interactive)
#   -t  installation type  (h = HIVE = full standalone with WebUI)
#   -u  web UI username
#   -p  web UI password
#
# We run it as tsec via sudo to match T-Pot's expected ownership model.
cd "$TPOT_INSTALL_DIR"

# Export to make them visible inside the sudo environment
export TPOT_MYUSER="$TPOT_WEB_USER"
export TPOT_MYPASSWORD="$TPOT_WEB_PASSWORD"

sudo -u tsec bash -c "
  cd '$TPOT_INSTALL_DIR'
  ./install.sh -s -t h -u '$TPOT_WEB_USER' -p '$TPOT_WEB_PASSWORD'
" || {
  log "WARNING: T-Pot installer exited non-zero. Checking if services are running..."
  # The installer sometimes exits 1 after a successful install when it cannot
  # reboot the system.  Check the compose stack is present before failing.
  if [ ! -f "$TPOT_INSTALL_DIR/.env" ]; then
    log "ERROR: T-Pot install appears to have failed (.env not found)"
    exit 1
  fi
  log "T-Pot .env found — treating as successful install"
}

log "T-Pot CE installed"

# ---------------------------------------------------------------------------
# 6. Identify the compose directory used by T-Pot
#    T-Pot 24.x may place compose files in different subdirectories.
# ---------------------------------------------------------------------------
log "=== Phase 6: Locate compose files ==="

COMPOSE_DIR=""
for candidate in \
  "$TPOT_INSTALL_DIR" \
  "$TPOT_INSTALL_DIR/docker" \
  "$TPOT_INSTALL_DIR/compose"
do
  if ls "$candidate"/docker-compose*.yml &>/dev/null 2>&1 \
     || ls "$candidate"/compose*.yml &>/dev/null 2>&1; then
    COMPOSE_DIR="$candidate"
    break
  fi
done

if [ -z "$COMPOSE_DIR" ]; then
  log "ERROR: Could not locate T-Pot compose files under $TPOT_INSTALL_DIR"
  exit 1
fi

log "Compose directory: $COMPOSE_DIR"

# ---------------------------------------------------------------------------
# 7. docker-compose.override.yml
#    Restrict T-Pot nginx to localhost only so that external traffic MUST
#    pass through oauth2-proxy on port 443.
# ---------------------------------------------------------------------------
log "=== Phase 7: Write docker-compose.override.yml ==="

cat > "$COMPOSE_DIR/docker-compose.override.yml" << 'OVERRIDE'
# docker-compose.override.yml
# Applied on top of T-Pot's main compose file.
# Binds the nginx web UI ports to 127.0.0.1 so they are not directly
# reachable from the internet; all external web UI access goes through
# the oauth2-proxy service on port 443.
services:
  nginx:
    ports:
      - "127.0.0.1:64297:64297"
      - "127.0.0.1:64295:64295"
OVERRIDE

chown tsec:tsec "$COMPOSE_DIR/docker-compose.override.yml"
log "docker-compose.override.yml written"

# ---------------------------------------------------------------------------
# 8. Install oauth2-proxy
#    oauth2-proxy sits in front of T-Pot's nginx and enforces Microsoft
#    Entra ID OIDC (OpenID Connect) authentication.
#
#    Microsoft Entra ID supports both SAML 2.0 and OIDC. OIDC is the
#    recommended modern protocol and is functionally equivalent for web
#    application SSO.  The Entra ID App Registration must be configured
#    as an OIDC/OAuth2 app (not a SAML Enterprise Application).
# ---------------------------------------------------------------------------
log "=== Phase 8: Install oauth2-proxy ==="

OAUTH2_ARCH="linux-amd64"
OAUTH2_TARBALL="oauth2-proxy-v${OAUTH2_PROXY_VERSION}.${OAUTH2_ARCH}.tar.gz"
OAUTH2_URL="https://github.com/oauth2-proxy/oauth2-proxy/releases/download/v${OAUTH2_PROXY_VERSION}/${OAUTH2_TARBALL}"

curl -fsSL "$OAUTH2_URL" -o /tmp/oauth2-proxy.tar.gz
tar -xzf /tmp/oauth2-proxy.tar.gz -C /tmp
install -m 755 /tmp/oauth2-proxy-v${OAUTH2_PROXY_VERSION}.${OAUTH2_ARCH}/oauth2-proxy \
  "$OAUTH2_PROXY_BIN"
rm -rf /tmp/oauth2-proxy.tar.gz /tmp/oauth2-proxy-v*

log "oauth2-proxy $($OAUTH2_PROXY_BIN --version 2>&1 | head -1) installed"

# ---------------------------------------------------------------------------
# 9. Generate self-signed TLS certificate for oauth2-proxy
#    In production, replace with a certificate from your PKI or Let's Encrypt.
# ---------------------------------------------------------------------------
log "=== Phase 9: TLS certificate ==="

mkdir -p "$OAUTH2_PROXY_CONF_DIR"

openssl req -x509 -newkey rsa:4096 \
  -keyout "$OAUTH2_PROXY_CONF_DIR/tpot.key" \
  -out    "$OAUTH2_PROXY_CONF_DIR/tpot.crt" \
  -days 825 \
  -nodes \
  -subj "/CN=${TPOT_FQDN}/O=T-Pot Honeypot/C=US" \
  -addext "subjectAltName=DNS:${TPOT_FQDN},IP:$(curl -sf http://169.254.169.254/latest/meta-data/public-ipv4 || echo 127.0.0.1)"

chmod 640 "$OAUTH2_PROXY_CONF_DIR/tpot.key"
log "Self-signed TLS certificate generated (CN=${TPOT_FQDN})"

# ---------------------------------------------------------------------------
# 10. Write oauth2-proxy configuration file
# ---------------------------------------------------------------------------
log "=== Phase 10: oauth2-proxy configuration ==="

cat > "$OAUTH2_PROXY_CONF_DIR/oauth2-proxy.cfg" << EOF
# oauth2-proxy configuration for T-Pot + Microsoft Entra ID OIDC
#
# Microsoft Entra ID App Registration requirements:
#   - Platform: Web
#   - Redirect URI: https://${TPOT_FQDN}/oauth2/callback
#   - Supported account types: Accounts in this organizational directory
#   - API permissions: openid, profile, email (all delegated)
#
# For SAML 2.0 specifically: Entra ID's OIDC endpoint is the recommended
# path for new application registrations. If your organisation requires
# strict SAML 2.0 protocol, replace this proxy with a SAML SP such as
# SimpleSAMLphp or configure an AWS ALB with Cognito SAML federation.

provider = "oidc"
oidc_issuer_url = "https://login.microsoftonline.com/${AZURE_TENANT_ID}/v2.0"

client_id     = "${AZURE_CLIENT_ID}"
client_secret = "${AZURE_CLIENT_SECRET}"

cookie_secret = "${OAUTH2_COOKIE_SECRET}"
cookie_secure = true

# Upstream: T-Pot nginx on localhost (restricted to loopback by compose override)
upstreams = ["https://127.0.0.1:64297"]
ssl_insecure_skip_verify = true   # T-Pot nginx uses a self-signed cert internally

# Listen on all interfaces on HTTPS port 443
https_address = "0.0.0.0:443"
tls_cert_file = "${OAUTH2_PROXY_CONF_DIR}/tpot.crt"
tls_key_file  = "${OAUTH2_PROXY_CONF_DIR}/tpot.key"

redirect_url = "https://${TPOT_FQDN}/oauth2/callback"

# Allow any authenticated Entra ID user; tighten with email_domains or
# allowed_groups for your organisation's domain / security group.
email_domains = ["*"]

# Skip the intermediate "Sign in with ..." button; redirect immediately.
skip_provider_button = true

# Pass the authenticated user's email/name to upstream as headers.
set_xauthrequest = true
set_authorization_header = true

# Session cookie name
cookie_name = "_tpot_auth"
EOF

chmod 640 "$OAUTH2_PROXY_CONF_DIR/oauth2-proxy.cfg"
log "oauth2-proxy configuration written"

# ---------------------------------------------------------------------------
# 11. oauth2-proxy systemd service
# ---------------------------------------------------------------------------
log "=== Phase 11: oauth2-proxy systemd service ==="

cat > /etc/systemd/system/oauth2-proxy.service << 'UNIT'
[Unit]
Description=oauth2-proxy for T-Pot SAML/OIDC authentication (Microsoft Entra ID)
Documentation=https://oauth2-proxy.github.io/oauth2-proxy/
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/oauth2-proxy --config=/etc/oauth2-proxy/oauth2-proxy.cfg
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=oauth2-proxy

# Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/etc/oauth2-proxy /var/log

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
log "oauth2-proxy systemd unit written"

# ---------------------------------------------------------------------------
# 12. iptables rules — belt-and-suspenders port restriction
#     Block direct external access to T-Pot's web UI port (64297) even if
#     the docker-compose.override binding were to be removed.
# ---------------------------------------------------------------------------
log "=== Phase 12: iptables ==="

# Drop inbound connections to 64297 from non-loopback addresses
iptables -I INPUT -p tcp --dport 64297 ! -s 127.0.0.1 -j DROP

# Persist rules across reboots
netfilter-persistent save || iptables-save > /etc/iptables/rules.v4
log "iptables rules saved"

# ---------------------------------------------------------------------------
# 13. Restart T-Pot with the compose override, then start oauth2-proxy
# ---------------------------------------------------------------------------
log "=== Phase 13: Start services ==="

# Restart T-Pot so the compose override (localhost port binding) takes effect.
# T-Pot may be managed by a systemd unit named tpot or tpotce.
if systemctl is-active --quiet tpot 2>/dev/null; then
  systemctl restart tpot
  log "T-Pot systemd service restarted"
elif systemctl is-active --quiet tpotce 2>/dev/null; then
  systemctl restart tpotce
  log "tpotce systemd service restarted"
else
  log "No tpot/tpotce systemd service found; starting compose stack directly..."
  # Discover the main compose file
  COMPOSE_FILE=$(ls "$COMPOSE_DIR"/docker-compose.yml \
                    "$COMPOSE_DIR"/compose*.yml 2>/dev/null | head -1 || true)
  if [ -n "$COMPOSE_FILE" ]; then
    sudo -u tsec docker compose -f "$COMPOSE_FILE" \
      -f "$COMPOSE_DIR/docker-compose.override.yml" \
      up -d
    log "T-Pot compose stack started"
  else
    log "WARNING: Could not find compose file to restart T-Pot"
  fi
fi

# Start oauth2-proxy
systemctl enable oauth2-proxy
systemctl start oauth2-proxy
log "oauth2-proxy started"

# ---------------------------------------------------------------------------
# 14. Summary
# ---------------------------------------------------------------------------
log "==================================================================="
log "T-Pot installation complete!"
log ""
log "  Web UI (SAML/OIDC SSO): https://${TPOT_FQDN}"
log "  Direct T-Pot UI:        https://localhost:64297  (localhost only)"
log "  SSH management:         port 64295 (T-Pot moves sshd to 64295)"
log ""
log "  Microsoft Entra ID OIDC configuration:"
log "    Tenant:              ${AZURE_TENANT_ID}"
log "    Client ID:           ${AZURE_CLIENT_ID}"
log "    Redirect URI:        https://${TPOT_FQDN}/oauth2/callback"
log ""
log "  TLS certificate:       ${OAUTH2_PROXY_CONF_DIR}/tpot.crt  (self-signed)"
log "  oauth2-proxy config:   ${OAUTH2_PROXY_CONF_DIR}/oauth2-proxy.cfg"
log "  T-Pot install dir:     ${TPOT_INSTALL_DIR}"
log "==================================================================="
