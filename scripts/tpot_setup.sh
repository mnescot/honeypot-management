#!/usr/bin/env bash
# scripts/tpot_setup.sh
# Full T-Pot CE installation script for AWS EC2 (Ubuntu 22.04 LTS).
#
# This script is uploaded to S3 by the CI pipeline and downloaded/executed
# by user_data.sh at instance launch.
#
# Architecture (two-phase, reboot-safe):
#
#   PHASE A — runs inline during cloud-init (this script, Phases 0-5):
#     0. Fetch secrets from SSM Parameter Store
#     1. System prerequisites (apt, ansible, Docker)
#     2. Kernel / sysctl tuning
#     3. Docker via official apt/GPG
#     4. Create tsec user
#     4b. Write /opt/tpot_post_install.sh and register tpot-post-install.service
#     5. Clone T-Pot CE and run installer (may trigger a system reboot)
#     5c. Trigger tpot-post-install.service immediately (no-reboot case)
#
#   PHASE B — runs via tpot-post-install.service (Phases 6-14):
#     6. Locate T-Pot compose directory
#     7. Write docker-compose.override.yml (nginx → 127.0.0.1 only)
#     8. Install oauth2-proxy from S3 (SHA256-verified)
#     9-10. Configure oauth2-proxy (plain HTTP:4180, ALB terminates TLS)
#     11. oauth2-proxy systemd unit
#     12. iptables block on port 64297 from non-loopback
#     13. Create systemd drop-in for T-Pot service to enforce compose override;
#         restart T-Pot and start oauth2-proxy
#     14. Summary log; disable tpot-post-install.service
#
#   WHY TWO PHASES?
#     cloud-init executes user_data exactly once on the first boot and never
#     resumes after a reboot.  The T-Pot Ansible installer may trigger a
#     reboot.  By registering Phase B as an enabled systemd one-shot service
#     before the installer runs, Phase B executes correctly whether or not a
#     reboot occurs.

set -euo pipefail

LOG="/var/log/tpot-setup.log"
exec > >(tee -a "$LOG") 2>&1

# ---------------------------------------------------------------------------
# Configuration — sourced from environment variables set by user_data.sh
# ---------------------------------------------------------------------------
TPOT_HOSTNAME="${TPOT_HOSTNAME:-tpot}"
TPOT_WEB_USER="${TPOT_WEB_USER:-admin}"
TPOT_FQDN="${TPOT_FQDN:?TPOT_FQDN is required}"
AZURE_TENANT_ID="${AZURE_TENANT_ID:?AZURE_TENANT_ID is required}"
AZURE_CLIENT_ID="${AZURE_CLIENT_ID:?AZURE_CLIENT_ID is required}"
AWS_REGION="${AWS_REGION:?AWS_REGION is required}"

# SSM paths for secrets (set by user_data.sh — paths are not sensitive)
SSM_PATH_WEB_PASSWORD="${SSM_PATH_WEB_PASSWORD:?SSM_PATH_WEB_PASSWORD is required}"
SSM_PATH_AZURE_CLIENT_SECRET="${SSM_PATH_AZURE_CLIENT_SECRET:?SSM_PATH_AZURE_CLIENT_SECRET is required}"
SSM_PATH_OAUTH2_COOKIE_SECRET="${SSM_PATH_OAUTH2_COOKIE_SECRET:?SSM_PATH_OAUTH2_COOKIE_SECRET is required}"

# S3 bucket used to stage setup scripts and supplementary binaries (oauth2-proxy)
SETUP_SCRIPT_S3_BUCKET="${SETUP_SCRIPT_S3_BUCKET:?SETUP_SCRIPT_S3_BUCKET is required}"

TPOT_REPO="https://github.com/telekom-security/tpotce"
TPOT_INSTALL_DIR="/home/tsec/tpotce"

OAUTH2_PROXY_VERSION="7.14.3"
OAUTH2_PROXY_BIN="/usr/local/bin/oauth2-proxy"
OAUTH2_PROXY_CONF_DIR="/etc/oauth2-proxy"

log() { echo "[$(date -u +%FT%TZ)] $*"; }

# ---------------------------------------------------------------------------
# Phase 0: Fetch secrets from SSM Parameter Store
# ---------------------------------------------------------------------------
log "=== Phase 0: Fetch secrets from SSM ==="

ssm_get() {
  aws ssm get-parameter \
    --name "$1" \
    --with-decryption \
    --query 'Parameter.Value' \
    --output text \
    --region "$AWS_REGION"
}

TPOT_WEB_PASSWORD=$(ssm_get "$SSM_PATH_WEB_PASSWORD")
AZURE_CLIENT_SECRET=$(ssm_get "$SSM_PATH_AZURE_CLIENT_SECRET")
OAUTH2_COOKIE_SECRET=$(ssm_get "$SSM_PATH_OAUTH2_COOKIE_SECRET")

log "Secrets fetched from SSM"

for secret_name in TPOT_WEB_PASSWORD AZURE_CLIENT_SECRET OAUTH2_COOKIE_SECRET; do
  eval "secret_val=\$$secret_name"
  if [ -z "$secret_val" ]; then
    log "ERROR: SSM returned empty value for $secret_name — aborting"
    exit 1
  fi
done

# ---------------------------------------------------------------------------
# Phase 1: System prerequisites (apt-only, no curl|sh)
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
  ca-certificates \
  gnupg \
  lsb-release \
  ansible

log "System prerequisites installed"

# ---------------------------------------------------------------------------
# Phase 2: Kernel / sysctl tuning recommended by T-Pot
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
# Phase 3: Docker installation via official apt repository (GPG-verified)
# ---------------------------------------------------------------------------
log "=== Phase 3: Docker (apt / GPG-verified) ==="

install -m 0755 -d /etc/apt/keyrings

curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu \
$(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  | tee /etc/apt/sources.list.d/docker.list > /dev/null

apt-get update -y
apt-get install -y \
  docker-ce \
  docker-ce-cli \
  containerd.io \
  docker-buildx-plugin \
  docker-compose-plugin

systemctl enable docker
systemctl start docker

log "Docker $(docker --version)"
log "Docker Compose $(docker compose version)"

# ---------------------------------------------------------------------------
# Phase 4: Create T-Pot user (tsec)
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
# Phase 4b: Write post-install env file and register one-shot service
#
# The T-Pot installer (Phase 5) may trigger a system reboot.  cloud-init
# does NOT resume after a reboot, so any work that must run after the
# installer (compose override, oauth2-proxy, iptables) is extracted into
# /opt/tpot_post_install.sh and registered as an enabled systemd one-shot
# service BEFORE the installer runs.
#
# - If the installer reboots: the service runs automatically on the next boot.
# - If no reboot: Phase 5c starts the service immediately after the installer.
#
# Non-sensitive config is written to /etc/tpot-post-install.env so the
# service has the values it needs on a subsequent boot.  Secrets are never
# persisted — they are re-fetched from SSM at the start of Phase B.
# ---------------------------------------------------------------------------
log "=== Phase 4b: Register post-install one-shot service ==="

# Write non-sensitive env vars to disk (NO secret values)
cat > /etc/tpot-post-install.env << ENVFILE
AWS_REGION=${AWS_REGION}
TPOT_HOSTNAME=${TPOT_HOSTNAME}
TPOT_WEB_USER=${TPOT_WEB_USER}
TPOT_FQDN=${TPOT_FQDN}
AZURE_TENANT_ID=${AZURE_TENANT_ID}
AZURE_CLIENT_ID=${AZURE_CLIENT_ID}
SSM_PATH_WEB_PASSWORD=${SSM_PATH_WEB_PASSWORD}
SSM_PATH_AZURE_CLIENT_SECRET=${SSM_PATH_AZURE_CLIENT_SECRET}
SSM_PATH_OAUTH2_COOKIE_SECRET=${SSM_PATH_OAUTH2_COOKIE_SECRET}
SETUP_SCRIPT_S3_BUCKET=${SETUP_SCRIPT_S3_BUCKET}
TPOT_INSTALL_DIR=${TPOT_INSTALL_DIR}
OAUTH2_PROXY_VERSION=${OAUTH2_PROXY_VERSION}
OAUTH2_PROXY_BIN=${OAUTH2_PROXY_BIN}
OAUTH2_PROXY_CONF_DIR=${OAUTH2_PROXY_CONF_DIR}
ENVFILE
chmod 600 /etc/tpot-post-install.env
log "Post-install env file written to /etc/tpot-post-install.env"

# ---------------------------------------------------------------------------
# Write the Phase B script.
# Single-quoted heredoc (POSTINSTALL): nothing is expanded now — all
# ${VARIABLE} references expand when the post-install script runs.
# Inner heredocs (EOF, DROPIN, OVERRIDE, UNIT) are literal text here;
# they execute with their normal semantics when the script runs.
# ---------------------------------------------------------------------------
cat > /opt/tpot_post_install.sh << 'POSTINSTALL'
#!/usr/bin/env bash
# /opt/tpot_post_install.sh
# Phase B of T-Pot setup — run by tpot-post-install.service.
# Applies the compose override, installs oauth2-proxy, configures iptables,
# creates a systemd drop-in so the override persists across reboots, then
# starts all services.

set -euo pipefail

LOG="/var/log/tpot-setup.log"
exec >> "$LOG" 2>&1

log() { echo "[$(date -u +%FT%TZ)] [post-install] $*"; }

log "============================================================"
log "Phase B (post-install) starting"
log "============================================================"

# Source non-sensitive config written by Phase A
# shellcheck disable=SC1091
source /etc/tpot-post-install.env

# Re-fetch secrets from SSM — secrets are never persisted to disk.
# Retry loop handles the case where the SSM endpoint is briefly unreachable
# immediately after a system reboot.
ssm_get() {
  aws ssm get-parameter \
    --name "$1" \
    --with-decryption \
    --query 'Parameter.Value' \
    --output text \
    --region "$AWS_REGION"
}

log "Fetching secrets from SSM..."
for attempt in $(seq 1 10); do
  if TPOT_WEB_PASSWORD=$(ssm_get "$SSM_PATH_WEB_PASSWORD") \
     && AZURE_CLIENT_SECRET=$(ssm_get "$SSM_PATH_AZURE_CLIENT_SECRET") \
     && OAUTH2_COOKIE_SECRET=$(ssm_get "$SSM_PATH_OAUTH2_COOKIE_SECRET"); then
    break
  fi
  log "SSM not ready (attempt ${attempt}/10) — retrying in 15s..."
  sleep 15
  [ "$attempt" -eq 10 ] && { log "ERROR: Could not fetch secrets after 10 attempts"; exit 1; }
done
log "Secrets fetched from SSM"

# Wait for Docker to be ready (critical in the reboot case)
log "Waiting for Docker to be ready..."
for i in $(seq 1 30); do
  docker info &>/dev/null && break
  [ "$i" -eq 30 ] && { log "ERROR: Docker not ready after 60s"; exit 1; }
  sleep 2
done
log "Docker is ready"

# ---------------------------------------------------------------------------
# Phase 6: Identify the compose directory used by T-Pot
# ---------------------------------------------------------------------------
log "=== Phase 6: Locate compose files ==="

COMPOSE_DIR=""
for candidate in \
  "${TPOT_INSTALL_DIR}" \
  "${TPOT_INSTALL_DIR}/docker" \
  "${TPOT_INSTALL_DIR}/compose"
do
  found=false
  for _f in "${candidate}"/docker-compose*.yml "${candidate}"/compose*.yml; do
    [ -f "$_f" ] && { found=true; break; }
  done
  if $found; then
    COMPOSE_DIR="$candidate"
    break
  fi
done

if [ -z "$COMPOSE_DIR" ]; then
  log "ERROR: Could not locate T-Pot compose files under ${TPOT_INSTALL_DIR}"
  exit 1
fi
log "Compose directory: ${COMPOSE_DIR}"

# Locate the primary compose file (docker-compose.yml preferred, then compose*.yml)
COMPOSE_FILE=""
for _candidate in \
  "${COMPOSE_DIR}/docker-compose.yml" \
  "${COMPOSE_DIR}"/compose*.yml
do
  [ -f "$_candidate" ] && { COMPOSE_FILE="$_candidate"; break; }
done

if [ -z "$COMPOSE_FILE" ]; then
  log "ERROR: Primary compose file not found in ${COMPOSE_DIR}"
  exit 1
fi
log "Primary compose file: ${COMPOSE_FILE}"

# ---------------------------------------------------------------------------
# Phase 7: docker-compose.override.yml
#    Restrict T-Pot nginx to localhost so external traffic MUST pass through
#    oauth2-proxy on port 4180 (behind the ALB).
# ---------------------------------------------------------------------------
log "=== Phase 7: Write docker-compose.override.yml ==="

cat > "${COMPOSE_DIR}/docker-compose.override.yml" << 'OVERRIDE'
# docker-compose.override.yml
# Applied on top of T-Pot's main compose file.
# Binds the nginx web UI port (64297) to 127.0.0.1 so the T-Pot web UI is
# not directly reachable from the network; all external access goes through
# oauth2-proxy on port 4180 (ALB terminates TLS).
#
# Port 64295 is intentionally omitted: T-Pot's installer moves the HOST
# sshd to 64295, so it is managed by the OS — not by Docker.  Adding a
# container binding for 64295 here causes an "address already in use" error.
services:
  nginx:
    ports:
      - "127.0.0.1:64297:64297"
OVERRIDE

chown tsec:tsec "${COMPOSE_DIR}/docker-compose.override.yml"
log "docker-compose.override.yml written to ${COMPOSE_DIR}"

# ---------------------------------------------------------------------------
# Phase 8: Install oauth2-proxy with SHA256 verification
#    Downloaded from S3 (staged by CI pipeline) to avoid a direct runtime
#    dependency on github.com, which may be blocked in LZA environments.
# ---------------------------------------------------------------------------
log "=== Phase 8: Install oauth2-proxy (SHA256-verified) ==="

OAUTH2_ARCH="linux-amd64"
OAUTH2_TARBALL="oauth2-proxy-v${OAUTH2_PROXY_VERSION}.${OAUTH2_ARCH}.tar.gz"
OAUTH2_S3_KEY="tpot/${OAUTH2_TARBALL}"
OAUTH2_SHA256_S3_KEY="tpot/${OAUTH2_TARBALL}-sha256sum.txt"

aws s3 cp "s3://${SETUP_SCRIPT_S3_BUCKET}/${OAUTH2_S3_KEY}" \
  /tmp/oauth2-proxy.tar.gz --region "$AWS_REGION"
aws s3 cp "s3://${SETUP_SCRIPT_S3_BUCKET}/${OAUTH2_SHA256_S3_KEY}" \
  /tmp/oauth2-proxy.sha256sum.txt --region "$AWS_REGION"

EXPECTED_HASH=$(grep "${OAUTH2_TARBALL}" /tmp/oauth2-proxy.sha256sum.txt | awk '{print $1}')
ACTUAL_HASH=$(sha256sum /tmp/oauth2-proxy.tar.gz | awk '{print $1}')

if [ "$EXPECTED_HASH" != "$ACTUAL_HASH" ]; then
  log "ERROR: SHA256 mismatch for oauth2-proxy tarball — aborting"
  log "  expected: ${EXPECTED_HASH}"
  log "  actual:   ${ACTUAL_HASH}"
  exit 1
fi
log "oauth2-proxy SHA256 verified"

tar -xzf /tmp/oauth2-proxy.tar.gz -C /tmp
install -m 755 "/tmp/oauth2-proxy-v${OAUTH2_PROXY_VERSION}.${OAUTH2_ARCH}/oauth2-proxy" \
  "${OAUTH2_PROXY_BIN}"
rm -rf /tmp/oauth2-proxy.tar.gz /tmp/oauth2-proxy.sha256sum.txt \
       "/tmp/oauth2-proxy-v${OAUTH2_PROXY_VERSION}.${OAUTH2_ARCH}"

log "oauth2-proxy ${OAUTH2_PROXY_VERSION} installed to ${OAUTH2_PROXY_BIN}"

# ---------------------------------------------------------------------------
# Phase 9: Prepare oauth2-proxy configuration directory
#    TLS is terminated at the ALB (ACM certificate).  oauth2-proxy listens
#    on plain HTTP port 4180; no self-signed certificate is required.
# ---------------------------------------------------------------------------
log "=== Phase 9: Prepare oauth2-proxy configuration directory ==="

mkdir -p "${OAUTH2_PROXY_CONF_DIR}"
chown root:tsec "${OAUTH2_PROXY_CONF_DIR}"
chmod 750 "${OAUTH2_PROXY_CONF_DIR}"
log "Configuration directory ready: ${OAUTH2_PROXY_CONF_DIR}"

# ---------------------------------------------------------------------------
# Phase 10: Write oauth2-proxy configuration file
# ---------------------------------------------------------------------------
log "=== Phase 10: oauth2-proxy configuration ==="

# oauth2-proxy v7.x treats cookie_secret as raw bytes, not base64-encoded.
# It must be exactly 16, 24, or 32 bytes.  `openssl rand -base64 32` produces
# a 44-char string which is rejected.  Normalise to 32 bytes by truncating;
# the first 32 chars of a base64 string are all printable ASCII (no padding).
if [ "${#OAUTH2_COOKIE_SECRET}" -gt 32 ]; then
  OAUTH2_COOKIE_SECRET="${OAUTH2_COOKIE_SECRET:0:32}"
  log "Cookie secret normalised to 32 bytes for oauth2-proxy compatibility"
elif [ "${#OAUTH2_COOKIE_SECRET}" -lt 16 ]; then
  log "ERROR: OAUTH2_COOKIE_SECRET is ${#OAUTH2_COOKIE_SECRET} bytes — must be 16, 24, or 32"
  exit 1
fi

cat > "${OAUTH2_PROXY_CONF_DIR}/oauth2-proxy.cfg" << EOF
# oauth2-proxy configuration for T-Pot + Microsoft Entra ID OIDC
#
# Microsoft Entra ID App Registration requirements:
#   - Platform: Web
#   - Redirect URI: https://${TPOT_FQDN}/oauth2/callback
#   - Supported account types: Accounts in this organisational directory
#   - API permissions: openid, profile, email (all delegated)

provider = "oidc"
oidc_issuer_url = "https://login.microsoftonline.com/${AZURE_TENANT_ID}/v2.0"

client_id     = "${AZURE_CLIENT_ID}"
client_secret = "${AZURE_CLIENT_SECRET}"

cookie_secret = "${OAUTH2_COOKIE_SECRET}"
cookie_secure = true

# Upstream: T-Pot nginx on localhost (restricted to loopback by compose override)
upstreams = ["https://127.0.0.1:64297"]
ssl_insecure_skip_verify = true   # T-Pot nginx uses a self-signed cert internally

# Listen on plain HTTP — TLS is terminated at the ALB (ACM certificate).
# The ALB security group ensures only the ALB can reach this port.
http_address = "0.0.0.0:4180"

# Trust X-Forwarded-Proto and X-Forwarded-For headers from the ALB so that
# oauth2-proxy knows the original request was HTTPS and sets cookies correctly.
reverse_proxy = true

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

chown root:tsec "${OAUTH2_PROXY_CONF_DIR}/oauth2-proxy.cfg"
chmod 640 "${OAUTH2_PROXY_CONF_DIR}/oauth2-proxy.cfg"
log "oauth2-proxy configuration written"

# ---------------------------------------------------------------------------
# Phase 11: oauth2-proxy systemd service
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
# Runs as tsec (non-root) — port 4180 does not require elevated privileges.
# TLS is terminated at the ALB; no certificate binding needed here.
User=tsec
Group=tsec
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
ProtectHome=true

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
log "oauth2-proxy systemd unit written"

# ---------------------------------------------------------------------------
# Phase 12: iptables rules — belt-and-suspenders port restriction
#
# IMPORTANT: We do NOT use `netfilter-persistent save` here.
# T-Pot's Ansible installer adds its own iptables rules during Phase 5b
# (including rules that may restrict outbound traffic).  Calling
# `netfilter-persistent save` would capture ALL of those rules and persist
# them permanently, which can block the SSM agent's outbound HTTPS after
# every reboot.  T-Pot manages its own iptables persistence separately.
#
# Instead we apply our single rule immediately and register a dedicated
# systemd one-shot service that re-applies ONLY this rule on each boot,
# after Docker and T-Pot have had a chance to set up their own chains.
# ---------------------------------------------------------------------------
log "=== Phase 12: iptables ==="

# Apply immediately for this session
iptables -I INPUT -p tcp --dport 64297 ! -s 127.0.0.1 -j DROP
log "iptables rule applied (current session)"

# Persist only this rule across reboots via a dedicated service
cat > /etc/systemd/system/tpot-iptables.service << 'IPTABLES_UNIT'
[Unit]
Description=T-Pot iptables: restrict port 64297 to loopback only
After=network.target docker.service

[Service]
Type=oneshot
ExecStart=/sbin/iptables -I INPUT -p tcp --dport 64297 ! -s 127.0.0.1 -j DROP
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
IPTABLES_UNIT

systemctl daemon-reload
systemctl enable tpot-iptables.service
log "tpot-iptables.service registered — rule will be re-applied on every boot"

# ---------------------------------------------------------------------------
# Phase 13: Apply compose override and start services
#
# FIX for Issue 1 (reboot safety): This entire block now runs inside the
# tpot-post-install.service, which executes correctly whether the T-Pot
# installer caused a reboot or not.
#
# FIX for Issue 2 (override not applied): T-Pot's tpot.service may use an
# explicit -f flag (e.g. docker compose -f /path/docker-compose.yml up),
# which prevents Docker Compose from auto-reading docker-compose.override.yml.
# We create a systemd drop-in that replaces ExecStart with a command that
# explicitly includes both compose files.  This persists across all future
# reboots.
# ---------------------------------------------------------------------------
log "=== Phase 13: Apply compose override and start services ==="

# Identify the T-Pot systemd unit (name varies by installer version)
TPOT_SVC=""
for svc in tpot tpotce; do
  if systemctl list-unit-files "${svc}.service" 2>/dev/null | grep -q "${svc}"; then
    TPOT_SVC="$svc"
    break
  fi
done

# Stop the T-Pot service (if found) before compose down to avoid races
if [ -n "$TPOT_SVC" ]; then
  systemctl stop "$TPOT_SVC" 2>/dev/null || true
  log "T-Pot service (${TPOT_SVC}) stopped"
fi

# Remove all containers so every port binding is fully released
docker compose -f "${COMPOSE_FILE}" down --timeout 30 2>/dev/null || true
log "T-Pot containers removed; ports released"
sleep 3

OVERRIDE_FILE="${COMPOSE_DIR}/docker-compose.override.yml"

if [ -n "$TPOT_SVC" ]; then
  DROPIN_DIR="/etc/systemd/system/${TPOT_SVC}.service.d"
  mkdir -p "${DROPIN_DIR}"

  # Read the original ExecStart from the installed T-Pot service file.
  # We extend it surgically rather than replacing it wholesale, so that any
  # extra -f flags, environment variables, or other options T-Pot uses are
  # preserved.
  ORIGINAL_EXEC=$(systemctl cat "${TPOT_SVC}" 2>/dev/null \
    | grep '^ExecStart=' | head -1 | sed 's/^ExecStart=//')

  if [ -n "${ORIGINAL_EXEC}" ] && echo "${ORIGINAL_EXEC}" | grep -qF -- '-f '; then
    # Service uses explicit -f flags.  Insert our override file before the
    # action word 'up' so all existing flags are preserved.
    NEW_EXEC=$(echo "${ORIGINAL_EXEC}" | sed "s| up\b| -f ${OVERRIDE_FILE} up|")
    cat > "${DROPIN_DIR}/90-compose-override.conf" << DROPIN
[Service]
# Extend the original ExecStart to include the compose override file.
# Only ExecStart is changed; all other service directives are preserved.
ExecStart=
ExecStart=${NEW_EXEC}
DROPIN
    systemctl daemon-reload
    log "Drop-in created: override file inserted into original ExecStart"
  else
    # Service does not use explicit -f flags (relies on WorkingDirectory).
    # Docker Compose will auto-read docker-compose.override.yml from the
    # working directory — no drop-in modification needed.
    log "T-Pot service uses implicit compose discovery; override auto-applied from ${COMPOSE_DIR}"
  fi

  # Start T-Pot.  A failure here is logged as a warning rather than aborting
  # the post-install script, so oauth2-proxy is always attempted regardless.
  systemctl start "${TPOT_SVC}" \
    && log "T-Pot service (${TPOT_SVC}) started with compose override" \
    || log "WARNING: T-Pot service (${TPOT_SVC}) failed to start — check: journalctl -u ${TPOT_SVC}"
else
  # No systemd service found — start compose stack directly with both files
  log "No T-Pot systemd service found; starting compose stack directly"
  docker compose \
    -f "${COMPOSE_FILE}" \
    -f "${OVERRIDE_FILE}" \
    up -d \
    && log "T-Pot compose stack started" \
    || log "WARNING: docker compose up failed — check docker logs"
fi

systemctl enable oauth2-proxy
systemctl start oauth2-proxy
log "oauth2-proxy started"

# ---------------------------------------------------------------------------
# Phase 14: Summary and self-disable
# ---------------------------------------------------------------------------
log "==================================================================="
log "T-Pot installation complete!"
log ""
log "  Web UI (SAML/OIDC SSO): https://${TPOT_FQDN}"
log "  Direct T-Pot UI:        https://localhost:64297  (localhost only)"
log "  SSH management:         port 64295 (T-Pot moves sshd to 64295)"
log ""
log "  Microsoft Entra ID OIDC:"
log "    Tenant:     ${AZURE_TENANT_ID}"
log "    Client ID:  ${AZURE_CLIENT_ID}"
log "    Redirect:   https://${TPOT_FQDN}/oauth2/callback"
log ""
log "  TLS:        Terminated at the ALB (ACM certificate); oauth2-proxy uses HTTP:4180"
log "  oauth2-proxy config: ${OAUTH2_PROXY_CONF_DIR}/oauth2-proxy.cfg"
log "  T-Pot dir:  ${TPOT_INSTALL_DIR}"
log "==================================================================="

# Remove passwordless sudo for tsec now that installation is complete.
# It was required by the T-Pot Ansible installer; keeping it permanently
# would allow any process running as tsec to escalate to root without a password.
rm -f /etc/sudoers.d/99-tsec-nopasswd
log "Passwordless sudo for tsec removed"

# Disable this one-shot service so it does not re-run on subsequent reboots
systemctl disable tpot-post-install.service 2>/dev/null || true
log "tpot-post-install.service disabled (one-shot complete)"
POSTINSTALL

chmod +x /opt/tpot_post_install.sh
log "Post-install script written to /opt/tpot_post_install.sh"

# Register the post-install service — enabled BEFORE the T-Pot installer runs
cat > /etc/systemd/system/tpot-post-install.service << 'SERVICE'
[Unit]
Description=T-Pot post-install configuration (one-shot)
Documentation=file:///opt/tpot_post_install.sh
# Run after Docker and networking are available.
# If tpot.service or tpotce.service exists, run after it so that the
# installer-started containers are up before we tear them down and restart
# with the compose override.
After=docker.service network-online.target tpot.service tpotce.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/opt/tpot_post_install.sh
# Do not restart on failure — investigate /var/log/tpot-setup.log instead
Restart=no
StandardOutput=journal
StandardError=journal
SyslogIdentifier=tpot-post-install
# Allow up to 30 minutes for the full post-install to complete
TimeoutStartSec=1800

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable tpot-post-install.service
log "tpot-post-install.service enabled (will run on next boot if reboot is triggered)"

# ---------------------------------------------------------------------------
# Phase 5: Clone and install T-Pot CE
# ---------------------------------------------------------------------------
# Grant tsec passwordless sudo — required by the T-Pot Ansible-based installer,
# which calls sudo internally and cannot accept an interactive password prompt.
echo "tsec ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/99-tsec-nopasswd
chmod 440 /etc/sudoers.d/99-tsec-nopasswd
log "Passwordless sudo granted to tsec for T-Pot installer"

log "=== Phase 5: Clone T-Pot CE ==="

# Issue 3 mitigation: verify GitHub is reachable before attempting clone.
# In Landing Zone Accelerator (LZA) VPCs, github.com may be blocked at the
# egress firewall.  A clear error here is better than a silent git hang.
if ! curl -fsS --max-time 15 -o /dev/null https://github.com; then
  log "ERROR: Cannot reach github.com — T-Pot repo clone will fail."
  log "  Check VPC egress rules, NAT gateway routing, and LZA firewall policy."
  log "  github.com (140.82.112.0/20, 185.199.108.0/22) must be reachable on TCP/443."
  exit 1
fi
log "GitHub is reachable"

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
cd "$TPOT_INSTALL_DIR"

sudo -u tsec bash -c "
  cd '$TPOT_INSTALL_DIR'
  ./install.sh -s -t h -u '$TPOT_WEB_USER' -p '$TPOT_WEB_PASSWORD'
" || {
  log "WARNING: T-Pot installer exited non-zero. Checking if services are running..."
  if [ ! -f "$TPOT_INSTALL_DIR/.env" ]; then
    log "ERROR: T-Pot install appears to have failed (.env not found)"
    exit 1
  fi
  log "T-Pot .env found — treating as successful install"
}

log "T-Pot CE installed"

# ---------------------------------------------------------------------------
# Phase 5c: Trigger post-install service (no-reboot case)
#
# If the T-Pot installer did NOT reboot the instance, start the post-install
# service immediately so Phase B runs in the same boot session.
#
# If the installer DID schedule a reboot, this start may fail or the instance
# may reboot before it completes — both are harmless because the service is
# already enabled and will run automatically after the reboot.
# ---------------------------------------------------------------------------
log "=== Phase 5c: Trigger post-install service ==="

systemctl start tpot-post-install.service \
  && log "tpot-post-install.service started successfully (no reboot detected)" \
  || log "Note: Could not start tpot-post-install.service immediately — will run automatically after reboot if one was scheduled"

log "======================================================"
log "tpot_setup.sh (Phase A) complete."
log "Phase B handled by tpot-post-install.service."
log "Monitor progress: journalctl -u tpot-post-install -f"
log "Full log: /var/log/tpot-setup.log"
log "======================================================"
