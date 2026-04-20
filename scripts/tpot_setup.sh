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

# Optional: Bedrock model IDs for the remote-node deploy picker (comma-separated,
# no "bedrock:" prefix). Empty when enable_bedrock=false in Terraform.
BEDROCK_MODEL_IDS="${BEDROCK_MODEL_IDS:-}"

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
BEELZEBUB_VERSION="3.6.7"   # verify against github.com/mariocandela/beelzebub/releases

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
BEELZEBUB_VERSION=${BEELZEBUB_VERSION}
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
# External access to the T-Pot web UI (port 64297) is restricted by the
# iptables rule applied in Phase 12 (tpot-iptables.service):
#   iptables -I INPUT -p tcp --dport 64297 ! -s 127.0.0.1 -j DROP
#
# NOTE: Do NOT override nginx ports here.  Docker Compose APPENDS to the
# existing ports list rather than replacing it, which would create a duplicate
# host-port 64297 binding conflict and prevent the nginx container from starting.
services:
  citrixhoneypot:
    container_name: citrixhoneypot
    restart: always
    depends_on:
      tpotinit:
        condition: service_healthy
    networks:
      - citrixhoneypot_local
    ports:
      - "443:443"
    image: ${TPOT_REPO}/citrixhoneypot:${TPOT_VERSION}
    pull_policy: ${TPOT_PULL_POLICY}
    read_only: true
    volumes:
      - ${TPOT_DATA_PATH}/citrixhoneypot/log:/opt/citrixhoneypot/logs

networks:
  citrixhoneypot_local:
    driver: bridge
OVERRIDE

chown tsec:tsec "${COMPOSE_DIR}/docker-compose.override.yml"
log "docker-compose.override.yml written to ${COMPOSE_DIR}"

# Remove port 443 from honeytrap in T-Pot's base compose file.
# Docker Compose APPENDS to port lists in overrides, so we cannot remove a
# port via docker-compose.override.yml.  Instead we patch the base file
# directly: citrixhoneypot owns port 443; honeytrap should not bind it.
#
# NOTE: plain `sed -i '/"443:443"/d'` was used previously.  When 443:443 is
# the ONLY entry in a service's ports: list, deleting that line leaves
# `ports:` with a null value (not an empty array), which Docker Compose
# rejects with "must be a array".  The Python script below handles this by
# replacing an empty ports: block with `ports: []`.
COMPOSE_BASE="${COMPOSE_DIR}/docker-compose.yml"
if [ -f "${COMPOSE_BASE}" ]; then
  if grep -q '"443:443"' "${COMPOSE_BASE}"; then
    _PATCH=$(mktemp)
    cat > "${_PATCH}" << 'PYPATCH'
import sys

path = sys.argv[1]
with open(path) as f:
    lines = f.readlines()

out = []
for i, line in enumerate(lines):
    if '"443:443"' in line:
        # Omit this line.  If it was the last item in a ports: block,
        # the block is now empty — find the ports: line and turn it into
        # `ports: []` so Docker Compose gets a valid empty array.
        for j in range(len(out) - 1, -1, -1):
            if out[j].strip() == 'ports:':
                next_i = i + 1
                while next_i < len(lines) and not lines[next_i].strip():
                    next_i += 1
                if next_i >= len(lines) or not lines[next_i].lstrip().startswith('-'):
                    indent = len(out[j]) - len(out[j].lstrip())
                    out[j] = ' ' * indent + 'ports: []\n'
                break
            elif out[j].strip():
                break
    else:
        out.append(line)

with open(path, 'w') as f:
    f.writelines(out)
print("Patched: removed 443:443 from {}".format(path))
PYPATCH
    python3 "${_PATCH}" "${COMPOSE_BASE}"
    rm -f "${_PATCH}"
    log "Removed port 443:443 from base compose (honeytrap conflict resolved)"
  else
    log "Port 443:443 not found in base compose — no patch needed"
  fi
else
  log "WARNING: base compose file not found at ${COMPOSE_BASE}"
fi

# Pre-create the citrixhoneypot log directory (tpotinit may not know about
# services added via override; container runs as UID 2000).
mkdir -p /data/citrixhoneypot/log
chown 2000:2000 /data/citrixhoneypot/log
log "citrixhoneypot log directory created"

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
# Phase 8b: Host nginx reverse proxy — T-Pot upstream bridge
#
# Problem: oauth2-proxy v7.x panics when combining credentials in the
# upstream URL with ssl_upstream_insecure_skip_verify.  Even without
# credentials, T-Pot nginx returns HTTP/2 GOAWAY (ENHANCE_YOUR_CALM) after
# the Basic Auth 401, which oauth2-proxy surfaces as a 502.
#
# Solution: install nginx on the HOST to sit between oauth2-proxy and T-Pot:
#   oauth2-proxy (HTTP) → host nginx (HTTP/1.1+TLS+BasicAuth) → T-Pot nginx
#
# This lets oauth2-proxy use a plain http:// upstream (no TLS, no HTTP/2),
# while host nginx handles TLS termination, cert verification skip, HTTP/1.1
# enforcement, and Basic Auth injection transparently.
#
# Port 18080 on loopback is used; the default nginx site (port 80) is removed
# to avoid conflicting with T-Pot's Dionaea/honeypot containers.
# ---------------------------------------------------------------------------
log "=== Phase 8b: Host nginx upstream proxy ==="

TPOT_NGINX_PROXY_PORT=18080
TPOT_NGINX_PROXY_CONF="/etc/nginx/sites-available/tpot-upstream.conf"

apt-get install -y nginx
# Remove default site — its port-80 listener conflicts with T-Pot honeypots
rm -f /etc/nginx/sites-enabled/default
log "nginx installed; default site disabled"

# Compute Basic Auth header value (user:pass → base64, no newline)
BASIC_AUTH_CREDS=$(printf '%s:%s' "${TPOT_WEB_USER}" "${TPOT_WEB_PASSWORD}" | base64 -w0)

cat > "${TPOT_NGINX_PROXY_CONF}" << EOF
# tpot-upstream.conf — host nginx bridge between oauth2-proxy and T-Pot nginx.
# Listens on HTTP (loopback only); oauth2-proxy needs no TLS config.
# Routes /manage to the management UI (port 8889) and everything else to
# T-Pot nginx (HTTPS/TLS1.3, Basic Auth injected).
server {
    listen 127.0.0.1:${TPOT_NGINX_PROXY_PORT};
    server_name localhost;

    # oauth2-proxy session cookies are several KB; raise buffer limits to
    # prevent nginx returning 400 "Request Header Or Cookie Too Large".
    large_client_header_buffers 8 32k;
    client_header_buffer_size   32k;

    # Management UI — served by FastAPI on port 8889 (loopback only).
    # No path stripping: the app handles routes with the /manage prefix.
    location /manage {
        proxy_pass          http://127.0.0.1:8889;
        proxy_http_version  1.1;
        proxy_set_header    Host            \$host;
        proxy_set_header    X-Real-IP       \$remote_addr;
        proxy_set_header    X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header    Upgrade         \$http_upgrade;
        proxy_set_header    Connection      "upgrade";
        proxy_read_timeout  60s;
    }

    # Fred Hutch landing page — exact-match root only.
    # Replaces the default T-Pot landing page; other T-Pot paths
    # (/kibana/, /map/, /spiderfoot/, /cyberchef/, /elasticvue/, static
    # assets) continue to flow through the catch-all `location /` below.
    location = / {
        proxy_pass          http://127.0.0.1:8889/;
        proxy_http_version  1.1;
        proxy_set_header    Host            \$host;
        proxy_set_header    X-Real-IP       \$remote_addr;
        proxy_set_header    X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_read_timeout  30s;
    }

    # Remote-node agent API — same FastAPI upstream, no Basic Auth injection.
    # oauth2-proxy is configured to skip OIDC on these paths; FastAPI
    # authenticates via the agent bearer token issued at enrolment.
    location /api/v1/agent {
        proxy_pass          http://127.0.0.1:8889;
        proxy_http_version  1.1;
        proxy_set_header    Host            \$host;
        proxy_set_header    X-Real-IP       \$remote_addr;
        proxy_set_header    X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_buffering     off;
        client_max_body_size 4m;
        proxy_read_timeout  90s;
    }

    # Centralised LLM proxy — remote Beelzebub instances POST OpenAI-compatible
    # chat completions here. FastAPI validates a per-node LLM bearer token
    # (distinct from the agent heartbeat token) and routes to local Ollama
    # or Amazon Bedrock based on the "model" prefix. LLM inference can be
    # slow, so the read timeout is raised to 120s.
    location /llm/ {
        proxy_pass          http://127.0.0.1:8889;
        proxy_http_version  1.1;
        proxy_set_header    Host            \$host;
        proxy_set_header    X-Real-IP       \$remote_addr;
        proxy_set_header    X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_buffering     off;
        client_max_body_size 1m;
        proxy_read_timeout  120s;
    }

    # T-Pot web UI — all other traffic.
    location / {
        proxy_pass          https://127.0.0.1:64297;
        proxy_http_version  1.1;          # force HTTP/1.1; avoid HTTP/2 GOAWAY
        proxy_ssl_verify    off;          # T-Pot nginx uses a self-signed cert
        proxy_ssl_protocols TLSv1.3;     # T-Pot nginx (Alpine/24.04.1) only accepts TLS 1.3
        # Inject T-Pot web-UI credentials — user already authenticated via OIDC.
        proxy_set_header    Authorization "Basic ${BASIC_AUTH_CREDS}";
        proxy_set_header    Host            "127.0.0.1:64297";
        proxy_set_header    X-Real-IP       \$remote_addr;
        proxy_set_header    X-Forwarded-For \$proxy_add_x_forwarded_for;
        # Strip oauth2-proxy session cookie — T-Pot auth is via injected Basic Auth;
        # forwarding the large cookie would cause 400 errors at T-Pot nginx.
        proxy_set_header    Cookie          "";
        # Buffers for large upstream response headers
        proxy_buffer_size        128k;
        proxy_buffers            4 256k;
        proxy_busy_buffers_size  256k;
        # WebSocket support (T-Pot attack-map live feed)
        proxy_set_header    Upgrade    \$http_upgrade;
        proxy_set_header    Connection "upgrade";
    }
}
EOF

ln -sf "${TPOT_NGINX_PROXY_CONF}" /etc/nginx/sites-enabled/tpot-upstream.conf
nginx -t
systemctl enable nginx
systemctl restart nginx
log "Host nginx upstream proxy listening on 127.0.0.1:${TPOT_NGINX_PROXY_PORT}"

# ---------------------------------------------------------------------------
# Phase 8c: Install Ollama (CPU LLM inference for Beelzebub honeypot)
#
# Ollama is installed on the host and restricted to loopback (127.0.0.1:11434)
# so it is not reachable from the network.  phi3 (~2.3 GB) is pulled as the
# default model; additional models can be managed via the management UI.
# ---------------------------------------------------------------------------
log "=== Phase 8c: Install Ollama ==="

curl -fsSL https://ollama.com/install.sh | sh

# Override Ollama's default listen address to loopback only.
mkdir -p /etc/systemd/system/ollama.service.d
cat > /etc/systemd/system/ollama.service.d/loopback.conf << 'OLLAMA_OVERRIDE'
[Service]
Environment="OLLAMA_HOST=127.0.0.1:11434"
OLLAMA_OVERRIDE

systemctl daemon-reload
systemctl enable ollama
systemctl start ollama

# Wait for the API to become ready before pulling the model.
log "Waiting for Ollama API..."
for i in $(seq 1 30); do
  curl -sf http://127.0.0.1:11434/api/tags > /dev/null && break
  sleep 2
done

log "Pulling phi3 model (this may take several minutes on first run)..."
ollama pull phi3 || log "WARNING: phi3 pull failed — retry via the management UI"
log "Ollama installed; phi3 model ready"

# ---------------------------------------------------------------------------
# Phase 8d: Install Beelzebub LLM honeypot
#
# Beelzebub is downloaded from GitHub (staged in S3 by CI) and run as a
# host-level systemd service so it can reach Ollama on 127.0.0.1:11434
# without Docker networking overhead.
#
# Ports (open in security group):
#   2222/tcp  — AI-powered SSH honeypot
#   8888/tcp  — AI-powered HTTP honeypot
#
# Config lives in /etc/beelzebub/configurations/ and can be edited live
# via the management UI at /manage/beelzebub (restarts service on save).
# ---------------------------------------------------------------------------
log "=== Phase 8d: Install Beelzebub ==="

BEELZEBUB_TARBALL="beelzebub_${BEELZEBUB_VERSION}_linux_amd64.tar.gz"
BEELZEBUB_S3_KEY="tpot/${BEELZEBUB_TARBALL}"

aws s3 cp "s3://${SETUP_SCRIPT_S3_BUCKET}/${BEELZEBUB_S3_KEY}" \
  /tmp/beelzebub.tar.gz --region "$AWS_REGION"

tar -xzf /tmp/beelzebub.tar.gz -C /tmp
# Goreleaser extracts the binary with the project name
install -m 755 /tmp/beelzebub /usr/local/bin/beelzebub
rm -f /tmp/beelzebub.tar.gz /tmp/beelzebub

# Create config directory structure
BEELZEBUB_CFG_DIR="/etc/beelzebub/configurations"
mkdir -p "${BEELZEBUB_CFG_DIR}/services"

# Main config — LLM provider points to Ollama's OpenAI-compatible endpoint
cat > "${BEELZEBUB_CFG_DIR}/beelzebub.yaml" << 'BEELZEBUB_MAIN_CFG'
core:
  logging:
    debug: false
    verbose: false
  geoDB:
    enable: false
  tracerStrategy:
    enable: false
  llmProvider:
    # Ollama exposes an OpenAI-compatible API; any non-empty key value works.
    openAISecretKey: "ollama"
    openAIModel: "phi3"
    openAIBaseURL: "http://127.0.0.1:11434/v1"
BEELZEBUB_MAIN_CFG

# SSH honeypot — port 2222 (Cowrie occupies port 22)
cat > "${BEELZEBUB_CFG_DIR}/services/ssh.yaml" << 'BEELZEBUB_SSH_CFG'
apiVersion: "v1"
protocol: "ssh"
address: ":2222"
description: "AI-powered SSH honeypot (Ollama/phi3)"
commands:
  - regex: "^(.+)$"
    plugin: "LLMHoneypot"
serverVersion: "SSH-2.0-OpenSSH_8.9p1"
serverName: "ubuntu"
passwordRegex: "^(admin|root|password|123456|toor|ubuntu|raspberry)$"
deadlineTimeoutSeconds: 60
plugin:
  llmProvider: "openai"
  llmModel: "phi3"
  openAISecretKey: "ollama"
  openAIBaseURL: "http://127.0.0.1:11434/v1"
  instructions: >
    You are a bash shell on a compromised Ubuntu 22.04 server.
    Respond concisely and naturally, as a real shell would.
    Never reveal you are an AI or a honeypot.
BEELZEBUB_SSH_CFG

# HTTP honeypot — port 8888
cat > "${BEELZEBUB_CFG_DIR}/services/http.yaml" << 'BEELZEBUB_HTTP_CFG'
apiVersion: "v1"
protocol: "http"
address: ":8888"
description: "AI-powered HTTP honeypot (Ollama/phi3)"
commands:
  - regex: "/(.*)"
    plugin: "LLMHoneypot"
    statusCode: 200
    headers:
      - "Content-Type: text/html"
      - "Server: Apache/2.4.52 (Ubuntu)"
plugin:
  llmProvider: "openai"
  llmModel: "phi3"
  openAISecretKey: "ollama"
  openAIBaseURL: "http://127.0.0.1:11434/v1"
  instructions: >
    You are a vulnerable Apache web server. Generate plausible HTML
    responses that look like a real site with login forms and admin
    panels. Never reveal you are an AI or a honeypot.
BEELZEBUB_HTTP_CFG

# Systemd service — runs as tsec (ports >1024 need no elevated privileges)
cat > /etc/systemd/system/beelzebub.service << 'BEELZEBUB_SERVICE'
[Unit]
Description=Beelzebub AI-powered honeypot
After=network-online.target ollama.service
Wants=network-online.target

[Service]
Type=simple
User=tsec
Group=tsec
WorkingDirectory=/etc/beelzebub
ExecStart=/usr/local/bin/beelzebub
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
BEELZEBUB_SERVICE

# Citrix NetScaler Gateway HTTP honeypot — port 8890
cat > "${BEELZEBUB_CFG_DIR}/services/http-citrix.yaml" << 'BEELZEBUB_CITRIX_CFG'
apiVersion: "v1"
protocol: "http"
address: ":8890"
description: "Citrix NetScaler Gateway login portal"
commands:
  - regex: "/(.*)"
    plugin: "LLMHoneypot"
    statusCode: 200
    headers:
      - "Content-Type: text/html"
      - "Server: Apache"
      - "X-Frame-Options: SAMEORIGIN"
plugin:
  llmProvider: "openai"
  llmModel: "phi3"
  openAISecretKey: "ollama"
  openAIBaseURL: "http://127.0.0.1:11434/v1"
  instructions: >
    You are a Citrix NetScaler Gateway login portal for a corporate healthcare
    network. Respond with realistic HTML that mimics a Citrix StoreFront or
    NetScaler Gateway authentication page, including form fields for username,
    password, and domain. Include plausible Citrix branding, error messages,
    and session tokens. Never reveal you are an AI or a honeypot.
BEELZEBUB_CITRIX_CFG

# WordPress admin HTTP honeypot — port 8891
cat > "${BEELZEBUB_CFG_DIR}/services/http-wordpress.yaml" << 'BEELZEBUB_WP_CFG'
apiVersion: "v1"
protocol: "http"
address: ":8891"
description: "WordPress site with exposed admin panel"
commands:
  - regex: "/(.*)"
    plugin: "LLMHoneypot"
    statusCode: 200
    headers:
      - "Content-Type: text/html"
      - "Server: Apache/2.4.52 (Ubuntu)"
      - "X-Powered-By: PHP/8.1.2"
plugin:
  llmProvider: "openai"
  llmModel: "phi3"
  openAISecretKey: "ollama"
  openAIBaseURL: "http://127.0.0.1:11434/v1"
  instructions: >
    You are a WordPress 6.4 site with a publicly reachable wp-admin panel and
    several common vulnerable plugins installed (WP File Manager, Contact Form 7,
    Elementor). Respond with realistic WordPress HTML — including wp-login.php
    forms, admin-ajax.php responses, and plugin endpoints. Show plausible PHP
    error messages and directory listings where appropriate. Never reveal you
    are an AI or a honeypot.
BEELZEBUB_WP_CFG

# Ensure tsec owns the config so the management UI can edit it
chown -R tsec:tsec /etc/beelzebub

systemctl daemon-reload
systemctl enable beelzebub
systemctl start beelzebub
log "Beelzebub installed: SSH :2222, Apache HTTP :8888, Citrix HTTP :8890, WordPress HTTP :8891"

# ---------------------------------------------------------------------------
# Phase 8e: Install management UI
#
# A FastAPI web app served at /manage via the host nginx proxy (Phase 8b).
# Already behind oauth2-proxy so no additional auth is required.
# The app uses the Docker socket to start/stop T-Pot containers, and calls
# the Ollama API and systemd to manage Beelzebub.
#
# Runs as root (required for Docker socket access).  The socket itself is
# readable by the docker group; tsec is added to that group for this purpose.
# ---------------------------------------------------------------------------
log "=== Phase 8e: Install management UI ==="

MGMT_UI_S3_KEY="tpot/mgmt-ui.tar.gz"
MGMT_UI_DIR="/opt/honeypot-mgmt"
MGMT_STATE_DIR="/var/lib/honeypot-mgmt"
AGENT_BUNDLE_DIR="${MGMT_UI_DIR}/agent-bundle"

aws s3 cp "s3://${SETUP_SCRIPT_S3_BUCKET}/${MGMT_UI_S3_KEY}" \
  /tmp/mgmt-ui.tar.gz --region "$AWS_REGION"

mkdir -p "${MGMT_UI_DIR}"
tar -xzf /tmp/mgmt-ui.tar.gz -C "${MGMT_UI_DIR}" --strip-components=1
rm -f /tmp/mgmt-ui.tar.gz

# SQLite state directory (nodes, commands, honeypots, events_ingest).
mkdir -p "${MGMT_STATE_DIR}"
chmod 750 "${MGMT_STATE_DIR}"

# Stage the remote-node agent bundle so the mgmt-ui can serve it at
# /api/v1/agent/artefacts/agent.tar.gz for the bootstrap one-liner.
mkdir -p "${AGENT_BUNDLE_DIR}"
if aws s3 cp "s3://${SETUP_SCRIPT_S3_BUCKET}/tpot/agent.tar.gz" \
     "${AGENT_BUNDLE_DIR}/agent.tar.gz" --region "$AWS_REGION"; then
  log "agent bundle staged at ${AGENT_BUNDLE_DIR}/agent.tar.gz"
else
  log "WARNING: agent.tar.gz not found in S3; remote-node onboarding disabled"
fi

# Install Python dependencies in an isolated venv
apt-get install -y python3-venv python3-pip
python3 -m venv "${MGMT_UI_DIR}/venv"
"${MGMT_UI_DIR}/venv/bin/pip" install --quiet \
  -r "${MGMT_UI_DIR}/requirements.txt"

# Add tsec to docker group so the UI can manage containers
usermod -aG docker tsec

# Systemd service
cat > /etc/systemd/system/honeypot-mgmt.service << MGMT_SERVICE
[Unit]
Description=T-Pot Honeypot Management UI
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/honeypot-mgmt
Environment=TPOT_FQDN=${TPOT_FQDN}
Environment=AWS_REGION=${AWS_REGION}
Environment=BEDROCK_MODEL_IDS=${BEDROCK_MODEL_IDS}
ReadWritePaths=/var/lib/honeypot-mgmt
ExecStart=/opt/honeypot-mgmt/venv/bin/uvicorn app:app \\
    --host 127.0.0.1 --port 8889 --workers 1
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
MGMT_SERVICE

systemctl daemon-reload
systemctl enable honeypot-mgmt
systemctl start honeypot-mgmt
log "Management UI installed; accessible at /manage after auth"

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

# Upstream: host nginx proxy on localhost (plain HTTP).
# Host nginx (Phase 8b) handles TLS, HTTP/1.1 enforcement, and Basic Auth
# injection so oauth2-proxy connects via simple HTTP with no TLS complexity.
upstreams = ["http://127.0.0.1:18080"]

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

# Remote-node agent API: agents authenticate via bearer token issued at
# enrolment, not via OIDC. Bypass oauth2-proxy for these exact paths only.
# FastAPI validates the bearer token independently (defence-in-depth).
#
# The /llm/v1/* paths are used by remote Beelzebub instances for OpenAI-
# compatible chat completions; FastAPI validates a per-node LLM bearer
# token before routing to Ollama or Bedrock.
skip_auth_routes = [
  "^/api/v1/agent/enrol\$",
  "^/api/v1/agent/heartbeat\$",
  "^/api/v1/agent/events\$",
  "^/api/v1/agent/bootstrap/[A-Za-z0-9_-]{22}\$",
  "^/api/v1/agent/artefacts/[a-z0-9_.-]+\$",
  "^/llm/v1/chat/completions\$",
  "^/llm/v1/models\$"
]

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
# Phase 12: iptables guard — pin management-path rules above tpotinit's NFQUEUE
#
# T-Pot's tpotinit container runs rules.sh on every `docker compose up`.
# rules.sh adds ACCEPT rules for known honeypot ports plus a catch-all
# NFQUEUE rule on INPUT that captures everything else.  Two consequences:
#
#   1. Port 4180 (oauth2-proxy / ALB backend) is not in T-Pot's allowlist,
#      so SYNs from the ALB are silently queued and dropped → ALB health
#      check fails → 504 from the ALB.
#   2. Return packets for host-originated outbound connections (SSM agent
#      reporting to ssm.<region>.amazonaws.com, apt, Docker Hub) arrive on
#      INPUT and hit the NFQUEUE catch-all → queued and dropped → SSM
#      "RequestError: send request failed" ~20 min after boot.
#
# Fix: a guard script that keeps three rules pinned at the top of INPUT.
# Run once at boot and every 60 s via a systemd timer, so even when
# tpotinit re-runs rules.sh (restart, upgrade, or crash), our rules are
# restored within one minute.  Delete-then-insert is idempotent: no
# duplicates, and the rule ends up at position 1 either way.
#
# We do NOT use `netfilter-persistent save` — T-Pot's Ansible installer
# adds rules we don't want to persist wholesale across reboots.
# ---------------------------------------------------------------------------
log "=== Phase 12: iptables guard ==="

cat > /usr/local/sbin/tpot-iptables-guard.sh << 'GUARD'
#!/bin/bash
set -u
ensure_top() {
    iptables -D INPUT "$@" 2>/dev/null || true
    iptables -I INPUT 1 "$@"
}
# (1) Return packets for outbound host connections — fixes SSM + any other
#     host-originated outbound HTTPS (apt, Docker Hub, etc.).
ensure_top -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# (2) ALB → oauth2-proxy on 4180 — fixes ALB health check and 504.
ensure_top -p tcp --dport 4180 -j ACCEPT
# (3) Restrict T-Pot WebUI port 64297 to loopback (defence in depth).
ensure_top -p tcp --dport 64297 ! -s 127.0.0.1 -j DROP
GUARD
chmod 755 /usr/local/sbin/tpot-iptables-guard.sh

cat > /etc/systemd/system/tpot-iptables.service << 'IPTABLES_UNIT'
[Unit]
Description=T-Pot iptables guard — pin management rules above tpotinit's NFQUEUE
After=network.target docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/tpot-iptables-guard.sh

[Install]
WantedBy=multi-user.target
IPTABLES_UNIT

cat > /etc/systemd/system/tpot-iptables.timer << 'IPTABLES_TIMER'
[Unit]
Description=Re-apply tpot-iptables guard every 60 s so rules survive tpotinit restarts

[Timer]
OnBootSec=30s
OnUnitActiveSec=60s
Unit=tpot-iptables.service

[Install]
WantedBy=timers.target
IPTABLES_TIMER

systemctl daemon-reload
systemctl enable --now tpot-iptables.timer
# Apply immediately for this session — don't wait for the 30 s first fire.
/usr/local/sbin/tpot-iptables-guard.sh
log "tpot-iptables guard + 60s timer registered and applied"

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
# Phase 13b: Stop all honeypot containers so they start in a known-stopped
#   state.  Users selectively start/stop them via the management UI.
#   Infrastructure containers (nginx, elasticsearch, kibana, logstash,
#   spiderfoot, tanner_phpox, tanner_redis, tpotinit, map_*) are left running.
# ---------------------------------------------------------------------------
log "=== Phase 13b: Stop honeypot containers (pausing for T-Pot start-up) ==="
sleep 45  # allow tpotinit to finish and all containers to reach running state

INFRA_LIST="nginx elasticsearch kibana logstash spiderfoot tanner_phpox tanner_redis tpotinit"

docker ps --format '{{.Names}}' | while IFS= read -r CNAME; do
  # Keep infrastructure containers and map_* containers running
  IS_INFRA=false
  for INFRA in ${INFRA_LIST}; do
    if [ "${CNAME}" = "${INFRA}" ]; then
      IS_INFRA=true
      break
    fi
  done
  # map_* prefix check
  case "${CNAME}" in map_*) IS_INFRA=true ;; esac

  if [ "${IS_INFRA}" = "false" ]; then
    docker stop "${CNAME}" 2>/dev/null \
      && log "Stopped honeypot container: ${CNAME}" \
      || log "WARNING: could not stop ${CNAME}"
  fi
done

log "All honeypot containers stopped — use /manage to start them selectively"

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

# Redirect installer stdio to $LOG only. `docker compose pull` emits a
# progress-stream flood (thousands of "Extracting NB" lines) that otherwise
# fills the cloud-init journal and blows past the 64 KB EC2 console-output
# cap, making remote diagnosis impossible.  BUILDKIT_PROGRESS=plain collapses
# the pull output into a single line per layer.
sudo -u tsec bash -c "
  cd '$TPOT_INSTALL_DIR'
  BUILDKIT_PROGRESS=plain ./install.sh -s -t h -u '$TPOT_WEB_USER' -p '$TPOT_WEB_PASSWORD'
" >>"$LOG" 2>&1 || {
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
