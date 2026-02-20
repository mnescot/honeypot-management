#!/usr/bin/env bash
# user_data.sh
# EC2 user-data bootstrap script for T-Pot honeypot.
#
# This script is rendered by Terraform's templatefile() function; the
# $${variable} placeholders are substituted before the script reaches the
# instance.  It runs once on first boot as root via cloud-init.
#
# Responsibilities:
#   1. Basic system preparation (hostname, deps)
#   2. Download the full tpot_setup.sh from S3
#   3. Execute tpot_setup.sh with all required environment variables

set -euo pipefail

LOG="/var/log/tpot-bootstrap.log"
exec > >(tee -a "$LOG") 2>&1

echo "======================================================"
echo "[$(date -u +%FT%TZ)] T-Pot bootstrap starting"
echo "======================================================"

# ---------------------------------------------------------------------------
# 1. Set hostname
# ---------------------------------------------------------------------------
hostnamectl set-hostname "${tpot_hostname}"
echo "127.0.1.1 ${tpot_hostname}" >> /etc/hosts

# ---------------------------------------------------------------------------
# 2. Basic system update and dependencies
# ---------------------------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends \
  curl \
  unzip \
  ca-certificates \
  gnupg

# Install AWS CLI v2
if ! command -v aws &>/dev/null; then
  curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" \
    -o /tmp/awscliv2.zip
  unzip -q /tmp/awscliv2.zip -d /tmp/awscliv2
  /tmp/awscliv2/aws/install
  rm -rf /tmp/awscliv2 /tmp/awscliv2.zip
fi

echo "[$(date -u +%FT%TZ)] AWS CLI: $(aws --version)"

# ---------------------------------------------------------------------------
# 3. Download tpot_setup.sh from S3
# ---------------------------------------------------------------------------
SETUP_SCRIPT="/opt/tpot_setup.sh"

echo "[$(date -u +%FT%TZ)] Downloading tpot_setup.sh from S3..."
aws s3 cp \
  "s3://${setup_script_s3_bucket}/${setup_script_s3_key}" \
  "$SETUP_SCRIPT" \
  --region "${aws_region}"

chmod +x "$SETUP_SCRIPT"
echo "[$(date -u +%FT%TZ)] tpot_setup.sh downloaded"

# ---------------------------------------------------------------------------
# 4. Export configuration values for tpot_setup.sh
# ---------------------------------------------------------------------------
export TPOT_HOSTNAME="${tpot_hostname}"
export TPOT_WEB_USER="${tpot_web_user}"
export TPOT_WEB_PASSWORD="${tpot_web_password}"
export TPOT_FQDN="${tpot_fqdn}"
export AZURE_TENANT_ID="${azure_tenant_id}"
export AZURE_CLIENT_ID="${azure_client_id}"
export AZURE_CLIENT_SECRET="${azure_client_secret}"
export OAUTH2_COOKIE_SECRET="${oauth2_cookie_secret}"
export AWS_REGION="${aws_region}"

# ---------------------------------------------------------------------------
# 5. Run the full T-Pot installation
# ---------------------------------------------------------------------------
echo "[$(date -u +%FT%TZ)] Starting T-Pot installation..."
"$SETUP_SCRIPT"

echo "======================================================"
echo "[$(date -u +%FT%TZ)] T-Pot bootstrap completed"
echo "======================================================"
