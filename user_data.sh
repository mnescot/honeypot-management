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
#   3. Verify integrity (SHA256) before execution
#   4. Execute tpot_setup.sh — secrets are fetched from SSM at runtime;
#      NO credentials appear in this file or in EC2 instance metadata.

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
# 3. Download tpot_setup.sh and its SHA256 digest from S3, then verify
#    before execution.  Both objects are in the same IAM-gated bucket;
#    the digest provides integrity assurance against in-transit tampering.
# ---------------------------------------------------------------------------
SETUP_SCRIPT="/opt/tpot_setup.sh"
SETUP_DIGEST="/opt/tpot_setup.sh.sha256"

echo "[$(date -u +%FT%TZ)] Downloading tpot_setup.sh from S3..."
aws s3 cp \
  "s3://${setup_script_s3_bucket}/${setup_script_s3_key}" \
  "$SETUP_SCRIPT" \
  --region "${aws_region}"

echo "[$(date -u +%FT%TZ)] Downloading SHA256 digest from S3..."
aws s3 cp \
  "s3://${setup_script_s3_bucket}/${setup_script_s3_key}.sha256" \
  "$SETUP_DIGEST" \
  --region "${aws_region}"

echo "[$(date -u +%FT%TZ)] Verifying SHA256 integrity..."
EXPECTED_SHA256=$(cat "$SETUP_DIGEST")
ACTUAL_SHA256=$(sha256sum "$SETUP_SCRIPT" | awk '{print $1}')
if [ "$EXPECTED_SHA256" != "$ACTUAL_SHA256" ]; then
  echo "[$(date -u +%FT%TZ)] ERROR: SHA256 mismatch — aborting"
  echo "  expected: $EXPECTED_SHA256"
  echo "  actual:   $ACTUAL_SHA256"
  exit 1
fi
echo "[$(date -u +%FT%TZ)] SHA256 verified OK"

chmod +x "$SETUP_SCRIPT"

# ---------------------------------------------------------------------------
# 4. Export non-sensitive configuration for tpot_setup.sh.
#    Secrets (web password, Azure client secret, cookie secret) are NOT
#    exported here.  tpot_setup.sh fetches them directly from SSM
#    Parameter Store using the instance IAM role.
# ---------------------------------------------------------------------------
export TPOT_HOSTNAME="${tpot_hostname}"
export TPOT_WEB_USER="${tpot_web_user}"
export TPOT_FQDN="${tpot_fqdn}"
export AZURE_TENANT_ID="${azure_tenant_id}"
export AZURE_CLIENT_ID="${azure_client_id}"
export AWS_REGION="${aws_region}"

# SSM parameter paths — paths are not sensitive; only the values are secret
export SSM_PATH_WEB_PASSWORD="${ssm_path_web_password}"
export SSM_PATH_AZURE_CLIENT_SECRET="${ssm_path_azure_client_secret}"
export SSM_PATH_OAUTH2_COOKIE_SECRET="${ssm_path_oauth2_cookie_secret}"

# ---------------------------------------------------------------------------
# 5. Run the full T-Pot installation
# ---------------------------------------------------------------------------
echo "[$(date -u +%FT%TZ)] Starting T-Pot installation..."
"$SETUP_SCRIPT"

echo "======================================================"
echo "[$(date -u +%FT%TZ)] T-Pot bootstrap completed"
echo "======================================================"
