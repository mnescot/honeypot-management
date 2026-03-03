# terraform/variables.tf
# Input variables for the T-Pot honeypot deployment

# ---------------------------------------------------------------------------
# AWS / networking
# ---------------------------------------------------------------------------

variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "vpc_id" {
  description = "ID of the existing VPC to deploy T-Pot into"
  type        = string
}

variable "subnet_ids" {
  description = "List of existing subnet IDs for the T-Pot EC2 instance. Provide at least one public subnet."
  type        = list(string)
}

# ---------------------------------------------------------------------------
# EC2
# ---------------------------------------------------------------------------

variable "instance_type" {
  description = "EC2 instance type for the T-Pot server. T-Pot recommends at least 8 GB RAM (t3.xlarge = 4 vCPU / 16 GB)."
  type        = string
  default     = "t3.xlarge"
}

variable "key_name" {
  description = "Name of the existing EC2 key pair used for SSH access"
  type        = string
}

variable "tpot_hostname" {
  description = "Hostname assigned to the T-Pot EC2 instance"
  type        = string
  default     = "tpot"
}

variable "root_volume_size" {
  description = "Root EBS volume size in GB. T-Pot stores Elasticsearch data locally; 128 GB is the recommended minimum."
  type        = number
  default     = 128
}

variable "root_volume_type" {
  description = "EBS volume type for the root volume"
  type        = string
  default     = "gp3"
}

# ---------------------------------------------------------------------------
# Access control
# ---------------------------------------------------------------------------

variable "tpot_admin_cidr" {
  description = "List of CIDR blocks allowed to reach management ports (SSH on 64295, web UI on 64297 direct, and the SAML-protected UI on 443)."
  type        = list(string)
}

# ---------------------------------------------------------------------------
# T-Pot web credentials
# ---------------------------------------------------------------------------

variable "tpot_web_user" {
  description = "Username for the T-Pot web UI (BasicAuth, used before SAML layer)"
  type        = string
  default     = "admin"
}

variable "tpot_web_password" {
  description = "Password for the T-Pot web UI BasicAuth account"
  type        = string
  sensitive   = true
}

# ---------------------------------------------------------------------------
# DNS / TLS
# ---------------------------------------------------------------------------

variable "tpot_fqdn" {
  description = "Fully-qualified domain name for the T-Pot server (used as the oauth2-proxy redirect URL and TLS CN). Example: tpot.example.com"
  type        = string
}

# ---------------------------------------------------------------------------
# Microsoft Entra ID OIDC (SAML-compatible SSO)
# ---------------------------------------------------------------------------

variable "azure_tenant_id" {
  description = "Microsoft Entra ID (Azure AD) Tenant ID for the OIDC application"
  type        = string
}

variable "azure_client_id" {
  description = "Application (client) ID of the Entra ID app registration for T-Pot"
  type        = string
}

variable "azure_client_secret" {
  description = "Client secret for the Entra ID app registration"
  type        = string
  sensitive   = true
}

variable "oauth2_cookie_secret" {
  description = "Random 32-byte base64-encoded secret used by oauth2-proxy to sign session cookies. Generate with: openssl rand -base64 32"
  type        = string
  sensitive   = true
}

# ---------------------------------------------------------------------------
# S3 — setup scripts
# ---------------------------------------------------------------------------

variable "setup_script_s3_bucket" {
  description = "S3 bucket containing the T-Pot setup script (uploaded by the CI upload-scripts stage)"
  type        = string
}

variable "setup_script_s3_key" {
  description = "S3 object key for the T-Pot setup script"
  type        = string
  default     = "tpot/tpot_setup.sh"
}

# ---------------------------------------------------------------------------
# Tagging
# ---------------------------------------------------------------------------

variable "environment" {
  description = "Environment name applied as a resource tag"
  type        = string
  default     = "production"
}

variable "project" {
  description = "Project name applied as a resource tag"
  type        = string
  default     = "tpot-honeypot"
}

variable "ssm_kms_key_arn" {
  description = "ARN of the KMS key configured in SSM Session Manager preferences for session encryption. Required when your account enforces KMS-encrypted SSM sessions. Leave empty if sessions are unencrypted."
  type        = string
  default     = ""
}

variable "ssm_logs_s3_bucket" {
  description = "Name of the S3 bucket configured in SSM Session Manager preferences for session logging (e.g. the central LZA logging bucket). Required when your account ships SSM session logs to S3. Leave empty if S3 logging is not configured."
  type        = string
  default     = ""
}
