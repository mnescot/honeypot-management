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
  description = "EC2 instance type for the T-Pot server. t3.2xlarge (8 vCPU / 32 GB) is recommended when running Ollama LLM inference for Beelzebub; t3.xlarge (4 vCPU / 16 GB) is the minimum without LLM features."
  type        = string
  default     = "t3.2xlarge"
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

# ---------------------------------------------------------------------------
# ALB integration
# ---------------------------------------------------------------------------

variable "alb_listener_arn" {
  description = "ARN of the existing ALB HTTPS listener (port 443) to attach the T-Pot listener rule to. TLS is terminated at the ALB using its ACM certificate; oauth2-proxy on the EC2 instance receives plain HTTP on port 4180."
  type        = string
}

variable "alb_security_group_id" {
  description = "Security group ID of the existing ALB. The T-Pot EC2 security group will allow inbound HTTP on port 4180 only from this security group, ensuring traffic must pass through the ALB."
  type        = string
}

variable "alb_listener_rule_priority" {
  description = "Priority for the ALB listener rule that routes requests matching tpot_fqdn to the T-Pot target group. Must be unique within the listener (1-50000). Lower values are evaluated first."
  type        = number
  default     = 100
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

# ---------------------------------------------------------------------------
# Amazon Bedrock (optional LLM backend for honeypots)
#
# When enabled, the mgmt-ui exposes a unified OpenAI-compatible proxy at
# /llm/v1/chat/completions and routes model IDs prefixed with "bedrock:"
# (e.g. "bedrock:anthropic.claude-3-haiku-20240307-v1:0") to Bedrock via
# boto3 using the EC2 instance IAM role. Non-prefixed model IDs continue
# to route to the local Ollama daemon.
# ---------------------------------------------------------------------------

variable "enable_bedrock" {
  description = "If true, grant the EC2 instance IAM role permission to invoke Amazon Bedrock models and provision a VPC interface endpoint for bedrock-runtime so traffic stays on the AWS backbone."
  type        = bool
  default     = false
}

variable "bedrock_model_arns" {
  description = "List of Bedrock foundation-model ARNs the instance is allowed to invoke (e.g. arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-haiku-20240307-v1:0). Used to scope the bedrock:InvokeModel/Converse policy. Required when enable_bedrock = true; ignored otherwise."
  type        = list(string)
  default     = []
}

variable "bedrock_default_models" {
  description = "List of Bedrock model IDs (without the 'bedrock:' prefix) to offer in the mgmt-ui model picker when deploying honeypots to remote nodes. Purely cosmetic; the IAM policy controls what can actually be invoked."
  type        = list(string)
  default     = []
}
