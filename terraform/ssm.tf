# terraform/ssm.tf
# SSM Parameter Store — SecureString parameters for T-Pot secrets.
#
# Secrets are stored here rather than in EC2 user_data so that:
#   - user_data (visible via IMDS and cloud-init artifacts) contains no credentials
#   - Terraform state exposure is limited to the encrypted S3 backend
#   - Access is gated by IAM on the EC2 instance role (see iam.tf)
#
# The EC2 instance fetches these at runtime via `aws ssm get-parameter
# --with-decryption`, using the instance profile IAM role.

resource "aws_ssm_parameter" "tpot_web_password" {
  name        = "/${var.project}/web_password"
  description = "T-Pot web UI BasicAuth password"
  type        = "SecureString"
  value       = var.tpot_web_password

  tags = {
    Name = "${var.project}-web-password"
  }
}

resource "aws_ssm_parameter" "azure_client_secret" {
  name        = "/${var.project}/azure_client_secret"
  description = "Microsoft Entra ID app registration client secret for oauth2-proxy"
  type        = "SecureString"
  value       = var.azure_client_secret

  tags = {
    Name = "${var.project}-azure-client-secret"
  }
}

resource "aws_ssm_parameter" "oauth2_cookie_secret" {
  name        = "/${var.project}/oauth2_cookie_secret"
  description = "oauth2-proxy session cookie signing secret"
  type        = "SecureString"
  value       = var.oauth2_cookie_secret

  tags = {
    Name = "${var.project}-oauth2-cookie-secret"
  }
}
