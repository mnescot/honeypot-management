# terraform/main.tf
# Core infrastructure for T-Pot honeypot deployment on AWS

terraform {
  # Partial backend — bucket, key, and region are supplied at `terraform init`
  # time by the GitLab CI pipeline via -backend-config flags.
  backend "s3" {}

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  required_version = ">= 1.5.0"
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

# ---------------------------------------------------------------------------
# Data sources
# ---------------------------------------------------------------------------

# Resolve the latest Ubuntu 22.04 LTS (Jammy) HVM/EBS AMI in the target region.
# T-Pot CE 24.x officially supports Ubuntu 22.04 LTS.
data "aws_ami" "ubuntu_22_04" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

data "aws_vpc" "selected" {
  id = var.vpc_id
}

# ---------------------------------------------------------------------------
# EC2 instance
# ---------------------------------------------------------------------------

resource "aws_instance" "tpot" {
  ami                    = data.aws_ami.ubuntu_22_04.id
  instance_type          = var.instance_type
  subnet_id              = var.subnet_ids[0]
  key_name               = var.key_name
  iam_instance_profile   = aws_iam_instance_profile.tpot.name
  vpc_security_group_ids = [aws_security_group.tpot.id]

  # Disable source/dest check — T-Pot acts as a network sensor and may
  # need to receive traffic destined for other hosts in test scenarios.
  source_dest_check = false

  # Enforce IMDSv2 (token-required) to prevent SSRF-based credential
  # theft from honeypot containers that may be able to reach 169.254.169.254.
  # hop_limit=1 prevents container workloads from reaching IMDS.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_type           = var.root_volume_type
    volume_size           = var.root_volume_size
    delete_on_termination = true
    encrypted             = true

    tags = {
      Name = "${var.project}-root"
    }
  }

  # Secrets are NOT passed through user_data.  They are stored in SSM
  # Parameter Store (SecureString) and fetched at runtime by tpot_setup.sh
  # using the instance IAM role.  user_data therefore contains no credentials
  # and is safe to expose via EC2 metadata or Terraform state.
  user_data = templatefile("${path.module}/../user_data.sh", {
    aws_region                   = var.aws_region
    tpot_hostname                = var.tpot_hostname
    tpot_web_user                = var.tpot_web_user
    tpot_fqdn                    = var.tpot_fqdn
    azure_tenant_id              = var.azure_tenant_id
    azure_client_id              = var.azure_client_id
    setup_script_s3_bucket       = var.setup_script_s3_bucket
    setup_script_s3_key          = var.setup_script_s3_key
    # SSM paths — non-sensitive; the values are fetched at runtime
    ssm_path_web_password        = aws_ssm_parameter.tpot_web_password.name
    ssm_path_azure_client_secret = aws_ssm_parameter.azure_client_secret.name
    ssm_path_oauth2_cookie_secret = aws_ssm_parameter.oauth2_cookie_secret.name
  })

  # Ensure the instance profile exists before the instance is created
  depends_on = [aws_iam_instance_profile.tpot]

  tags = {
    Name = var.tpot_hostname
    Role = "honeypot"
  }

  lifecycle {
    # Prevent accidental replacement of a running honeypot instance.
    # The AMI id changes over time, but we want to keep the existing instance.
    ignore_changes = [ami]
  }
}

# ---------------------------------------------------------------------------
# Elastic IP — stable public address for the honeypot
# ---------------------------------------------------------------------------

resource "aws_eip" "tpot" {
  instance = aws_instance.tpot.id
  domain   = "vpc"

  tags = {
    Name = "${var.project}-eip"
  }
}
