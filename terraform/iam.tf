# terraform/iam.tf
# IAM role and instance profile for the T-Pot EC2 instance.
#
# The instance role grants:
#   - S3 read access scoped to the scripts bucket (for user-data bootstrap)
#   - SSM GetParameter (with decryption) scoped to /tpot/* secrets
#   - CloudWatch Logs write access (for shipping T-Pot logs to CWL)
#   - SSM Session Manager access (alternative management path)

data "aws_caller_identity" "current" {}

# ---------------------------------------------------------------------------
# Trust policy — allow EC2 to assume this role
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "ec2_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

# ---------------------------------------------------------------------------
# IAM role
# ---------------------------------------------------------------------------

resource "aws_iam_role" "tpot" {
  name               = "${var.project}-ec2-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json

  tags = {
    Name = "${var.project}-ec2-role"
  }
}

# ---------------------------------------------------------------------------
# Inline policy — S3 read for setup scripts
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "tpot_s3_scripts" {
  statement {
    sid    = "ReadSetupScripts"
    effect = "Allow"

    actions = [
      "s3:GetObject",
      "s3:HeadObject",
    ]

    resources = [
      "arn:aws:s3:::${var.setup_script_s3_bucket}/${var.setup_script_s3_key}",
      "arn:aws:s3:::${var.setup_script_s3_bucket}/tpot/*",
    ]
  }

  statement {
    sid    = "ListScriptsBucket"
    effect = "Allow"

    actions = ["s3:ListBucket"]

    resources = ["arn:aws:s3:::${var.setup_script_s3_bucket}"]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["tpot/*"]
    }
  }
}

resource "aws_iam_role_policy" "tpot_s3_scripts" {
  name   = "tpot-s3-scripts"
  role   = aws_iam_role.tpot.id
  policy = data.aws_iam_policy_document.tpot_s3_scripts.json
}

# ---------------------------------------------------------------------------
# SSM Parameter Store — read secrets at runtime (never via user_data)
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "tpot_ssm_secrets" {
  statement {
    sid    = "GetTpotSecrets"
    effect = "Allow"

    actions = [
      "ssm:GetParameter",
      "ssm:GetParameters",
    ]

    # Scoped to the exact parameters created in ssm.tf
    resources = [
      "arn:aws:ssm:${var.aws_region}:${data.aws_caller_identity.current.account_id}:parameter/${var.project}/*",
    ]
  }
}

resource "aws_iam_role_policy" "tpot_ssm_secrets" {
  name   = "tpot-ssm-secrets"
  role   = aws_iam_role.tpot.id
  policy = data.aws_iam_policy_document.tpot_ssm_secrets.json
}

# ---------------------------------------------------------------------------
# CloudWatch Logs — ship T-Pot and system logs
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "tpot_cloudwatch" {
  statement {
    sid    = "CloudWatchLogs"
    effect = "Allow"

    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
    ]

    resources = [
      "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/tpot/*",
    ]
  }
}

resource "aws_iam_role_policy" "tpot_cloudwatch" {
  name   = "tpot-cloudwatch"
  role   = aws_iam_role.tpot.id
  policy = data.aws_iam_policy_document.tpot_cloudwatch.json
}

# ---------------------------------------------------------------------------
# Attach AWS managed SSM policy — enables Session Manager as a fallback
# management path without needing a direct SSH security group rule
# ---------------------------------------------------------------------------

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.tpot.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# ---------------------------------------------------------------------------
# KMS — Session Manager session encryption
#
# When SSM Session Manager preferences enforce KMS encryption, the EC2
# instance role must be able to decrypt the session data key.
# Set var.ssm_kms_key_arn to the key ARN shown in the Session Manager
# preferences console (or the error message at session start).
# ---------------------------------------------------------------------------

resource "aws_iam_role_policy" "tpot_ssm_kms" {
  count = var.ssm_kms_key_arn != "" ? 1 : 0

  name = "tpot-ssm-kms"
  role = aws_iam_role.tpot.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SessionManagerKmsDecrypt"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
        ]
        Resource = var.ssm_kms_key_arn
      }
    ]
  })
}

# ---------------------------------------------------------------------------
# S3 — SSM Session Manager session logging
#
# When SSM Session Manager preferences ship session logs to an S3 bucket
# (common in Landing Zone Accelerator accounts), the EC2 instance role must
# be able to read the bucket's encryption configuration and write log objects.
# Set var.ssm_logs_s3_bucket to the bucket name shown in the Session Manager
# preferences console (or the AccessDenied error message).
# ---------------------------------------------------------------------------

resource "aws_iam_role_policy" "tpot_ssm_s3_logs" {
  count = var.ssm_logs_s3_bucket != "" ? 1 : 0

  name = "tpot-ssm-s3-logs"
  role = aws_iam_role.tpot.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SessionManagerS3Logging"
        Effect = "Allow"
        Action = [
          "s3:GetEncryptionConfiguration",
          "s3:PutObject",
          "s3:PutObjectAcl",
        ]
        Resource = [
          "arn:aws:s3:::${var.ssm_logs_s3_bucket}",
          "arn:aws:s3:::${var.ssm_logs_s3_bucket}/*",
        ]
      }
    ]
  })
}

# ---------------------------------------------------------------------------
# Inline policy — Amazon Bedrock (optional)
#
# When var.enable_bedrock is true, allow the instance to invoke the Bedrock
# foundation models listed in var.bedrock_model_arns. InvokeModel and
# Converse cover the sync and streaming APIs used by the mgmt-ui llm_proxy.
# The policy is scoped to the exact model ARNs — there is no wildcard grant.
# ---------------------------------------------------------------------------

resource "aws_iam_role_policy" "tpot_bedrock" {
  count = var.enable_bedrock && length(var.bedrock_model_arns) > 0 ? 1 : 0

  name = "tpot-bedrock-invoke"
  role = aws_iam_role.tpot.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "InvokeScopedFoundationModels"
        Effect = "Allow"
        Action = [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream",
          "bedrock:Converse",
          "bedrock:ConverseStream",
        ]
        Resource = var.bedrock_model_arns
      }
    ]
  })
}

# ---------------------------------------------------------------------------
# Instance profile
# ---------------------------------------------------------------------------

resource "aws_iam_instance_profile" "tpot" {
  name = "${var.project}-ec2-profile"
  role = aws_iam_role.tpot.name

  tags = {
    Name = "${var.project}-ec2-profile"
  }
}
