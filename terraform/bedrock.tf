# terraform/bedrock.tf
# VPC interface endpoint for Amazon Bedrock runtime.
#
# When var.enable_bedrock is true, the mgmt-ui llm_proxy forwards OpenAI-
# compatible chat completions to Bedrock via boto3. Provisioning a PrivateLink
# interface endpoint for com.amazonaws.<region>.bedrock-runtime keeps that
# traffic on the AWS backbone (no egress to the public internet) and lets the
# Bedrock client resolve to private IPs inside the VPC.
#
# Private DNS is enabled so that boto3's default endpoint
# `bedrock-runtime.<region>.amazonaws.com` resolves to the endpoint's private
# IPs with no client-side configuration.

resource "aws_security_group" "bedrock_endpoint" {
  count = var.enable_bedrock ? 1 : 0

  name        = "${var.project}-bedrock-endpoint-sg"
  description = "Allow T-Pot EC2 to reach the Bedrock runtime VPC endpoint on 443"
  vpc_id      = var.vpc_id

  tags = {
    Name = "${var.project}-bedrock-endpoint-sg"
  }
}

resource "aws_security_group_rule" "bedrock_endpoint_ingress" {
  count = var.enable_bedrock ? 1 : 0

  security_group_id        = aws_security_group.bedrock_endpoint[0].id
  type                     = "ingress"
  description              = "HTTPS from T-Pot EC2 to Bedrock runtime endpoint"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.tpot.id
}

resource "aws_security_group_rule" "bedrock_endpoint_egress" {
  count = var.enable_bedrock ? 1 : 0

  security_group_id = aws_security_group.bedrock_endpoint[0].id
  type              = "egress"
  description       = "Endpoint ENI return traffic"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
}

resource "aws_vpc_endpoint" "bedrock_runtime" {
  count = var.enable_bedrock ? 1 : 0

  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${var.aws_region}.bedrock-runtime"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.subnet_ids
  security_group_ids  = [aws_security_group.bedrock_endpoint[0].id]
  private_dns_enabled = true

  tags = {
    Name = "${var.project}-bedrock-runtime-vpce"
  }
}
