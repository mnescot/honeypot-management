# terraform/outputs.tf

output "tpot_instance_id" {
  description = "EC2 instance ID of the T-Pot server"
  value       = aws_instance.tpot.id
}

output "tpot_private_ip" {
  description = "Private IP address of the T-Pot server within the VPC"
  value       = aws_instance.tpot.private_ip
}

output "web_ui_url" {
  description = "T-Pot web UI URL via SAML/OIDC authentication (ALB → oauth2-proxy → T-Pot nginx)"
  value       = "https://${var.tpot_fqdn}"
}

output "target_group_arn" {
  description = "ARN of the ALB target group for the T-Pot instance"
  value       = aws_lb_target_group.tpot.arn
}

output "ssh_management" {
  description = "SSH command to connect to the T-Pot management interface (T-Pot remaps sshd to port 64295)"
  value       = "ssh -p 64295 tsec@${aws_instance.tpot.private_ip}"
}

output "tpot_iam_role_arn" {
  description = "ARN of the IAM role attached to the T-Pot EC2 instance"
  value       = aws_iam_role.tpot.arn
}

output "security_group_id" {
  description = "Security group ID attached to the T-Pot EC2 instance"
  value       = aws_security_group.tpot.id
}
