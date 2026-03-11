# terraform/security_groups.tf
# Security group for the T-Pot honeypot EC2 instance.
#
# Design principles:
#   - Honeypot ports are open to 0.0.0.0/0 (the whole point is to attract traffic)
#   - Management ports are restricted to tpot_admin_cidr
#   - The web UI backend (port 4180, oauth2-proxy HTTP) accepts traffic only
#     from the ALB security group — the ALB terminates HTTPS with its ACM cert
#   - Port 64297 (T-Pot nginx direct) is NOT exposed externally; access is
#     only via oauth2-proxy on port 4180 → localhost:64297
#   - All outbound traffic is permitted (T-Pot components need internet access
#     for threat-intel feeds, Docker image pulls, etc.)

resource "aws_security_group" "tpot" {
  name        = "${var.project}-sg"
  description = "T-Pot honeypot - management and honeypot ports"
  vpc_id      = var.vpc_id

  tags = {
    Name = "${var.project}-sg"
  }
}

# ---------------------------------------------------------------------------
# Management ports — admin CIDR only
# ---------------------------------------------------------------------------

# SSH management (T-Pot remaps SSH to 64295; port 22 is used by Cowrie honeypot)
resource "aws_security_group_rule" "mgmt_ssh" {
  security_group_id = aws_security_group.tpot.id
  type              = "ingress"
  description       = "SSH management access (T-Pot moves sshd to 64295)"
  from_port         = 64295
  to_port           = 64295
  protocol          = "tcp"
  cidr_blocks       = var.tpot_admin_cidr
}

# oauth2-proxy backend (HTTP:4180) — ALB security group only
# The ALB terminates HTTPS with its ACM certificate and forwards plain HTTP
# to this port. Direct access from clients on port 443 is no longer needed;
# the ALB is the sole entry point for web UI traffic.
resource "aws_security_group_rule" "alb_backend" {
  security_group_id        = aws_security_group.tpot.id
  type                     = "ingress"
  description              = "oauth2-proxy backend - from ALB only (ALB terminates TLS)"
  from_port                = 4180
  to_port                  = 4180
  protocol                 = "tcp"
  source_security_group_id = var.alb_security_group_id
}

# ---------------------------------------------------------------------------
# Honeypot ports — open to the internet
# These correspond to the services emulated by T-Pot's default HIVE profile.
# ---------------------------------------------------------------------------

# FTP (Dionaea / HoneyFTP)
resource "aws_security_group_rule" "hp_ftp" {
  security_group_id = aws_security_group.tpot.id
  type              = "ingress"
  description       = "Honeypot - FTP"
  from_port         = 21
  to_port           = 21
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  ipv6_cidr_blocks  = ["::/0"]
}

# SSH honeypot (Cowrie) — port 22
resource "aws_security_group_rule" "hp_ssh" {
  security_group_id = aws_security_group.tpot.id
  type              = "ingress"
  description       = "Honeypot - SSH (Cowrie)"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  ipv6_cidr_blocks  = ["::/0"]
}

# Telnet (Cowrie)
resource "aws_security_group_rule" "hp_telnet" {
  security_group_id = aws_security_group.tpot.id
  type              = "ingress"
  description       = "Honeypot - Telnet (Cowrie)"
  from_port         = 23
  to_port           = 23
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  ipv6_cidr_blocks  = ["::/0"]
}

# SMTP (Mailoney)
resource "aws_security_group_rule" "hp_smtp" {
  security_group_id = aws_security_group.tpot.id
  type              = "ingress"
  description       = "Honeypot - SMTP (Mailoney)"
  from_port         = 25
  to_port           = 25
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  ipv6_cidr_blocks  = ["::/0"]
}

# HTTP (various honeypots)
resource "aws_security_group_rule" "hp_http" {
  security_group_id = aws_security_group.tpot.id
  type              = "ingress"
  description       = "Honeypot - HTTP"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  ipv6_cidr_blocks  = ["::/0"]
}

# POP3 (Heralding)
resource "aws_security_group_rule" "hp_pop3" {
  security_group_id = aws_security_group.tpot.id
  type              = "ingress"
  description       = "Honeypot - POP3 (Heralding)"
  from_port         = 110
  to_port           = 110
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  ipv6_cidr_blocks  = ["::/0"]
}

# IMAP (Heralding)
resource "aws_security_group_rule" "hp_imap" {
  security_group_id = aws_security_group.tpot.id
  type              = "ingress"
  description       = "Honeypot - IMAP (Heralding)"
  from_port         = 143
  to_port           = 143
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  ipv6_cidr_blocks  = ["::/0"]
}

# SNMP UDP (Honeytrap)
resource "aws_security_group_rule" "hp_snmp" {
  security_group_id = aws_security_group.tpot.id
  type              = "ingress"
  description       = "Honeypot - SNMP UDP (Honeytrap)"
  from_port         = 161
  to_port           = 161
  protocol          = "udp"
  cidr_blocks       = ["0.0.0.0/0"]
  ipv6_cidr_blocks  = ["::/0"]
}

# HTTPS honeypot
resource "aws_security_group_rule" "hp_https_honeypot" {
  security_group_id = aws_security_group.tpot.id
  type              = "ingress"
  description       = "Honeypot - HTTPS"
  from_port         = 8443
  to_port           = 8443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  ipv6_cidr_blocks  = ["::/0"]
}

# SMB (Dionaea)
resource "aws_security_group_rule" "hp_smb" {
  security_group_id = aws_security_group.tpot.id
  type              = "ingress"
  description       = "Honeypot - SMB (Dionaea)"
  from_port         = 445
  to_port           = 445
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  ipv6_cidr_blocks  = ["::/0"]
}

# MSSQL (Dionaea)
resource "aws_security_group_rule" "hp_mssql" {
  security_group_id = aws_security_group.tpot.id
  type              = "ingress"
  description       = "Honeypot - MSSQL (Dionaea)"
  from_port         = 1433
  to_port           = 1433
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  ipv6_cidr_blocks  = ["::/0"]
}

# MySQL (Heralding / Dionaea)
resource "aws_security_group_rule" "hp_mysql" {
  security_group_id = aws_security_group.tpot.id
  type              = "ingress"
  description       = "Honeypot - MySQL (Heralding/Dionaea)"
  from_port         = 3306
  to_port           = 3306
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  ipv6_cidr_blocks  = ["::/0"]
}

# RDP (Heralding / RDPY)
resource "aws_security_group_rule" "hp_rdp" {
  security_group_id = aws_security_group.tpot.id
  type              = "ingress"
  description       = "Honeypot - RDP (Heralding/RDPY)"
  from_port         = 3389
  to_port           = 3389
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  ipv6_cidr_blocks  = ["::/0"]
}

# PostgreSQL (Heralding)
resource "aws_security_group_rule" "hp_postgres" {
  security_group_id = aws_security_group.tpot.id
  type              = "ingress"
  description       = "Honeypot - PostgreSQL (Heralding)"
  from_port         = 5432
  to_port           = 5432
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  ipv6_cidr_blocks  = ["::/0"]
}

# VNC (Heralding)
resource "aws_security_group_rule" "hp_vnc" {
  security_group_id = aws_security_group.tpot.id
  type              = "ingress"
  description       = "Honeypot - VNC (Heralding)"
  from_port         = 5900
  to_port           = 5900
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  ipv6_cidr_blocks  = ["::/0"]
}

# Redis (RedisHoneypot)
resource "aws_security_group_rule" "hp_redis" {
  security_group_id = aws_security_group.tpot.id
  type              = "ingress"
  description       = "Honeypot - Redis (RedisHoneypot)"
  from_port         = 6379
  to_port           = 6379
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  ipv6_cidr_blocks  = ["::/0"]
}

# HTTP-alt (various)
resource "aws_security_group_rule" "hp_http_alt" {
  security_group_id = aws_security_group.tpot.id
  type              = "ingress"
  description       = "Honeypot - HTTP-alt (Glutton, Honeytrap)"
  from_port         = 8080
  to_port           = 8080
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  ipv6_cidr_blocks  = ["::/0"]
}

# Elasticsearch (Elasticpot)
resource "aws_security_group_rule" "hp_elasticsearch" {
  security_group_id = aws_security_group.tpot.id
  type              = "ingress"
  description       = "Honeypot - Elasticsearch (Elasticpot)"
  from_port         = 9200
  to_port           = 9200
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  ipv6_cidr_blocks  = ["::/0"]
}

# MongoDB (HoneyMongo)
resource "aws_security_group_rule" "hp_mongodb" {
  security_group_id = aws_security_group.tpot.id
  type              = "ingress"
  description       = "Honeypot - MongoDB (HoneyMongo)"
  from_port         = 27017
  to_port           = 27017
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  ipv6_cidr_blocks  = ["::/0"]
}

# Modbus / ICS (Conpot — industrial honeypot)
resource "aws_security_group_rule" "hp_modbus" {
  security_group_id = aws_security_group.tpot.id
  type              = "ingress"
  description       = "Honeypot - Modbus/TCP (Conpot ICS)"
  from_port         = 502
  to_port           = 502
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  ipv6_cidr_blocks  = ["::/0"]
}

# S7comm / ICS (Conpot — industrial honeypot)
resource "aws_security_group_rule" "hp_s7" {
  security_group_id = aws_security_group.tpot.id
  type              = "ingress"
  description       = "Honeypot - S7comm (Conpot ICS)"
  from_port         = 102
  to_port           = 102
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  ipv6_cidr_blocks  = ["::/0"]
}

# SIP (SentryPeer)
resource "aws_security_group_rule" "hp_sip" {
  security_group_id = aws_security_group.tpot.id
  type              = "ingress"
  description       = "Honeypot - SIP UDP (SentryPeer)"
  from_port         = 5060
  to_port           = 5060
  protocol          = "udp"
  cidr_blocks       = ["0.0.0.0/0"]
  ipv6_cidr_blocks  = ["::/0"]
}

# LDAP (Heralding)
resource "aws_security_group_rule" "hp_ldap" {
  security_group_id = aws_security_group.tpot.id
  type              = "ingress"
  description       = "Honeypot - LDAP (Heralding)"
  from_port         = 389
  to_port           = 389
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  ipv6_cidr_blocks  = ["::/0"]
}

# HTTPS / Citrix honeypot (CitrixHoneypot)
resource "aws_security_group_rule" "hp_citrix" {
  security_group_id = aws_security_group.tpot.id
  type              = "ingress"
  description       = "Honeypot - HTTPS/Citrix (CitrixHoneypot)"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  ipv6_cidr_blocks  = ["::/0"]
}

# ---------------------------------------------------------------------------
# Beelzebub LLM honeypot ports
# Beelzebub runs as a host service alongside T-Pot.  Cowrie occupies port 22
# (SSH) so Beelzebub uses 2222.  Port 8888 is used for its HTTP honeypot.
# ---------------------------------------------------------------------------

# SSH LLM honeypot (Beelzebub)
resource "aws_security_group_rule" "hp_beelzebub_ssh" {
  security_group_id = aws_security_group.tpot.id
  type              = "ingress"
  description       = "Honeypot - AI SSH (Beelzebub/Ollama)"
  from_port         = 2222
  to_port           = 2222
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  ipv6_cidr_blocks  = ["::/0"]
}

# HTTP LLM honeypot (Beelzebub) — Apache persona
resource "aws_security_group_rule" "hp_beelzebub_http" {
  security_group_id = aws_security_group.tpot.id
  type              = "ingress"
  description       = "Honeypot - AI HTTP Apache (Beelzebub/Ollama)"
  from_port         = 8888
  to_port           = 8888
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  ipv6_cidr_blocks  = ["::/0"]
}

# HTTP LLM honeypot (Beelzebub) — Citrix NetScaler persona
resource "aws_security_group_rule" "hp_beelzebub_http_citrix" {
  security_group_id = aws_security_group.tpot.id
  type              = "ingress"
  description       = "Honeypot - AI HTTP Citrix (Beelzebub/Ollama)"
  from_port         = 8890
  to_port           = 8890
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  ipv6_cidr_blocks  = ["::/0"]
}

# HTTP LLM honeypot (Beelzebub) — WordPress persona
resource "aws_security_group_rule" "hp_beelzebub_http_wordpress" {
  security_group_id = aws_security_group.tpot.id
  type              = "ingress"
  description       = "Honeypot - AI HTTP WordPress (Beelzebub/Ollama)"
  from_port         = 8891
  to_port           = 8891
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  ipv6_cidr_blocks  = ["::/0"]
}

# ---------------------------------------------------------------------------
# Egress — unrestricted outbound
# ---------------------------------------------------------------------------

resource "aws_security_group_rule" "egress_all" {
  security_group_id = aws_security_group.tpot.id
  type              = "egress"
  description       = "Allow all outbound traffic (Docker pulls, threat-intel feeds)"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  ipv6_cidr_blocks  = ["::/0"]
}
