# terraform/alb.tf
# Attaches the T-Pot instance to an existing ALB.
#
# Architecture:
#   Client  →  ALB:443 (HTTPS, ACM cert)
#           →  Target group (HTTP:4180)
#           →  EC2 / oauth2-proxy (HTTP:4180)
#           →  T-Pot nginx (HTTPS:64297, loopback only)
#
# TLS is terminated at the ALB; oauth2-proxy handles OIDC authentication
# and proxies authenticated requests to the T-Pot nginx on localhost.

# ---------------------------------------------------------------------------
# Target group
# ---------------------------------------------------------------------------

resource "aws_lb_target_group" "tpot" {
  name     = "${var.project}-tg"
  port     = 4180
  protocol = "HTTP"
  vpc_id   = var.vpc_id

  # oauth2-proxy exposes /ping which returns 200 without authentication —
  # the correct endpoint for ALB health checks.
  health_check {
    enabled             = true
    protocol            = "HTTP"
    path                = "/ping"
    port                = "traffic-port"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
    matcher             = "200"
  }

  tags = {
    Name        = "${var.project}-tg"
    Project     = var.project
    Environment = var.environment
  }
}

# ---------------------------------------------------------------------------
# Target group attachment — register the T-Pot EC2 instance
# ---------------------------------------------------------------------------

resource "aws_lb_target_group_attachment" "tpot" {
  target_group_arn = aws_lb_target_group.tpot.arn
  target_id        = aws_instance.tpot.id
  port             = 4180
}

# ---------------------------------------------------------------------------
# Listener rule — host-header routing on the existing HTTPS listener
#
# Requests where Host == tpot_fqdn are forwarded to the T-Pot target group.
# All other requests are handled by existing rules on the shared listener.
# ---------------------------------------------------------------------------

resource "aws_lb_listener_rule" "tpot" {
  listener_arn = var.alb_listener_arn
  priority     = var.alb_listener_rule_priority

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tpot.arn
  }

  condition {
    host_header {
      values = [var.tpot_fqdn]
    }
  }

  tags = {
    Name        = "${var.project}-rule"
    Project     = var.project
    Environment = var.environment
  }
}
