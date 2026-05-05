# ──────────────────────────────────────────────────────
# Trust Zone Network Foundation — AWS Side
# Implements TZ-1 (Edge), TZ-2 (App), TZ-3 (Data)
# ──────────────────────────────────────────────────────

locals {
  vpc_cidr           = "10.100.0.0/16"
  az_list            = ["us-east-1a", "us-east-1b"]
  dc_peer_cidr       = "10.200.0.0/16"  # Fintech DC range

  trust_zones = {
    tz1_edge = {
      cidrs = ["10.100.10.0/24", "10.100.11.0/24"]
      tier  = "public"
    }
    tz2_app = {
      cidrs = ["10.100.20.0/24", "10.100.21.0/24"]
      tier  = "private"
    }
    tz3_data = {
      cidrs = ["10.100.30.0/24", "10.100.31.0/24"]
      tier  = "isolated"
    }
  }
}

# ── VPC with flow logs to S3 (encrypted, 365-day retention) ──
resource "aws_vpc" "fintech_main" {
  cidr_block           = local.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "fintech-hybrid-vpc"
           Environment = "production"
           Compliance  = "pci-dss-v4,23-nycrr-500" }
}

# ── TZ-2 Application Security Group (ingress from TZ-1 only) ──
resource "aws_security_group" "tz2_app_services" {
  name_prefix = "tz2-app-"
  vpc_id      = aws_vpc.fintech_main.id

  # Allow inbound ONLY from TZ-1 edge (ALB) on port 8443
  ingress {
    from_port       = 8443
    to_port         = 8443
    protocol        = "tcp"
    security_groups = [aws_security_group.tz1_alb.id]
    description     = "TZ-1 -> TZ-2: mTLS from ALB"
  }

  # Deny all other ingress (implicit in AWS SGs)
  # Egress: TZ-3 (data) and TZ-4 (transit) only
  egress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.tz3_aurora.id]
    description     = "TZ-2 -> TZ-3: Aurora PostgreSQL"
  }
  egress {
    from_port   = 8443
    to_port     = 8443
    protocol    = "tcp"
    cidr_blocks = [local.dc_peer_cidr]
    description = "TZ-2 -> TZ-4/TZ-5: DC core ledger"
  }
}

# ── TZ-3 Data Zone: Aurora with encryption + IAM auth ──
resource "aws_rds_cluster" "tz3_payment_db" {
  cluster_identifier           = "fintech-payments"
  engine                       = "aurora-postgresql"
  storage_encrypted            = true  # AES-256, CMK
  kms_key_id                   = aws_kms_key.tz3_db.arn
  iam_database_authentication_enabled = true
  deletion_protection          = true
  backup_retention_period      = 35  # 23 NYCRR 500
  db_subnet_group_name         = aws_db_subnet_group.tz3.name
  vpc_security_group_ids       = [aws_security_group.tz3_aurora.id]
  enabled_cloudwatch_logs_exports = ["postgresql"]
}
