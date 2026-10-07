locals {
  # Proposed initial sizing; a change is a reviewed code edit, not an input.
  db_instance_class    = "db.t4g.micro"
  db_allocated_storage = 20
  report_bucket_policy = {
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport", Effect = "Deny", Principal = "*", Action = ["s3:*"]
        Resource  = [local.report_bucket_arn, "${local.report_bucket_arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid      = "DenyVersionDeletion", Effect = "Deny", Principal = "*", Action = ["s3:DeleteObjectVersion"]
        Resource = [local.report_bucket_arn, "${local.report_bucket_arn}/*"]
      },
      {
        Sid      = "DenyWorkloadsOutsideEndpoint", Effect = "Deny", Principal = "*", Action = ["s3:*"]
        Resource = [local.report_bucket_arn, "${local.report_bucket_arn}/*"]
        Condition = {
          ArnLike         = { "aws:PrincipalArn" = module.names.workload_role_patterns }
          StringNotEquals = { "aws:SourceVpce" = aws_vpc_endpoint.s3.id }
        }
      },
    ]
  }
}

resource "aws_db_subnet_group" "this" {
  name        = "${var.name_prefix}-db"
  description = "Private DB subnets for ${var.name_prefix}"
  subnet_ids  = [for subnet in aws_subnet.db : subnet.id]
}

resource "aws_db_parameter_group" "postgres16" {
  name        = "${var.name_prefix}-postgres16"
  family      = "postgres16"
  description = "TLS-only PostgreSQL 16 for ${var.name_prefix}"
  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
  parameter {
    name  = "ssl_min_protocol_version"
    value = "TLSv1.2"
  }
}

# Runtime's execution ledger and Search's product data stay in separate
# instances with separate security groups and administrator secrets.
resource "aws_db_instance" "this" {
  for_each                            = module.names.db_identifiers
  identifier                          = each.value
  engine                              = "postgres"
  engine_version                      = var.postgres_engine_version
  engine_lifecycle_support            = "open-source-rds-extended-support-disabled"
  instance_class                      = local.db_instance_class
  allocated_storage                   = local.db_allocated_storage
  storage_type                        = "gp3"
  storage_encrypted                   = true
  username                            = "${each.key}_admin"
  manage_master_user_password         = true
  db_subnet_group_name                = aws_db_subnet_group.this.name
  parameter_group_name                = aws_db_parameter_group.postgres16.name
  vpc_security_group_ids              = [aws_security_group.this["${each.key}_db"].id]
  ca_cert_identifier                  = var.rds_ca_identifier
  network_type                        = "IPV4"
  port                                = 5432
  publicly_accessible                 = false
  multi_az                            = false
  iam_database_authentication_enabled = false
  performance_insights_enabled        = false
  monitoring_interval                 = 0
  backup_retention_period             = 7
  copy_tags_to_snapshot               = true
  delete_automated_backups            = false
  deletion_protection                 = true
  skip_final_snapshot                 = false
  final_snapshot_identifier           = "${each.value}-final"
  auto_minor_version_upgrade          = false
  allow_major_version_upgrade         = false
  apply_immediately                   = false
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket" "reports" {
  bucket        = module.names.report_bucket
  force_destroy = false
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_ownership_controls" "reports" {
  bucket = aws_s3_bucket.reports.bucket
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket                  = aws_s3_bucket.reports.bucket
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "reports" {
  bucket = aws_s3_bucket.reports.bucket
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.bucket
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "reports" {
  bucket = aws_s3_bucket.reports.bucket
  rule {
    id     = "bounded-report-retention"
    status = "Enabled"
    filter {}
    expiration {
      days = var.report_retention_days
    }
    noncurrent_version_expiration {
      noncurrent_days = var.report_retention_days
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
  depends_on = [aws_s3_bucket_versioning.reports]
}

resource "aws_s3_bucket_policy" "reports" {
  bucket     = aws_s3_bucket.reports.bucket
  policy     = jsonencode(local.report_bucket_policy)
  depends_on = [aws_s3_bucket_public_access_block.reports]
}
