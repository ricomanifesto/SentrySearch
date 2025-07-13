terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.1"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# Generate unique suffix for S3 bucket
resource "random_id" "bucket_suffix" {
  byte_length = 8
}

# S3 Bucket for report storage
resource "aws_s3_bucket" "sentrysearch_reports" {
  bucket = "${var.project_name}-reports-${random_id.bucket_suffix.hex}"

  tags = {
    Name        = "SentrySearch Reports"
    Environment = "production"
    Project     = var.project_name
  }
}

# S3 Bucket Versioning
resource "aws_s3_bucket_versioning" "sentrysearch_reports" {
  bucket = aws_s3_bucket.sentrysearch_reports.id
  versioning_configuration {
    status = "Enabled"
  }
}

# S3 Bucket Server-Side Encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "sentrysearch_reports" {
  bucket = aws_s3_bucket.sentrysearch_reports.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# S3 Bucket Public Access Block
resource "aws_s3_bucket_public_access_block" "sentrysearch_reports" {
  bucket = aws_s3_bucket.sentrysearch_reports.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# S3 Bucket Lifecycle Configuration
resource "aws_s3_bucket_lifecycle_configuration" "sentrysearch_reports" {
  bucket = aws_s3_bucket.sentrysearch_reports.id

  rule {
    id     = "archive_old_reports"
    status = "Enabled"

    filter {
      prefix = ""
    }

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 2555 # 7 years retention
    }
  }
}

# Get default VPC
data "aws_vpc" "default" {
  default = true
}

# Get default VPC subnets
data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

# Security Group for RDS
resource "aws_security_group" "sentrysearch_db" {
  name_prefix = "${var.project_name}-db-"
  vpc_id      = data.aws_vpc.default.id
  description = "Security group for SentrySearch PostgreSQL database"

  ingress {
    description = "PostgreSQL"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Note: Restrict this in production
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-db-security-group"
  }
}

# RDS Subnet Group
resource "aws_db_subnet_group" "sentrysearch" {
  name       = "${var.project_name}-subnet-group"
  subnet_ids = data.aws_subnets.default.ids

  tags = {
    Name = "${var.project_name} DB subnet group"
  }
}

# RDS PostgreSQL Instance
resource "aws_db_instance" "sentrysearch" {
  identifier = "${var.project_name}-db"

  # Engine configuration
  engine         = "postgres"
  engine_version = "15.13"
  instance_class = "db.t3.micro"

  # Storage configuration
  allocated_storage     = 20
  max_allocated_storage = 100
  storage_type          = "gp2"
  storage_encrypted     = true

  # Database configuration
  db_name  = var.project_name
  username = "postgres"
  password = var.db_password
  port     = 5432

  # Network configuration
  vpc_security_group_ids = [aws_security_group.sentrysearch_db.id]
  db_subnet_group_name   = aws_db_subnet_group.sentrysearch.name
  publicly_accessible    = true

  # Backup configuration
  backup_retention_period = 7
  backup_window           = "03:00-04:00"
  maintenance_window      = "sun:04:00-sun:05:00"

  # Monitoring
  monitoring_interval = 60
  monitoring_role_arn = aws_iam_role.rds_monitoring.arn

  # Performance insights
  performance_insights_enabled = true

  # Deletion protection
  deletion_protection = false # Set to true in production
  skip_final_snapshot = true  # Set to false in production

  tags = {
    Name = "${var.project_name} Database"
  }
}

# IAM Role for RDS Monitoring
resource "aws_iam_role" "rds_monitoring" {
  name = "${var.project_name}-rds-monitoring-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "monitoring.rds.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

# IAM User for application access
resource "aws_iam_user" "sentrysearch_app" {
  name = "${var.project_name}-app"
  path = "/"

  tags = {
    Name = "${var.project_name} Application User"
  }
}

# IAM Access Key for application
resource "aws_iam_access_key" "sentrysearch_app" {
  user = aws_iam_user.sentrysearch_app.name
}

# IAM Policy for S3 access
resource "aws_iam_user_policy" "sentrysearch_s3" {
  name = "${var.project_name}-s3-policy"
  user = aws_iam_user.sentrysearch_app.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket",
          "s3:GetBucketLocation",
          "s3:GetBucketVersioning"
        ]
        Resource = [
          aws_s3_bucket.sentrysearch_reports.arn,
          "${aws_s3_bucket.sentrysearch_reports.arn}/*"
        ]
      }
    ]
  })
}

# CloudWatch Log Group for application logs
resource "aws_cloudwatch_log_group" "sentrysearch" {
  name              = "/aws/application/${var.project_name}"
  retention_in_days = 30

  tags = {
    Name = "${var.project_name} Application Logs"
  }
}