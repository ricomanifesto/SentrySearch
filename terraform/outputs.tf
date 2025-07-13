# Terraform Outputs for SentrySearch Infrastructure

# Database outputs
output "database_endpoint" {
  description = "RDS PostgreSQL database endpoint"
  value       = aws_db_instance.sentrysearch.endpoint
}

output "database_name" {
  description = "Database name"
  value       = aws_db_instance.sentrysearch.db_name
}

output "database_username" {
  description = "Database master username"
  value       = aws_db_instance.sentrysearch.username
}

output "database_port" {
  description = "Database port"
  value       = aws_db_instance.sentrysearch.port
}

# S3 outputs
output "s3_bucket_name" {
  description = "S3 bucket name for report storage"
  value       = aws_s3_bucket.sentrysearch_reports.id
}

output "s3_bucket_arn" {
  description = "S3 bucket ARN"
  value       = aws_s3_bucket.sentrysearch_reports.arn
}

output "s3_bucket_region" {
  description = "S3 bucket region"
  value       = aws_s3_bucket.sentrysearch_reports.region
}

# IAM outputs
output "iam_user_name" {
  description = "IAM user name for application access"
  value       = aws_iam_user.sentrysearch_app.name
}

output "iam_user_arn" {
  description = "IAM user ARN"
  value       = aws_iam_user.sentrysearch_app.arn
}

output "aws_access_key_id" {
  description = "AWS Access Key ID for application"
  value       = aws_iam_access_key.sentrysearch_app.id
}

output "aws_secret_access_key" {
  description = "AWS Secret Access Key for application"
  value       = aws_iam_access_key.sentrysearch_app.secret
  sensitive   = true
}

# CloudWatch outputs
output "cloudwatch_log_group_name" {
  description = "CloudWatch Log Group name"
  value       = aws_cloudwatch_log_group.sentrysearch.name
}

output "cloudwatch_log_group_arn" {
  description = "CloudWatch Log Group ARN"
  value       = aws_cloudwatch_log_group.sentrysearch.arn
}

# Security Group outputs
output "database_security_group_id" {
  description = "Security Group ID for the database"
  value       = aws_security_group.sentrysearch_db.id
}

# Environment configuration output
output "environment_configuration" {
  description = "Environment variables configuration for the application"
  value = {
    DB_HOST           = aws_db_instance.sentrysearch.endpoint
    DB_PORT           = aws_db_instance.sentrysearch.port
    DB_NAME           = aws_db_instance.sentrysearch.db_name
    DB_USER           = aws_db_instance.sentrysearch.username
    AWS_REGION        = var.aws_region
    AWS_S3_BUCKET     = aws_s3_bucket.sentrysearch_reports.id
    AWS_ACCESS_KEY_ID = aws_iam_access_key.sentrysearch_app.id
  }
}

# Cost estimation outputs
output "estimated_monthly_cost" {
  description = "Estimated monthly cost breakdown (USD)"
  value = {
    rds_instance = "~15-20"
    rds_storage  = "~2-3"
    s3_storage   = "~1-5 (depends on usage)"
    cloudwatch   = "~0.50"
    total        = "~18-30"
    note         = "Costs may vary based on usage patterns and data transfer"
  }
}

# Summary output
output "deployment_summary" {
  description = "Summary of deployed resources"
  value = {
    region            = var.aws_region
    project_name      = var.project_name
    database_endpoint = aws_db_instance.sentrysearch.endpoint
    s3_bucket         = aws_s3_bucket.sentrysearch_reports.id
    iam_user          = aws_iam_user.sentrysearch_app.name
    setup_complete    = "Run 'terraform output aws_secret_access_key' to get the secret key"
    next_steps        = "Configure .env file with the output values"
  }
}