# Terraform Variables for SentrySearch Infrastructure

variable "aws_region" {
  description = "AWS region where resources will be created"
  type        = string
  default     = "us-east-1"

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.aws_region))
    error_message = "AWS region must be a valid region identifier."
  }
}

variable "project_name" {
  description = "Project name used for resource naming and tagging"
  type        = string
  default     = "sentrysearch"

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.project_name))
    error_message = "Project name must contain only lowercase letters, numbers, and hyphens."
  }
}

variable "db_password" {
  description = "Password for the PostgreSQL database master user"
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.db_password) >= 8
    error_message = "Database password must be at least 8 characters long."
  }

  validation {
    condition     = can(regex("^[A-Za-z0-9!@#$%^&*()_+=-]+$", var.db_password))
    error_message = "Database password contains invalid characters."
  }
}

variable "db_instance_class" {
  description = "RDS instance class for the PostgreSQL database"
  type        = string
  default     = "db.t3.micro"

  validation {
    condition = contains([
      "db.t3.micro", "db.t3.small", "db.t3.medium", "db.t3.large",
      "db.t3.xlarge", "db.t3.2xlarge", "db.r5.large", "db.r5.xlarge"
    ], var.db_instance_class)
    error_message = "Database instance class must be a valid RDS instance type."
  }
}

variable "db_allocated_storage" {
  description = "Initial allocated storage for the RDS instance (GB)"
  type        = number
  default     = 20

  validation {
    condition     = var.db_allocated_storage >= 20 && var.db_allocated_storage <= 16384
    error_message = "Database allocated storage must be between 20 and 16384 GB."
  }
}

variable "db_max_allocated_storage" {
  description = "Maximum allocated storage for RDS auto-scaling (GB)"
  type        = number
  default     = 100

  validation {
    condition     = var.db_max_allocated_storage >= var.db_allocated_storage
    error_message = "Maximum allocated storage must be greater than or equal to initial allocated storage."
  }
}

variable "db_backup_retention_period" {
  description = "Number of days to retain database backups"
  type        = number
  default     = 7

  validation {
    condition     = var.db_backup_retention_period >= 0 && var.db_backup_retention_period <= 35
    error_message = "Backup retention period must be between 0 and 35 days."
  }
}

variable "s3_lifecycle_transition_ia_days" {
  description = "Number of days after which objects are transitioned to Standard-IA"
  type        = number
  default     = 30

  validation {
    condition     = var.s3_lifecycle_transition_ia_days >= 30
    error_message = "Transition to Standard-IA must be at least 30 days."
  }
}

variable "s3_lifecycle_transition_glacier_days" {
  description = "Number of days after which objects are transitioned to Glacier"
  type        = number
  default     = 90

  validation {
    condition     = var.s3_lifecycle_transition_glacier_days >= 90
    error_message = "Transition to Glacier must be at least 90 days."
  }
}

variable "s3_lifecycle_expiration_days" {
  description = "Number of days after which objects are deleted"
  type        = number
  default     = 2555 # 7 years

  validation {
    condition     = var.s3_lifecycle_expiration_days >= 365
    error_message = "Object expiration must be at least 1 year (365 days)."
  }
}

variable "cloudwatch_log_retention_days" {
  description = "Number of days to retain CloudWatch logs"
  type        = number
  default     = 30

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653], var.cloudwatch_log_retention_days)
    error_message = "CloudWatch log retention must be a valid retention period."
  }
}

variable "enable_deletion_protection" {
  description = "Enable deletion protection for RDS instance"
  type        = bool
  default     = false

  # Note: Set to true in production environments
}

variable "enable_performance_insights" {
  description = "Enable Performance Insights for RDS instance"
  type        = bool
  default     = true
}

variable "enable_enhanced_monitoring" {
  description = "Enable enhanced monitoring for RDS instance"
  type        = bool
  default     = true
}

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}

# Local values for computed configurations
locals {
  common_tags = merge(var.tags, {
    Project     = var.project_name
    Environment = "production"
    ManagedBy   = "terraform"
    CreatedAt   = formatdate("YYYY-MM-DD", timestamp())
  })
}