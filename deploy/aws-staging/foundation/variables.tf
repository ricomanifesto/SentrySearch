variable "account_id" {
  type        = string
  description = "Explicit 12-digit staging account ID. There is no default and no ambient lookup."
  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "An explicit 12-digit staging account ID is required."
  }
}

variable "region" {
  type        = string
  description = "Explicit commercial AWS region."
  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-[0-9]$", var.region))
    error_message = "Use a commercial AWS region identifier."
  }
}

variable "name_prefix" {
  type        = string
  description = "Environment prefix shared by every staging root; at most 28 characters and ending in -staging or -production."
  validation {
    condition     = can(regex("^[a-z][a-z0-9]*(-[a-z0-9]+)*-(staging|production)$", var.name_prefix)) && length(var.name_prefix) <= 28
    error_message = "Use at most 28 lowercase letters, digits and single hyphens, ending in -staging or -production."
  }
}

variable "availability_zones" {
  type        = list(string)
  description = "Exactly two distinct availability zones in the selected region, chosen during approved account inspection."
  validation {
    condition = (length(var.availability_zones) == 2 && length(toset(var.availability_zones)) == 2 &&
    alltrue([for zone in var.availability_zones : can(regex("^${var.region}[a-z]$", zone))]))
    error_message = "Supply two distinct zone names from the selected region."
  }
}

variable "vpc_cidr" {
  type        = string
  description = "Dedicated private IPv4 range (/16 to /24) that does not overlap any network this VPC might later reach. Split into four equal subnets."
  validation {
    condition = (can(cidrnetmask(var.vpc_cidr)) &&
      can(regex("^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)", var.vpc_cidr)) &&
      tonumber(split("/", var.vpc_cidr)[1]) >= 16 && tonumber(split("/", var.vpc_cidr)[1]) <= 24 &&
    cidrhost(var.vpc_cidr, 0) == split("/", var.vpc_cidr)[0])
    error_message = "Use an aligned RFC 1918 network between /16 and /24."
  }
}

variable "private_dns_namespace" {
  type        = string
  description = "Approved private DNS namespace. Runtime's certificate SAN is runtime.<namespace>."
  validation {
    condition = (can(regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", var.private_dns_namespace)) &&
    !can(regex("^[0-9.]+$", var.private_dns_namespace)) && length(var.private_dns_namespace) <= 200)
    error_message = "Use a lowercase multi-label DNS name without scheme, wildcard, trailing dot or IP address."
  }
}

variable "postgres_engine_version" {
  type        = string
  description = "Exact PostgreSQL 16 minor supported in the selected account and region."
  validation {
    condition     = can(regex("^16\\.[0-9]+$", var.postgres_engine_version))
    error_message = "Pin an exact PostgreSQL 16 minor version such as 16.x."
  }
}

variable "rds_ca_identifier" {
  type        = string
  default     = "rds-ca-rsa2048-g1"
  description = "RDS server certificate authority. Its regional CA bundle belongs in each material bundle for verify-full."
  validation {
    condition     = can(regex("^rds-ca-[a-z0-9-]+$", var.rds_ca_identifier))
    error_message = "Use an RDS certificate authority identifier."
  }
}

variable "log_retention_days" {
  type        = number
  default     = 14
  description = "Bounded CloudWatch retention for service and job logs."
  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90], var.log_retention_days)
    error_message = "Use a bounded CloudWatch retention of at most 90 days."
  }
}

variable "report_retention_days" {
  type        = number
  default     = 30
  description = "Current and noncurrent report-version retention, subject to the deletion-policy approval."
  validation {
    condition     = var.report_retention_days >= 1 && var.report_retention_days <= 365 && floor(var.report_retention_days) == var.report_retention_days
    error_message = "Use a whole number of days between 1 and 365."
  }
}

variable "multi_az" {
  type        = bool
  default     = false
  description = "Run both databases Multi-AZ (a standby in the second zone). Off for staging; an option for production."
}

variable "backup_retention_days" {
  type        = number
  default     = 7
  description = "Days of automated backups and point-in-time recovery. A production environment keeps at least 14."
  validation {
    condition = (var.backup_retention_days == floor(var.backup_retention_days) && var.backup_retention_days >= 7 &&
    var.backup_retention_days <= 35 && (!endswith(var.name_prefix, "-production") || var.backup_retention_days >= 14))
    error_message = "Keep 7 to 35 whole days of backups, and at least 14 for a production environment."
  }
}

variable "pre_release_snapshots" {
  type        = set(string)
  default     = []
  description = "Release keys (r plus eight hex digits) to take a manual snapshot of both databases for, before that release runs. Each is kept until a retention decision; a rollback names them as its backups."
  validation {
    condition     = alltrue([for key in var.pre_release_snapshots : can(regex("^r[0-9a-f]{8}$", key))])
    error_message = "Name each pre-release snapshot by its release key: r plus the first eight hex digits of the release UUID."
  }
}
