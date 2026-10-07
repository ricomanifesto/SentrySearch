# Resource-free naming contract shared by every staging root. Roots derive the
# same names from the same explicit inputs instead of trusting copied strings.
terraform {
  required_version = ">= 1.16.5, < 1.17.0"
}

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
  description = "Short environment prefix ending in -staging. Its length keeps release-scoped IAM role names within 64 characters."
  validation {
    condition     = can(regex("^[a-z][a-z0-9]*(-[a-z0-9]+)*-staging$", var.name_prefix)) && length(var.name_prefix) <= 28
    error_message = "Use at most 28 lowercase letters, digits and single hyphens, ending in -staging."
  }
}

variable "private_dns_namespace" {
  type        = string
  default     = null
  description = "Approved private DNS namespace. Runtime's certificate SAN is runtime.<namespace>."
  validation {
    condition = var.private_dns_namespace == null ? true : (
      can(regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", var.private_dns_namespace)) &&
      !can(regex("^[0-9.]+$", var.private_dns_namespace)) && length(var.private_dns_namespace) <= 200
    )
    error_message = "Use a lowercase multi-label DNS name without scheme, wildcard, trailing dot or IP address."
  }
}

locals {
  prefix   = var.name_prefix
  ecs_arn  = "arn:aws:ecs:${var.region}:${var.account_id}"
  services = { runtime = "${local.prefix}-runtime", api = "${local.prefix}-api", worker = "${local.prefix}-worker" }
  # Families match deploy/aws-platform-fit; revisions identify releases.
  task_families = {
    runtime         = "${local.prefix}-runtime"
    api             = "${local.prefix}-api"
    worker          = "${local.prefix}-worker"
    runtime-release = "${local.prefix}-runtime-release"
    product-release = "${local.prefix}-product-release"
  }
}

output "cluster_name" {
  value = local.prefix
}

output "cluster_arn" {
  value = "${local.ecs_arn}:cluster/${local.prefix}"
}

output "service_names" {
  value = local.services
}

output "service_arns" {
  value = { for role, name in local.services : role => "${local.ecs_arn}:service/${local.prefix}/${name}" }
}

output "log_groups" {
  value = { for name in keys(local.task_families) : name => "/${local.prefix}/${name}" }
}

output "ecr_repositories" {
  value = { runtime = "${local.prefix}/runtime", search = "${local.prefix}/search", release_tools = "${local.prefix}/release-tools" }
}

output "report_bucket" {
  value = "${local.prefix}-${var.account_id}-reports"
}

output "control_bucket" {
  value = "${local.prefix}-${var.account_id}-control"
}

output "secret_name_prefix" {
  value = "${local.prefix}/"
}

output "workload_role_patterns" {
  description = "Every application, maintenance and proof task/execution role name ends in -task or -execution."
  value = [
    "arn:aws:iam::${var.account_id}:role/${local.prefix}-*-task",
    "arn:aws:iam::${var.account_id}:role/${local.prefix}-*-execution",
  ]
}

output "state_keys" {
  value = { for root in ["bootstrap", "foundation", "releases", "services"] : root => "state/${root}.tfstate" }
}

output "release_lock_key" {
  description = "Matches release.journal.lock_key(manifest.environment.name) when the manifest environment name equals name_prefix."
  value       = "locks/${local.prefix}.json"
}

output "db_identifiers" {
  value = { runtime = "${local.prefix}-runtime-db", product = "${local.prefix}-product-db" }
}

output "discovery_names" {
  value = { runtime = "runtime", api = "api" }
}

output "runtime_server_name" {
  value = var.private_dns_namespace == null ? null : "runtime.${var.private_dns_namespace}"
}

output "api_server_name" {
  value = var.private_dns_namespace == null ? null : "api.${var.private_dns_namespace}"
}
