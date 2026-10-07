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
  description = "Environment prefix shared by every staging root; at most 28 characters and ending in -staging."
  validation {
    condition     = can(regex("^[a-z][a-z0-9]*(-[a-z0-9]+)*-staging$", var.name_prefix)) && length(var.name_prefix) <= 28
    error_message = "Use at most 28 lowercase letters, digits and single hyphens, ending in -staging."
  }
}

variable "task_subnet_ids" {
  type        = list(string)
  description = "The foundation's two private task subnets."
  validation {
    condition = (length(var.task_subnet_ids) == 2 && length(toset(var.task_subnet_ids)) == 2 &&
    alltrue([for subnet in var.task_subnet_ids : can(regex("^subnet-[0-9a-f]{8,17}$", subnet))]))
    error_message = "Supply the foundation's two distinct task subnet IDs."
  }
}

variable "security_group_ids" {
  type        = object({ runtime = string, api = string, worker = string })
  description = "The foundation's per-service security groups."
  validation {
    condition = (length(toset(values(var.security_group_ids))) == 3 &&
    alltrue([for group in values(var.security_group_ids) : can(regex("^sg-[0-9a-f]{8,17}$", group))]))
    error_message = "Each service needs its own distinct security group ID from the foundation."
  }
}

variable "discovery_service_arns" {
  type        = object({ runtime = string, api = string })
  description = "The foundation's Cloud Map services for private Runtime and API names."
  validation {
    condition = alltrue([for arn in values(var.discovery_service_arns) :
      can(regex("^arn:aws:servicediscovery:${var.region}:${var.account_id}:service/srv-[a-z0-9]{8,64}$", arn))
    ]) && var.discovery_service_arns.runtime != var.discovery_service_arns.api
    error_message = "Use the foundation's distinct same-account regional Cloud Map service ARNs."
  }
}

variable "task_definition_arns" {
  type        = object({ runtime = string, api = string, worker = string })
  description = "Initial revisions from the releases root's current release. After creation the release controller owns service revisions."
  validation {
    condition = alltrue([for name in ["runtime", "api", "worker"] :
      can(regex("^arn:aws:ecs:${var.region}:${var.account_id}:task-definition/${var.name_prefix}-${name}:[1-9][0-9]*$", var.task_definition_arns[name]))
    ])
    error_message = "Each service needs an exact same-account revision of its own task family."
  }
}
