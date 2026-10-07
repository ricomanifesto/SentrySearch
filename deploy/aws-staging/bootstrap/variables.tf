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
