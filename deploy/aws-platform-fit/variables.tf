variable "region" {
  type        = string
  description = "Approved commercial AWS region; no provider account is queried by mocked tests."
  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-[0-9]+$", var.region))
    error_message = "Use a commercial AWS region identifier."
  }
}

variable "account_id" {
  type = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "An explicit 12-digit staging account ID is required."
  }
}

variable "name_prefix" {
  type = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,29}-staging$", var.name_prefix))
    error_message = "Use a short lowercase prefix ending in -staging."
  }
}

variable "release_scope" {
  type        = string
  default     = null
  description = "Optional short release key. When set, task/execution role names are release-scoped so a retained rollback keeps its own exact-version roles; task families stay stable."
  validation {
    condition = var.release_scope == null ? true : (
      can(regex("^[a-z][a-z0-9]{1,11}$", var.release_scope)) &&
      length("${var.name_prefix}-${var.release_scope}-runtime-release-execution") <= 64
    )
    error_message = "Use 2-12 lowercase letters/digits starting with a letter, short enough that every scoped IAM role name fits in 64 characters."
  }
}

variable "release_id" {
  type        = string
  default     = null
  description = "Manifest release UUID fixed in the worker revision as SENTRYSEARCH_RELEASE_ID. Its supervisor then emits readiness receipts for the attended gate (docs/release-controller.md). Null, for local fit checks, emits none."
  validation {
    condition     = var.release_id == null ? true : can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", var.release_id))
    error_message = "Use the manifest's lowercase release UUID."
  }
  validation {
    condition     = var.release_tools == null ? true : try(var.release_id == var.release_tools.release_id, false)
    error_message = "A release with release-tools jobs must fix the same release_id in its worker revision."
  }
}

variable "images" {
  type        = object({ runtime = string, search = string })
  description = "Previously built ARM64 images in pre-existing same-account regional ECR repositories, pinned by digest."
  validation {
    condition = alltrue([for image in values(var.images) : can(regex(
      "^${var.account_id}\\.dkr\\.ecr\\.${var.region}\\.amazonaws\\.com/[a-z0-9]+([._/-][a-z0-9]+)*@sha256:[a-f0-9]{64}$", image
    ))])
    error_message = "Both images must be same-account, same-region ECR images pinned by sha256 digest; tags are forbidden."
  }
}

variable "runtime_server_name" {
  type        = string
  description = "Explicit DNS SAN on the runtime certificate; resolves privately when eventually deployed."
  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", var.runtime_server_name)) && !can(regex("^[0-9.]+$", var.runtime_server_name))
    error_message = "Use the runtime certificate's DNS name, without scheme, port, path, wildcard, or IP address."
  }
}

variable "artifact_bucket" {
  type        = string
  description = "Pre-existing isolated staging bucket; this module only grants access under reports/."
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.artifact_bucket)) && !strcontains(var.artifact_bucket, "..")
    error_message = "Supply a valid staging bucket name, not an ARN or path."
  }
}

variable "log_groups" {
  type        = map(string)
  description = "Three pre-existing log groups with externally configured retention. No CreateLogGroup permission is granted."
  validation {
    condition     = toset(keys(var.log_groups)) == toset(["runtime", "api", "worker"]) && alltrue([for name in values(var.log_groups) : can(regex("^/[a-zA-Z0-9_/.-]+$", name))])
    error_message = "Provide exactly runtime, api and worker log-group names with no ARN wildcards."
  }
}

variable "environment_bundles" {
  type        = map(object({ arn = string, version_id = string }))
  description = "Separate runtime/api/worker JSON Secrets Manager bundles encrypted with the AWS-managed secrets key. Values are never read by Terraform."
  validation {
    condition     = toset(keys(var.environment_bundles)) == toset(["runtime", "api", "worker"])
    error_message = "Exactly runtime, api and worker environment bundles are required."
  }
  validation {
    condition = alltrue([for bundle in values(var.environment_bundles) :
      can(regex("^arn:aws:secretsmanager:${var.region}:${var.account_id}:secret:[A-Za-z0-9/_+=.@-]+-[A-Za-z0-9]{6}$", bundle.arn)) &&
      can(regex("^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$", bundle.version_id))
    ])
    error_message = "Environment bundles need full regional/account Secret ARNs and exact lowercase UUID VersionIds."
  }
}

variable "material_bundles" {
  type        = map(object({ arn = string, version_id = string }))
  description = "Separate per-task file-material bundles. Runtime: TLS key/cert, both CAs and probe token; Search: both CAs only."
  validation {
    condition     = toset(keys(var.material_bundles)) == toset(["runtime", "api", "worker"])
    error_message = "Exactly runtime, api and worker material bundles are required."
  }
  validation {
    condition = alltrue([for bundle in values(var.material_bundles) :
      can(regex("^arn:aws:secretsmanager:${var.region}:${var.account_id}:secret:[A-Za-z0-9/_+=.@-]+-[A-Za-z0-9]{6}$", bundle.arn)) &&
      can(regex("^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$", bundle.version_id))
    ])
    error_message = "Material bundles need full regional/account Secret ARNs and exact lowercase UUID VersionIds."
  }
  validation {
    condition     = length(toset(concat([for bundle in values(var.material_bundles) : bundle.arn], [for bundle in values(var.environment_bundles) : bundle.arn]))) == 6
    error_message = "All six environment/material bundle ARNs must be distinct to preserve per-role boundaries."
  }
}
