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

variable "private_dns_namespace" {
  type        = string
  description = "The foundation's private DNS namespace. Runtime's certificate SAN is runtime.<namespace>."
  validation {
    condition = (can(regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", var.private_dns_namespace)) &&
    !can(regex("^[0-9.]+$", var.private_dns_namespace)) && length(var.private_dns_namespace) <= 200)
    error_message = "Use a lowercase multi-label DNS name without scheme, wildcard, trailing dot or IP address."
  }
}

variable "releases" {
  description = <<-EOT
    The current release and, for an upgrade, exactly one explicitly compatible
    rollback release. Keys are "r" plus the first eight hex digits of the
    manifest release UUID. Every bundle is a full secret ARN under the
    environment's secret prefix plus an exact VersionId; never a value or a
    moving staging label. A release's inputs never change after first apply:
    new versions are a new release key.
  EOT
  type = map(object({
    release_id = string
    slot       = string
    images     = object({ runtime = string, search = string })
    environment_bundles = object({
      runtime = object({ arn = string, version_id = string })
      api     = object({ arn = string, version_id = string })
      worker  = object({ arn = string, version_id = string })
    })
    material_bundles = object({
      runtime = object({ arn = string, version_id = string })
      api     = object({ arn = string, version_id = string })
      worker  = object({ arn = string, version_id = string })
    })
    release_jobs = object({
      runtime        = object({ environment_bundle = object({ arn = string, version_id = string }), material_bundle = object({ arn = string, version_id = string }) })
      product        = object({ environment_bundle = object({ arn = string, version_id = string }), material_bundle = object({ arn = string, version_id = string }) })
      runtime_grants = object({ source_commit = string, sql_sha256 = string })
    })
    # Guarded grant/proof/reconciliation jobs; deploy/aws-platform-fit validates
    # the deadline, digests and identities. Values are fixed for the release.
    release_tools = object({
      image          = string
      not_after      = string
      budget_seconds = number
      tools_sha256   = string
      sql_sha256 = object({
        runtime_grant = string, product_grant = string, runtime_proof = string, product_proof = string, reconcile = string
      })
      runtime = object({ database = string, owner = string, service = string, proof_bundle = object({ arn = string, version_id = string }) })
      product = object({ database = string, owner = string, service = string, proof_bundle = object({ arn = string, version_id = string }) })
    })
  }))
  validation {
    condition = (length(var.releases) >= 1 && length(var.releases) <= 2 &&
      length([for release in values(var.releases) : release if release.slot == "current"]) == 1 &&
    alltrue([for release in values(var.releases) : contains(["current", "rollback"], release.slot)]))
    error_message = "Retain exactly one current release and at most one compatible rollback; a first deployment has no rollback release."
  }
  validation {
    condition = alltrue([for key, release in var.releases :
      can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", release.release_id)) && key == "r${substr(release.release_id, 0, 8)}"
    ])
    error_message = "Each release key must be r plus the first eight hex digits of its lowercase manifest release UUID."
  }
  validation {
    condition = alltrue(flatten([for release in values(var.releases) : [for name, image in merge(release.images, { "release-tools" = release.release_tools.image }) :
      can(regex("^${var.account_id}\\.dkr\\.ecr\\.${var.region}\\.amazonaws\\.com/${var.name_prefix}/${name}@sha256:[0-9a-f]{64}$", image))
    ]]))
    error_message = "Images must be digest-pinned from this environment's own runtime, search and release-tools ECR repositories in the selected account and region."
  }
  validation {
    condition = alltrue(flatten([for release in values(var.releases) : [for bundle in concat(
      values(release.environment_bundles), values(release.material_bundles),
      [release.release_jobs.runtime.environment_bundle, release.release_jobs.runtime.material_bundle,
        release.release_jobs.product.environment_bundle, release.release_jobs.product.material_bundle,
      release.release_tools.runtime.proof_bundle, release.release_tools.product.proof_bundle]) :
      can(regex("^arn:aws:secretsmanager:${var.region}:${var.account_id}:secret:${var.name_prefix}/[A-Za-z0-9/_+=.@-]+-[A-Za-z0-9]{6}$", bundle.arn)) &&
      can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", bundle.version_id))
    ]]))
    error_message = "Bundles need full same-account regional secret ARNs under this environment's prefix and exact lowercase UUID VersionIds, never staging labels."
  }
  validation {
    condition = alltrue([for release in values(var.releases) : length(distinct([for bundle in concat(
      values(release.environment_bundles), values(release.material_bundles),
      [release.release_jobs.runtime.environment_bundle, release.release_jobs.runtime.material_bundle,
        release.release_jobs.product.environment_bundle, release.release_jobs.product.material_bundle,
      release.release_tools.runtime.proof_bundle, release.release_tools.product.proof_bundle]) : bundle.arn
    ])) == 12])
    error_message = "Within a release, all twelve service, material, owner and proof bundle ARNs must be distinct."
  }
  validation {
    # A secret may hold several releases' versions, but always for the same
    # task and purpose, so a rollback cannot move a bundle across a boundary.
    condition = alltrue([for arn, purposes in {
      for pair in flatten([for release in values(var.releases) : concat(
        [for name, bundle in release.environment_bundles : { arn = bundle.arn, purpose = "environment/${name}" }],
        [for name, bundle in release.material_bundles : { arn = bundle.arn, purpose = "material/${name}" }],
        [for name in ["runtime", "product"] : { arn = release.release_jobs[name].environment_bundle.arn, purpose = "owner-environment/${name}" }],
        [for name in ["runtime", "product"] : { arn = release.release_jobs[name].material_bundle.arn, purpose = "owner-material/${name}" }],
        [for name in ["runtime", "product"] : { arn = release.release_tools[name].proof_bundle.arn, purpose = "proof-environment/${name}" }],
      )]) : pair.arn => pair.purpose...
    } : length(distinct(purposes)) == 1])
    error_message = "A secret ARN must keep the same task and purpose in every retained release."
  }
  validation {
    condition = alltrue([for release in values(var.releases) :
      can(regex("^[0-9a-f]{40}$", release.release_jobs.runtime_grants.source_commit)) &&
      can(regex("^[0-9a-f]{64}$", release.release_jobs.runtime_grants.sql_sha256))
    ])
    error_message = "Pin each release's Runtime grant source to a full commit and the SHA-256 of db/roles/service.sql."
  }
}
