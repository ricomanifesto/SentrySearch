output "releases" {
  value = { for key, release in module.release : key => {
    release_id           = var.releases[key].release_id
    slot                 = var.releases[key].slot
    task_definition_arns = release.task_definition_arns
    iam_role_names       = release.iam_role_names
    grant_contract       = release.release_grant_contract
    tools_bindings       = release.release_tools_bindings
    observer_bindings    = release.observer_bindings
    bootstrap_bindings   = release.bootstrap_bindings
  } }
}

output "current_release" {
  value = local.current_key
}

output "rollback_release" {
  description = "Null for a first deployment (empty hold); never an invented prior version."
  value       = local.rollback_key
}

output "current_service_task_definitions" {
  description = "Initial task definitions for the services root. After creation, the release controller owns service revisions."
  value       = { for name in ["runtime", "api", "worker"] : name => module.release[local.current_key].task_definition_arns[name] }
}

output "release_launcher_policies" {
  description = "The attended launcher set: jobs, services, receipts, tasks and, when the current release has observers, observe."
  value       = local.attended_launcher_policies
}

output "release_launcher_bootstrap_policy" {
  description = "The separate first-deployment bootstrap launcher, outside the attended set; null without bootstrap jobs and null once a second release is retained."
  value       = local.bootstrap_launcher_policy
}

output "observer_networks" {
  description = "Security groups for each observer task's RunTask network configuration, as the manifest names them."
  value = var.observer_security_group_ids == null ? null : {
    runtime-observe = [var.observer_security_group_ids.runtime], api-observe = [var.observer_security_group_ids.api]
  }
}
