output "releases" {
  value = { for key, release in module.release : key => {
    release_id           = var.releases[key].release_id
    slot                 = var.releases[key].slot
    task_definition_arns = release.task_definition_arns
    iam_role_names       = release.iam_role_names
    grant_contract       = release.release_grant_contract
    tools_bindings       = release.release_tools_bindings
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
  value = local.release_launcher_policies
}
