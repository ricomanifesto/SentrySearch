output "control_bucket" {
  value = module.names.control_bucket
}

output "state_keys" {
  description = "Fixed backend keys used by the bootstrap migration and the three environment roots."
  value       = module.names.state_keys
}

output "control_bucket_policy" {
  value = local.control_bucket_policy
}

output "state_access_policies" {
  value = local.state_access_policies
}

output "release_evidence_policy" {
  value = local.release_evidence_policy
}
