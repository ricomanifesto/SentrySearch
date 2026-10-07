output "service_arns" {
  description = "Deterministic service ARNs used by the releases root's launcher policy and the release manifest."
  value       = module.names.service_arns
}
