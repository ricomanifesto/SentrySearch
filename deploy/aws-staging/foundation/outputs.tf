# Reviewed outputs become explicit inputs to the releases and services roots;
# no root reads another root's state.
output "vpc_id" {
  value = aws_vpc.this.id
}

output "task_subnet_ids" {
  value = [for subnet in aws_subnet.task : subnet.id]
}

output "security_group_ids" {
  value = { for name, group in aws_security_group.this : name => group.id }
}

output "cluster_arn" {
  value = aws_ecs_cluster.this.arn
}

output "discovery_service_arns" {
  value = { for name, service in aws_service_discovery_service.this : name => service.arn }
}

output "private_dns_namespace" {
  value = var.private_dns_namespace
}

output "runtime_server_name" {
  value = module.names.runtime_server_name
}

output "api_server_name" {
  value = module.names.api_server_name
}

output "report_bucket" {
  value = aws_s3_bucket.reports.bucket
}

output "repository_urls" {
  value = { for name, repository in aws_ecr_repository.this : name => repository.repository_url }
}

output "log_groups" {
  value = { for name, group in aws_cloudwatch_log_group.this : name => group.name }
}

output "database_endpoints" {
  description = "Hostnames for the verify-full connection strings in the secret bundles."
  value       = { for name, db in aws_db_instance.this : name => db.address }
}

output "database_admin_secret_arns" {
  description = "RDS-managed administrator secret ARNs for the credential owner. Terraform never reads their values."
  value       = { for name, db in aws_db_instance.this : name => try(db.master_user_secret[0].secret_arn, null) }
}

output "endpoint_policies" {
  value = local.endpoint_policies
}

output "report_bucket_policy" {
  value = local.report_bucket_policy
}

output "pre_release_snapshot_arns" {
  description = "Each pre-release snapshot by database and release key, for a rollback's backups."
  value       = { for name, snapshot in aws_db_snapshot.pre_release : name => snapshot.db_snapshot_arn }
}

output "worker_metric_filters" {
  description = "Each worker-receipt metric filter's pattern, for a platform check of what it matches."
  value       = { for name, filter in aws_cloudwatch_log_metric_filter.worker : name => filter.pattern }
}

output "event_metric_filters" {
  description = "Each JSON event filter's pattern (the worker's metric event and the Runtime's operator events), for a platform check of what it matches."
  value       = { for name, filter in aws_cloudwatch_log_metric_filter.events : name => filter.pattern }
}
