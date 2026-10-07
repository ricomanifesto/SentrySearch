# Images are published by digest after separate approval. No lifecycle policy
# deletes candidate or rollback digests.
resource "aws_ecr_repository" "this" {
  for_each             = module.names.ecr_repositories
  name                 = each.value
  image_tag_mutability = "IMMUTABLE"
  force_delete         = false
  image_scanning_configuration {
    scan_on_push = true
  }
  encryption_configuration {
    encryption_type = "AES256"
  }
  lifecycle {
    prevent_destroy = true
  }
}

# Pre-created so execution roles never need logs:CreateLogGroup.
resource "aws_cloudwatch_log_group" "this" {
  for_each                    = module.names.log_groups
  name                        = each.value
  retention_in_days           = var.log_retention_days
  log_group_class             = "STANDARD"
  deletion_protection_enabled = true
  skip_destroy                = true
}

resource "aws_ecs_cluster" "this" {
  name = module.names.cluster_name
  setting {
    name  = "containerInsights"
    value = "disabled"
  }
}

resource "aws_service_discovery_private_dns_namespace" "this" {
  name        = var.private_dns_namespace
  description = "Private service names for ${var.name_prefix}"
  vpc         = aws_vpc.this.id
}

# DNS-only discovery. ECS reports task health, but DNS can still return
# unhealthy records when none are healthy: it is not a readiness gate.
resource "aws_service_discovery_service" "this" {
  for_each      = module.names.discovery_names
  name          = each.value
  force_destroy = false
  dns_config {
    namespace_id   = aws_service_discovery_private_dns_namespace.this.id
    routing_policy = "MULTIVALUE"
    dns_records {
      type = "A"
      ttl  = 10
    }
  }
  health_check_custom_config {}
}
