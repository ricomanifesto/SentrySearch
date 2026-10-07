module "names" {
  source      = "../modules/naming"
  account_id  = var.account_id
  region      = var.region
  name_prefix = var.name_prefix
}

# Terraform owns placement, networking, discovery and supervision settings.
# The release controller alone owns the task definition and desired count:
# Terraform never starts a service and never reverts a controller release.
resource "aws_ecs_service" "this" {
  for_each                           = module.names.service_names
  name                               = each.value
  cluster                            = module.names.cluster_arn
  task_definition                    = var.task_definition_arns[each.key]
  desired_count                      = 0
  launch_type                        = "FARGATE"
  platform_version                   = "1.4.0"
  scheduling_strategy                = "REPLICA"
  enable_execute_command             = false
  enable_ecs_managed_tags            = true
  propagate_tags                     = "SERVICE"
  availability_zone_rebalancing      = "DISABLED"
  deployment_minimum_healthy_percent = 0
  deployment_maximum_percent         = 100
  wait_for_steady_state              = false
  force_new_deployment               = false
  force_delete                       = false

  deployment_controller {
    type = "ECS"
  }

  # A failed deployment holds for the operator; the prior binary may be
  # incompatible with migrated schemas, so ECS never rolls back on its own.
  deployment_circuit_breaker {
    enable   = true
    rollback = false
  }

  network_configuration {
    subnets          = var.task_subnet_ids
    security_groups  = [var.security_group_ids[each.key]]
    assign_public_ip = false
  }

  dynamic "service_registries" {
    for_each = contains(["runtime", "api"], each.key) ? [var.discovery_service_arns[each.key]] : []
    content {
      registry_arn = service_registries.value
    }
  }

  lifecycle {
    ignore_changes = [task_definition, desired_count]
  }
}
