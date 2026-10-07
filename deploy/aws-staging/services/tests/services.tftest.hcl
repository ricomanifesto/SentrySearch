mock_provider "aws" {}

variables {
  account_id      = "111122223333"
  region          = "us-east-1"
  name_prefix     = "sentry-staging"
  task_subnet_ids = ["subnet-0a1a1a1a1a1a1a1a1", "subnet-0b2b2b2b2b2b2b2b2"]
  security_group_ids = {
    runtime = "sg-0aaaaaaaaaaaaaaa1"
    api     = "sg-0bbbbbbbbbbbbbbb2"
    worker  = "sg-0ccccccccccccccc3"
  }
  discovery_service_arns = {
    runtime = "arn:aws:servicediscovery:us-east-1:111122223333:service/srv-runtime0000000001"
    api     = "arn:aws:servicediscovery:us-east-1:111122223333:service/srv-api00000000000002"
  }
  task_definition_arns = {
    runtime = "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-runtime:2"
    api     = "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-api:2"
    worker  = "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-worker:2"
  }
}

run "services_are_created_paused_at_zero" {
  command = plan
  assert {
    condition = ({ for name, service in aws_ecs_service.this : name => service.name } == {
      runtime = "sentry-staging-runtime", api = "sentry-staging-api", worker = "sentry-staging-worker"
      } && alltrue([for name, service in aws_ecs_service.this :
        service.cluster == "arn:aws:ecs:us-east-1:111122223333:cluster/sentry-staging" &&
        service.task_definition == var.task_definition_arns[name] && service.desired_count == 0 &&
        service.launch_type == "FARGATE" && service.platform_version == "1.4.0" && service.scheduling_strategy == "REPLICA" &&
        service.enable_execute_command == false && service.availability_zone_rebalancing == "DISABLED" &&
        service.wait_for_steady_state == false && service.force_new_deployment == false && service.force_delete == false &&
        length(service.capacity_provider_strategy) == 0 && length(service.load_balancer) == 0 &&
        length(service.service_connect_configuration) == 0 && length(service.vpc_lattice_configurations) == 0 && length(service.alarms) == 0
    ]))
    error_message = "Three named Fargate 1.4.0 services start at desired zero with ECS Exec disabled and no load balancer or scheduler extras."
  }
  assert {
    condition = alltrue([for service in aws_ecs_service.this :
      one(service.deployment_controller).type == "ECS" &&
      one(service.deployment_circuit_breaker).enable == true && one(service.deployment_circuit_breaker).rollback == false &&
      service.deployment_minimum_healthy_percent == 0 && service.deployment_maximum_percent == 100
    ])
    error_message = "Deployment failure detection holds without automatic rollback, and old and new writers never overlap."
  }
  assert {
    condition = alltrue([for name, service in aws_ecs_service.this :
      one(service.network_configuration).assign_public_ip == false &&
      one(service.network_configuration).subnets == toset(var.task_subnet_ids) &&
      one(service.network_configuration).security_groups == toset([var.security_group_ids[name]])
    ])
    error_message = "Every service runs only in the private task subnets behind its own security group, with no public IP."
  }
  assert {
    condition = ({ for name, service in aws_ecs_service.this : name => [for registry in service.service_registries : registry.registry_arn] } == {
      runtime = [var.discovery_service_arns.runtime], api = [var.discovery_service_arns.api], worker = []
      } && alltrue([for service in aws_ecs_service.this : alltrue([for registry in service.service_registries :
        registry.port == null && registry.container_name == null && registry.container_port == null
    ])]))
    error_message = "Runtime and API register private A records; the worker is not discoverable."
  }
}

run "reject_unpinned_task_definition" {
  command = plan
  variables {
    task_definition_arns = merge(var.task_definition_arns, { api = "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-api" })
  }
  expect_failures = [var.task_definition_arns]
}

run "reject_cross_account_task_definition" {
  command = plan
  variables {
    task_definition_arns = merge(var.task_definition_arns, { runtime = "arn:aws:ecs:us-east-1:999999999999:task-definition/sentry-staging-runtime:2" })
  }
  expect_failures = [var.task_definition_arns]
}

run "reject_task_definition_from_another_family" {
  command = plan
  variables {
    task_definition_arns = merge(var.task_definition_arns, { worker = "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-runtime-release:2" })
  }
  expect_failures = [var.task_definition_arns]
}

run "reject_shared_security_group" {
  command = plan
  variables {
    security_group_ids = merge(var.security_group_ids, { worker = var.security_group_ids.api })
  }
  expect_failures = [var.security_group_ids]
}

run "reject_single_subnet" {
  command = plan
  variables { task_subnet_ids = ["subnet-0a1a1a1a1a1a1a1a1", "subnet-0a1a1a1a1a1a1a1a1"] }
  expect_failures = [var.task_subnet_ids]
}

run "reject_cross_account_discovery_service" {
  command = plan
  variables {
    discovery_service_arns = merge(var.discovery_service_arns, { api = "arn:aws:servicediscovery:us-east-1:999999999999:service/srv-api00000000000002" })
  }
  expect_failures = [var.discovery_service_arns]
}

run "reject_non_security_group_identifier" {
  command = plan
  variables {
    security_group_ids = merge(var.security_group_ids, { runtime = "0.0.0.0/0" })
  }
  expect_failures = [var.security_group_ids]
}
