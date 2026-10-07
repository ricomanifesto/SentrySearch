mock_provider "aws" {}

variables {
  region              = "us-east-1"
  account_id          = "111122223333"
  name_prefix         = "sentry-fit-staging"
  runtime_server_name = "runtime.staging.example.test"
  artifact_bucket     = "sentry-fit-staging-artifacts"
  images = {
    runtime = "111122223333.dkr.ecr.us-east-1.amazonaws.com/sentryruntime@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    search  = "111122223333.dkr.ecr.us-east-1.amazonaws.com/sentrysearch@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  }
  log_groups = { runtime = "/staging/runtime", api = "/staging/api", worker = "/staging/worker" }
  environment_bundles = {
    runtime = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/runtime-env-AAAAAA", version_id = "11111111-1111-4111-8111-111111111111" }
    api     = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/api-env-BBBBBB", version_id = "22222222-2222-4222-8222-222222222222" }
    worker  = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/worker-env-CCCCCC", version_id = "33333333-3333-4333-8333-333333333333" }
  }
  material_bundles = {
    runtime = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/runtime-material-DDDDDD", version_id = "44444444-4444-4444-8444-444444444444" }
    api     = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/api-material-EEEEEE", version_id = "55555555-5555-4555-8555-555555555555" }
    worker  = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/worker-material-FFFFFF", version_id = "66666666-6666-4666-8666-666666666666" }
  }
  release_jobs = {
    runtime = {
      environment_bundle = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/runtime-owner-GGGGGG", version_id = "77777777-7777-4777-8777-777777777777" }
      material_bundle    = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/runtime-owner-ca-HHHHHH", version_id = "88888888-8888-4888-8888-888888888888" }
      log_group          = "/staging/runtime-release"
    }
    product = {
      environment_bundle = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/product-owner-IIIIII", version_id = "99999999-9999-4999-8999-999999999999" }
      material_bundle    = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/product-owner-ca-JJJJJJ", version_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" }
      log_group          = "/staging/product-release"
    }
    runtime_grants = {
      source_commit = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
      sql_sha256    = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    }
  }
}

run "release_jobs_are_opt_in" {
  command = plan
  variables { release_jobs = null }
  assert {
    condition = (length(aws_ecs_task_definition.release) == 0 &&
      length(aws_iam_role.release_task) == 0 && length(aws_iam_role.release_execution) == 0 &&
      output.release_grant_contract == null && length(output.release_task_contracts) == 0 &&
    toset(keys(aws_ecs_task_definition.service)) == toset(["runtime", "api", "worker"]))
    error_message = "Omitting release inputs must preserve the three-service interface without creating owner jobs or identities."
  }
}

run "two_isolated_owner_jobs" {
  command = plan
  assert {
    condition = (toset(keys(aws_ecs_task_definition.release)) == toset(["runtime", "product"]) &&
      toset(keys(aws_iam_role.release_task)) == toset(["runtime", "product"]) &&
      toset(keys(aws_iam_role.release_execution)) == toset(["runtime", "product"]) &&
      alltrue([for name, task in aws_ecs_task_definition.release :
        task.family == "${var.name_prefix}-${name}-release" && task.cpu == "256" && task.memory == "512" &&
        task.network_mode == "awsvpc" && task.requires_compatibilities == toset(["FARGATE"]) &&
        one(task.runtime_platform).cpu_architecture == "ARM64" &&
        jsondecode(task.container_definitions) == jsondecode(jsonencode(output.release_task_contracts[name])) &&
        length(task.volume) == 1 && one(task.volume).name == "material" &&
        (one(task.volume).host_path == null || one(task.volume).host_path == "") &&
        length(one(task.volume).efs_volume_configuration) == 0 && length(one(task.volume).docker_volume_configuration) == 0
    ]))
    error_message = "The actual resources must define only two independent ARM64 owner jobs with fresh CA-only storage."
  }
  assert {
    condition = alltrue([for name, containers in output.release_task_contracts :
      length(containers) == 2 && containers[0].name == "init" && containers[1].name == "migration" &&
      !containers[0].essential && containers[1].essential && containers[0].user == "0:0" &&
      alltrue([for container in containers : container.readonlyRootFilesystem && container.workingDirectory == "/"]) &&
      containers[0].startTimeout == 120 && containers[1].startTimeout == 120 && containers[1].stopTimeout == 30 &&
      !can(containers[0].linuxParameters.capabilities.add) &&
      length(containers[0].linuxParameters.capabilities.drop) == 13 &&
      !contains(containers[0].linuxParameters.capabilities.drop, "CHOWN") &&
      containers[1].linuxParameters.capabilities.drop == ["ALL"] &&
      containers[1].dependsOn == [{ containerName = "init", condition = "SUCCESS" }] &&
      containers[0].mountPoints == [{ sourceVolume = "material", containerPath = "/run/material", readOnly = false }] &&
      containers[1].mountPoints == [{ sourceVolume = "material", containerPath = "/run/material", readOnly = true }] &&
      !can(containers[0].secrets) && !can(containers[1].healthCheck) && !can(containers[1].restartPolicy) &&
      length(containers[1].portMappings) == 0 &&
      containers[0].image == var.images.search &&
      containers[0].command == ["python", "-m", "dev.prepare_service_volumes", "--profile", name == "runtime" ? "runtime-release" : "search-release", "--material-dir", "/run/material", "--secret-id", var.release_jobs[name].material_bundle.arn, "--version-id", var.release_jobs[name].material_bundle.version_id, "--region", var.region]
    ])
    error_message = "Owner jobs must fail closed on CA init, run nonroot with read-only roots, and have no service health/restart/port behavior."
  }
  assert {
    condition = (output.release_task_contracts.runtime[1].user == "65532:65532" &&
      output.release_task_contracts.product[1].user == "10001:10001" &&
      output.release_task_contracts.runtime[1].image == var.images.runtime &&
      output.release_task_contracts.product[1].image == var.images.search &&
      output.release_task_contracts.runtime[1].command == tolist(["/app/migrate"]) &&
      output.release_task_contracts.product[1].command == tolist(["python", "-m", "dev.migrate_storage"]) &&
      { for item in output.release_task_contracts.runtime[1].environment : item.name => item.value } == { SENTRYRUNTIME_MIGRATIONS_DIRECTORY = "/app/db/migrations" } &&
      { for item in output.release_task_contracts.product[1].environment : item.name => item.value } == {
        ENVIRONMENT = "staging", DB_SSLMODE = "verify-full", DB_SSLROOTCERT = "/run/material/postgres-ca.pem", DB_DEBUG = "false", PYTHON_DOTENV_DISABLED = "1"
    })
    error_message = "Commands, UIDs and environment are fixed DB-only contracts; Runtime needs an absolute migration path after changing cwd."
  }
  assert {
    condition = (toset([for secret in output.release_task_contracts.runtime[1].secrets : secret.name]) == toset(["DATABASE_URL"]) &&
      toset([for secret in output.release_task_contracts.product[1].secrets : secret.name]) == toset(["DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD"]) &&
      alltrue([for name, containers in output.release_task_contracts : alltrue([
        for secret in containers[1].secrets : secret.valueFrom == "${var.release_jobs[name].environment_bundle.arn}:${secret.name}::${var.release_jobs[name].environment_bundle.version_id}"
      ])]) &&
      { for item in output.task_contracts.api[1].environment : item.name => item.value }["SENTRYSEARCH_EXECUTION_MODE"] == "paused" &&
      { for item in output.task_contracts.worker[1].environment : item.name => item.value }["OPENROUTER_BASE_URL"] == "http://127.0.0.1:9" &&
      !strcontains(jsonencode(output.task_contracts), "dev.migrate_storage") && !strcontains(jsonencode(output.task_contracts), "/app/migrate") &&
      alltrue([for name in ["runtime", "product"] : !strcontains(jsonencode(output.task_contracts), var.release_jobs[name].environment_bundle.arn)])
    )
    error_message = "Owner secrets belong only to separate migration processes; services must keep disabled defaults and never run startup DDL."
  }
}

run "release_identity_and_grant_boundary" {
  command = plan
  assert {
    condition = alltrue([for name in ["runtime", "product"] :
      jsondecode(aws_iam_role_policy.release_task[name].policy) == jsondecode(jsonencode(output.release_task_policies[name])) &&
      length(output.release_task_policies[name].Statement) == 1 &&
      output.release_task_policies[name].Statement[0].Action == ["secretsmanager:GetSecretValue"] &&
      output.release_task_policies[name].Statement[0].Resource == [var.release_jobs[name].material_bundle.arn] &&
      output.release_task_policies[name].Statement[0].Condition.StringEquals["secretsmanager:VersionId"] == var.release_jobs[name].material_bundle.version_id &&
      jsondecode(aws_iam_role_policy.release_execution[name].policy) == jsondecode(jsonencode(output.release_execution_policies[name])) &&
      length(output.release_execution_policies[name].Statement) == 4 &&
      output.release_execution_policies[name].Statement[0].Action == ["ecr:GetAuthorizationToken"] &&
      output.release_execution_policies[name].Statement[0].Resource == ["*"] &&
      output.release_execution_policies[name].Statement[1].Action == ["ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"] &&
      output.release_execution_policies[name].Statement[1].Resource == (name == "runtime" ? ["arn:aws:ecr:us-east-1:111122223333:repository/sentryruntime", "arn:aws:ecr:us-east-1:111122223333:repository/sentrysearch"] : ["arn:aws:ecr:us-east-1:111122223333:repository/sentrysearch"]) &&
      output.release_execution_policies[name].Statement[2].Action == ["logs:CreateLogStream", "logs:PutLogEvents"] &&
      output.release_execution_policies[name].Statement[2].Resource == ["arn:aws:logs:${var.region}:${var.account_id}:log-group:${var.release_jobs[name].log_group}:log-stream:${name}-release/*"] &&
      output.release_execution_policies[name].Statement[3].Action == ["secretsmanager:GetSecretValue"] &&
      output.release_execution_policies[name].Statement[3].Resource == [var.release_jobs[name].environment_bundle.arn] &&
      output.release_execution_policies[name].Statement[3].Condition.StringEquals["secretsmanager:VersionId"] == var.release_jobs[name].environment_bundle.version_id &&
      jsondecode(aws_iam_role.release_task[name].assume_role_policy).Statement[0].Condition.StringEquals["aws:SourceAccount"] == var.account_id &&
      jsondecode(aws_iam_role.release_execution[name].assume_role_policy).Statement[0].Condition.ArnLike["aws:SourceArn"] == "arn:aws:ecs:${var.region}:${var.account_id}:*" &&
      aws_iam_role.release_task[name].name == "${var.name_prefix}-${name}-release-task" &&
      aws_iam_role.release_execution[name].name == "${var.name_prefix}-${name}-release-execution"
    ])
    error_message = "Every release role must bind its own immutable CA/owner bundle, bounded image pulls and logs; no S3, model, service credentials or other task authority."
  }
  assert {
    condition = (output.release_grant_contract.source_commit == var.release_jobs.runtime_grants.source_commit &&
      output.release_grant_contract.sql_sha256 == var.release_jobs.runtime_grants.sql_sha256 &&
      output.release_grant_contract.path == "db/roles/service.sql" &&
      output.release_grant_contract.execution == "operator-only-after-runtime-migration" &&
      !strcontains(jsonencode(output.release_task_contracts), "service.sql") &&
      !strcontains(jsonencode(output.release_task_contracts), "psql") &&
      alltrue([for name in ["runtime", "product"] :
        !strcontains(jsonencode(output.task_policies), var.release_jobs[name].material_bundle.arn) &&
        !strcontains(jsonencode(output.execution_policies), var.release_jobs[name].environment_bundle.arn)
    ]))
    error_message = "Grant provenance is explicit operator metadata, never hidden migration/startup SQL or service IAM access to owner bundles."
  }
}

run "reject_release_moving_secret_version" {
  command = plan
  variables {
    release_jobs = merge(var.release_jobs, {
      runtime = merge(var.release_jobs.runtime, {
        environment_bundle = merge(var.release_jobs.runtime.environment_bundle, { version_id = "AWSCURRENT" })
      })
    })
  }
  expect_failures = [var.release_jobs]
}

run "reject_release_owner_aliasing_service_secret" {
  command = plan
  variables {
    release_jobs = merge(var.release_jobs, {
      product = merge(var.release_jobs.product, { environment_bundle = var.environment_bundles.api })
    })
  }
  expect_failures = [var.release_jobs]
}

run "reject_release_material_aliasing_owner_secret" {
  command = plan
  variables {
    release_jobs = merge(var.release_jobs, {
      runtime = merge(var.release_jobs.runtime, { material_bundle = var.release_jobs.product.environment_bundle })
    })
  }
  expect_failures = [var.release_jobs]
}

run "reject_release_owner_aliasing_other_owner" {
  command = plan
  variables {
    release_jobs = merge(var.release_jobs, {
      product = merge(var.release_jobs.product, { environment_bundle = var.release_jobs.runtime.environment_bundle })
    })
  }
  expect_failures = [var.release_jobs]
}

run "reject_release_material_aliasing_service_material" {
  command = plan
  variables {
    release_jobs = merge(var.release_jobs, {
      runtime = merge(var.release_jobs.runtime, { material_bundle = var.material_bundles.runtime })
    })
  }
  expect_failures = [var.release_jobs]
}

run "reject_release_cross_account_material" {
  command = plan
  variables {
    release_jobs = merge(var.release_jobs, {
      runtime = merge(var.release_jobs.runtime, {
        material_bundle = merge(var.release_jobs.runtime.material_bundle, { arn = "arn:aws:secretsmanager:us-east-1:999999999999:secret:staging/runtime-owner-ca-HHHHHH" })
      })
    })
  }
  expect_failures = [var.release_jobs]
}

run "reject_release_log_wildcard" {
  command = plan
  variables {
    release_jobs = merge(var.release_jobs, { runtime = merge(var.release_jobs.runtime, { log_group = "/staging/*" }) })
  }
  expect_failures = [var.release_jobs]
}

run "reject_moving_grant_revision" {
  command = plan
  variables {
    release_jobs = merge(var.release_jobs, { runtime_grants = merge(var.release_jobs.runtime_grants, { source_commit = "main" }) })
  }
  expect_failures = [var.release_jobs]
}

run "reject_unhashed_grant_source" {
  command = plan
  variables {
    release_jobs = merge(var.release_jobs, { runtime_grants = merge(var.release_jobs.runtime_grants, { sql_sha256 = "latest" }) })
  }
  expect_failures = [var.release_jobs]
}
