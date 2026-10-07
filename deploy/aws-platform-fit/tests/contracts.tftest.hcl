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
  log_groups = {
    runtime = "/sentry-fit-staging/runtime"
    api     = "/sentry-fit-staging/api"
    worker  = "/sentry-fit-staging/worker"
  }
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
}

run "three_role_contract" {
  command = plan
  assert {
    condition     = toset(keys(output.task_contracts)) == toset(["runtime", "api", "worker"])
    error_message = "The platform-fit module must define exactly the three independent service roles."
  }
  assert {
    condition = alltrue([for name, task in aws_ecs_task_definition.service :
      task.network_mode == "awsvpc" && task.requires_compatibilities == toset(["FARGATE"]) &&
      one(task.runtime_platform).cpu_architecture == "ARM64" &&
      jsondecode(task.container_definitions) == output.task_contracts[name]
    ])
    error_message = "The actual task resources must bind the reviewed ARM64 Fargate container contracts."
  }
}

run "fail_closed_process_and_volume_contract" {
  command = plan
  assert {
    condition = alltrue([for name, containers in output.task_contracts :
      length(containers) == 2 && containers[0].name == "init" && !containers[0].essential &&
      containers[0].user == "0:0" && containers[0].readonlyRootFilesystem && containers[0].startTimeout == 120 &&
      containers[1].name == "app" && containers[1].essential && containers[1].readonlyRootFilesystem &&
      containers[1].dependsOn == [{ containerName = "init", condition = "SUCCESS" }] &&
      containers[1].linuxParameters.capabilities.drop == ["ALL"] &&
      !can(containers[0].linuxParameters.capabilities.add) &&
      !contains(containers[0].linuxParameters.capabilities.drop, "CHOWN") &&
      length(containers[0].linuxParameters.capabilities.drop) == 13 &&
      contains(containers[0].linuxParameters.capabilities.drop, "DAC_OVERRIDE") &&
      containers[0].workingDirectory == "/" &&
      alltrue([for mount in containers[0].mountPoints : !mount.readOnly]) &&
      one([for mount in containers[1].mountPoints : mount if mount.sourceVolume == "material"]).readOnly &&
      !can(containers[0].secrets)
    ])
    error_message = "Init must be nonessential root with only CHOWN retained; applications require successful init, readonly material and no capabilities."
  }
  assert {
    condition = alltrue([for name in ["api", "worker"] :
      output.task_contracts[name][1].user == "10001:10001" &&
      toset([for mount in output.task_contracts[name][1].mountPoints : mount.containerPath if !mount.readOnly]) == toset(["/tmp", "/var/lib/sentrysearch"]) &&
      contains(output.task_contracts[name][0].command, "--tmp-dir") &&
      contains(output.task_contracts[name][0].command, "--work-dir") &&
      toset([for volume in aws_ecs_task_definition.service[name].volume : volume.name]) == toset(["material", "tmp", "work"])
    ])
    error_message = "Search requires UID10001 and fresh writable tmp/work volumes, not persistent storage or tmpfs."
  }
  assert {
    condition = (output.task_contracts.runtime[1].user == "65532:65532" &&
      length(output.task_contracts.runtime[1].mountPoints) == 1 &&
      !contains(output.task_contracts.runtime[0].command, "--tmp-dir") &&
      alltrue(flatten([for task in aws_ecs_task_definition.service : [for volume in task.volume :
        (volume.host_path == null || volume.host_path == "") && length(volume.efs_volume_configuration) == 0 && length(volume.docker_volume_configuration) == 0
    ]])))
    error_message = "Runtime must use UID65532 and only read-only material; all volumes must be task-scoped and nonpersistent."
  }
}

run "health_admission_and_role_credentials" {
  command = plan
  assert {
    condition = (output.task_contracts.runtime[1].healthCheck.command == ["CMD", "/app/probe", "healthz"] &&
      output.task_contracts.runtime[1].stopTimeout == 30 &&
      output.task_contracts.worker[1].stopTimeout == 60 &&
      contains(output.task_contracts.worker[1].command, "--drain-seconds") &&
      contains(output.task_contracts.worker[1].command, "30") &&
      length(output.task_contracts.worker[1].portMappings) == 0 &&
      strcontains(output.task_contracts.worker[1].healthCheck.command[3], "127.0.0.1") &&
      strcontains(output.task_contracts.worker[1].healthCheck.command[3], "'/healthz'") &&
    strcontains(output.task_contracts.api[1].healthCheck.command[3], "'/'"))
    error_message = "Liveness probes must stay local, worker ports private, and stop grace greater than drain/shutdown budgets."
  }
  assert {
    condition = ({ for item in output.task_contracts.api[1].environment : item.name => item.value }["SENTRYSEARCH_EXECUTION_MODE"] == "paused" &&
      { for item in output.task_contracts.runtime[1].environment : item.name => item.value }["SENTRYRUNTIME_PROBE_SERVER_NAME"] == var.runtime_server_name &&
      { for item in output.task_contracts.runtime[1].environment : item.name => item.value }["SENTRYRUNTIME_PROBE_ADDRESS"] == "127.0.0.1:8443" &&
      { for item in output.task_contracts.runtime[1].environment : item.name => item.value }["SENTRYRUNTIME_PROBE_TOKEN_FILE"] == "/run/material/probe-token" &&
      toset([for item in output.task_contracts.api[1].secrets : item.name]) == toset(["DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD"]) &&
      toset([for item in output.task_contracts.runtime[1].secrets : item.name]) == toset(["DATABASE_URL", "SENTRYRUNTIME_AUTH_CREDENTIALS"]) &&
    toset([for item in output.task_contracts.worker[1].secrets : item.name]) == toset(["DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD", "SENTRYRUNTIME_PRODUCER_TOKEN", "SENTRYRUNTIME_WORKER_TOKEN"]))
    error_message = "Admission must stay paused and API must receive neither runtime/provider tokens nor auth-service secrets."
  }
  assert {
    condition = alltrue([for name, containers in output.task_contracts :
      alltrue([for secret in containers[1].secrets : secret.valueFrom == "${var.environment_bundles[name].arn}:${secret.name}::${var.environment_bundles[name].version_id}"]) &&
      contains(containers[0].command, var.material_bundles[name].arn) &&
      contains(containers[0].command, var.material_bundles[name].version_id) &&
      alltrue([for env in containers[1].environment : !contains(["DATABASE_URL", "DB_PASSWORD", "SENTRYRUNTIME_AUTH_CREDENTIALS", "SENTRYRUNTIME_PRODUCER_TOKEN", "SENTRYRUNTIME_WORKER_TOKEN"], env.name)])
    ])
    error_message = "Secret values must never be Terraform inputs/env plaintext; both material and JSON-key secret injection must pin exact versions."
  }
  assert {
    condition = (
      { for item in output.task_contracts.worker[1].environment : item.name => item.value }["OPENROUTER_BASE_URL"] == "http://127.0.0.1:9" &&
      { for item in output.task_contracts.worker[1].environment : item.name => item.value }["OPENROUTER_API_KEY"] == "disabled-local-platform-fit" &&
      !contains([for secret in output.task_contracts.worker[1].secrets : secret.name], "OPENROUTER_API_KEY") &&
      !contains([for env in output.task_contracts.api[1].environment : env.name], "NEXT_PUBLIC_SUPABASE_URL") &&
      !contains([for secret in output.task_contracts.api[1].secrets : secret.name], "SUPABASE_SERVICE_ROLE_KEY")
    )
    error_message = "The draft must remain disabled-generation and auth-unconfigured; no live provider credentials may be wired."
  }
}

run "least_privilege_identity_contract" {
  command = plan
  assert {
    condition = alltrue([for name in ["runtime", "api", "worker"] :
      jsondecode(aws_iam_role_policy.task[name].policy) == jsondecode(jsonencode(output.task_policies[name])) &&
      jsondecode(aws_iam_role_policy.execution[name].policy) == jsondecode(jsonencode(output.execution_policies[name])) &&
      output.task_policies[name].Statement[0].Action == ["secretsmanager:GetSecretValue"] &&
      output.task_policies[name].Statement[0].Resource == [var.material_bundles[name].arn] &&
      output.task_policies[name].Statement[0].Condition.StringEquals["secretsmanager:VersionId"] == var.material_bundles[name].version_id &&
      output.execution_policies[name].Statement[3].Resource == [var.environment_bundles[name].arn] &&
      output.execution_policies[name].Statement[3].Condition.StringEquals["secretsmanager:VersionId"] == var.environment_bundles[name].version_id &&
      jsondecode(aws_iam_role.task[name].assume_role_policy).Statement[0].Condition.StringEquals["aws:SourceAccount"] == var.account_id &&
      jsondecode(aws_iam_role.execution[name].assume_role_policy).Statement[0].Condition.ArnLike["aws:SourceArn"] == "arn:aws:ecs:${var.region}:${var.account_id}:*"
    ])
    error_message = "Real IAM resources must bind bounded policies, source-account trust and exact secret versions."
  }
  assert {
    condition = (length(output.task_policies.runtime.Statement) == 1 &&
      output.task_policies.worker.Statement[1].Action == ["s3:GetObject", "s3:PutObject"] &&
      output.task_policies.api.Statement[1].Action == ["s3:GetObject", "s3:DeleteObject"] &&
      output.task_policies.api.Statement[2].Action == ["s3:ListBucket"] &&
      output.task_policies.api.Statement[2].Condition.StringLike["s3:prefix"] == ["reports/*"] &&
      alltrue([for name in ["api", "worker"] : output.task_policies[name].Statement[1].Resource == ["arn:aws:s3:::${var.artifact_bucket}/reports/*"]]) &&
      !strcontains(jsonencode(output.task_policies), "DeleteObjectVersion") &&
    !strcontains(jsonencode(output.task_policies), "kms:"))
    error_message = "Runtime cannot access S3; product identities are reports-prefix bounded, preserve object versions, and do not assume custom KMS access."
  }
  assert {
    condition = alltrue([for name, policy in output.execution_policies :
      policy.Statement[0].Action == ["ecr:GetAuthorizationToken"] && policy.Statement[0].Resource == ["*"] &&
      policy.Statement[2].Action == ["logs:CreateLogStream", "logs:PutLogEvents"] &&
      policy.Statement[2].Resource == ["arn:aws:logs:${var.region}:${var.account_id}:log-group:${var.log_groups[name]}:log-stream:${name}/*"] &&
      alltrue([for statement in slice(policy.Statement, 1, length(policy.Statement)) : !contains(statement.Resource, "*")])
    ])
    error_message = "Execution wildcard permission is limited to ECR token acquisition; log streams and pulls must stay explicitly scoped."
  }
}

run "worker_readiness_receipts_contract" {
  command = plan
  variables { release_id = "0b9f7c1e-4d2a-4f6b-9a3e-2c1d0e9f8a7b" }
  assert {
    condition = (
      { for item in output.task_contracts.worker[1].environment : item.name => item.value }["SENTRYSEARCH_RELEASE_ID"] == var.release_id &&
      alltrue([for name in ["runtime", "api"] : !contains([for item in output.task_contracts[name][1].environment : item.name], "SENTRYSEARCH_RELEASE_ID")]) &&
      jsondecode(aws_ecs_task_definition.service["worker"].container_definitions) == output.task_contracts.worker
    )
    error_message = "Only the worker revision fixes the release identity its supervisor receipts echo."
  }
  assert {
    condition = alltrue([for container in output.task_contracts.worker : container.logConfiguration == {
      logDriver = "awslogs"
      options = {
        awslogs-group         = var.log_groups.worker
        awslogs-region        = var.region
        awslogs-stream-prefix = "worker"
        mode                  = "non-blocking"
        max-buffer-size       = "4m"
      }
    }])
    error_message = "Worker logging must be explicitly non-blocking with the measured 4 MiB buffer, never the account default mode."
  }
  assert {
    condition = (
      output.readiness_log_stream == "arn:aws:logs:us-east-1:111122223333:log-group:/sentry-fit-staging/worker:log-stream:worker/app/*" &&
      output.task_contracts.worker[1].name == "app" &&
      output.execution_policies.worker.Statement[2].Resource == ["arn:aws:logs:us-east-1:111122223333:log-group:/sentry-fit-staging/worker:log-stream:worker/*"]
    )
    error_message = "Receipts are read only from the worker app container's configured stream, which its execution role writes."
  }
}

run "local_runs_emit_no_receipts" {
  command = plan
  assert {
    condition     = !contains([for item in output.task_contracts.worker[1].environment : item.name], "SENTRYSEARCH_RELEASE_ID")
    error_message = "Without a release identity the worker emits no readiness receipts."
  }
  assert {
    condition = alltrue([for name in ["runtime", "api"] :
      !can(output.task_contracts[name][1].logConfiguration.options.mode) &&
      !can(output.task_contracts[name][1].logConfiguration.options["max-buffer-size"])
    ])
    error_message = "Runtime and API log modes are unchanged until their own output is measured."
  }
}

run "reject_release_id_not_uuid" {
  command = plan
  variables { release_id = "LATEST" }
  expect_failures = [var.release_id]
}

run "reject_mutable_image_tag" {
  command = plan
  variables {
    images = {
      runtime = "111122223333.dkr.ecr.us-east-1.amazonaws.com/sentryruntime:latest"
      search  = "111122223333.dkr.ecr.us-east-1.amazonaws.com/sentrysearch@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    }
  }
  expect_failures = [var.images]
}

run "reject_non_dns_runtime_identity" {
  command = plan
  variables { runtime_server_name = "127.0.0.1" }
  expect_failures = [var.runtime_server_name]
}

run "reject_moving_secret_version" {
  command = plan
  variables {
    material_bundles = {
      runtime = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/runtime-material-DDDDDD", version_id = "AWSCURRENT" }
      api     = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/api-material-EEEEEE", version_id = "55555555-5555-4555-8555-555555555555" }
      worker  = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/worker-material-FFFFFF", version_id = "66666666-6666-4666-8666-666666666666" }
    }
  }
  expect_failures = [var.material_bundles]
}

run "reject_shared_role_secret" {
  command = plan
  variables {
    environment_bundles = {
      runtime = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/runtime-env-AAAAAA", version_id = "11111111-1111-4111-8111-111111111111" }
      api     = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/runtime-env-AAAAAA", version_id = "22222222-2222-4222-8222-222222222222" }
      worker  = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/worker-env-CCCCCC", version_id = "33333333-3333-4333-8333-333333333333" }
    }
  }
  expect_failures = [var.material_bundles]
}

run "reject_cross_account_bundle" {
  command = plan
  variables {
    environment_bundles = {
      runtime = { arn = "arn:aws:secretsmanager:us-east-1:999999999999:secret:staging/runtime-env-AAAAAA", version_id = "11111111-1111-4111-8111-111111111111" }
      api     = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/api-env-BBBBBB", version_id = "22222222-2222-4222-8222-222222222222" }
      worker  = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/worker-env-CCCCCC", version_id = "33333333-3333-4333-8333-333333333333" }
    }
  }
  expect_failures = [var.environment_bundles]
}
