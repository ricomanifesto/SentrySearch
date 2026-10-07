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
  release_id = "22222222-2222-4222-8222-222222222222"
  release_tools = {
    release_id     = "22222222-2222-4222-8222-222222222222"
    image          = "111122223333.dkr.ecr.us-east-1.amazonaws.com/sentry-release-tools@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    not_after      = "2026-10-07T18:00:00Z"
    budget_seconds = 900
    tools_sha256   = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    sql_sha256 = {
      runtime_grant = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
      product_grant = "1111111111111111111111111111111111111111111111111111111111111111"
      runtime_proof = "2222222222222222222222222222222222222222222222222222222222222222"
      product_proof = "3333333333333333333333333333333333333333333333333333333333333333"
      reconcile     = "4444444444444444444444444444444444444444444444444444444444444444"
    }
    runtime = {
      database     = "sentryruntime", owner = "runtime_owner", service = "runtime_app"
      proof_bundle = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/runtime-proof-KKKKKK", version_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" }
    }
    product = {
      database     = "sentrysearch", owner = "search_owner", service = "search_app"
      proof_bundle = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/product-proof-LLLLLL", version_id = "cccccccc-cccc-4ccc-8ccc-cccccccccccc" }
    }
  }
}

run "tools_jobs_are_opt_in" {
  command = plan
  variables { release_tools = null }
  assert {
    condition = (length(aws_ecs_task_definition.tools) == 0 && length(aws_iam_role.tools_execution) == 0 &&
      length(output.tools_task_contracts) == 0 && output.release_tools_bindings == null &&
      toset(keys(output.task_definition_arns)) == toset(["runtime", "api", "worker", "runtime-release", "product-release"]) &&
    toset(keys(output.receipt_log_streams)) == toset(["runtime-migrate", "product-migrate"]))
    error_message = "Omitting release-tools inputs must keep the reviewed migration-only release interface."
  }
}

run "reject_tools_without_owner_jobs" {
  command = plan
  variables { release_jobs = null }
  expect_failures = [var.release_tools]
}

run "six_guarded_tools_jobs" {
  command = plan
  assert {
    condition = (toset(keys(aws_ecs_task_definition.tools)) == toset(["runtime-grant", "product-grant", "runtime-proof", "product-proof", "runtime-reconcile", "product-reconcile"]) &&
      alltrue([for key, task in aws_ecs_task_definition.tools :
        task.family == "${var.name_prefix}-${key}" && task.cpu == "256" && task.memory == "512" &&
        task.network_mode == "awsvpc" && task.requires_compatibilities == toset(["FARGATE"]) &&
        one(task.runtime_platform).cpu_architecture == "ARM64" &&
        jsondecode(task.container_definitions) == jsondecode(jsonencode(output.tools_task_contracts[key])) &&
        length(task.volume) == 1 && one(task.volume).name == "material" &&
        length(one(task.volume).efs_volume_configuration) == 0 && length(one(task.volume).docker_volume_configuration) == 0
    ]))
    error_message = "Each guarded job is its own ARM64 task definition with fresh CA-only storage (role bindings: deploy/aws-staging/releases tests)."
  }
  assert {
    condition = alltrue([for key, containers in output.tools_task_contracts :
      length(containers) == 2 && containers[0].name == "init" &&
      jsonencode(merge(containers[0], { logConfiguration = null })) == jsonencode(merge(output.release_task_contracts[startswith(key, "runtime") ? "runtime" : "product"][0], { logConfiguration = null })) &&
      containers[1].name == split("-", key)[1] && containers[1].essential && !containers[0].essential &&
      containers[1].image == var.release_tools.image &&
      containers[1].user == (startswith(key, "runtime") ? "65532:65532" : "10001:10001") &&
      containers[1].readonlyRootFilesystem && containers[1].workingDirectory == "/" &&
      containers[1].linuxParameters.capabilities.drop == ["ALL"] && !can(containers[1].linuxParameters.capabilities.add) &&
      containers[1].dependsOn == [{ containerName = "init", condition = "SUCCESS" }] &&
      containers[1].startTimeout == 120 && containers[1].stopTimeout == 30 &&
      containers[1].command == [split("-", key)[1]] && !can(containers[1].entryPoint) &&
      containers[1].mountPoints == [{ sourceVolume = "material", containerPath = "/run/material", readOnly = true }] &&
      length(containers[1].portMappings) == 0 && !can(containers[1].healthCheck) && !can(containers[1].restartPolicy) &&
      alltrue([for container in containers :
        container.logConfiguration == {
          logDriver = "awslogs"
          options = {
            awslogs-group         = var.release_jobs[startswith(key, "runtime") ? "runtime" : "product"].log_group
            awslogs-region        = var.region
            awslogs-stream-prefix = key
          }
        }
      ])
    ])
    error_message = "Jobs run the pinned release-tools image nonroot and read-only after a successful CA init, with one fixed command and no service behavior."
  }
}

run "deadline_hashes_and_identities_are_fixed_in_each_definition" {
  command = plan
  assert {
    condition = alltrue([for key, containers in output.tools_task_contracts :
      { for item in containers[1].environment : item.name => item.value } == merge(
        {
          RELEASE_ID                 = var.release_tools.release_id
          RELEASE_JOB_ID             = key
          RELEASE_DATABASE           = split("-", key)[0]
          RELEASE_NOT_AFTER          = "2026-10-07T18:00:00Z"
          RELEASE_JOB_BUDGET_SECONDS = "900"
          RELEASE_TOOLS_SHA256       = var.release_tools.tools_sha256
          RELEASE_SQL_SHA256 = {
            runtime-grant     = var.release_jobs.runtime_grants.sql_sha256, product-grant = var.release_tools.sql_sha256.product_grant
            runtime-proof     = var.release_tools.sql_sha256.runtime_proof, product-proof = var.release_tools.sql_sha256.product_proof
            runtime-reconcile = var.release_tools.sql_sha256.reconcile, product-reconcile = var.release_tools.sql_sha256.reconcile
          }[key]
          RELEASE_EXPECT_DATABASE  = var.release_tools[split("-", key)[0]].database
          RELEASE_EXPECT_PRINCIPAL = split("-", key)[1] == "proof" ? var.release_tools[split("-", key)[0]].service : var.release_tools[split("-", key)[0]].owner
        },
        split("-", key)[1] == "grant" ? { RELEASE_SERVICE_ROLE = var.release_tools[split("-", key)[0]].service } : {},
        split("-", key)[1] == "proof" ? { RELEASE_OWNER_ROLE = var.release_tools[split("-", key)[0]].owner } : {},
      ) &&
      length(containers[1].environment) == length(distinct([for item in containers[1].environment : item.name]))
    ])
    error_message = "Release ID, job ID, the absolute deadline, budget, tools/SQL digests and the expected identity are immutable task-definition values."
  }
  assert {
    condition = alltrue([for key, containers in output.tools_task_contracts :
      !strcontains(jsonencode(containers), "ECS_CONTAINER_METADATA_URI") && !strcontains(jsonencode(containers), "PGOPTIONS") &&
      !strcontains(jsonencode(containers), "PGPASSWORD") && !strcontains(jsonencode(containers), "RELEASE_OWNER_PASSWORD") &&
      !strcontains(jsonencode(containers), "PYTHON")
    ])
    error_message = "Session limits, metadata and interpreter settings stay inside the image; no credential or override travels as plain environment."
  }
  assert {
    condition = alltrue([for key, containers in output.tools_task_contracts :
      toset([for secret in containers[1].secrets : secret.name]) == toset(startswith(key, "runtime") ? ["DATABASE_URL"] : ["DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD"]) &&
      alltrue([for secret in containers[1].secrets : secret.valueFrom == (
        split("-", key)[1] == "proof"
        ? "${var.release_tools[split("-", key)[0]].proof_bundle.arn}:${secret.name}::${var.release_tools[split("-", key)[0]].proof_bundle.version_id}"
        : "${var.release_jobs[split("-", key)[0]].environment_bundle.arn}:${secret.name}::${var.release_jobs[split("-", key)[0]].environment_bundle.version_id}"
      )])
    ])
    error_message = "Grant and reconciliation use the owner bundle; proofs use only the service login's own exact-version proof bundle."
  }
  assert {
    condition = (output.release_tools_bindings.not_after == "2026-10-07T18:00:00Z" &&
      output.release_tools_bindings.budget_seconds == 900 &&
      output.release_tools_bindings.tools_sha256 == var.release_tools.tools_sha256 &&
      output.release_tools_bindings.receipt_schema == "sentry.release-tools.job.v1" &&
      output.release_tools_bindings.expectations["runtime-grant"] == {
        database = "sentryruntime", principal = "runtime_owner", service_role = "runtime_app", sql_digest = var.release_jobs.runtime_grants.sql_sha256
      } &&
    output.release_tools_bindings.expectations["product-proof"] == { database = "sentrysearch", principal = "search_app" })
    error_message = "The bindings output gives manifest authors the exact receipt expectations; proof schema comes from the migrated revision."
  }
}

run "tools_identity_is_per_job_and_least_authority" {
  command = plan
  assert {
    condition = alltrue([for key, job in output.tools_task_contracts :
      jsondecode(aws_iam_role_policy.tools_execution[key].policy) == jsondecode(jsonencode(output.tools_execution_policies[key])) &&
      jsonencode(output.tools_execution_policies[key].Statement) == jsonencode([
        { Sid = "RegistryToken", Effect = "Allow", Action = ["ecr:GetAuthorizationToken"], Resource = ["*"] },
        {
          Sid      = "PullImages", Effect = "Allow", Action = ["ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"]
          Resource = ["arn:aws:ecr:us-east-1:111122223333:repository/sentrysearch", "arn:aws:ecr:us-east-1:111122223333:repository/sentry-release-tools"]
        },
        {
          Sid      = "TaskLogs", Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"]
          Resource = ["arn:aws:logs:us-east-1:111122223333:log-group:${var.release_jobs[split("-", key)[0]].log_group}:log-stream:${key}/*"]
        },
        {
          Sid       = "PinnedJobEnvironment", Effect = "Allow", Action = ["secretsmanager:GetSecretValue"]
          Resource  = [split("-", key)[1] == "proof" ? var.release_tools[split("-", key)[0]].proof_bundle.arn : var.release_jobs[split("-", key)[0]].environment_bundle.arn]
          Condition = { StringEquals = { "secretsmanager:VersionId" = split("-", key)[1] == "proof" ? var.release_tools[split("-", key)[0]].proof_bundle.version_id : var.release_jobs[split("-", key)[0]].environment_bundle.version_id } }
        },
      ]) &&
      aws_iam_role.tools_execution[key].name == "${var.name_prefix}-${split("-", key)[0]}-${ { grant = "grant", proof = "proof", reconcile = "recon" }[split("-", key)[1]]}-execution" &&
      jsondecode(aws_iam_role.tools_execution[key].assume_role_policy).Statement[0].Condition.StringEquals["aws:SourceAccount"] == var.account_id
    ])
    error_message = "Each job pulls only init and tools images, writes only its own stream and reads only its own exact-version credential bundle."
  }
  assert {
    condition = (output.iam_role_names["runtime-recon-execution"] == "${var.name_prefix}-runtime-recon-execution" &&
      length(output.iam_role_names) == 16 &&
      toset(keys(output.task_definition_arns)) == toset(["runtime", "api", "worker", "runtime-release", "product-release", "runtime-grant", "product-grant", "runtime-proof", "product-proof", "runtime-reconcile", "product-reconcile"]) &&
      output.receipt_log_streams == {
        runtime-migrate   = "arn:aws:logs:us-east-1:111122223333:log-group:/staging/runtime-release:log-stream:runtime-release/migration/*"
        product-migrate   = "arn:aws:logs:us-east-1:111122223333:log-group:/staging/product-release:log-stream:product-release/migration/*"
        runtime-grant     = "arn:aws:logs:us-east-1:111122223333:log-group:/staging/runtime-release:log-stream:runtime-grant/grant/*"
        product-grant     = "arn:aws:logs:us-east-1:111122223333:log-group:/staging/product-release:log-stream:product-grant/grant/*"
        runtime-proof     = "arn:aws:logs:us-east-1:111122223333:log-group:/staging/runtime-release:log-stream:runtime-proof/proof/*"
        product-proof     = "arn:aws:logs:us-east-1:111122223333:log-group:/staging/product-release:log-stream:product-proof/proof/*"
        runtime-reconcile = "arn:aws:logs:us-east-1:111122223333:log-group:/staging/runtime-release:log-stream:runtime-reconcile/reconcile/*"
        product-reconcile = "arn:aws:logs:us-east-1:111122223333:log-group:/staging/product-release:log-stream:product-reconcile/reconcile/*"
      } &&
      alltrue([for key, policy in output.tools_execution_policies : alltrue([for name in ["runtime", "api", "worker"] :
        !strcontains(jsonencode(policy), var.environment_bundles[name].arn) && !strcontains(jsonencode(policy), var.material_bundles[name].arn)
      ])]) &&
      !strcontains(jsonencode(output.task_policies), var.release_tools.runtime.proof_bundle.arn) &&
    !strcontains(jsonencode(output.release_execution_policies), var.release_tools.product.proof_bundle.arn))
    error_message = "Receipts are read only from each job's app-container stream; service, material and proof bundles never cross job boundaries."
  }
}

run "reject_tools_image_tag" {
  command = plan
  variables {
    release_tools = merge(var.release_tools, { image = "111122223333.dkr.ecr.us-east-1.amazonaws.com/sentry-release-tools:latest" })
  }
  expect_failures = [var.release_tools]
}

run "reject_tools_cross_account_image" {
  command = plan
  variables {
    release_tools = merge(var.release_tools, { image = "999999999999.dkr.ecr.us-east-1.amazonaws.com/sentry-release-tools@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" })
  }
  expect_failures = [var.release_tools]
}

run "reject_non_utc_deadline" {
  command = plan
  variables { release_tools = merge(var.release_tools, { not_after = "2026-10-07T18:00:00+02:00" }) }
  expect_failures = [var.release_tools]
}

run "reject_impossible_deadline" {
  command = plan
  variables { release_tools = merge(var.release_tools, { not_after = "2026-02-30T18:00:00Z" }) }
  expect_failures = [var.release_tools]
}

run "reject_budget_out_of_bounds" {
  command = plan
  variables { release_tools = merge(var.release_tools, { budget_seconds = 3601 }) }
  expect_failures = [var.release_tools]
}

run "reject_fractional_budget" {
  command = plan
  variables { release_tools = merge(var.release_tools, { budget_seconds = 90.5 }) }
  expect_failures = [var.release_tools]
}

run "reject_unhashed_tools" {
  command = plan
  variables { release_tools = merge(var.release_tools, { tools_sha256 = "latest" }) }
  expect_failures = [var.release_tools]
}

run "reject_runtime_grant_hash_differing_from_pin" {
  command = plan
  variables {
    release_tools = merge(var.release_tools, { sql_sha256 = merge(var.release_tools.sql_sha256, { runtime_grant = "5555555555555555555555555555555555555555555555555555555555555555" }) })
  }
  expect_failures = [var.release_tools]
}

run "reject_owner_as_service" {
  command = plan
  variables {
    release_tools = merge(var.release_tools, { product = merge(var.release_tools.product, { service = "search_owner" }) })
  }
  expect_failures = [var.release_tools]
}

run "reject_invalid_identifier" {
  command = plan
  variables {
    release_tools = merge(var.release_tools, { runtime = merge(var.release_tools.runtime, { database = "Sentry-Runtime" }) })
  }
  expect_failures = [var.release_tools]
}

run "reject_proof_bundle_reusing_owner_bundle" {
  command = plan
  variables {
    release_tools = merge(var.release_tools, { runtime = merge(var.release_tools.runtime, { proof_bundle = var.release_jobs.runtime.environment_bundle }) })
  }
  expect_failures = [var.release_tools]
}

run "reject_proof_bundle_reusing_service_bundle" {
  command = plan
  variables {
    release_tools = merge(var.release_tools, { product = merge(var.release_tools.product, { proof_bundle = var.environment_bundles.api }) })
  }
  expect_failures = [var.release_tools]
}

run "reject_shared_proof_bundle" {
  command = plan
  variables {
    release_tools = merge(var.release_tools, { product = merge(var.release_tools.product, { proof_bundle = var.release_tools.runtime.proof_bundle }) })
  }
  expect_failures = [var.release_tools]
}

run "reject_moving_proof_bundle_version" {
  command = plan
  variables {
    release_tools = merge(var.release_tools, { runtime = merge(var.release_tools.runtime, { proof_bundle = merge(var.release_tools.runtime.proof_bundle, { version_id = "AWSCURRENT" }) }) })
  }
  expect_failures = [var.release_tools]
}

run "worker_and_tools_share_the_release_identity" {
  command = plan
  assert {
    condition     = { for item in output.task_contracts.worker[1].environment : item.name => item.value }["SENTRYSEARCH_RELEASE_ID"] == var.release_tools.release_id
    error_message = "The worker receipts and the release-tools jobs must name the same release."
  }
}

run "reject_worker_release_id_differing_from_tools" {
  command = plan
  variables { release_id = "33333333-3333-4333-8333-333333333333" }
  expect_failures = [var.release_id]
}

run "reject_tools_release_without_worker_release_id" {
  command = plan
  variables { release_id = null }
  expect_failures = [var.release_id]
}

run "reject_release_id_not_uuid" {
  command = plan
  variables { release_tools = merge(var.release_tools, { release_id = "r22222222" }) }
  expect_failures = [var.release_tools]
}

run "reject_deadline_beyond_seven_days" {
  command = plan
  variables { release_tools = merge(var.release_tools, { not_after = "2099-10-07T18:00:00Z" }) }
  expect_failures = [var.release_tools]
}
