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
  observers = {
    namespace      = "staging.example.test"
    budget_seconds = 300
    runtime_bundle = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/runtime-observer-MMMMMM", version_id = "dddddddd-dddd-4ddd-8ddd-dddddddddddd" }
    log_group      = "/staging/observe"
  }
  bootstrap = {
    sql_sha256 = "5555555555555555555555555555555555555555555555555555555555555555"
    runtime = {
      host          = "runtime-db.abcdefghijkl.us-east-1.rds.amazonaws.com"
      administrator = "runtime_admin"
      admin_secret  = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:rds!db-0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d-NNNNNN", version_id = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee" }
      credentials   = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/runtime-bootstrap-OOOOOO", version_id = "ffffffff-ffff-4fff-8fff-ffffffffffff" }
      ca_bundle     = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/runtime-bootstrap-ca-SSSSSS", version_id = "56565656-5656-4565-8565-565656565656" }
    }
    product = {
      host          = "product-db.abcdefghijkl.us-east-1.rds.amazonaws.com"
      administrator = "product_admin"
      admin_secret  = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:rds!db-1b2c3d4e-5f6a-4b7c-8d9e-0f1a2b3c4d5e-PPPPPP", version_id = "12121212-1212-4121-8121-121212121212" }
      credentials   = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/product-bootstrap-QQQQQQ", version_id = "34343434-3434-4343-8343-343434343434" }
      ca_bundle     = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/product-bootstrap-ca-TTTTTT", version_id = "78787878-7878-4787-8787-787878787878" }
    }
  }
}

run "observers_are_opt_in" {
  command = plan
  variables {
    observers = null
    bootstrap = null
  }
  assert {
    condition = (length(aws_ecs_task_definition.observer) == 0 && length(aws_iam_role.observer_task) == 0 &&
      length(aws_iam_role.observer_execution) == 0 && output.observer_bindings == null &&
      length(output.observer_receipt_streams) == 0 &&
    !anytrue([for key in keys(output.task_definition_arns) : endswith(key, "-observe")]))
    error_message = "Omitting observer inputs keeps the reviewed job-only release interface."
  }
}

run "reject_observers_without_release_tools" {
  command = plan
  variables {
    release_tools = null
    bootstrap     = null
  }
  expect_failures = [var.observers]
}

run "two_observer_tasks" {
  command = plan
  assert {
    condition = (toset(keys(aws_ecs_task_definition.observer)) == toset(["runtime-observe", "api-observe"]) &&
      alltrue([for key, task in aws_ecs_task_definition.observer :
        task.family == "${var.name_prefix}-${key}" && task.cpu == "256" && task.memory == "512" &&
        task.network_mode == "awsvpc" && task.requires_compatibilities == toset(["FARGATE"]) &&
        one(task.runtime_platform).cpu_architecture == "ARM64" &&
        jsondecode(task.container_definitions) == jsondecode(jsonencode(output.observer_task_contracts[key]))
      ]) &&
      length(aws_ecs_task_definition.observer["runtime-observe"].volume) == 1 &&
      one(aws_ecs_task_definition.observer["runtime-observe"].volume).name == "material" &&
      length(aws_ecs_task_definition.observer["api-observe"].volume) == 0 &&
    aws_ecs_task_definition.observer["api-observe"].task_role_arn == null)
    error_message = "Each observer is its own ARM64 task definition; only the Runtime observer has material and a task role."
  }
}

run "observer_containers_are_fixed" {
  command = plan
  assert {
    condition = (
      [for container in output.observer_task_contracts["runtime-observe"] : container.name] == ["init", "observer"] &&
      [for container in output.observer_task_contracts["api-observe"] : container.name] == ["observer"] &&
      output.observer_task_contracts["runtime-observe"][0].command == ["python", "-m", "dev.prepare_service_volumes", "--profile", "runtime-observer", "--material-dir", "/run/material", "--secret-id", var.observers.runtime_bundle.arn, "--version-id", var.observers.runtime_bundle.version_id, "--region", var.region] &&
      output.observer_task_contracts["runtime-observe"][0].image == var.images.search &&
      output.observer_task_contracts["runtime-observe"][0].user == "0:0" && !output.observer_task_contracts["runtime-observe"][0].essential &&
      alltrue([for key, target in { runtime-observe = "runtime", api-observe = "api" } : (
        output.observer_task_contracts[key][length(output.observer_task_contracts[key]) - 1].image == var.release_tools.image &&
        output.observer_task_contracts[key][length(output.observer_task_contracts[key]) - 1].user == "65532:65532" &&
        output.observer_task_contracts[key][length(output.observer_task_contracts[key]) - 1].essential &&
        output.observer_task_contracts[key][length(output.observer_task_contracts[key]) - 1].readonlyRootFilesystem &&
        output.observer_task_contracts[key][length(output.observer_task_contracts[key]) - 1].linuxParameters.capabilities.drop == ["ALL"] &&
        output.observer_task_contracts[key][length(output.observer_task_contracts[key]) - 1].command == ["observe-${target}"] &&
        output.observer_task_contracts[key][length(output.observer_task_contracts[key]) - 1].stopTimeout == 30 &&
        !can(output.observer_task_contracts[key][length(output.observer_task_contracts[key]) - 1].secrets) &&
        length(output.observer_task_contracts[key][length(output.observer_task_contracts[key]) - 1].portMappings) == 0 &&
        { for item in output.observer_task_contracts[key][length(output.observer_task_contracts[key]) - 1].environment : item.name => item.value } == {
          RELEASE_ID                   = var.release_tools.release_id
          RELEASE_CHECK_ID             = key
          RELEASE_NOT_AFTER            = var.release_tools.not_after
          RELEASE_CHECK_BUDGET_SECONDS = "300"
          RELEASE_TARGET_HOST          = "${target}.${var.observers.namespace}"
          RELEASE_TARGET_PORT          = target == "runtime" ? "8443" : "8001"
        } &&
        alltrue([for container in output.observer_task_contracts[key] : container.logConfiguration == {
          logDriver = "awslogs"
          options   = { awslogs-group = var.observers.log_group, awslogs-region = var.region, awslogs-stream-prefix = key }
        }])
      )]) &&
      output.observer_task_contracts["runtime-observe"][1].dependsOn == [{ containerName = "init", condition = "SUCCESS" }] &&
      output.observer_task_contracts["runtime-observe"][1].mountPoints == [{ sourceVolume = "material", containerPath = "/run/material", readOnly = true }] &&
      !can(output.observer_task_contracts["api-observe"][0].dependsOn) &&
      length(output.observer_task_contracts["api-observe"][0].mountPoints) == 0
    )
    error_message = "Observer containers are fixed: release-tools image, non-root, read-only, no secrets or ports, the target's private name and port, and the check id as stream prefix."
  }
}

run "observer_authority_is_minimal" {
  command = plan
  assert {
    condition = (length(output.observer_task_policy.Statement) == 1 &&
      output.observer_task_policy.Statement[0].Sid == "PinnedObserverMaterial" &&
      output.observer_task_policy.Statement[0].Action == ["secretsmanager:GetSecretValue"] &&
      output.observer_task_policy.Statement[0].Resource == [var.observers.runtime_bundle.arn] &&
    output.observer_task_policy.Statement[0].Condition.StringEquals["secretsmanager:VersionId"] == var.observers.runtime_bundle.version_id)
    error_message = "Only the Runtime observer's init reads a secret: its own bundle at its pinned version."
  }
  assert {
    condition = ([for statement in output.observer_execution_policies["runtime-observe"].Statement : statement.Sid] == ["RegistryToken", "PullImages", "TaskLogs"] &&
      output.observer_execution_policies["runtime-observe"].Statement[1].Resource == tolist([
        "arn:aws:ecr:us-east-1:111122223333:repository/sentrysearch", "arn:aws:ecr:us-east-1:111122223333:repository/sentry-release-tools"
      ]) &&
    output.observer_execution_policies["api-observe"].Statement[1].Resource == tolist(["arn:aws:ecr:us-east-1:111122223333:repository/sentry-release-tools"]))
    error_message = "Observers pull only the images they run."
  }
  assert {
    condition = alltrue([for key in ["runtime-observe", "api-observe"] :
      output.observer_execution_policies[key].Statement[2].Resource == ["arn:aws:logs:us-east-1:111122223333:log-group:/staging/observe:log-stream:${key}/*"] &&
      !strcontains(jsonencode(output.observer_execution_policies[key]), "secretsmanager")
    ])
    error_message = "Observers write only their own streams and read no secret at task start."
  }
  assert {
    condition = output.observer_receipt_streams == {
      runtime-observe = "arn:aws:logs:us-east-1:111122223333:log-group:/staging/observe:log-stream:runtime-observe/observer/*"
      api-observe     = "arn:aws:logs:us-east-1:111122223333:log-group:/staging/observe:log-stream:api-observe/observer/*"
    }
    error_message = "The controller reads an observer's receipt only from its observer container's stream."
  }
  assert {
    condition = (toset(keys(output.launch_scopes.observers.task_definitions)) == toset(["runtime-observe", "api-observe"]) &&
    !anytrue([for key in keys(output.launch_scopes.jobs.task_definitions) : endswith(key, "-observe")]))
    error_message = "Observers launch under their own scope, never the database jobs'."
  }
}

run "reject_observer_with_a_service_bundle" {
  command = plan
  variables {
    observers = {
      namespace      = "staging.example.test", budget_seconds = 300, log_group = "/staging/observe"
      runtime_bundle = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/runtime-material-DDDDDD", version_id = "44444444-4444-4444-8444-444444444444" }
    }
  }
  expect_failures = [var.observers]
}

run "reject_observer_with_a_proof_bundle" {
  command = plan
  variables {
    observers = {
      namespace      = "staging.example.test", budget_seconds = 300, log_group = "/staging/observe"
      runtime_bundle = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/runtime-proof-KKKKKK", version_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" }
    }
  }
  expect_failures = [var.observers]
}

run "reject_moving_observer_bundle_version" {
  command = plan
  variables {
    observers = {
      namespace      = "staging.example.test", budget_seconds = 300, log_group = "/staging/observe"
      runtime_bundle = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/runtime-observer-MMMMMM", version_id = "AWSCURRENT" }
    }
  }
  expect_failures = [var.observers]
}

run "reject_namespace_other_than_the_runtime_san" {
  command = plan
  variables {
    observers = {
      namespace      = "other.example.test", budget_seconds = 300, log_group = "/staging/observe"
      runtime_bundle = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/runtime-observer-MMMMMM", version_id = "dddddddd-dddd-4ddd-8ddd-dddddddddddd" }
    }
  }
  expect_failures = [var.observers]
}

run "reject_observer_budget_out_of_bounds" {
  command = plan
  variables {
    observers = {
      namespace      = "staging.example.test", budget_seconds = 59, log_group = "/staging/observe"
      runtime_bundle = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/runtime-observer-MMMMMM", version_id = "dddddddd-dddd-4ddd-8ddd-dddddddddddd" }
    }
  }
  expect_failures = [var.observers]
}

run "reject_observer_logs_in_a_job_group" {
  command = plan
  variables {
    observers = {
      namespace      = "staging.example.test", budget_seconds = 300, log_group = "/staging/runtime-release"
      runtime_bundle = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/runtime-observer-MMMMMM", version_id = "dddddddd-dddd-4ddd-8ddd-dddddddddddd" }
    }
  }
  expect_failures = [var.observers]
}

run "migrations_run_in_their_release_job_mode" {
  command = plan
  assert {
    condition = (
      output.release_task_contracts.runtime[1].command == tolist(["/app/migrate", "-release-job"]) &&
      output.release_task_contracts.product[1].command == tolist(["python", "-m", "dev.migrate_storage", "--release-job"]) &&
      alltrue([for name in ["runtime", "product"] : (
        { for item in output.release_task_contracts[name][1].environment : item.name => item.value if startswith(item.name, "RELEASE_") } == {
          RELEASE_ID                 = var.release_tools.release_id
          RELEASE_JOB_ID             = "${name}-migrate"
          RELEASE_NOT_AFTER          = var.release_tools.not_after
          RELEASE_JOB_BUDGET_SECONDS = "900"
          RELEASE_EXPECT_DATABASE    = var.release_tools[name].database
          RELEASE_EXPECT_PRINCIPAL   = var.release_tools[name].owner
        }
      )]) &&
      { for item in output.release_task_contracts.product[1].environment : item.name => item.value }["DB_SSLMODE"] == "verify-full" &&
      output.release_tools_bindings.migration_receipt_schema == "sentry.release-migration.v1" &&
      output.release_tools_bindings.migration_expectations == {
        runtime-migrate = { database = "sentryruntime", principal = "runtime_owner" }
        product-migrate = { database = "sentrysearch", principal = "search_owner" }
      }
    )
    error_message = "With release-tools inputs, each migration runs its guarded release-job mode under the release's fixed identity and deadline."
  }
}
