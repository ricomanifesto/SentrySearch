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

run "bootstrap_is_opt_in" {
  command = plan
  variables { bootstrap = null }
  assert {
    condition = (length(aws_ecs_task_definition.bootstrap) == 0 && length(aws_iam_role.bootstrap_task) == 0 &&
      length(aws_iam_role.bootstrap_execution) == 0 && output.bootstrap_bindings == null &&
    length(output.bootstrap_receipt_streams) == 0 && length(output.launch_scopes.bootstrap.task_definitions) == 0)
    error_message = "Omitting bootstrap inputs registers no administrator job."
  }
}

run "reject_bootstrap_without_release_tools" {
  command = plan
  variables {
    release_tools = null
    observers     = null
  }
  expect_failures = [var.bootstrap]
}

run "two_bootstrap_jobs" {
  command = plan
  assert {
    condition = (toset(keys(aws_ecs_task_definition.bootstrap)) == toset(["runtime-bootstrap", "product-bootstrap"]) &&
      alltrue([for key, task in aws_ecs_task_definition.bootstrap :
        task.family == "${var.name_prefix}-${key}" && one(task.runtime_platform).cpu_architecture == "ARM64" &&
        jsondecode(task.container_definitions) == jsondecode(jsonencode(output.bootstrap_task_contracts[key])) &&
        length(task.volume) == 1 && one(task.volume).name == "material"
    ]))
    error_message = "Each bootstrap job is its own ARM64 task definition with fresh CA-only storage."
  }
}

run "bootstrap_containers_are_fixed" {
  command = plan
  assert {
    condition = alltrue([for key, database in { runtime-bootstrap = "runtime", product-bootstrap = "product" } : (
      [for container in output.bootstrap_task_contracts[key] : container.name] == ["init", "bootstrap"] &&
      jsonencode(merge(output.bootstrap_task_contracts[key][0], { command = null, logConfiguration = null })) == jsonencode(merge(output.release_task_contracts[database][0], { command = null, logConfiguration = null })) &&
      output.bootstrap_task_contracts[key][0].command == [
        "python", "-m", "dev.prepare_service_volumes", "--profile", database == "runtime" ? "runtime-release" : "search-release",
        "--material-dir", "/run/material", "--secret-id", var.bootstrap[database].ca_bundle.arn,
        "--version-id", var.bootstrap[database].ca_bundle.version_id, "--region", var.region
      ] &&
      output.bootstrap_task_contracts[key][1].image == var.release_tools.image &&
      output.bootstrap_task_contracts[key][1].user == (database == "runtime" ? "65532:65532" : "10001:10001") &&
      output.bootstrap_task_contracts[key][1].command == ["bootstrap"] &&
      output.bootstrap_task_contracts[key][1].readonlyRootFilesystem &&
      output.bootstrap_task_contracts[key][1].linuxParameters.capabilities.drop == ["ALL"] &&
      { for item in output.bootstrap_task_contracts[key][1].environment : item.name => item.value } == {
        RELEASE_ID                 = var.release_tools.release_id
        RELEASE_JOB_ID             = key
        RELEASE_DATABASE           = database
        RELEASE_NOT_AFTER          = var.release_tools.not_after
        RELEASE_JOB_BUDGET_SECONDS = "900"
        RELEASE_TOOLS_SHA256       = var.release_tools.tools_sha256
        RELEASE_SQL_SHA256         = var.bootstrap.sql_sha256
        RELEASE_EXPECT_DATABASE    = "postgres"
        RELEASE_EXPECT_PRINCIPAL   = var.bootstrap[database].administrator
        RELEASE_TARGET_DATABASE    = var.release_tools[database].database
        RELEASE_OWNER_ROLE         = var.release_tools[database].owner
        RELEASE_SERVICE_ROLE       = var.release_tools[database].service
        DB_HOST                    = var.bootstrap[database].host
        DB_PORT                    = "5432"
        DB_NAME                    = "postgres"
      } &&
      { for item in output.bootstrap_task_contracts[key][1].secrets : item.name => item.valueFrom } == {
        DB_USER                  = "${var.bootstrap[database].admin_secret.arn}:username::${var.bootstrap[database].admin_secret.version_id}"
        DB_PASSWORD              = "${var.bootstrap[database].admin_secret.arn}:password::${var.bootstrap[database].admin_secret.version_id}"
        RELEASE_OWNER_PASSWORD   = "${var.bootstrap[database].credentials.arn}:RELEASE_OWNER_PASSWORD::${var.bootstrap[database].credentials.version_id}"
        RELEASE_SERVICE_PASSWORD = "${var.bootstrap[database].credentials.arn}:RELEASE_SERVICE_PASSWORD::${var.bootstrap[database].credentials.version_id}"
      } &&
      output.bootstrap_task_contracts[key][1].logConfiguration.options == {
        awslogs-group = var.release_jobs[database].log_group, awslogs-region = var.region, awslogs-stream-prefix = key
      }
    )])
    error_message = "Bootstrap connects to postgres as the pinned administrator and creates exactly the release's database, owner and service login."
  }
}

run "bootstrap_authority_is_its_own" {
  command = plan
  assert {
    condition = (alltrue([for key, database in { runtime-bootstrap = "runtime", product-bootstrap = "product" } : (
      output.bootstrap_task_policies[key].Statement[0].Sid == "PinnedBootstrapCA" &&
      output.bootstrap_task_policies[key].Statement[0].Resource == [var.bootstrap[database].ca_bundle.arn] &&
      output.bootstrap_task_policies[key].Statement[0].Condition.StringEquals["secretsmanager:VersionId"] == var.bootstrap[database].ca_bundle.version_id &&
      length(output.bootstrap_task_policies[key].Statement) == 1 &&
      !strcontains(jsonencode(output.bootstrap_task_contracts[key]), var.release_jobs[database].material_bundle.arn) &&
      !strcontains(jsonencode(merge(output.bootstrap_task_policies, output.bootstrap_execution_policies)), var.release_jobs[database].material_bundle.arn) &&
      [for statement in output.bootstrap_execution_policies[key].Statement : statement.Sid] == ["RegistryToken", "PullImages", "TaskLogs", "PinnedAdministrator", "PinnedBootstrapCredentials"] &&
      output.bootstrap_execution_policies[key].Statement[2].Resource == ["arn:aws:logs:us-east-1:111122223333:log-group:${var.release_jobs[database].log_group}:log-stream:${key}/*"] &&
      output.bootstrap_execution_policies[key].Statement[3].Resource == [var.bootstrap[database].admin_secret.arn] &&
      output.bootstrap_execution_policies[key].Statement[3].Condition.StringEquals["secretsmanager:VersionId"] == var.bootstrap[database].admin_secret.version_id &&
      output.bootstrap_execution_policies[key].Statement[4].Resource == [var.bootstrap[database].credentials.arn] &&
      output.bootstrap_receipt_streams[key] == "arn:aws:logs:us-east-1:111122223333:log-group:${var.release_jobs[database].log_group}:log-stream:${key}/bootstrap/*" &&
      !strcontains(jsonencode(merge(output.execution_policies, output.release_execution_policies, output.tools_execution_policies, output.observer_execution_policies)), var.bootstrap[database].admin_secret.arn) &&
      !strcontains(jsonencode([output.task_policies, output.release_task_policies, output.observer_task_policy, output.execution_policies, output.release_execution_policies, output.tools_execution_policies, output.observer_execution_policies]), var.bootstrap[database].ca_bundle.arn)
      )]) && toset(keys(output.launch_scopes.bootstrap.task_definitions)) == toset(["runtime-bootstrap", "product-bootstrap"]) &&
    !anytrue([for key in keys(output.launch_scopes.jobs.task_definitions) : endswith(key, "-bootstrap")]))
    error_message = "Only each bootstrap job's own roles read its administrator secret, credentials and CA bundle; no other task's bundle is named, and bootstrap launches under its own scope."
  }
}

run "reject_shared_administrator_secret" {
  command = plan
  variables {
    bootstrap = {
      sql_sha256 = "5555555555555555555555555555555555555555555555555555555555555555"
      runtime = {
        host         = "runtime-db.abcdefghijkl.us-east-1.rds.amazonaws.com", administrator = "runtime_admin"
        admin_secret = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/runtime-owner-GGGGGG", version_id = "77777777-7777-4777-8777-777777777777" }
        credentials  = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/runtime-bootstrap-OOOOOO", version_id = "ffffffff-ffff-4fff-8fff-ffffffffffff" }
        ca_bundle    = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/runtime-bootstrap-ca-SSSSSS", version_id = "56565656-5656-4565-8565-565656565656" }
      }
      product = {
        host         = "product-db.abcdefghijkl.us-east-1.rds.amazonaws.com", administrator = "product_admin"
        admin_secret = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:rds!db-1b2c3d4e-5f6a-4b7c-8d9e-0f1a2b3c4d5e-PPPPPP", version_id = "12121212-1212-4121-8121-121212121212" }
        credentials  = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/product-bootstrap-QQQQQQ", version_id = "34343434-3434-4343-8343-343434343434" }
        ca_bundle    = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/product-bootstrap-ca-TTTTTT", version_id = "78787878-7878-4787-8787-787878787878" }
      }
    }
  }
  expect_failures = [var.bootstrap]
}

run "reject_ca_bundle_reusing_the_owner_material" {
  command = plan
  variables {
    bootstrap = merge(var.bootstrap, { runtime = merge(var.bootstrap.runtime, { ca_bundle = var.release_jobs.runtime.material_bundle }) })
  }
  expect_failures = [var.bootstrap]
}

run "reject_ca_bundle_shared_between_databases" {
  command = plan
  variables {
    bootstrap = merge(var.bootstrap, { product = merge(var.bootstrap.product, { ca_bundle = var.bootstrap.runtime.ca_bundle }) })
  }
  expect_failures = [var.bootstrap]
}

run "reject_credentials_shared_between_databases" {
  command = plan
  variables {
    bootstrap = {
      sql_sha256 = "5555555555555555555555555555555555555555555555555555555555555555"
      runtime = {
        host         = "runtime-db.abcdefghijkl.us-east-1.rds.amazonaws.com", administrator = "runtime_admin"
        admin_secret = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:rds!db-0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d-NNNNNN", version_id = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee" }
        credentials  = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/shared-bootstrap-OOOOOO", version_id = "ffffffff-ffff-4fff-8fff-ffffffffffff" }
        ca_bundle    = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/runtime-bootstrap-ca-SSSSSS", version_id = "56565656-5656-4565-8565-565656565656" }
      }
      product = {
        host         = "product-db.abcdefghijkl.us-east-1.rds.amazonaws.com", administrator = "product_admin"
        admin_secret = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:rds!db-1b2c3d4e-5f6a-4b7c-8d9e-0f1a2b3c4d5e-PPPPPP", version_id = "12121212-1212-4121-8121-121212121212" }
        credentials  = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/shared-bootstrap-OOOOOO", version_id = "ffffffff-ffff-4fff-8fff-ffffffffffff" }
        ca_bundle    = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/product-bootstrap-ca-TTTTTT", version_id = "78787878-7878-4787-8787-787878787878" }
      }
    }
  }
  expect_failures = [var.bootstrap]
}

run "reject_administrator_as_owner" {
  command = plan
  variables {
    bootstrap = {
      sql_sha256 = "5555555555555555555555555555555555555555555555555555555555555555"
      runtime = {
        host         = "runtime-db.abcdefghijkl.us-east-1.rds.amazonaws.com", administrator = "runtime_owner"
        admin_secret = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:rds!db-0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d-NNNNNN", version_id = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee" }
        credentials  = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/runtime-bootstrap-OOOOOO", version_id = "ffffffff-ffff-4fff-8fff-ffffffffffff" }
        ca_bundle    = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/runtime-bootstrap-ca-SSSSSS", version_id = "56565656-5656-4565-8565-565656565656" }
      }
      product = {
        host         = "product-db.abcdefghijkl.us-east-1.rds.amazonaws.com", administrator = "product_admin"
        admin_secret = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:rds!db-1b2c3d4e-5f6a-4b7c-8d9e-0f1a2b3c4d5e-PPPPPP", version_id = "12121212-1212-4121-8121-121212121212" }
        credentials  = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/product-bootstrap-QQQQQQ", version_id = "34343434-3434-4343-8343-343434343434" }
        ca_bundle    = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/product-bootstrap-ca-TTTTTT", version_id = "78787878-7878-4787-8787-787878787878" }
      }
    }
  }
  expect_failures = [var.bootstrap]
}

run "reject_moving_administrator_version" {
  command = plan
  variables {
    bootstrap = {
      sql_sha256 = "5555555555555555555555555555555555555555555555555555555555555555"
      runtime = {
        host         = "runtime-db.abcdefghijkl.us-east-1.rds.amazonaws.com", administrator = "runtime_admin"
        admin_secret = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:rds!db-0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d-NNNNNN", version_id = "AWSCURRENT" }
        credentials  = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/runtime-bootstrap-OOOOOO", version_id = "ffffffff-ffff-4fff-8fff-ffffffffffff" }
        ca_bundle    = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/runtime-bootstrap-ca-SSSSSS", version_id = "56565656-5656-4565-8565-565656565656" }
      }
      product = {
        host         = "product-db.abcdefghijkl.us-east-1.rds.amazonaws.com", administrator = "product_admin"
        admin_secret = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:rds!db-1b2c3d4e-5f6a-4b7c-8d9e-0f1a2b3c4d5e-PPPPPP", version_id = "12121212-1212-4121-8121-121212121212" }
        credentials  = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/product-bootstrap-QQQQQQ", version_id = "34343434-3434-4343-8343-343434343434" }
        ca_bundle    = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/product-bootstrap-ca-TTTTTT", version_id = "78787878-7878-4787-8787-787878787878" }
      }
    }
  }
  expect_failures = [var.bootstrap]
}

run "reject_unpinned_bootstrap_sql" {
  command = plan
  variables {
    bootstrap = {
      sql_sha256 = "latest"
      runtime = {
        host         = "runtime-db.abcdefghijkl.us-east-1.rds.amazonaws.com", administrator = "runtime_admin"
        admin_secret = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:rds!db-0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d-NNNNNN", version_id = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee" }
        credentials  = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/runtime-bootstrap-OOOOOO", version_id = "ffffffff-ffff-4fff-8fff-ffffffffffff" }
        ca_bundle    = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/runtime-bootstrap-ca-SSSSSS", version_id = "56565656-5656-4565-8565-565656565656" }
      }
      product = {
        host         = "product-db.abcdefghijkl.us-east-1.rds.amazonaws.com", administrator = "product_admin"
        admin_secret = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:rds!db-1b2c3d4e-5f6a-4b7c-8d9e-0f1a2b3c4d5e-PPPPPP", version_id = "12121212-1212-4121-8121-121212121212" }
        credentials  = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/product-bootstrap-QQQQQQ", version_id = "34343434-3434-4343-8343-343434343434" }
        ca_bundle    = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/product-bootstrap-ca-TTTTTT", version_id = "78787878-7878-4787-8787-787878787878" }
      }
    }
  }
  expect_failures = [var.bootstrap]
}
