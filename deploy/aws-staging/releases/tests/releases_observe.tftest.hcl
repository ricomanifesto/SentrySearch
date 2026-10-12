mock_provider "aws" {}

# Fake registered revisions: the current release is revision 2 of each family,
# the retained compatible rollback is revision 1.
override_resource {
  target          = module.release["r22222222"].aws_ecs_task_definition.service["runtime"]
  values          = { arn = "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-runtime:2" }
  override_during = plan
}
override_resource {
  target          = module.release["r22222222"].aws_ecs_task_definition.service["api"]
  values          = { arn = "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-api:2" }
  override_during = plan
}
override_resource {
  target          = module.release["r22222222"].aws_ecs_task_definition.service["worker"]
  values          = { arn = "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-worker:2" }
  override_during = plan
}
override_resource {
  target          = module.release["r22222222"].aws_ecs_task_definition.release["runtime"]
  values          = { arn = "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-runtime-release:2" }
  override_during = plan
}
override_resource {
  target          = module.release["r22222222"].aws_ecs_task_definition.release["product"]
  values          = { arn = "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-product-release:2" }
  override_during = plan
}
override_resource {
  target          = module.release["r11111111"].aws_ecs_task_definition.service["runtime"]
  values          = { arn = "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-runtime:1" }
  override_during = plan
}
override_resource {
  target          = module.release["r11111111"].aws_ecs_task_definition.service["api"]
  values          = { arn = "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-api:1" }
  override_during = plan
}
override_resource {
  target          = module.release["r11111111"].aws_ecs_task_definition.service["worker"]
  values          = { arn = "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-worker:1" }
  override_during = plan
}
override_resource {
  target          = module.release["r11111111"].aws_ecs_task_definition.release["runtime"]
  values          = { arn = "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-runtime-release:1" }
  override_during = plan
}
override_resource {
  target          = module.release["r11111111"].aws_ecs_task_definition.release["product"]
  values          = { arn = "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-product-release:1" }
  override_during = plan
}

# Guarded release-tools revisions and the current release's job role identities.
override_resource {
  target          = module.release["r22222222"].aws_ecs_task_definition.tools["runtime-grant"]
  values          = { arn = "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-runtime-grant:2" }
  override_during = plan
}
override_resource {
  target          = module.release["r22222222"].aws_ecs_task_definition.tools["runtime-proof"]
  values          = { arn = "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-runtime-proof:2" }
  override_during = plan
}
override_resource {
  target          = module.release["r22222222"].aws_ecs_task_definition.tools["runtime-reconcile"]
  values          = { arn = "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-runtime-reconcile:2" }
  override_during = plan
}
override_resource {
  target          = module.release["r22222222"].aws_ecs_task_definition.tools["product-grant"]
  values          = { arn = "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-product-grant:2" }
  override_during = plan
}
override_resource {
  target          = module.release["r22222222"].aws_ecs_task_definition.tools["product-proof"]
  values          = { arn = "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-product-proof:2" }
  override_during = plan
}
override_resource {
  target          = module.release["r22222222"].aws_ecs_task_definition.tools["product-reconcile"]
  values          = { arn = "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-product-reconcile:2" }
  override_during = plan
}
override_resource {
  target          = module.release["r11111111"].aws_ecs_task_definition.tools["runtime-grant"]
  values          = { arn = "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-runtime-grant:1" }
  override_during = plan
}
override_resource {
  target          = module.release["r11111111"].aws_ecs_task_definition.tools["runtime-proof"]
  values          = { arn = "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-runtime-proof:1" }
  override_during = plan
}
override_resource {
  target          = module.release["r11111111"].aws_ecs_task_definition.tools["runtime-reconcile"]
  values          = { arn = "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-runtime-reconcile:1" }
  override_during = plan
}
override_resource {
  target          = module.release["r11111111"].aws_ecs_task_definition.tools["product-grant"]
  values          = { arn = "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-product-grant:1" }
  override_during = plan
}
override_resource {
  target          = module.release["r11111111"].aws_ecs_task_definition.tools["product-proof"]
  values          = { arn = "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-product-proof:1" }
  override_during = plan
}
override_resource {
  target          = module.release["r11111111"].aws_ecs_task_definition.tools["product-reconcile"]
  values          = { arn = "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-product-reconcile:1" }
  override_during = plan
}
override_resource {
  target          = module.release["r22222222"].aws_iam_role.release_task["runtime"]
  values          = { arn = "arn:aws:iam::111122223333:role/sentry-staging-r22222222-runtime-release-task" }
  override_during = plan
}
override_resource {
  target          = module.release["r22222222"].aws_iam_role.tools_execution["runtime-grant"]
  values          = { arn = "arn:aws:iam::111122223333:role/sentry-staging-r22222222-runtime-grant-execution" }
  override_during = plan
}
override_resource {
  target          = module.release["r22222222"].aws_iam_role.tools_execution["runtime-proof"]
  values          = { arn = "arn:aws:iam::111122223333:role/sentry-staging-r22222222-runtime-proof-execution" }
  override_during = plan
}
override_resource {
  target          = module.release["r22222222"].aws_iam_role.tools_execution["runtime-reconcile"]
  values          = { arn = "arn:aws:iam::111122223333:role/sentry-staging-r22222222-runtime-recon-execution" }
  override_during = plan
}
override_resource {
  target          = module.release["r22222222"].aws_iam_role.release_task["product"]
  values          = { arn = "arn:aws:iam::111122223333:role/sentry-staging-r22222222-product-release-task" }
  override_during = plan
}
override_resource {
  target          = module.release["r22222222"].aws_iam_role.tools_execution["product-grant"]
  values          = { arn = "arn:aws:iam::111122223333:role/sentry-staging-r22222222-product-grant-execution" }
  override_during = plan
}
override_resource {
  target          = module.release["r22222222"].aws_iam_role.tools_execution["product-proof"]
  values          = { arn = "arn:aws:iam::111122223333:role/sentry-staging-r22222222-product-proof-execution" }
  override_during = plan
}
override_resource {
  target          = module.release["r22222222"].aws_iam_role.tools_execution["product-reconcile"]
  values          = { arn = "arn:aws:iam::111122223333:role/sentry-staging-r22222222-product-recon-execution" }
  override_during = plan
}

override_resource {
  target          = module.release["r22222222"].aws_ecs_task_definition.observer["runtime-observe"]
  values          = { arn = "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-runtime-observe:2" }
  override_during = plan
}
override_resource {
  target          = module.release["r22222222"].aws_ecs_task_definition.observer["api-observe"]
  values          = { arn = "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-api-observe:2" }
  override_during = plan
}
override_resource {
  target          = module.release["r11111111"].aws_ecs_task_definition.observer["runtime-observe"]
  values          = { arn = "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-runtime-observe:1" }
  override_during = plan
}
override_resource {
  target          = module.release["r11111111"].aws_ecs_task_definition.observer["api-observe"]
  values          = { arn = "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-api-observe:1" }
  override_during = plan
}
override_resource {
  target          = module.release["r22222222"].aws_ecs_task_definition.bootstrap["runtime-bootstrap"]
  values          = { arn = "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-runtime-bootstrap:2" }
  override_during = plan
}
override_resource {
  target          = module.release["r22222222"].aws_ecs_task_definition.bootstrap["product-bootstrap"]
  values          = { arn = "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-product-bootstrap:2" }
  override_during = plan
}

variables {
  account_id            = "111122223333"
  region                = "us-east-1"
  name_prefix           = "sentry-staging"
  private_dns_namespace = "sentry-staging.internal.example"
  releases = {
    r22222222 = {
      release_id = "22222222-2222-4222-8222-222222222222"
      slot       = "current"
      images = {
        runtime = "111122223333.dkr.ecr.us-east-1.amazonaws.com/sentry-staging/runtime@sha256:2222222222222222222222222222222222222222222222222222222222222222"
        search  = "111122223333.dkr.ecr.us-east-1.amazonaws.com/sentry-staging/search@sha256:3333333333333333333333333333333333333333333333333333333333333333"
      }
      environment_bundles = {
        runtime = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/runtime-env-AAAAAA", version_id = "a0000000-0000-4000-8000-000000000002" }
        api     = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/api-env-BBBBBB", version_id = "b0000000-0000-4000-8000-000000000002" }
        worker  = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/worker-env-CCCCCC", version_id = "c0000000-0000-4000-8000-000000000002" }
      }
      material_bundles = {
        runtime = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/runtime-material-DDDDDD", version_id = "d0000000-0000-4000-8000-000000000002" }
        api     = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/api-material-EEEEEE", version_id = "e0000000-0000-4000-8000-000000000002" }
        worker  = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/worker-material-FFFFFF", version_id = "f0000000-0000-4000-8000-000000000002" }
      }
      release_jobs = {
        runtime = {
          environment_bundle = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/runtime-owner-GGGGGG", version_id = "a1000000-0000-4000-8000-000000000002" }
          material_bundle    = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/runtime-owner-ca-HHHHHH", version_id = "b1000000-0000-4000-8000-000000000002" }
        }
        product = {
          environment_bundle = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/product-owner-IIIIII", version_id = "c1000000-0000-4000-8000-000000000002" }
          material_bundle    = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/product-owner-ca-JJJJJJ", version_id = "d1000000-0000-4000-8000-000000000002" }
        }
        runtime_grants = { source_commit = "bb6e523da3c6f4bb186a548f3be696a40798fae9", sql_sha256 = "02a2b55161506254b1977f26351ec3bbba4de7c94a54b3b697153d622ae02aa0" }
      }
      release_tools = {
        image          = "111122223333.dkr.ecr.us-east-1.amazonaws.com/sentry-staging/release-tools@sha256:2222222222222222222222222222222222222222222222222222222222222222"
        not_after      = "2026-10-07T18:00:00Z"
        budget_seconds = 900
        tools_sha256   = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee2"
        sql_sha256 = {
          runtime_grant = "02a2b55161506254b1977f26351ec3bbba4de7c94a54b3b697153d622ae02aa0"
          product_grant = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2"
          runtime_proof = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb2"
          product_proof = "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc2"
          reconcile     = "ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd2"
        }
        runtime = {
          database     = "sentryruntime", owner = "runtime_owner", service = "runtime_app"
          proof_bundle = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/runtime-proof-KKKKKK", version_id = "e1000000-0000-4000-8000-000000000002" }
        }
        product = {
          database     = "sentrysearch", owner = "search_owner", service = "search_app"
          proof_bundle = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/product-proof-LLLLLL", version_id = "f1000000-0000-4000-8000-000000000002" }
        }
      }
    }
    r11111111 = {
      release_id = "11111111-1111-4111-8111-111111111111"
      slot       = "rollback"
      images = {
        runtime = "111122223333.dkr.ecr.us-east-1.amazonaws.com/sentry-staging/runtime@sha256:0000000000000000000000000000000000000000000000000000000000000000"
        search  = "111122223333.dkr.ecr.us-east-1.amazonaws.com/sentry-staging/search@sha256:1111111111111111111111111111111111111111111111111111111111111111"
      }
      environment_bundles = {
        runtime = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/runtime-env-AAAAAA", version_id = "a0000000-0000-4000-8000-000000000001" }
        api     = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/api-env-BBBBBB", version_id = "b0000000-0000-4000-8000-000000000001" }
        worker  = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/worker-env-CCCCCC", version_id = "c0000000-0000-4000-8000-000000000001" }
      }
      material_bundles = {
        runtime = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/runtime-material-DDDDDD", version_id = "d0000000-0000-4000-8000-000000000001" }
        api     = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/api-material-EEEEEE", version_id = "e0000000-0000-4000-8000-000000000001" }
        worker  = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/worker-material-FFFFFF", version_id = "f0000000-0000-4000-8000-000000000001" }
      }
      release_jobs = {
        runtime = {
          environment_bundle = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/runtime-owner-GGGGGG", version_id = "a1000000-0000-4000-8000-000000000001" }
          material_bundle    = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/runtime-owner-ca-HHHHHH", version_id = "b1000000-0000-4000-8000-000000000001" }
        }
        product = {
          environment_bundle = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/product-owner-IIIIII", version_id = "c1000000-0000-4000-8000-000000000001" }
          material_bundle    = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/product-owner-ca-JJJJJJ", version_id = "d1000000-0000-4000-8000-000000000001" }
        }
        runtime_grants = { source_commit = "bb6e523da3c6f4bb186a548f3be696a40798fae9", sql_sha256 = "02a2b55161506254b1977f26351ec3bbba4de7c94a54b3b697153d622ae02aa0" }
      }
      release_tools = {
        image          = "111122223333.dkr.ecr.us-east-1.amazonaws.com/sentry-staging/release-tools@sha256:1111111111111111111111111111111111111111111111111111111111111111"
        not_after      = "2026-10-01T18:00:00Z"
        budget_seconds = 900
        tools_sha256   = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee1"
        sql_sha256 = {
          runtime_grant = "02a2b55161506254b1977f26351ec3bbba4de7c94a54b3b697153d622ae02aa0"
          product_grant = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"
          runtime_proof = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb1"
          product_proof = "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc1"
          reconcile     = "ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd1"
        }
        runtime = {
          database     = "sentryruntime", owner = "runtime_owner", service = "runtime_app"
          proof_bundle = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/runtime-proof-KKKKKK", version_id = "e1000000-0000-4000-8000-000000000001" }
        }
        product = {
          database     = "sentrysearch", owner = "search_owner", service = "search_app"
          proof_bundle = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/product-proof-LLLLLL", version_id = "f1000000-0000-4000-8000-000000000001" }
        }
      }
    }
  }
}


run "observers_launch_only_under_the_current_releases_observe_policy" {
  command = plan
  variables {
    releases = {
      r22222222 = merge(var.releases.r22222222, { observers = { budget_seconds = 300, runtime_bundle = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/runtime-observer-MMMMMM", version_id = "a2000000-0000-4000-8000-000000000002" } } })
      r11111111 = merge(var.releases.r11111111, { observers = { budget_seconds = 300, runtime_bundle = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/runtime-observer-MMMMMM", version_id = "a2000000-0000-4000-8000-000000000001" } } })
    }
    observer_security_group_ids = { runtime = "sg-0aaaaaaaaaaaaaaa1", api = "sg-0aaaaaaaaaaaaaaa2" }
  }
  assert {
    condition = (toset(keys(aws_iam_policy.release_launcher)) == toset(["jobs", "services", "receipts", "tasks", "observe"]) &&
      aws_iam_policy.release_launcher["observe"].name == "sentry-staging-release-launcher-observe" &&
    jsondecode(aws_iam_policy.release_launcher["observe"].policy) == jsondecode(jsonencode(output.release_launcher_policies.observe)))
    error_message = "With observers, the attended set gains its observe policy as reviewed."
  }
  assert {
    condition = jsonencode(output.release_launcher_policies.observe.Statement) == jsonencode([
      {
        Sid       = "RunCurrentReleaseObservers", Effect = "Allow", Action = ["ecs:RunTask"]
        Resource  = [for name in ["api-observe", "runtime-observe"] : "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-${name}:2"]
        Condition = { ArnEquals = { "ecs:cluster" = "arn:aws:ecs:us-east-1:111122223333:cluster/sentry-staging" } }
      },
      {
        Sid       = "PassCurrentObserverRoles", Effect = "Allow", Action = ["iam:PassRole"]
        Resource  = [for kind in ["api-observe-execution", "runtime-observe-execution", "runtime-observe-task"] : "arn:aws:iam::111122223333:role/sentry-staging-r22222222-${kind}"]
        Condition = { StringEquals = { "iam:PassedToService" = "ecs-tasks.amazonaws.com" } }
      },
      {
        Sid      = "ReadCurrentObserverReceipts", Effect = "Allow", Action = ["logs:GetLogEvents"]
        Resource = [for name in ["api-observe", "runtime-observe"] : "arn:aws:logs:us-east-1:111122223333:log-group:/sentry-staging/observe:log-stream:${name}/observer/*"]
      },
      { Sid = "DenyExecuteCommandOnObservers", Effect = "Deny", Action = ["ecs:RunTask"], Resource = ["*"], Condition = { StringEqualsIgnoreCase = { "ecs:enable-execute-command" = "true" } } },
    ])
    error_message = "Only the current release's observer revisions run, with only their own roles, reading only their observer streams."
  }
  assert {
    condition = (!strcontains(jsonencode(output.release_launcher_policies), "observe:1") &&
      !strcontains(jsonencode(output.release_launcher_policies), "r11111111-runtime-observe") &&
      !anytrue([for resource in [for statement in output.release_launcher_policies.jobs.Statement : statement.Resource if statement.Sid == "RunCurrentReleaseJobs"][0] : strcontains(resource, "observe")]) &&
    !strcontains(jsonencode(output.release_launcher_policies.receipts), "observe"))
    error_message = "No observe revision outside the current release, and no observer under the job or receipt policies."
  }
  assert {
    condition = ({ for item in module.release["r22222222"].observer_task_contracts["runtime-observe"][1].environment : item.name => item.value }["RELEASE_TARGET_HOST"] == "runtime.sentry-staging.internal.example" &&
      { for item in module.release["r22222222"].observer_task_contracts["api-observe"][0].environment : item.name => item.value }["RELEASE_TARGET_HOST"] == "api.sentry-staging.internal.example" &&
      module.release["r22222222"].observer_task_contracts["api-observe"][0].logConfiguration.options["awslogs-group"] == "/sentry-staging/observe" &&
      output.observer_networks == { runtime-observe = ["sg-0aaaaaaaaaaaaaaa1"], api-observe = ["sg-0aaaaaaaaaaaaaaa2"] } &&
    output.release_launcher_bootstrap_policy == null && length(aws_iam_policy.release_launcher_bootstrap) == 0)
    error_message = "Observers target this environment's private names and log group; observer networks are the foundation's proof groups."
  }
}

run "first_deployment_bootstrap_has_its_own_unattached_launcher" {
  command = plan
  variables {
    releases = { r22222222 = merge(var.releases.r22222222, { observers = { budget_seconds = 300, runtime_bundle = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/runtime-observer-MMMMMM", version_id = "a2000000-0000-4000-8000-000000000002" } }, bootstrap = {
      sql_sha256 = "5555555555555555555555555555555555555555555555555555555555555555"
      runtime = {
        host         = "sentry-staging-runtime-db.abcdefghijkl.us-east-1.rds.amazonaws.com", administrator = "runtime_admin"
        admin_secret = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:rds!db-11111111-aaaa-4aaa-8aaa-111111111111-AbCdEf", version_id = "b2000000-0000-4000-8000-000000000002" }
        credentials  = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/runtime-bootstrap-NNNNNN", version_id = "c2000000-0000-4000-8000-000000000002" }
        ca_bundle    = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/runtime-bootstrap-ca-SSSSSS", version_id = "f2000000-0000-4000-8000-000000000002" }
      }
      product = {
        host         = "sentry-staging-product-db.abcdefghijkl.us-east-1.rds.amazonaws.com", administrator = "product_admin"
        admin_secret = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:rds!db-22222222-bbbb-4bbb-8bbb-222222222222-GhIjKl", version_id = "d2000000-0000-4000-8000-000000000002" }
        credentials  = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/product-bootstrap-OOOOOO", version_id = "e2000000-0000-4000-8000-000000000002" }
        ca_bundle    = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/product-bootstrap-ca-TTTTTT", version_id = "f3000000-0000-4000-8000-000000000002" }
      }
    } }) }
  }
  assert {
    condition = (length(aws_iam_policy.release_launcher_bootstrap) == 1 &&
      aws_iam_policy.release_launcher_bootstrap[0].name == "sentry-staging-release-launcher-bootstrap" &&
      jsondecode(aws_iam_policy.release_launcher_bootstrap[0].policy) == jsondecode(jsonencode(output.release_launcher_bootstrap_policy)) &&
      !contains(keys(aws_iam_policy.release_launcher), "bootstrap") &&
      jsonencode(output.release_launcher_bootstrap_policy.Statement) == jsonencode([
        {
          Sid       = "RunFirstDeploymentBootstrap", Effect = "Allow", Action = ["ecs:RunTask"]
          Resource  = [for name in ["product-bootstrap", "runtime-bootstrap"] : "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-${name}:2"]
          Condition = { ArnEquals = { "ecs:cluster" = "arn:aws:ecs:us-east-1:111122223333:cluster/sentry-staging" } }
        },
        {
          Sid       = "PassBootstrapRoles", Effect = "Allow", Action = ["iam:PassRole"]
          Resource  = [for kind in ["product-boot-execution", "product-boot-task", "runtime-boot-execution", "runtime-boot-task"] : "arn:aws:iam::111122223333:role/sentry-staging-r22222222-${kind}"]
          Condition = { StringEquals = { "iam:PassedToService" = "ecs-tasks.amazonaws.com" } }
        },
        {
          Sid      = "ReadBootstrapReceipts", Effect = "Allow", Action = ["logs:GetLogEvents"]
          Resource = [for name in ["product", "runtime"] : "arn:aws:logs:us-east-1:111122223333:log-group:/sentry-staging/${name}-release:log-stream:${name}-bootstrap/bootstrap/*"]
        },
        { Sid = "DenyExecuteCommandOnBootstrap", Effect = "Deny", Action = ["ecs:RunTask"], Resource = ["*"], Condition = { StringEqualsIgnoreCase = { "ecs:enable-execute-command" = "true" } } },
      ]) &&
    !strcontains(jsonencode(output.release_launcher_policies), "bootstrap"))
    error_message = "Bootstrap launches only through its own unattached policy; the attended set never names a bootstrap revision, role or stream."
  }
}

run "reject_bootstrap_ca_reusing_the_owner_material" {
  command = plan
  variables {
    releases = { r22222222 = merge(var.releases.r22222222, { bootstrap = {
      sql_sha256 = "5555555555555555555555555555555555555555555555555555555555555555"
      runtime = {
        host         = "sentry-staging-runtime-db.abcdefghijkl.us-east-1.rds.amazonaws.com", administrator = "runtime_admin"
        admin_secret = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:rds!db-11111111-aaaa-4aaa-8aaa-111111111111-AbCdEf", version_id = "b2000000-0000-4000-8000-000000000002" }
        credentials  = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/runtime-bootstrap-NNNNNN", version_id = "c2000000-0000-4000-8000-000000000002" }
        ca_bundle    = var.releases.r22222222.release_jobs.runtime.material_bundle
      }
      product = {
        host         = "sentry-staging-product-db.abcdefghijkl.us-east-1.rds.amazonaws.com", administrator = "product_admin"
        admin_secret = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:rds!db-22222222-bbbb-4bbb-8bbb-222222222222-GhIjKl", version_id = "d2000000-0000-4000-8000-000000000002" }
        credentials  = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/product-bootstrap-OOOOOO", version_id = "e2000000-0000-4000-8000-000000000002" }
        ca_bundle    = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/product-bootstrap-ca-TTTTTT", version_id = "f3000000-0000-4000-8000-000000000002" }
      }
    } }) }
  }
  expect_failures = [var.releases]
}

run "reject_bootstrap_with_a_non_rds_administrator_secret" {
  command = plan
  variables {
    releases = { r22222222 = merge(var.releases.r22222222, { bootstrap = merge({
      sql_sha256 = "5555555555555555555555555555555555555555555555555555555555555555"
      runtime = {
        host         = "sentry-staging-runtime-db.abcdefghijkl.us-east-1.rds.amazonaws.com", administrator = "runtime_admin"
        admin_secret = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:rds!db-11111111-aaaa-4aaa-8aaa-111111111111-AbCdEf", version_id = "b2000000-0000-4000-8000-000000000002" }
        credentials  = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/runtime-bootstrap-NNNNNN", version_id = "c2000000-0000-4000-8000-000000000002" }
        ca_bundle    = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/runtime-bootstrap-ca-SSSSSS", version_id = "f2000000-0000-4000-8000-000000000002" }
      }
      product = {
        host         = "sentry-staging-product-db.abcdefghijkl.us-east-1.rds.amazonaws.com", administrator = "product_admin"
        admin_secret = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:rds!db-22222222-bbbb-4bbb-8bbb-222222222222-GhIjKl", version_id = "d2000000-0000-4000-8000-000000000002" }
        credentials  = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/product-bootstrap-OOOOOO", version_id = "e2000000-0000-4000-8000-000000000002" }
        ca_bundle    = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/product-bootstrap-ca-TTTTTT", version_id = "f3000000-0000-4000-8000-000000000002" }
      }
      }, { runtime = {
        host         = "sentry-staging-runtime-db.abcdefghijkl.us-east-1.rds.amazonaws.com", administrator = "runtime_admin"
        admin_secret = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/runtime-admin-ZZZZZZ", version_id = "b2000000-0000-4000-8000-000000000002" }
        credentials  = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/runtime-bootstrap-NNNNNN", version_id = "c2000000-0000-4000-8000-000000000002" }
        ca_bundle    = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/runtime-bootstrap-ca-SSSSSS", version_id = "f2000000-0000-4000-8000-000000000002" }
    } }) }) }
  }
  expect_failures = [var.releases]
}

run "reject_observer_bundle_aliasing_a_proof_bundle" {
  command = plan
  variables {
    releases = { r22222222 = merge(var.releases.r22222222, { observers = { budget_seconds = 300, runtime_bundle = var.releases.r22222222.release_tools.runtime.proof_bundle } }) }
  }
  expect_failures = [var.releases]
}

run "reject_observer_bundle_changing_purpose_between_releases" {
  command = plan
  variables {
    releases = {
      r22222222 = merge(var.releases.r22222222, { observers = { budget_seconds = 300, runtime_bundle = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/runtime-observer-MMMMMM", version_id = "a2000000-0000-4000-8000-000000000002" } } })
      r11111111 = merge(var.releases.r11111111, { observers = { budget_seconds = 300, runtime_bundle = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/runtime-material-DDDDDD", version_id = "a2000000-0000-4000-8000-000000000001" } } })
    }
  }
  expect_failures = [var.releases]
}

run "reject_observer_security_groups_that_coincide" {
  command = plan
  variables {
    observer_security_group_ids = { runtime = "sg-0aaaaaaaaaaaaaaa1", api = "sg-0aaaaaaaaaaaaaaa1" }
  }
  expect_failures = [var.observer_security_group_ids]
}
