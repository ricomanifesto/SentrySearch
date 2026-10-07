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

run "retained_current_and_rollback_releases" {
  command = plan
  assert {
    condition = (toset(keys(module.release)) == toset(["r22222222", "r11111111"]) &&
      output.releases.r22222222.release_id == "22222222-2222-4222-8222-222222222222" && output.releases.r22222222.slot == "current" &&
      output.releases.r11111111.release_id == "11111111-1111-4111-8111-111111111111" && output.releases.r11111111.slot == "rollback" &&
      alltrue([for key, release in output.releases :
        length(release.iam_role_names) == 16 && alltrue([for kind, name in release.iam_role_names : name == "sentry-staging-${key}-${kind}"]) &&
        release.task_definition_arns == { for family in [
          "runtime", "api", "worker", "runtime-release", "product-release", "runtime-grant", "product-grant",
          "runtime-proof", "product-proof", "runtime-reconcile", "product-reconcile",
        ] : family => "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-${family}:${key == "r22222222" ? 2 : 1}" }
      ]) &&
      output.current_service_task_definitions == {
        runtime = "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-runtime:2"
        api     = "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-api:2"
        worker  = "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-worker:2"
    })
    error_message = "Current and one compatible rollback stay as keyed releases with their own roles and exact revisions; only current seeds new services."
  }
  assert {
    condition = alltrue([for key, release in module.release :
      { for item in release.task_contracts.runtime[1].environment : item.name => item.value }["SENTRYRUNTIME_PROBE_SERVER_NAME"] == "runtime.sentry-staging.internal.example" &&
      { for item in release.task_contracts.worker[1].environment : item.name => item.value }["SENTRYRUNTIME_URL"] == "https://runtime.sentry-staging.internal.example:8443" &&
      { for item in release.task_contracts.api[1].environment : item.name => item.value }["SENTRYSEARCH_EXECUTION_MODE"] == "paused" &&
      { for item in release.task_contracts.api[1].environment : item.name => item.value }["AWS_S3_BUCKET"] == "sentry-staging-111122223333-reports" &&
      release.task_policies.worker.Statement[1].Resource == ["arn:aws:s3:::sentry-staging-111122223333-reports/reports/*"] &&
      { for name, containers in release.task_contracts : name => containers[1].logConfiguration.options["awslogs-group"] } == {
        runtime = "/sentry-staging/runtime", api = "/sentry-staging/api", worker = "/sentry-staging/worker"
      } &&
      { for name, containers in release.release_task_contracts : name => containers[1].logConfiguration.options["awslogs-group"] } == {
        runtime = "/sentry-staging/runtime-release", product = "/sentry-staging/product-release"
      } &&
      release.release_grant_contract.source_commit == var.releases[key].release_jobs.runtime_grants.source_commit &&
      { for item in release.task_contracts.worker[1].environment : item.name => item.value }["SENTRYSEARCH_RELEASE_ID"] == var.releases[key].release_id &&
      release.task_contracts.worker[1].logConfiguration.options.mode == "non-blocking" &&
      release.task_contracts.worker[1].logConfiguration.options["max-buffer-size"] == "4m" &&
      alltrue([for name in ["runtime", "api", "worker"] :
        alltrue([for secret in release.task_contracts[name][1].secrets : endswith(secret.valueFrom, "::${var.releases[key].environment_bundles[name].version_id}")])
      ])
    ])
    error_message = "Each release binds the foundation's names, private Runtime SAN, report bucket, paused admission, its own exact secret versions and the release identity its worker receipts echo."
  }
}

run "launcher_policies_name_exact_releases_roles_and_services" {
  command = plan
  assert {
    condition = ({ for name, policy in aws_iam_policy.release_launcher : name => policy.name } == {
      jobs     = "sentry-staging-release-launcher-jobs", services = "sentry-staging-release-launcher-services", tasks = "sentry-staging-release-launcher-tasks"
      receipts = "sentry-staging-release-launcher-receipts"
      } && alltrue([for name, policy in aws_iam_policy.release_launcher :
        jsondecode(policy.policy) == jsondecode(jsonencode(output.release_launcher_policies[name]))
    ]))
    error_message = "Each launcher policy resource must be its reviewed document."
  }
  assert {
    condition = jsonencode(output.release_launcher_policies.jobs.Statement) == jsonencode([
      {
        Sid = "RunCurrentReleaseJobs", Effect = "Allow", Action = ["ecs:RunTask"]
        Resource = sort([for family in ["runtime-release", "product-release", "runtime-grant", "product-grant", "runtime-proof", "product-proof", "runtime-reconcile", "product-reconcile"] :
        "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-${family}:2"])
        Condition = { ArnEquals = { "ecs:cluster" = "arn:aws:ecs:us-east-1:111122223333:cluster/sentry-staging" } }
      },
      {
        Sid       = "TagReleaseTasksOnLaunch", Effect = "Allow", Action = ["ecs:TagResource"], Resource = ["arn:aws:ecs:us-east-1:111122223333:task/sentry-staging/*"]
        Condition = { StringEquals = { "ecs:CreateAction" = "RunTask" } }
      },
      {
        Sid       = "StopReleaseJobTasks", Effect = "Allow", Action = ["ecs:StopTask"], Resource = ["arn:aws:ecs:us-east-1:111122223333:task/sentry-staging/*"]
        Condition = { ArnEquals = { "ecs:cluster" = "arn:aws:ecs:us-east-1:111122223333:cluster/sentry-staging" }, Null = { "aws:ResourceTag/sentry:job-id" = "false" } }
      },
      {
        Sid = "PassCurrentJobRoles", Effect = "Allow", Action = ["iam:PassRole"]
        Resource = sort([for kind in [
          "runtime-release-task", "runtime-release-execution", "product-release-task", "product-release-execution",
          "runtime-grant-execution", "product-grant-execution", "runtime-proof-execution", "product-proof-execution",
          "runtime-recon-execution", "product-recon-execution",
        ] : "arn:aws:iam::111122223333:role/sentry-staging-r22222222-${kind}"])
        Condition = { StringEquals = { "iam:PassedToService" = "ecs-tasks.amazonaws.com" } }
      },
      { Sid = "DenyExecuteCommandOnLaunch", Effect = "Deny", Action = ["ecs:RunTask"], Resource = ["*"], Condition = { StringEqualsIgnoreCase = { "ecs:enable-execute-command" = "true" } } },
    ])
    error_message = "Only the current release's jobs run, with only their own roles; rollback never re-runs migrations or grants. Stops are limited to tagged job tasks."
  }
  assert {
    condition = jsonencode(output.release_launcher_policies.services.Statement) == jsonencode(concat(
      [for name in ["api", "runtime", "worker"] : {
        Sid      = "Update${title(name)}Service", Effect = "Allow", Action = ["ecs:UpdateService"]
        Resource = ["arn:aws:ecs:us-east-1:111122223333:service/sentry-staging/sentry-staging-${name}"]
        Condition = {
          ArnEquals = { "ecs:cluster" = "arn:aws:ecs:us-east-1:111122223333:cluster/sentry-staging" }
          ArnEqualsIfExists = { "ecs:task-definition" = [
            "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-${name}:1",
            "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-${name}:2",
          ] }
        }
      }],
      [
        {
          Sid       = "DescribePinnedServices", Effect = "Allow", Action = ["ecs:DescribeServices"]
          Resource  = [for name in ["api", "runtime", "worker"] : "arn:aws:ecs:us-east-1:111122223333:service/sentry-staging/sentry-staging-${name}"]
          Condition = { ArnEquals = { "ecs:cluster" = "arn:aws:ecs:us-east-1:111122223333:cluster/sentry-staging" } }
        },
        {
          Sid = "PassRetainedServiceRoles", Effect = "Allow", Action = ["iam:PassRole"]
          Resource = sort(flatten([for key in ["r11111111", "r22222222"] : [for kind in ["runtime-task", "runtime-execution", "api-task", "api-execution", "worker-task", "worker-execution"] :
          "arn:aws:iam::111122223333:role/sentry-staging-${key}-${kind}"]]))
          Condition = { StringEquals = { "iam:PassedToService" = "ecs-tasks.amazonaws.com" } }
        },
        { Sid = "DenyExecuteCommandOnServices", Effect = "Deny", Action = ["ecs:UpdateService"], Resource = ["*"], Condition = { StringEqualsIgnoreCase = { "ecs:enable-execute-command" = "true" } } },
      ],
    ))
    error_message = "Each service can point only at its own retained revisions (current or compatible rollback); scale-to-zero requests carry no definition."
  }
  assert {
    condition = jsonencode(output.release_launcher_policies.receipts.Statement) == jsonencode([
      {
        Sid = "ReadCurrentJobReceipts", Effect = "Allow", Action = ["logs:GetLogEvents"]
        Resource = sort(concat(
          [for name in ["runtime", "product"] : "arn:aws:logs:us-east-1:111122223333:log-group:/sentry-staging/${name}-release:log-stream:${name}-release/migration/*"],
          flatten([for name in ["runtime", "product"] : [for kind in ["grant", "proof", "reconcile"] :
          "arn:aws:logs:us-east-1:111122223333:log-group:/sentry-staging/${name}-release:log-stream:${name}-${kind}/${kind}/*"]]),
        ))
      },
      {
        Sid      = "ReadWorkerReadinessReceipts", Effect = "Allow", Action = ["logs:GetLogEvents"]
        Resource = ["arn:aws:logs:us-east-1:111122223333:log-group:/sentry-staging/worker:log-stream:worker/app/*"]
      },
    ])
    error_message = "Receipts are read only from job and worker app-container streams, never init, API or Runtime logs, and never written."
  }
  assert {
    condition = jsonencode(output.release_launcher_policies.tasks.Statement) == jsonencode([
      # ListTasks has no task-level resource for Fargate; the cluster condition scopes it.
      {
        Sid       = "ListClusterTasks", Effect = "Allow", Action = ["ecs:ListTasks"], Resource = ["*"]
        Condition = { ArnEquals = { "ecs:cluster" = "arn:aws:ecs:us-east-1:111122223333:cluster/sentry-staging" } }
      },
      {
        Sid       = "DescribeClusterTasks", Effect = "Allow", Action = ["ecs:DescribeTasks"], Resource = ["arn:aws:ecs:us-east-1:111122223333:task/sentry-staging/*"]
        Condition = { ArnEquals = { "ecs:cluster" = "arn:aws:ecs:us-east-1:111122223333:cluster/sentry-staging" } }
      },
      { Sid = "DenyExecuteCommand", Effect = "Deny", Action = ["ecs:ExecuteCommand"], Resource = ["*"] },
    ])
    error_message = "Task observation is cluster-scoped and ECS Exec is denied even if another policy is attached to the launcher principal."
  }
  assert {
    condition = (toset(flatten([for document in values(output.release_launcher_policies) : [for statement in document.Statement : statement.Action if statement.Effect == "Allow"]])) == toset([
      "ecs:RunTask", "ecs:TagResource", "ecs:StopTask", "ecs:UpdateService", "ecs:DescribeServices", "ecs:ListTasks", "ecs:DescribeTasks", "iam:PassRole",
      "logs:GetLogEvents",
      ]) && alltrue(flatten([for document in values(output.release_launcher_policies) : [for statement in document.Statement : [for resource in statement.Resource :
        (startswith(resource, "arn:aws:ecs:us-east-1:111122223333:") || startswith(resource, "arn:aws:iam::111122223333:role/sentry-staging-r") ||
        can(regex("^arn:aws:logs:us-east-1:111122223333:log-group:/sentry-staging/((runtime|product)-release:log-stream:[a-z-]+/[a-z]+|worker:log-stream:worker/app)/\\*$", resource))) &&
        (!strcontains(resource, "*") || resource == "arn:aws:ecs:us-east-1:111122223333:task/sentry-staging/*" || startswith(resource, "arn:aws:logs:"))
    ] if statement.Effect == "Allow" && statement.Sid != "ListClusterTasks"]])))
    error_message = "Allowed resources stay in this account, region and cluster; task IDs and job and worker receipt streams are the only wildcards. No definition registration, secret read, image push, log write or Exec."
  }
  assert {
    # IAM managed policies hold 6,144 non-whitespace characters. Bound each
    # document for a 28-character prefix, a 14-character region and six-digit
    # revisions.
    condition = alltrue([for document in values(output.release_launcher_policies) :
      length(jsonencode(document)) + 14 * (length(split("sentry-staging", jsonencode(document))) - 1) +
      5 * (length(split("us-east-1", jsonencode(document))) - 1) + 5 * (length(split(":task-definition/", jsonencode(document))) - 1) <= 6144
    ])
    error_message = "Every launcher policy must fit IAM's managed-policy size limit at the longest allowed names."
  }
}

run "guarded_jobs_bind_ca_task_role_own_execution_role_and_fixed_deadline" {
  command = plan
  assert {
    condition = (length(module.release["r22222222"].tools_task_roles) == 6 &&
      alltrue([for key, roles in module.release["r22222222"].tools_task_roles :
        roles.task_role_arn == "arn:aws:iam::111122223333:role/sentry-staging-r22222222-${split("-", key)[0]}-release-task" &&
        roles.execution_role_arn == "arn:aws:iam::111122223333:role/sentry-staging-r22222222-${split("-", key)[0]}-${ { grant = "grant", proof = "proof", reconcile = "recon" }[split("-", key)[1]]}-execution" &&
        { for item in module.release["r22222222"].tools_task_contracts[key][1].environment : item.name => item.value }["RELEASE_NOT_AFTER"] == "2026-10-07T18:00:00Z" &&
        { for item in module.release["r22222222"].tools_task_contracts[key][1].environment : item.name => item.value }["RELEASE_ID"] == "22222222-2222-4222-8222-222222222222"
    ]))
    error_message = "Each current job uses the CA-only release task role, its own execution role, and its release's fixed ID and deadline."
  }
  assert {
    condition = (output.releases.r22222222.tools_bindings.not_after == "2026-10-07T18:00:00Z" &&
      output.releases.r11111111.tools_bindings.not_after == "2026-10-01T18:00:00Z" &&
      output.releases.r22222222.tools_bindings.expectations["runtime-grant"].sql_digest == "02a2b55161506254b1977f26351ec3bbba4de7c94a54b3b697153d622ae02aa0" &&
      alltrue([for key, release in module.release : alltrue([for name, containers in release.tools_task_contracts :
        containers[1].image == var.releases[key].release_tools.image &&
        containers[1].logConfiguration.options["awslogs-group"] == "/sentry-staging/${split("-", name)[0]}-release"
    ])]))
    error_message = "A retained release keeps its own tools image, deadline and digests; job logs stay in the release log groups."
  }
}

run "reject_tools_image_from_another_repository" {
  command = plan
  variables {
    releases = merge(var.releases, { r22222222 = merge(var.releases.r22222222, { release_tools = merge(var.releases.r22222222.release_tools, {
      image = "111122223333.dkr.ecr.us-east-1.amazonaws.com/sentry-staging/search@sha256:2222222222222222222222222222222222222222222222222222222222222222"
    }) }) })
  }
  expect_failures = [var.releases]
}

run "reject_proof_bundle_outside_environment_prefix" {
  command = plan
  variables {
    releases = merge(var.releases, { r22222222 = merge(var.releases.r22222222, { release_tools = merge(var.releases.r22222222.release_tools, {
      runtime = merge(var.releases.r22222222.release_tools.runtime, {
        proof_bundle = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:production/runtime-proof-KKKKKK", version_id = "e1000000-0000-4000-8000-000000000002" }
      })
    }) }) })
  }
  expect_failures = [var.releases]
}

run "reject_proof_bundle_aliasing_owner_bundle" {
  command = plan
  variables {
    releases = merge(var.releases, { r22222222 = merge(var.releases.r22222222, { release_tools = merge(var.releases.r22222222.release_tools, {
      product = merge(var.releases.r22222222.release_tools.product, { proof_bundle = var.releases.r22222222.release_jobs.product.environment_bundle })
    }) }) })
  }
  expect_failures = [var.releases]
}

run "reject_proof_bundle_changing_purpose_between_releases" {
  command = plan
  variables {
    releases = merge(var.releases, { r11111111 = merge(var.releases.r11111111, { release_tools = merge(var.releases.r11111111.release_tools, {
      runtime = merge(var.releases.r11111111.release_tools.runtime, { proof_bundle = var.releases.r11111111.release_tools.product.proof_bundle })
      product = merge(var.releases.r11111111.release_tools.product, { proof_bundle = var.releases.r11111111.release_tools.runtime.proof_bundle })
    }) }) })
  }
  expect_failures = [var.releases]
}

run "first_deployment_holds_without_inventing_a_rollback" {
  command = plan
  variables {
    releases = { r22222222 = var.releases.r22222222 }
  }
  assert {
    condition = (toset(keys(module.release)) == toset(["r22222222"]) && output.rollback_release == null &&
      length([for statement in output.release_launcher_policies.services.Statement : statement if statement.Sid == "PassRetainedServiceRoles"][0].Resource) == 6 &&
      jsonencode([for statement in output.release_launcher_policies.services.Statement : statement.Condition.ArnEqualsIfExists["ecs:task-definition"] if statement.Sid == "UpdateRuntimeService"]) == jsonencode([
        ["arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-runtime:2"]
      ]) &&
    output.current_service_task_definitions.runtime == "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-runtime:2")
    error_message = "A first deployment is an empty hold: one current release and no fabricated prior version."
  }
}

run "reject_no_release" {
  command = plan
  variables { releases = {} }
  expect_failures = [var.releases]
}

run "reject_two_current_releases" {
  command = plan
  variables {
    releases = merge(var.releases, { r11111111 = merge(var.releases.r11111111, { slot = "current" }) })
  }
  expect_failures = [var.releases]
}

run "reject_rollback_without_current" {
  command = plan
  variables {
    releases = { r11111111 = var.releases.r11111111 }
  }
  expect_failures = [var.releases]
}

run "reject_release_key_not_bound_to_release_id" {
  command = plan
  variables {
    releases = { r22222222 = var.releases.r22222222, rcurrent1 = var.releases.r11111111 }
  }
  expect_failures = [var.releases]
}

run "reject_three_retained_releases" {
  command = plan
  variables {
    releases = merge(var.releases, { r33333333 = merge(var.releases.r11111111, { release_id = "33333333-3333-4333-8333-333333333333" }) })
  }
  expect_failures = [var.releases]
}

run "reject_image_from_another_repository" {
  command = plan
  variables {
    releases = merge(var.releases, { r22222222 = merge(var.releases.r22222222, { images = merge(var.releases.r22222222.images, {
      runtime = "111122223333.dkr.ecr.us-east-1.amazonaws.com/sentry-staging/search@sha256:2222222222222222222222222222222222222222222222222222222222222222"
    }) }) })
  }
  expect_failures = [var.releases]
}

run "reject_cross_account_image" {
  command = plan
  variables {
    releases = merge(var.releases, { r22222222 = merge(var.releases.r22222222, { images = merge(var.releases.r22222222.images, {
      search = "999999999999.dkr.ecr.us-east-1.amazonaws.com/sentry-staging/search@sha256:3333333333333333333333333333333333333333333333333333333333333333"
    }) }) })
  }
  expect_failures = [var.releases]
}

run "reject_mutable_image_tag" {
  command = plan
  variables {
    releases = merge(var.releases, { r22222222 = merge(var.releases.r22222222, { images = merge(var.releases.r22222222.images, {
      search = "111122223333.dkr.ecr.us-east-1.amazonaws.com/sentry-staging/search:latest"
    }) }) })
  }
  expect_failures = [var.releases]
}

run "reject_moving_secret_label" {
  command = plan
  variables {
    releases = merge(var.releases, { r22222222 = merge(var.releases.r22222222, { material_bundles = merge(var.releases.r22222222.material_bundles, {
      runtime = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/runtime-material-DDDDDD", version_id = "AWSCURRENT" }
    }) }) })
  }
  expect_failures = [var.releases]
}

run "reject_secret_outside_environment_prefix" {
  command = plan
  variables {
    releases = merge(var.releases, { r22222222 = merge(var.releases.r22222222, { environment_bundles = merge(var.releases.r22222222.environment_bundles, {
      api = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:production/api-env-BBBBBB", version_id = "b0000000-0000-4000-8000-000000000002" }
    }) }) })
  }
  expect_failures = [var.releases]
}

run "reject_wildcard_secret_arn" {
  command = plan
  variables {
    releases = merge(var.releases, { r22222222 = merge(var.releases.r22222222, { environment_bundles = merge(var.releases.r22222222.environment_bundles, {
      api = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/*", version_id = "b0000000-0000-4000-8000-000000000002" }
    }) }) })
  }
  expect_failures = [var.releases]
}

run "reject_cross_account_secret" {
  command = plan
  variables {
    releases = merge(var.releases, { r22222222 = merge(var.releases.r22222222, { environment_bundles = merge(var.releases.r22222222.environment_bundles, {
      api = { arn = "arn:aws:secretsmanager:us-east-1:999999999999:secret:sentry-staging/api-env-BBBBBB", version_id = "b0000000-0000-4000-8000-000000000002" }
    }) }) })
  }
  expect_failures = [var.releases]
}

run "reject_shared_bundle_within_release" {
  command = plan
  variables {
    releases = merge(var.releases, { r22222222 = merge(var.releases.r22222222, { environment_bundles = merge(var.releases.r22222222.environment_bundles, {
      api = var.releases.r22222222.environment_bundles.runtime
    }) }) })
  }
  expect_failures = [var.releases]
}

run "reject_bundle_changing_role_between_releases" {
  command = plan
  variables {
    releases = merge(var.releases, { r11111111 = merge(var.releases.r11111111, {
      environment_bundles = merge(var.releases.r11111111.environment_bundles, {
        api    = var.releases.r11111111.environment_bundles.worker
        worker = var.releases.r11111111.environment_bundles.api
      })
    }) })
  }
  expect_failures = [var.releases]
}

run "reject_unpinned_grant_source" {
  command = plan
  variables {
    releases = merge(var.releases, { r22222222 = merge(var.releases.r22222222, { release_jobs = merge(var.releases.r22222222.release_jobs, {
      runtime_grants = { source_commit = "main", sql_sha256 = "02a2b55161506254b1977f26351ec3bbba4de7c94a54b3b697153d622ae02aa0" }
    }) }) })
  }
  expect_failures = [var.releases]
}

run "reject_namespace_with_scheme" {
  command = plan
  variables { private_dns_namespace = "https://sentry-staging.internal.example" }
  expect_failures = [var.private_dns_namespace]
}
