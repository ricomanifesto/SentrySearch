mock_provider "aws" {}

# Restore verifications (F077): the current release's databases verified on a restored
# instance through their own definitions, roles and launcher document. Every retained
# release keeps the definitions it rendered without them.

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


# The restore definitions and execution roles a verification registers.
override_resource {
  target          = aws_ecs_task_definition.restore["runtime-rv-recon"]
  values          = { arn = "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-restore-reconcile-runtime:1" }
  override_during = plan
}
override_resource {
  target          = aws_ecs_task_definition.restore["runtime-rv-proof"]
  values          = { arn = "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-restore-proof-runtime:1" }
  override_during = plan
}
override_resource {
  target          = aws_ecs_task_definition.restore["product-rv-recon"]
  values          = { arn = "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-restore-reconcile-product:1" }
  override_during = plan
}
override_resource {
  target          = aws_ecs_task_definition.restore["product-rv-proof"]
  values          = { arn = "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-restore-proof-product:1" }
  override_during = plan
}
override_resource {
  target          = aws_iam_role.restore_execution["runtime-rv-recon"]
  values          = { arn = "arn:aws:iam::111122223333:role/sentry-staging-runtime-rv-recon-execution" }
  override_during = plan
}
override_resource {
  target          = aws_iam_role.restore_execution["runtime-rv-proof"]
  values          = { arn = "arn:aws:iam::111122223333:role/sentry-staging-runtime-rv-proof-execution" }
  override_during = plan
}
override_resource {
  target          = aws_iam_role.restore_execution["product-rv-recon"]
  values          = { arn = "arn:aws:iam::111122223333:role/sentry-staging-product-rv-recon-execution" }
  override_during = plan
}
override_resource {
  target          = aws_iam_role.restore_execution["product-rv-proof"]
  values          = { arn = "arn:aws:iam::111122223333:role/sentry-staging-product-rv-proof-execution" }
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
  restore_verifications = {
    runtime = {
      database            = "runtime"
      instance_identifier = "sentry-staging-runtime-db-restore-r1"
      not_after           = timeadd(timestamp(), "24h")
      budget_seconds      = 900
      image               = "111122223333.dkr.ecr.us-east-1.amazonaws.com/sentry-staging/release-tools@sha256:4444444444444444444444444444444444444444444444444444444444444444"
      tools_sha256        = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee3"
      sql_sha256          = { reconcile = "ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd2", proof = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb2" }
      owner_bundle        = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/restore-owner-environment/runtime-MMMMMM", version_id = "a2000000-0000-4000-8000-000000000003" }
      proof_bundle        = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/restore-proof-environment/runtime-NNNNNN", version_id = "b2000000-0000-4000-8000-000000000003" }
    }
  }
}

run "no_verification_renders_nothing_and_keeps_every_release" {
  command = plan
  variables { restore_verifications = {} }
  assert {
    condition = (length(output.restore_verifications) == 0 && length(output.restore_task_contracts) == 0 &&
      jsonencode(sort(keys(output.release_launcher_policies))) == jsonencode(["jobs", "receipts", "services", "tasks"]) &&
      output.releases.r11111111.definitions_sha256 == "890ad9024b5ddd7b1a227e731296432d457ae882f1d6fc9a5a050947ee87b5c1" &&
    output.releases.r22222222.definitions_sha256 == "86f1b7ec0d48bbf0c07a64c7e6d0848b37f717ebddf4a4081ae6c98c1137de55")
    error_message = "Without a verification nothing restore-related renders and every retained release keeps its definitions."
  }
}

run "a_verification_renders_its_two_guarded_jobs_against_the_restore_bundles" {
  command = plan
  assert {
    condition = (aws_ecs_task_definition.restore["runtime-rv-recon"].family == "sentry-staging-restore-reconcile-runtime" &&
      aws_ecs_task_definition.restore["runtime-rv-proof"].family == "sentry-staging-restore-proof-runtime" &&
      alltrue([for key in ["runtime-rv-recon", "runtime-rv-proof"] :
        jsondecode(aws_ecs_task_definition.restore[key].container_definitions) == jsondecode(jsonencode(output.restore_task_contracts[key])) &&
        [for container in output.restore_task_contracts[key] : container.name] == ["init", trimprefix(key, "runtime-")] &&
        output.restore_task_contracts[key][1].command == [trimprefix(key, "runtime-")] &&
        output.restore_task_contracts[key][1].image == var.restore_verifications.runtime.image &&
        output.restore_task_contracts[key][1].user == "65532:65532" &&
        output.restore_task_contracts[key][1].logConfiguration.options == {
          awslogs-group = "/sentry-staging/runtime-release", awslogs-region = "us-east-1", awslogs-stream-prefix = key
        } &&
        output.restore_task_contracts[key][0].logConfiguration == output.restore_task_contracts[key][1].logConfiguration &&
        merge(output.restore_task_contracts[key][0], { logConfiguration = null }) ==
        merge(module.release["r22222222"].release_task_contracts.runtime[0], { logConfiguration = null }) &&
        aws_ecs_task_definition.restore[key].task_role_arn == "arn:aws:iam::111122223333:role/sentry-staging-r22222222-runtime-release-task" &&
        aws_ecs_task_definition.restore[key].execution_role_arn == "arn:aws:iam::111122223333:role/sentry-staging-${key}-execution"
    ]))
    error_message = "Each restore job is its own family with the release's CA-only init, the pinned tools image, its own stream prefix and its own execution role."
  }
  assert {
    condition = ({ for item in output.restore_task_contracts["runtime-rv-recon"][1].environment : item.name => item.value } == {
      RELEASE_ID              = "22222222-2222-4222-8222-222222222222", RELEASE_JOB_ID = "runtime-rv-recon", RELEASE_DATABASE = "runtime"
      RELEASE_NOT_AFTER       = var.restore_verifications.runtime.not_after, RELEASE_JOB_BUDGET_SECONDS = "900"
      RELEASE_TOOLS_SHA256    = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee3"
      RELEASE_SQL_SHA256      = "ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd2"
      RELEASE_EXPECT_DATABASE = "sentryruntime", RELEASE_EXPECT_PRINCIPAL = "runtime_owner"
      } && { for item in output.restore_task_contracts["runtime-rv-proof"][1].environment : item.name => item.value } == {
      RELEASE_ID              = "22222222-2222-4222-8222-222222222222", RELEASE_JOB_ID = "runtime-rv-proof", RELEASE_DATABASE = "runtime"
      RELEASE_NOT_AFTER       = var.restore_verifications.runtime.not_after, RELEASE_JOB_BUDGET_SECONDS = "900"
      RELEASE_TOOLS_SHA256    = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee3"
      RELEASE_SQL_SHA256      = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb2"
      RELEASE_EXPECT_DATABASE = "sentryruntime", RELEASE_EXPECT_PRINCIPAL = "runtime_app", RELEASE_OWNER_ROLE = "runtime_owner"
      } && output.restore_task_contracts["runtime-rv-recon"][1].secrets == [{
        name = "DATABASE_URL", valueFrom = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/restore-owner-environment/runtime-MMMMMM:DATABASE_URL::a2000000-0000-4000-8000-000000000003"
        }] && output.restore_task_contracts["runtime-rv-proof"][1].secrets == [{
        name = "DATABASE_URL", valueFrom = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/restore-proof-environment/runtime-NNNNNN:DATABASE_URL::b2000000-0000-4000-8000-000000000003"
    }])
    error_message = "The restore jobs name the current release, run as its owner and service login, and read only their restore bundles at the exact versions."
  }
  assert {
    condition = (jsonencode(output.restore_execution_policies["runtime-rv-recon"].Statement) == jsonencode([
      { Sid = "RegistryToken", Effect = "Allow", Action = ["ecr:GetAuthorizationToken"], Resource = ["*"] },
      { Sid = "PullImages", Effect = "Allow", Action = ["ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"],
      Resource = ["arn:aws:ecr:us-east-1:111122223333:repository/sentry-staging/search", "arn:aws:ecr:us-east-1:111122223333:repository/sentry-staging/release-tools"] },
      { Sid = "TaskLogs", Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"],
      Resource = ["arn:aws:logs:us-east-1:111122223333:log-group:/sentry-staging/runtime-release:log-stream:runtime-rv-recon/*"] },
      { Sid      = "PinnedJobEnvironment", Effect = "Allow", Action = ["secretsmanager:GetSecretValue"],
        Resource = ["arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/restore-owner-environment/runtime-MMMMMM"],
      Condition = { StringEquals = { "secretsmanager:VersionId" = "a2000000-0000-4000-8000-000000000003" } } },
      ]) && jsondecode(aws_iam_role_policy.restore_execution["runtime-rv-proof"].policy) == jsondecode(jsonencode(output.restore_execution_policies["runtime-rv-proof"])) &&
    !strcontains(jsonencode(output.restore_execution_policies), "restore-owner-environment/runtime-MMMMMM\",\"secretsmanager:VersionId\":\"b2"))
    error_message = "Each restore execution role pulls the search and release-tools images, writes only its own streams and reads only its own bundle version."
  }
  assert {
    condition = (jsonencode(output.release_launcher_policies.restore.Statement) == jsonencode([
      { Sid = "RunRestoreVerifications", Effect = "Allow", Action = ["ecs:RunTask"], Resource = [
        "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-restore-proof-runtime:1",
        "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-restore-reconcile-runtime:1",
      ], Condition = { ArnEquals = { "ecs:cluster" = "arn:aws:ecs:us-east-1:111122223333:cluster/sentry-staging" } } },
      { Sid = "PassRestoreRoles", Effect = "Allow", Action = ["iam:PassRole"], Resource = [
        "arn:aws:iam::111122223333:role/sentry-staging-r22222222-runtime-release-task",
        "arn:aws:iam::111122223333:role/sentry-staging-runtime-rv-proof-execution",
        "arn:aws:iam::111122223333:role/sentry-staging-runtime-rv-recon-execution",
      ], Condition = { StringEquals = { "iam:PassedToService" = "ecs-tasks.amazonaws.com" } } },
      { Sid = "ReadRestoreReceipts", Effect = "Allow", Action = ["logs:GetLogEvents"], Resource = [
        "arn:aws:logs:us-east-1:111122223333:log-group:/sentry-staging/runtime-release:log-stream:runtime-rv-proof/rv-proof/*",
        "arn:aws:logs:us-east-1:111122223333:log-group:/sentry-staging/runtime-release:log-stream:runtime-rv-recon/rv-recon/*",
      ] },
      { Sid = "DenyExecuteCommandOnRestore", Effect = "Deny", Action = ["ecs:RunTask"], Resource = ["*"],
      Condition = { StringEqualsIgnoreCase = { "ecs:enable-execute-command" = "true" } } },
      ]) && aws_iam_policy.release_launcher["restore"].name == "sentry-staging-release-launcher-restore" &&
      alltrue([for name in ["jobs", "receipts", "services", "tasks"] :
      output.release_launcher_policies[name] == run.no_verification_renders_nothing_and_keeps_every_release.release_launcher_policies[name]]) &&
      output.releases.r11111111.definitions_sha256 == "890ad9024b5ddd7b1a227e731296432d457ae882f1d6fc9a5a050947ee87b5c1" &&
    output.releases.r22222222.definitions_sha256 == "86f1b7ec0d48bbf0c07a64c7e6d0848b37f717ebddf4a4081ae6c98c1137de55")
    error_message = "The verification's own launcher document scopes launch, role passing and receipts to its definitions; every other document and release is unchanged."
  }
  assert {
    condition = (output.restore_verifications.runtime.release_id == "22222222-2222-4222-8222-222222222222" &&
      output.restore_verifications.runtime.jobs["runtime-rv-recon"].expect == { database = "sentryruntime", principal = "runtime_owner" } &&
      output.restore_verifications.runtime.jobs["runtime-rv-proof"].expect == {
        database = "sentryruntime", principal = "runtime_app", sql_digest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb2"
      } &&
    output.restore_verifications.runtime.jobs["runtime-rv-proof"].task_definition == "arn:aws:ecs:us-east-1:111122223333:task-definition/sentry-staging-restore-proof-runtime:1")
    error_message = "The review values name the current release, the exact revisions and the expectations Terraform fixes."
  }
}

run "a_product_verification_reads_the_product_keys_from_its_bundles" {
  command = plan
  variables {
    restore_verifications = { product = merge(var.restore_verifications.runtime, {
      database            = "product"
      instance_identifier = "sentry-staging-product-db-restore-r1"
      sql_sha256          = { reconcile = "ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd2", proof = "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc2" }
      owner_bundle        = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/restore-owner-environment/product-OOOOOO", version_id = "c2000000-0000-4000-8000-000000000003" }
      proof_bundle        = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/restore-proof-environment/product-PPPPPP", version_id = "d2000000-0000-4000-8000-000000000003" }
    }) }
  }
  assert {
    condition = (aws_ecs_task_definition.restore["product-rv-recon"].family == "sentry-staging-restore-reconcile-product" &&
      [for secret in output.restore_task_contracts["product-rv-proof"][1].secrets : secret.name] == ["DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD"] &&
      output.restore_task_contracts["product-rv-proof"][1].user == "10001:10001" &&
      { for item in output.restore_task_contracts["product-rv-proof"][1].environment : item.name => item.value }["RELEASE_EXPECT_PRINCIPAL"] == "search_app" &&
    aws_ecs_task_definition.restore["product-rv-proof"].task_role_arn == "arn:aws:iam::111122223333:role/sentry-staging-r22222222-product-release-task")
    error_message = "A product verification takes the product job's user, keys, logins and CA-only task role."
  }
}

run "reject_a_key_other_than_its_database" {
  command = plan
  variables {
    restore_verifications = { product = var.restore_verifications.runtime }
  }
  expect_failures = [var.restore_verifications]
}

run "reject_an_unknown_database_key" {
  command = plan
  variables {
    restore_verifications = { other = merge(var.restore_verifications.runtime, { database = "other" }) }
  }
  expect_failures = [var.restore_verifications]
}

run "reject_an_instance_outside_the_restore_names" {
  command = plan
  variables {
    restore_verifications = { runtime = merge(var.restore_verifications.runtime, { instance_identifier = "sentry-staging-runtime-db" }) }
  }
  expect_failures = [var.restore_verifications]
}

run "reject_a_restore_label_over_twenty_characters" {
  command = plan
  variables {
    restore_verifications = { runtime = merge(var.restore_verifications.runtime, { instance_identifier = "sentry-staging-runtime-db-restore-abcdefghijklmnopqrstu" }) }
  }
  expect_failures = [var.restore_verifications]
}

run "reject_a_restore_label_with_a_double_hyphen" {
  command = plan
  variables {
    restore_verifications = { runtime = merge(var.restore_verifications.runtime, { instance_identifier = "sentry-staging-runtime-db-restore-a--b" }) }
  }
  expect_failures = [var.restore_verifications]
}

run "reject_a_deadline_already_past" {
  command = plan
  variables {
    restore_verifications = { runtime = merge(var.restore_verifications.runtime, { not_after = timeadd(timestamp(), "-1h") }) }
  }
  expect_failures = [var.restore_verifications]
}

run "reject_a_deadline_beyond_seven_days" {
  command = plan
  variables {
    restore_verifications = { runtime = merge(var.restore_verifications.runtime, { not_after = timeadd(timestamp(), "200h") }) }
  }
  expect_failures = [var.restore_verifications]
}

run "reject_a_budget_outside_its_range" {
  command = plan
  variables {
    restore_verifications = { runtime = merge(var.restore_verifications.runtime, { budget_seconds = 30 }) }
  }
  expect_failures = [var.restore_verifications]
}

run "reject_a_tools_image_from_another_repository" {
  command = plan
  variables {
    restore_verifications = { runtime = merge(var.restore_verifications.runtime, { image = "111122223333.dkr.ecr.us-east-1.amazonaws.com/sentry-staging/search@sha256:4444444444444444444444444444444444444444444444444444444444444444" }) }
  }
  expect_failures = [var.restore_verifications]
}

run "reject_a_tools_image_by_tag" {
  command = plan
  variables {
    restore_verifications = { runtime = merge(var.restore_verifications.runtime, { image = "111122223333.dkr.ecr.us-east-1.amazonaws.com/sentry-staging/release-tools:latest" }) }
  }
  expect_failures = [var.restore_verifications]
}

run "reject_another_reconcile_program" {
  command = plan
  variables {
    restore_verifications = { runtime = merge(var.restore_verifications.runtime, { sql_sha256 = { reconcile = "ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd1", proof = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb2" } }) }
  }
  expect_failures = [var.restore_verifications]
}

run "reject_another_proof_program" {
  command = plan
  variables {
    restore_verifications = { runtime = merge(var.restore_verifications.runtime, { sql_sha256 = { reconcile = "ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd2", proof = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb1" } }) }
  }
  expect_failures = [var.restore_verifications]
}

run "reject_an_owner_bundle_of_another_database" {
  command = plan
  variables {
    restore_verifications = { runtime = merge(var.restore_verifications.runtime, { owner_bundle = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/restore-owner-environment/product-MMMMMM", version_id = "a2000000-0000-4000-8000-000000000003" } }) }
  }
  expect_failures = [var.restore_verifications]
}

run "reject_a_proof_bundle_outside_the_environment_prefix" {
  command = plan
  variables {
    restore_verifications = { runtime = merge(var.restore_verifications.runtime, { proof_bundle = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:other-staging/restore-proof-environment/runtime-NNNNNN", version_id = "b2000000-0000-4000-8000-000000000003" } }) }
  }
  expect_failures = [var.restore_verifications]
}

run "reject_a_bundle_version_label" {
  command = plan
  variables {
    restore_verifications = { runtime = merge(var.restore_verifications.runtime, { proof_bundle = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/restore-proof-environment/runtime-NNNNNN", version_id = "AWSCURRENT" } }) }
  }
  expect_failures = [var.restore_verifications]
}

run "reject_a_restore_bundle_that_is_a_release_bundle" {
  command = plan
  variables {
    # The current release's own proof login under a restore name: never a restore bundle.
    releases = merge(var.releases, { r22222222 = merge(var.releases.r22222222, { release_tools = merge(var.releases.r22222222.release_tools, {
      runtime = merge(var.releases.r22222222.release_tools.runtime, { proof_bundle = {
        arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/restore-proof-environment/runtime-NNNNNN", version_id = "e1000000-0000-4000-8000-000000000002"
      } })
    }) }) })
  }
  expect_failures = [var.restore_verifications]
}

run "reject_a_database_other_than_its_key" {
  command = plan
  variables {
    # Everything else names the runtime database; only the database field disagrees.
    restore_verifications = { runtime = merge(var.restore_verifications.runtime, { database = "product" }) }
  }
  expect_failures = [var.restore_verifications]
}

run "reject_a_restore_bundle_that_is_a_release_environment_bundle" {
  command = plan
  variables {
    releases = merge(var.releases, { r22222222 = merge(var.releases.r22222222, { environment_bundles = merge(var.releases.r22222222.environment_bundles, {
      runtime = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/restore-owner-environment/runtime-MMMMMM", version_id = "a0000000-0000-4000-8000-000000000002" }
    }) }) })
  }
  expect_failures = [var.restore_verifications]
}

run "reject_a_restore_bundle_that_is_a_release_material_bundle" {
  command = plan
  variables {
    releases = merge(var.releases, { r22222222 = merge(var.releases.r22222222, { release_jobs = merge(var.releases.r22222222.release_jobs, {
      runtime = merge(var.releases.r22222222.release_jobs.runtime, { material_bundle = {
        arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/restore-proof-environment/runtime-NNNNNN", version_id = "b1000000-0000-4000-8000-000000000002"
      } })
    }) }) })
  }
  expect_failures = [var.restore_verifications]
}
