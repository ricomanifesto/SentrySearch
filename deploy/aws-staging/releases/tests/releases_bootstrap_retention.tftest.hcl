# The first release through its life in the catalog, applied against one mocked
# state: deployed alone with its bootstrap definitions, then retained as the
# rollback release beside a new current release, then made current again for a
# rollback run. Its bootstrap roles, policies and revisions are prevent_destroy,
# so a step that removed one would fail its run. A mocked provider updates a
# changed definition in place and keeps its ARN, so it cannot show a
# replacement; the runs compare the release's definitions_sha256 instead, which
# covers every container contract and policy document it registered.
mock_provider "aws" {
  # Applying a task definition validates its role ARNs; every mocked role gets
  # a well-formed one. Roles are told apart by their names.
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::111122223333:role/mocked" }
  }
}

# The upgraded catalog: r11111111 is the first release, retained with every input
# it was deployed with; r22222222 is the new current release.
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
      bootstrap = {
        sql_sha256 = "5555555555555555555555555555555555555555555555555555555555555555"
        runtime = {
          host         = "sentry-staging-runtime-db.abcdefghijkl.us-east-1.rds.amazonaws.com", administrator = "runtime_admin"
          admin_secret = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:rds!db-11111111-aaaa-4aaa-8aaa-111111111111-AbCdEf", version_id = "b2000000-0000-4000-8000-000000000001" }
          credentials  = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/runtime-bootstrap-NNNNNN", version_id = "c2000000-0000-4000-8000-000000000001" }
          ca_bundle    = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/runtime-bootstrap-ca-SSSSSS", version_id = "f2000000-0000-4000-8000-000000000001" }
        }
        product = {
          host         = "sentry-staging-product-db.abcdefghijkl.us-east-1.rds.amazonaws.com", administrator = "product_admin"
          admin_secret = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:rds!db-22222222-bbbb-4bbb-8bbb-222222222222-GhIjKl", version_id = "d2000000-0000-4000-8000-000000000001" }
          credentials  = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/product-bootstrap-OOOOOO", version_id = "e2000000-0000-4000-8000-000000000001" }
          ca_bundle    = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/product-bootstrap-ca-TTTTTT", version_id = "f3000000-0000-4000-8000-000000000001" }
        }
      }
    }
  }
}

run "first_deployment_registers_bootstrap_and_its_separate_launcher" {
  command = apply
  variables {
    releases = { r11111111 = merge(var.releases.r11111111, { slot = "current" }) }
  }
  assert {
    condition = (output.current_release == "r11111111" && output.rollback_release == null &&
      length(aws_iam_policy.release_launcher_bootstrap) == 1 &&
      sort(keys(module.release["r11111111"].launch_scopes.bootstrap.task_definitions)) == tolist(["product-bootstrap", "runtime-bootstrap"]) &&
      length(module.release["r11111111"].launch_scopes.bootstrap.roles) == 4 &&
    !strcontains(jsonencode(output.release_launcher_policies), "boot"))
    error_message = "A first deployment registers both bootstrap revisions and their four roles, launched only through the separate bootstrap launcher."
  }
}

run "the_first_release_is_retained_with_its_bootstrap_definitions_and_no_launcher" {
  command = apply
  assert {
    condition     = output.current_release == "r22222222" && output.rollback_release == "r11111111"
    error_message = "The upgrade retains the first release as the rollback release beside the new current release."
  }
  assert {
    # The same revisions as first registered: nothing was removed or replaced.
    condition = (sort(values(module.release["r11111111"].launch_scopes.bootstrap.task_definitions)) ==
      sort(run.first_deployment_registers_bootstrap_and_its_separate_launcher.release_launcher_bootstrap_policy.Statement[0].Resource) &&
      sort([for name in module.release["r11111111"].launch_scopes.bootstrap.roles : "arn:aws:iam::111122223333:role/${name}"]) ==
      sort(run.first_deployment_registers_bootstrap_and_its_separate_launcher.release_launcher_bootstrap_policy.Statement[1].Resource) &&
      jsonencode(output.releases["r11111111"]) == jsonencode(merge(run.first_deployment_registers_bootstrap_and_its_separate_launcher.releases["r11111111"], { slot = "rollback" })) &&
      length(module.release["r22222222"].launch_scopes.bootstrap.task_definitions) == 0 &&
    length(module.release["r22222222"].launch_scopes.bootstrap.roles) == 0)
    error_message = "The retained first release keeps exactly the bootstrap revisions and roles it was deployed with; the new release has none."
  }
  assert {
    # Retaining the definitions grants nothing: no policy can launch them, pass
    # their roles or read their streams.
    condition = (output.release_launcher_bootstrap_policy == null && length(aws_iam_policy.release_launcher_bootstrap) == 0 &&
      !strcontains(jsonencode(output.release_launcher_policies), "boot") &&
      alltrue([for arn in values(module.release["r11111111"].launch_scopes.bootstrap.task_definitions) : !strcontains(jsonencode(output.release_launcher_policies), arn)]) &&
      alltrue([for policy in values(aws_iam_policy.release_launcher) : !strcontains(policy.policy, "boot")]) &&
    sort(keys(aws_iam_policy.release_launcher)) == tolist(["jobs", "receipts", "services", "tasks"]))
    error_message = "After the first upgrade no launcher policy names a bootstrap revision, role or stream, and the bootstrap launcher is gone."
  }
}

run "a_rollback_replan_makes_the_first_release_current_without_bootstrap_authority" {
  command = apply
  variables {
    releases = {
      r11111111 = merge(var.releases.r11111111, { slot = "current" })
      r22222222 = merge(var.releases.r22222222, { slot = "rollback" })
    }
  }
  assert {
    condition = (output.current_release == "r11111111" && output.rollback_release == "r22222222" &&
      sort(values(module.release["r11111111"].launch_scopes.bootstrap.task_definitions)) ==
      sort(run.first_deployment_registers_bootstrap_and_its_separate_launcher.release_launcher_bootstrap_policy.Statement[0].Resource) &&
      output.release_launcher_bootstrap_policy == null && length(aws_iam_policy.release_launcher_bootstrap) == 0 &&
      !strcontains(jsonencode(output.release_launcher_policies), "boot") &&
      alltrue([for arn in values(module.release["r11111111"].launch_scopes.bootstrap.task_definitions) : !strcontains(jsonencode(output.release_launcher_policies), arn)]) &&
    alltrue([for policy in values(aws_iam_policy.release_launcher) : !strcontains(policy.policy, "boot")]))
    error_message = "A rollback run launches the prior release's reconcile, proof and observer revisions only: making the first release current again beside another renders no bootstrap launcher."
  }
  assert {
    condition     = jsonencode(output.releases["r11111111"]) == jsonencode(run.first_deployment_registers_bootstrap_and_its_separate_launcher.releases["r11111111"])
    error_message = "Made current again, the first release is exactly what was first deployed: the same revisions, roles, bindings and definitions digest."
  }
  assert {
    # The attended jobs scope is the now-current first release's database jobs.
    condition = alltrue([for arn in values(module.release["r11111111"].launch_scopes.jobs.task_definitions) :
    strcontains(aws_iam_policy.release_launcher["jobs"].policy, arn)])
    error_message = "The attended launcher follows the current release's database jobs."
  }
}

run "reject_bootstrap_definitions_on_both_retained_releases" {
  command = plan
  variables {
    releases = {
      r11111111 = var.releases.r11111111
      r22222222 = merge(var.releases.r22222222, { bootstrap = merge(var.releases.r11111111.bootstrap, {
        runtime = merge(var.releases.r11111111.bootstrap.runtime, {
          credentials = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/runtime-bootstrap-NNNNNN", version_id = "c2000000-0000-4000-8000-000000000002" }
          ca_bundle   = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/runtime-bootstrap-ca-SSSSSS", version_id = "f2000000-0000-4000-8000-000000000002" }
        })
        product = merge(var.releases.r11111111.bootstrap.product, {
          credentials = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/product-bootstrap-OOOOOO", version_id = "e2000000-0000-4000-8000-000000000002" }
          ca_bundle   = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/product-bootstrap-ca-TTTTTT", version_id = "f3000000-0000-4000-8000-000000000002" }
        })
      }) })
    }
  }
  expect_failures = [var.releases]
}
