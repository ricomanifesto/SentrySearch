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

run "unscoped_names_remain_compatible_and_revisions_are_retained" {
  command = plan
  assert {
    condition = (output.iam_role_names == {
      runtime-task         = "sentry-fit-staging-runtime-task", runtime-execution = "sentry-fit-staging-runtime-execution"
      api-task             = "sentry-fit-staging-api-task", api-execution = "sentry-fit-staging-api-execution"
      worker-task          = "sentry-fit-staging-worker-task", worker-execution = "sentry-fit-staging-worker-execution"
      runtime-release-task = "sentry-fit-staging-runtime-release-task", runtime-release-execution = "sentry-fit-staging-runtime-release-execution"
      product-release-task = "sentry-fit-staging-product-release-task", product-release-execution = "sentry-fit-staging-product-release-execution"
      } && alltrue([for name, role in aws_iam_role.task : output.iam_role_names["${name}-task"] == role.name]) &&
      alltrue([for name, role in aws_iam_role.execution : output.iam_role_names["${name}-execution"] == role.name]) &&
      alltrue([for name, role in aws_iam_role.release_task : output.iam_role_names["${name}-release-task"] == role.name]) &&
    alltrue([for name, role in aws_iam_role.release_execution : output.iam_role_names["${name}-release-execution"] == role.name]))
    error_message = "Without a release scope, existing role names are unchanged and every role is reported."
  }
  assert {
    condition = (alltrue([for task in concat(values(aws_ecs_task_definition.service), values(aws_ecs_task_definition.release)) :
      task.skip_destroy == true
    ]))
    error_message = "Registered revisions must survive Terraform replacement or removal so a compatible rollback remains launchable."
  }
  assert {
    condition = alltrue([for policy in concat(values(aws_iam_role_policy.task), values(aws_iam_role_policy.execution),
      values(aws_iam_role_policy.release_task), values(aws_iam_role_policy.release_execution)) :
      endswith(policy.name, "-${substr(sha256(policy.policy), 0, 16)}") && length(split("-", policy.name)) == 4
    ])
    error_message = "Inline policy names bind their exact content, so changing a retained release's grants is a replacement that prevent_destroy rejects."
  }
}

run "release_scope_isolates_identities_not_families" {
  command = plan
  variables { release_scope = "r0123abcd" }
  assert {
    condition = (alltrue([for key, name in output.iam_role_names : name == "sentry-fit-staging-r0123abcd-${key}"]) &&
      length(output.iam_role_names) == 10 &&
      { for name, task in aws_ecs_task_definition.service : name => task.family } == {
        runtime = "sentry-fit-staging-runtime", api = "sentry-fit-staging-api", worker = "sentry-fit-staging-worker"
      } &&
    { for name, task in aws_ecs_task_definition.release : name => task.family } == { runtime = "sentry-fit-staging-runtime-release", product = "sentry-fit-staging-product-release" })
    error_message = "A release scope gives each retained release its own task/execution roles while revisions stay in the stable families."
  }
}

run "reject_uppercase_release_scope" {
  command = plan
  variables { release_scope = "R0123ABCD" }
  expect_failures = [var.release_scope]
}

run "reject_scope_that_overflows_role_names" {
  command = plan
  variables {
    name_prefix   = "sentry-search-platform-fit-staging"
    release_scope = "r0123abcd"
  }
  expect_failures = [var.release_scope]
}
