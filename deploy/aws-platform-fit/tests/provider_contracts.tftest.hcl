# The optional provider input (AWS-08b preparation). Null renders the worker exactly as
# before it existed; set, only the worker gets the base URL, the canary manifest and its
# key from the exact bundle version. Hashes pin the render before the input existed.
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

run "null_provider_renders_every_role_byte_for_byte_as_before" {
  command = plan
  assert {
    condition = (sha256(jsonencode(output.task_contracts)) == "19654be699149ea35dcf75f69d910011c2d4e9051924408c17b39cf5414de395" &&
      sha256(jsonencode(output.execution_policies)) == "640780af7100bfb4d3b29774f0bee6eb6e973e925567082e9607a23aefa91608" &&
      sha256(jsonencode(output.task_policies)) == "21357ea5e3e0c8bbac63e0249253fb570432c838a462f19c8d923d3e3fe0ce60" &&
    sha256(jsonencode({ for name, task in aws_ecs_task_definition.service : name => task.container_definitions })) == "a19dab29d05bc3181a07fccaac833d5f532a3981300359a5d5c076d70ef88390")
    error_message = "Without a provider the task contracts, policies and definitions must be byte for byte the ones rendered before the input existed."
  }
}

run "a_manifest_hash_that_does_not_match_is_refused" {
  command = plan
  variables {
    model_provider = {
      base_url               = "https://openrouter.ai/api/v1"
      canary_manifest        = "{\"schema\":\"sentry.provider-canary.v1\",\"canary_id\":\"aws-08b-1\"}"
      canary_manifest_sha256 = "8c1e6fd3a52b0b0e1c0b2c0b1c7d2f3c8a6c4d1b6f0e9a8b7c6d5e4f3a2b1c0d"
      key_bundle             = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/provider-key/worker-GGGGGG", version_id = "77777777-7777-4777-8777-777777777777" }
    }
  }
  expect_failures = [var.model_provider]
}

run "a_provider_with_its_manifest_hash_renders_the_worker_secret_and_environment" {
  command = plan
  variables {
    model_provider = {
      base_url               = "https://openrouter.ai/api/v1"
      canary_manifest        = "{\"schema\":\"sentry.provider-canary.v1\",\"canary_id\":\"aws-08b-1\"}"
      canary_manifest_sha256 = sha256("{\"schema\":\"sentry.provider-canary.v1\",\"canary_id\":\"aws-08b-1\"}")
      key_bundle             = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/provider-key/worker-GGGGGG", version_id = "77777777-7777-4777-8777-777777777777" }
    }
  }
  assert {
    condition = ({ for item in output.task_contracts.worker[1].environment : item.name => item.value }["OPENROUTER_BASE_URL"] == "https://openrouter.ai/api/v1" &&
      { for item in output.task_contracts.worker[1].environment : item.name => item.value }["SENTRYSEARCH_PROVIDER_CANARY"] == "{\"schema\":\"sentry.provider-canary.v1\",\"canary_id\":\"aws-08b-1\"}" &&
      !contains([for item in output.task_contracts.worker[1].environment : item.name], "OPENROUTER_API_KEY") &&
    contains(output.task_contracts.worker[1].secrets, { name = "OPENROUTER_API_KEY", valueFrom = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/provider-key/worker-GGGGGG:OPENROUTER_API_KEY::77777777-7777-4777-8777-777777777777" }))
    error_message = "A provider gives the worker its base URL and canary manifest as values and its key only as a secret at the exact version."
  }
  assert {
    condition = contains(output.execution_policies.worker.Statement, {
      Sid       = "PinnedProviderKey", Effect = "Allow", Action = ["secretsmanager:GetSecretValue"]
      Resource  = ["arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/provider-key/worker-GGGGGG"]
      Condition = { StringEquals = { "secretsmanager:VersionId" = "77777777-7777-4777-8777-777777777777" } }
    })
    error_message = "The worker's execution role may read the provider key only at its pinned version."
  }
  assert {
    condition = (sha256(jsonencode(output.task_contracts.api)) == "b8406c42ebbb459064f41900639a34125a9674299a55efdd7d3a0338a395f9e9" &&
      sha256(jsonencode(output.task_contracts.runtime)) == "7ef58b11ad0f3f77bc91dace50b417787a020b65e74290d201f7bb30c5d12b3c" &&
      sha256(jsonencode(output.execution_policies.api)) == "477dad6dda4edba5d553259bc25d6362b05465385219a70e309d231bdfe4657c" &&
      sha256(jsonencode(output.execution_policies.runtime)) == "15ef6c6ca2ce4ae2e7983a1349c4ec90e5602c03e0fbb1796b3e47ebeffb4262" &&
    sha256(jsonencode(output.task_policies)) == "21357ea5e3e0c8bbac63e0249253fb570432c838a462f19c8d923d3e3fe0ce60")
    error_message = "A provider changes nothing for the API or the Runtime, and no task role gains access."
  }
}

run "a_manifest_that_is_not_a_provider_canary_is_refused" {
  command = plan
  variables {
    model_provider = {
      base_url               = "https://openrouter.ai/api/v1"
      canary_manifest        = "{\"schema\":\"something-else\"}"
      canary_manifest_sha256 = sha256("{\"schema\":\"something-else\"}")
      key_bundle             = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/provider-key/worker-GGGGGG", version_id = "77777777-7777-4777-8777-777777777777" }
    }
  }
  expect_failures = [var.model_provider]
}

run "a_plain_http_base_url_is_refused" {
  command = plan
  variables {
    model_provider = {
      base_url               = "http://openrouter.ai/api/v1"
      canary_manifest        = "{\"schema\":\"sentry.provider-canary.v1\",\"canary_id\":\"aws-08b-1\"}"
      canary_manifest_sha256 = sha256("{\"schema\":\"sentry.provider-canary.v1\",\"canary_id\":\"aws-08b-1\"}")
      key_bundle             = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/provider-key/worker-GGGGGG", version_id = "77777777-7777-4777-8777-777777777777" }
    }
  }
  expect_failures = [var.model_provider]
}

run "a_manifest_that_is_not_json_is_refused" {
  command = plan
  variables {
    model_provider = {
      base_url               = "https://openrouter.ai/api/v1"
      canary_manifest        = "not json"
      canary_manifest_sha256 = sha256("not json")
      key_bundle             = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/provider-key/worker-GGGGGG", version_id = "77777777-7777-4777-8777-777777777777" }
    }
  }
  expect_failures = [var.model_provider]
}

run "a_key_bundle_that_is_also_an_environment_or_material_bundle_is_refused" {
  command = plan
  variables {
    model_provider = {
      base_url               = "https://openrouter.ai/api/v1"
      canary_manifest        = "{\"schema\":\"sentry.provider-canary.v1\"}"
      canary_manifest_sha256 = sha256("{\"schema\":\"sentry.provider-canary.v1\"}")
      key_bundle             = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/worker-env-CCCCCC", version_id = "77777777-7777-4777-8777-777777777777" }
    }
  }
  expect_failures = [var.model_provider]
}
