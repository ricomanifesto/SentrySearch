# The rendering contract of one guarded release-tools job: no resource, no provider.
variables {
  account_id = "111122223333"
  region     = "us-east-1"
  job_id     = "runtime-rv-recon"
  kind       = "rv-recon"
  image      = "111122223333.dkr.ecr.us-east-1.amazonaws.com/sentry-staging/release-tools@sha256:4444444444444444444444444444444444444444444444444444444444444444"
  user       = "65532:65532"
  init = {
    name             = "init", image = "search-image", essential = false, user = "0:0"
    logConfiguration = { logDriver = "awslogs", options = { awslogs-stream-prefix = "runtime-release" } }
  }
  log_group         = "/sentry-staging/runtime-release"
  environment       = { RELEASE_JOB_ID = "runtime-rv-recon", RELEASE_DATABASE = "runtime" }
  secret_keys       = ["DATABASE_URL"]
  bundle            = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/restore-owner-environment/runtime-MMMMMM", version_id = "a2000000-0000-4000-8000-000000000003" }
  pull_repositories = ["arn:aws:ecr:us-east-1:111122223333:repository/sentry-staging/search", "arn:aws:ecr:us-east-1:111122223333:repository/sentry-staging/release-tools"]
}

run "renders_the_init_and_job_containers_with_one_log_configuration" {
  command = plan
  assert {
    condition = (output.log_configuration == {
      logDriver = "awslogs"
      options   = { awslogs-group = "/sentry-staging/runtime-release", awslogs-region = "us-east-1", awslogs-stream-prefix = "runtime-rv-recon" }
      } && [for container in output.task_contract : container.name] == ["init", "rv-recon"] &&
      output.task_contract[0] == merge(var.init, { logConfiguration = output.log_configuration }) &&
      output.task_contract[1].command == ["rv-recon"] && output.task_contract[1].image == var.image &&
      output.task_contract[1].user == "65532:65532" && output.task_contract[1].readonlyRootFilesystem &&
      output.task_contract[1].linuxParameters == { capabilities = { drop = ["ALL"] } } &&
      output.task_contract[1].dependsOn == [{ containerName = "init", condition = "SUCCESS" }] &&
      output.task_contract[1].environment == [
        { name = "RELEASE_DATABASE", value = "runtime" }, { name = "RELEASE_JOB_ID", value = "runtime-rv-recon" },
        ] && output.task_contract[1].secrets == [{
          name = "DATABASE_URL", valueFrom = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/restore-owner-environment/runtime-MMMMMM:DATABASE_URL::a2000000-0000-4000-8000-000000000003"
      }] && output.task_contract[1].portMappings == [] &&
    output.task_contract[1].mountPoints == [{ sourceVolume = "material", containerPath = "/run/material", readOnly = true }])
    error_message = "The job container is the named release-tools command after the CA-only init, both on the job's own stream prefix."
  }
  assert {
    condition = (output.receipt_stream == "arn:aws:logs:us-east-1:111122223333:log-group:/sentry-staging/runtime-release:log-stream:runtime-rv-recon/rv-recon/*" &&
      [for statement in output.execution_policy.Statement : statement.Sid] == ["RegistryToken", "PullImages", "TaskLogs", "PinnedJobEnvironment"] &&
      output.execution_policy.Statement[1].Resource == var.pull_repositories &&
      output.execution_policy.Statement[2].Resource == ["arn:aws:logs:us-east-1:111122223333:log-group:/sentry-staging/runtime-release:log-stream:runtime-rv-recon/*"] &&
      output.execution_policy.Statement[3].Resource == [var.bundle.arn] &&
    output.execution_policy.Statement[3].Condition == { StringEquals = { "secretsmanager:VersionId" = var.bundle.version_id } })
    error_message = "The execution policy pulls the two images, writes the job's own streams and reads one bundle version; receipts come from the job container only."
  }
}
