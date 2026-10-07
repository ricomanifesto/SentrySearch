# Owner jobs are deliberately separate from service roles: no service startup
# migration, Runtime API tokens, artifact permissions or model configuration.
variable "release_jobs" {
  description = "Optional pair of separate owner-only release jobs. Null preserves the disabled three-service scaffold. Bundles contain references only, never secret values."
  type = object({
    runtime = object({
      environment_bundle = object({ arn = string, version_id = string })
      material_bundle    = object({ arn = string, version_id = string })
      log_group          = string
    })
    product = object({
      environment_bundle = object({ arn = string, version_id = string })
      material_bundle    = object({ arn = string, version_id = string })
      log_group          = string
    })
    runtime_grants = object({ source_commit = string, sql_sha256 = string })
  })
  default = null
  validation {
    condition = var.release_jobs == null ? true : try(alltrue([
      for bundle in flatten([for job in [var.release_jobs.runtime, var.release_jobs.product] : [job.environment_bundle, job.material_bundle]]) :
      can(regex("^arn:aws:secretsmanager:${var.region}:${var.account_id}:secret:[A-Za-z0-9/_+=.@-]+-[A-Za-z0-9]{6}$", bundle.arn)) &&
      can(regex("^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$", bundle.version_id))
    ]), false)
    error_message = "Release bundles require full same-account regional Secret ARNs and exact lowercase UUID VersionIds."
  }
  validation {
    condition = var.release_jobs == null ? true : try(
      length(toset(flatten([for job in [var.release_jobs.runtime, var.release_jobs.product] : [job.environment_bundle.arn, job.material_bundle.arn]]))) == 4 &&
      alltrue([for arn in flatten([for job in [var.release_jobs.runtime, var.release_jobs.product] : [job.environment_bundle.arn, job.material_bundle.arn]]) :
        !contains(concat([for bundle in values(var.environment_bundles) : bundle.arn], [for bundle in values(var.material_bundles) : bundle.arn]), arn)
    ]), false)
    error_message = "The four release bundles must be distinct from one another and every service environment/material bundle."
  }
  validation {
    condition = var.release_jobs == null ? true : try(
      var.release_jobs.runtime.log_group != var.release_jobs.product.log_group &&
      alltrue([for job in [var.release_jobs.runtime, var.release_jobs.product] :
        can(regex("^/[a-zA-Z0-9_/.-]+$", job.log_group)) && !contains(values(var.log_groups), job.log_group)
    ]), false)
    error_message = "Release log groups must be separate pre-existing names without wildcards, distinct from both each other and service log groups."
  }
  validation {
    condition = var.release_jobs == null ? true : try(
      can(regex("^[a-f0-9]{40}$", var.release_jobs.runtime_grants.source_commit)) &&
      can(regex("^[a-f0-9]{64}$", var.release_jobs.runtime_grants.sql_sha256)), false
    )
    error_message = "Pin the operator-only Runtime grant source to a full Git commit and SHA256 of db/roles/service.sql."
  }
}

locals {
  release_roles = var.release_jobs == null ? {} : {
    runtime = {
      uid         = "65532:65532", profile = "runtime-release", image = var.images.runtime
      command     = ["/app/migrate"], secret_keys = ["DATABASE_URL"]
      environment = { SENTRYRUNTIME_MIGRATIONS_DIRECTORY = "/app/db/migrations" }
    }
    product = {
      uid     = "10001:10001", profile = "search-release", image = var.images.search
      command = ["python", "-m", "dev.migrate_storage"], secret_keys = local.db_secret_keys
      environment = {
        ENVIRONMENT = "staging", DB_SSLMODE = "verify-full", DB_SSLROOTCERT = "/run/material/postgres-ca.pem"
        DB_DEBUG    = "false", PYTHON_DOTENV_DISABLED = "1"
      }
    }
  }
  release_log_configuration = { for name in keys(local.release_roles) : name => {
    logDriver = "awslogs"
    options = {
      awslogs-group         = var.release_jobs[name].log_group
      awslogs-region        = var.region
      awslogs-stream-prefix = "${name}-release"
    }
  } }
  release_task_contracts = { for name, role in local.release_roles : name => [
    {
      name                   = "init"
      image                  = var.images.search
      essential              = false
      startTimeout           = 120
      user                   = "0:0"
      workingDirectory       = "/"
      readonlyRootFilesystem = true
      linuxParameters        = { capabilities = { drop = local.init_drop_capabilities } }
      command = [
        "python", "-m", "dev.prepare_service_volumes", "--profile", role.profile,
        "--material-dir", "/run/material", "--secret-id", var.release_jobs[name].material_bundle.arn,
        "--version-id", var.release_jobs[name].material_bundle.version_id, "--region", var.region
      ]
      mountPoints      = [{ sourceVolume = "material", containerPath = "/run/material", readOnly = false }]
      logConfiguration = local.release_log_configuration[name]
    },
    {
      name                   = "migration"
      image                  = role.image
      essential              = true
      user                   = role.uid
      workingDirectory       = "/"
      readonlyRootFilesystem = true
      linuxParameters        = { capabilities = { drop = ["ALL"] } }
      dependsOn              = [{ containerName = "init", condition = "SUCCESS" }]
      startTimeout           = 120
      stopTimeout            = 30
      command                = role.command
      environment            = [for key, value in role.environment : { name = key, value = value }]
      secrets = [for key in role.secret_keys : {
        name      = key
        valueFrom = "${var.release_jobs[name].environment_bundle.arn}:${key}::${var.release_jobs[name].environment_bundle.version_id}"
      }]
      mountPoints      = [{ sourceVolume = "material", containerPath = "/run/material", readOnly = true }]
      portMappings     = []
      logConfiguration = local.release_log_configuration[name]
    }
  ] }
  release_task_policies = { for name in keys(local.release_roles) : name => {
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PinnedDatabaseCA", Effect = "Allow", Action = ["secretsmanager:GetSecretValue"]
      Resource  = [var.release_jobs[name].material_bundle.arn]
      Condition = { StringEquals = { "secretsmanager:VersionId" = var.release_jobs[name].material_bundle.version_id } }
    }]
  } }
  release_execution_policies = { for name in keys(local.release_roles) : name => {
    Version = "2012-10-17"
    Statement = [
      { Sid = "RegistryToken", Effect = "Allow", Action = ["ecr:GetAuthorizationToken"], Resource = ["*"] },
      {
        Sid      = "PullImages", Effect = "Allow", Action = ["ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"]
        Resource = name == "runtime" ? [local.ecr_arns.runtime, local.ecr_arns.search] : [local.ecr_arns.search]
      },
      {
        Sid      = "TaskLogs", Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = ["arn:aws:logs:${var.region}:${var.account_id}:log-group:${var.release_jobs[name].log_group}:log-stream:${name}-release/*"]
      },
      {
        Sid       = "PinnedOwnerEnvironment", Effect = "Allow", Action = ["secretsmanager:GetSecretValue"]
        Resource  = [var.release_jobs[name].environment_bundle.arn]
        Condition = { StringEquals = { "secretsmanager:VersionId" = var.release_jobs[name].environment_bundle.version_id } }
      }
    ]
  } }
}

resource "aws_iam_role" "release_task" {
  for_each           = local.release_roles
  name               = "${var.name_prefix}-${each.key}-release-task"
  assume_role_policy = local.assume_task_role
}

resource "aws_iam_role_policy" "release_task" {
  for_each = local.release_roles
  name     = "bounded-release-material"
  role     = aws_iam_role.release_task[each.key].id
  policy   = jsonencode(local.release_task_policies[each.key])
}

resource "aws_iam_role" "release_execution" {
  for_each           = local.release_roles
  name               = "${var.name_prefix}-${each.key}-release-execution"
  assume_role_policy = local.assume_task_role
}

resource "aws_iam_role_policy" "release_execution" {
  for_each = local.release_roles
  name     = "bounded-release-bootstrap"
  role     = aws_iam_role.release_execution[each.key].id
  policy   = jsonencode(local.release_execution_policies[each.key])
}

resource "aws_ecs_task_definition" "release" {
  for_each                 = local.release_roles
  family                   = "${var.name_prefix}-${each.key}-release"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  task_role_arn            = aws_iam_role.release_task[each.key].arn
  execution_role_arn       = aws_iam_role.release_execution[each.key].arn
  container_definitions    = jsonencode(local.release_task_contracts[each.key])
  runtime_platform {
    cpu_architecture        = "ARM64"
    operating_system_family = "LINUX"
  }
  volume { name = "material" }
  depends_on = [aws_iam_role_policy.release_task, aws_iam_role_policy.release_execution]
}

output "release_task_contracts" {
  value = local.release_task_contracts
}

output "release_task_policies" {
  value = local.release_task_policies
}

output "release_execution_policies" {
  value = local.release_execution_policies
}

output "release_grant_contract" {
  description = "Operator-only source/provenance gate; this module does not retrieve, execute or grant SQL. Verify source-to-image correspondence separately."
  value = var.release_jobs == null ? null : {
    source_commit = var.release_jobs.runtime_grants.source_commit
    sql_sha256    = var.release_jobs.runtime_grants.sql_sha256
    path          = "db/roles/service.sql"
    execution     = "operator-only-after-runtime-migration"
  }
}
