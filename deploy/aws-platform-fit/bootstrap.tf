# First-deployment bootstrap jobs (release-tools bootstrap, one per database).
# Each connects to its own instance's postgres database as the RDS-managed
# administrator and creates the dedicated database, its owner and its service
# login. The administrator secret and the bootstrap credentials are bundles no
# service or other job shares; each job has its own task and execution roles.
# Only the separate release-launcher-bootstrap policy can launch these
# revisions, and nothing in this run attaches it: the live administrator path
# is a separate approval.
variable "bootstrap" {
  description = "Optional bootstrap jobs for a fresh instance pair. Requires release_tools. Bundles are references only, never secret values."
  type = object({
    sql_sha256 = string
    runtime = object({
      host          = string
      administrator = string
      admin_secret  = object({ arn = string, version_id = string })
      credentials   = object({ arn = string, version_id = string })
    })
    product = object({
      host          = string
      administrator = string
      admin_secret  = object({ arn = string, version_id = string })
      credentials   = object({ arn = string, version_id = string })
    })
  })
  default = null
  validation {
    condition     = var.bootstrap == null || var.release_tools != null
    error_message = "Bootstrap runs the release-tools image under the release's fixed deadline and identities: it needs release_tools."
  }
  validation {
    condition     = var.bootstrap == null ? true : try(can(regex("^[a-f0-9]{64}$", var.bootstrap.sql_sha256)), false)
    error_message = "Pin the bootstrap SQL digest from the release-tools image's build report."
  }
  validation {
    condition = var.bootstrap == null ? true : try(alltrue([for name in ["runtime", "product"] :
      can(regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", var.bootstrap[name].host)) &&
      can(regex("^[a-z_][a-z0-9_]{0,62}$", var.bootstrap[name].administrator)) &&
      !contains([var.release_tools[name].owner, var.release_tools[name].service], var.bootstrap[name].administrator)
    ]), false)
    error_message = "Name each instance's private endpoint and administrator login; the administrator is neither the owner nor the service login."
  }
  validation {
    condition = var.bootstrap == null ? true : try(
      alltrue([for bundle in flatten([for name in ["runtime", "product"] : [var.bootstrap[name].admin_secret, var.bootstrap[name].credentials]]) :
        can(regex("^arn:aws:secretsmanager:${var.region}:${var.account_id}:secret:[A-Za-z0-9/_+=.@!-]+-[A-Za-z0-9]{6}$", bundle.arn)) &&
        can(regex("^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$", bundle.version_id))
      ]) &&
      length(toset(flatten([for name in ["runtime", "product"] : [var.bootstrap[name].admin_secret.arn, var.bootstrap[name].credentials.arn]]))) == 4 &&
      alltrue([for arn in flatten([for name in ["runtime", "product"] : [var.bootstrap[name].admin_secret.arn, var.bootstrap[name].credentials.arn]]) :
        !contains(concat(
          [for bundle in values(var.environment_bundles) : bundle.arn], [for bundle in values(var.material_bundles) : bundle.arn],
          flatten([for job in ["runtime", "product"] : [var.release_jobs[job].environment_bundle.arn, var.release_jobs[job].material_bundle.arn]]),
          [for job in ["runtime", "product"] : var.release_tools[job].proof_bundle.arn],
          var.observers == null ? [] : [var.observers.runtime_bundle.arn],
      ), arn)]), false
    )
    error_message = "Each instance's administrator secret and bootstrap credentials are four distinct bundles at exact UUID versions, shared with no service, owner, proof or observer bundle."
  }
}

locals {
  bootstrap_jobs = var.bootstrap == null ? {} : {
    runtime-bootstrap = { database = "runtime" }
    product-bootstrap = { database = "product" }
  }
  bootstrap_environment = { for key, job in local.bootstrap_jobs : key => {
    RELEASE_ID                 = local.tools.release_id
    RELEASE_JOB_ID             = key
    RELEASE_DATABASE           = job.database
    RELEASE_NOT_AFTER          = local.tools.not_after
    RELEASE_JOB_BUDGET_SECONDS = tostring(local.tools.budget_seconds)
    RELEASE_TOOLS_SHA256       = local.tools.tools_sha256
    RELEASE_SQL_SHA256         = var.bootstrap.sql_sha256
    RELEASE_EXPECT_DATABASE    = "postgres"
    RELEASE_EXPECT_PRINCIPAL   = var.bootstrap[job.database].administrator
    RELEASE_TARGET_DATABASE    = local.tools[job.database].database
    RELEASE_OWNER_ROLE         = local.tools[job.database].owner
    RELEASE_SERVICE_ROLE       = local.tools[job.database].service
    DB_HOST                    = var.bootstrap[job.database].host
    DB_PORT                    = "5432"
    DB_NAME                    = "postgres"
  } }
  # The RDS-managed administrator secret holds username and password; the
  # bootstrap credentials bundle holds the owner and service passwords it sets.
  bootstrap_secrets = { for key, job in local.bootstrap_jobs : key => concat(
    [for name, field in { DB_USER = "username", DB_PASSWORD = "password" } : {
      name                        = name
      valueFrom                   = "${var.bootstrap[job.database].admin_secret.arn}:${field}::${var.bootstrap[job.database].admin_secret.version_id}"
    }],
    [for name in ["RELEASE_OWNER_PASSWORD", "RELEASE_SERVICE_PASSWORD"] : {
      name      = name
      valueFrom = "${var.bootstrap[job.database].credentials.arn}:${name}::${var.bootstrap[job.database].credentials.version_id}"
    }],
  ) }
  bootstrap_log_configuration = { for key, job in local.bootstrap_jobs : key => {
    logDriver = "awslogs"
    options = {
      awslogs-group         = var.release_jobs[job.database].log_group
      awslogs-region        = var.region
      awslogs-stream-prefix = key
    }
  } }
  bootstrap_task_contracts = { for key, job in local.bootstrap_jobs : key => [
    # The same fail-closed CA-only init as the owner migration job.
    merge(local.release_task_contracts[job.database][0], { logConfiguration = local.bootstrap_log_configuration[key] }),
    {
      name                   = "bootstrap"
      image                  = local.tools.image
      essential              = true
      user                   = local.release_roles[job.database].uid
      workingDirectory       = "/"
      readonlyRootFilesystem = true
      linuxParameters        = { capabilities = { drop = ["ALL"] } }
      dependsOn              = [{ containerName = "init", condition = "SUCCESS" }]
      startTimeout           = 120
      stopTimeout            = 30
      command                = ["bootstrap"]
      environment            = [for name, value in local.bootstrap_environment[key] : { name = name, value = value }]
      secrets                = local.bootstrap_secrets[key]
      mountPoints            = [{ sourceVolume = "material", containerPath = "/run/material", readOnly = true }]
      portMappings           = []
      logConfiguration       = local.bootstrap_log_configuration[key]
    }
  ] }
  bootstrap_task_policies = { for key, job in local.bootstrap_jobs : key => {
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PinnedDatabaseCA", Effect = "Allow", Action = ["secretsmanager:GetSecretValue"]
      Resource  = [var.release_jobs[job.database].material_bundle.arn]
      Condition = { StringEquals = { "secretsmanager:VersionId" = var.release_jobs[job.database].material_bundle.version_id } }
    }]
  } }
  bootstrap_execution_policies = { for key, job in local.bootstrap_jobs : key => {
    Version = "2012-10-17"
    Statement = [
      { Sid = "RegistryToken", Effect = "Allow", Action = ["ecr:GetAuthorizationToken"], Resource = ["*"] },
      {
        Sid      = "PullImages", Effect = "Allow", Action = ["ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"]
        Resource = [local.ecr_arns.search, local.tools_ecr_arn]
      },
      {
        Sid      = "TaskLogs", Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = ["arn:aws:logs:${var.region}:${var.account_id}:log-group:${var.release_jobs[job.database].log_group}:log-stream:${key}/*"]
      },
      {
        Sid       = "PinnedAdministrator", Effect = "Allow", Action = ["secretsmanager:GetSecretValue"]
        Resource  = [var.bootstrap[job.database].admin_secret.arn]
        Condition = { StringEquals = { "secretsmanager:VersionId" = var.bootstrap[job.database].admin_secret.version_id } }
      },
      {
        Sid       = "PinnedBootstrapCredentials", Effect = "Allow", Action = ["secretsmanager:GetSecretValue"]
        Resource  = [var.bootstrap[job.database].credentials.arn]
        Condition = { StringEquals = { "secretsmanager:VersionId" = var.bootstrap[job.database].credentials.version_id } }
      },
    ]
  } }
  bootstrap_receipt_streams = { for key, job in local.bootstrap_jobs : key =>
    "arn:aws:logs:${var.region}:${var.account_id}:log-group:${var.release_jobs[job.database].log_group}:log-stream:${key}/bootstrap/*"
  }
}

resource "aws_iam_role" "bootstrap_task" {
  for_each           = local.bootstrap_jobs
  name               = "${local.identity_prefix}-${each.value.database}-boot-task"
  assume_role_policy = local.assume_task_role
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_role_policy" "bootstrap_task" {
  for_each = local.bootstrap_jobs
  name     = "bounded-bootstrap-material-${substr(sha256(jsonencode(local.bootstrap_task_policies[each.key])), 0, 16)}"
  role     = aws_iam_role.bootstrap_task[each.key].id
  policy   = jsonencode(local.bootstrap_task_policies[each.key])
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_role" "bootstrap_execution" {
  for_each           = local.bootstrap_jobs
  name               = "${local.identity_prefix}-${each.value.database}-boot-execution"
  assume_role_policy = local.assume_task_role
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_role_policy" "bootstrap_execution" {
  for_each = local.bootstrap_jobs
  name     = "bounded-bootstrap-job-${substr(sha256(jsonencode(local.bootstrap_execution_policies[each.key])), 0, 16)}"
  role     = aws_iam_role.bootstrap_execution[each.key].id
  policy   = jsonencode(local.bootstrap_execution_policies[each.key])
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_ecs_task_definition" "bootstrap" {
  for_each                 = local.bootstrap_jobs
  family                   = "${var.name_prefix}-${each.key}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  task_role_arn            = aws_iam_role.bootstrap_task[each.key].arn
  execution_role_arn       = aws_iam_role.bootstrap_execution[each.key].arn
  container_definitions    = jsonencode(local.bootstrap_task_contracts[each.key])
  skip_destroy             = true
  runtime_platform {
    cpu_architecture        = "ARM64"
    operating_system_family = "LINUX"
  }
  volume { name = "material" }
  depends_on = [aws_iam_role_policy.bootstrap_task, aws_iam_role_policy.bootstrap_execution]
  lifecycle {
    prevent_destroy = true
  }
}

output "bootstrap_task_contracts" {
  value = local.bootstrap_task_contracts
}

output "bootstrap_task_policies" {
  value = local.bootstrap_task_policies
}

output "bootstrap_execution_policies" {
  value = local.bootstrap_execution_policies
}

output "bootstrap_receipt_streams" {
  description = "Per-bootstrap receipt stream ARN patterns, for the separate unattached bootstrap launcher only."
  value       = local.bootstrap_receipt_streams
}

output "bootstrap_bindings" {
  description = "Each bootstrap job's exact receipt expectation for a first-deployment manifest."
  value = var.bootstrap == null ? null : { for key, job in local.bootstrap_jobs : key => {
    database   = local.tools[job.database].database, principal = var.bootstrap[job.database].administrator
    owner_role = local.tools[job.database].owner, service_role = local.tools[job.database].service
  } }
}
