# Runtime and API operational observers (release-tools observe-runtime and
# observe-api, docs/release-tools.md#operational-observers). The controller
# launches each after the services start and binds its receipt to the recorded
# service task's network address. Each revision fixes the release, check id,
# deadline, budget and the service's private name and port. The Runtime
# observer's CA and probe token come from its own bundle, shared with no service
# or job; the API observer needs no material and no AWS authority.
variable "observers" {
  description = "Optional Runtime and API observer tasks for one release. Requires release_tools. The bundle holds references only, never values."
  type = object({
    namespace      = string
    budget_seconds = number
    runtime_bundle = object({ arn = string, version_id = string })
    log_group      = string
  })
  default = null
  validation {
    condition     = var.observers == null || var.release_tools != null
    error_message = "Observers run the release-tools image under the release's fixed deadline: they need release_tools."
  }
  validation {
    condition = var.observers == null ? true : try(
      can(regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", var.observers.namespace)) &&
      !can(regex("^[0-9.]+$", var.observers.namespace)) &&
      var.runtime_server_name == "runtime.${var.observers.namespace}", false
    )
    error_message = "Use the private DNS namespace whose runtime.<namespace> name is the Runtime certificate's SAN (runtime_server_name)."
  }
  validation {
    condition = var.observers == null ? true : try(
      var.observers.budget_seconds == floor(var.observers.budget_seconds) &&
      var.observers.budget_seconds >= 60 && var.observers.budget_seconds <= 3600, false
    )
    error_message = "An observer's budget is a whole number of seconds from 60 to 3600."
  }
  validation {
    condition = var.observers == null ? true : try(
      can(regex("^arn:aws:secretsmanager:${var.region}:${var.account_id}:secret:[A-Za-z0-9/_+=.@-]+-[A-Za-z0-9]{6}$", var.observers.runtime_bundle.arn)) &&
      can(regex("^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$", var.observers.runtime_bundle.version_id)) &&
      !contains(concat(
        [for bundle in values(var.environment_bundles) : bundle.arn], [for bundle in values(var.material_bundles) : bundle.arn],
        flatten([for job in ["runtime", "product"] : [var.release_jobs[job].environment_bundle.arn, var.release_jobs[job].material_bundle.arn]]),
        [for job in ["runtime", "product"] : var.release_tools[job].proof_bundle.arn],
      ), var.observers.runtime_bundle.arn), false
    )
    error_message = "The Runtime observer's bundle is its own secret at an exact UUID version, distinct from every service, material, owner and proof bundle."
  }
  validation {
    condition = var.observers == null ? true : try(
      can(regex("^/[a-zA-Z0-9_/.-]+$", var.observers.log_group)) &&
      !contains(concat(values(var.log_groups), [var.release_jobs.runtime.log_group, var.release_jobs.product.log_group]), var.observers.log_group), false
    )
    error_message = "Observers log to their own pre-existing group, distinct from every service and release-job log group."
  }
}

locals {
  observers = var.observers
  observer_jobs = local.observers == null ? {} : {
    runtime-observe = { target = "runtime", port = 8443, command = "observe-runtime" }
    api-observe     = { target = "api", port = 8001, command = "observe-api" }
  }
  observer_log_configuration = { for key in keys(local.observer_jobs) : key => {
    logDriver = "awslogs"
    options = {
      awslogs-group         = local.observers.log_group
      awslogs-region        = var.region
      awslogs-stream-prefix = key
    }
  } }
  observer_environment = { for key, job in local.observer_jobs : key => {
    RELEASE_ID                   = local.tools.release_id
    RELEASE_CHECK_ID             = key
    RELEASE_NOT_AFTER            = local.tools.not_after
    RELEASE_CHECK_BUDGET_SECONDS = tostring(local.observers.budget_seconds)
    RELEASE_TARGET_HOST          = "${job.target}.${local.observers.namespace}"
    RELEASE_TARGET_PORT          = tostring(job.port)
  } }
  # The two observers have different shapes (only the Runtime one has an init
  # and material), so each is built on its own and never unified by a conditional.
  observer_common = { for key, job in local.observer_jobs : key => {
    name                   = "observer"
    image                  = local.tools.image
    essential              = true
    user                   = "65532:65532"
    workingDirectory       = "/"
    readonlyRootFilesystem = true
    linuxParameters        = { capabilities = { drop = ["ALL"] } }
    startTimeout           = 120
    # Above the in-image 5 s stop grace.
    stopTimeout      = 30
    command          = [job.command]
    environment      = [for name, value in local.observer_environment[key] : { name = name, value = value }]
    portMappings     = []
    logConfiguration = local.observer_log_configuration[key]
  } }
  observer_runtime_contract = local.observers == null ? null : [
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
        "python", "-m", "dev.prepare_service_volumes", "--profile", "runtime-observer",
        "--material-dir", "/run/material", "--secret-id", local.observers.runtime_bundle.arn,
        "--version-id", local.observers.runtime_bundle.version_id, "--region", var.region
      ]
      mountPoints      = [{ sourceVolume = "material", containerPath = "/run/material", readOnly = false }]
      logConfiguration = local.observer_log_configuration["runtime-observe"]
    },
    merge(local.observer_common["runtime-observe"], {
      dependsOn   = [{ containerName = "init", condition = "SUCCESS" }]
      mountPoints = [{ sourceVolume = "material", containerPath = "/run/material", readOnly = true }]
    }),
  ]
  observer_api_contract = local.observers == null ? null : [
    merge(local.observer_common["api-observe"], { mountPoints = [] }),
  ]
  observer_task_contracts = merge(
    { for key in keys(local.observer_jobs) : key => local.observer_runtime_contract if key == "runtime-observe" },
    { for key in keys(local.observer_jobs) : key => local.observer_api_contract if key == "api-observe" },
  )
  # Only the Runtime observer's init reads a secret: its own material bundle.
  observer_task_policy = local.observers == null ? null : {
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PinnedObserverMaterial", Effect = "Allow", Action = ["secretsmanager:GetSecretValue"]
      Resource  = [local.observers.runtime_bundle.arn]
      Condition = { StringEquals = { "secretsmanager:VersionId" = local.observers.runtime_bundle.version_id } }
    }]
  }
  observer_execution_policies = { for key, job in local.observer_jobs : key => {
    Version = "2012-10-17"
    Statement = [
      { Sid = "RegistryToken", Effect = "Allow", Action = ["ecr:GetAuthorizationToken"], Resource = ["*"] },
      {
        Sid      = "PullImages", Effect = "Allow", Action = ["ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"]
        Resource = job.target == "runtime" ? [local.ecr_arns.search, local.tools_ecr_arn] : [local.tools_ecr_arn]
      },
      {
        Sid      = "TaskLogs", Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = ["arn:aws:logs:${var.region}:${var.account_id}:log-group:${local.observers.log_group}:log-stream:${key}/*"]
      },
    ]
  } }
  # The controller reads an observer's receipt only from <check>/observer/<task id>.
  observer_receipt_streams = { for key in keys(local.observer_jobs) : key =>
    "arn:aws:logs:${var.region}:${var.account_id}:log-group:${local.observers.log_group}:log-stream:${key}/observer/*"
  }
}

resource "aws_iam_role" "observer_task" {
  count              = local.observers == null ? 0 : 1
  name               = "${local.identity_prefix}-runtime-observe-task"
  assume_role_policy = local.assume_task_role
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_role_policy" "observer_task" {
  count  = local.observers == null ? 0 : 1
  name   = "bounded-observer-material-${substr(sha256(jsonencode(local.observer_task_policy)), 0, 16)}"
  role   = aws_iam_role.observer_task[0].id
  policy = jsonencode(local.observer_task_policy)
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_role" "observer_execution" {
  for_each           = local.observer_jobs
  name               = "${local.identity_prefix}-${each.key}-execution"
  assume_role_policy = local.assume_task_role
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_role_policy" "observer_execution" {
  for_each = local.observer_jobs
  name     = "bounded-observer-job-${substr(sha256(jsonencode(local.observer_execution_policies[each.key])), 0, 16)}"
  role     = aws_iam_role.observer_execution[each.key].id
  policy   = jsonencode(local.observer_execution_policies[each.key])
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_ecs_task_definition" "observer" {
  for_each                 = local.observer_jobs
  family                   = "${var.name_prefix}-${each.key}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  # The API observer needs no AWS authority at all; the Runtime observer's init
  # reads only its own pinned material.
  task_role_arn         = each.value.target == "runtime" ? aws_iam_role.observer_task[0].arn : null
  execution_role_arn    = aws_iam_role.observer_execution[each.key].arn
  container_definitions = jsonencode(local.observer_task_contracts[each.key])
  skip_destroy          = true
  runtime_platform {
    cpu_architecture        = "ARM64"
    operating_system_family = "LINUX"
  }
  dynamic "volume" {
    for_each = each.value.target == "runtime" ? ["material"] : []
    content {
      name = volume.value
    }
  }
  depends_on = [aws_iam_role_policy.observer_task, aws_iam_role_policy.observer_execution]
  lifecycle {
    prevent_destroy = true
  }
}

output "observer_task_contracts" {
  value = local.observer_task_contracts
}

output "observer_execution_policies" {
  value = local.observer_execution_policies
}

output "observer_task_policy" {
  value = local.observer_task_policy
}

output "observer_receipt_streams" {
  description = "Per-observer receipt stream ARN patterns (observer container only) for the attended launcher's observe policy."
  value       = local.observer_receipt_streams
}

output "observer_bindings" {
  description = "Review values for the manifest's operational checks: check ids, targets, ports and the receipt schema."
  value = local.observers == null ? null : {
    receipt_schema = "sentry.operational.v1"
    budget_seconds = local.observers.budget_seconds
    checks = { for key, job in local.observer_jobs : key => {
      target = job.target, host = "${job.target}.${local.observers.namespace}", port = job.port
    } }
  }
}
