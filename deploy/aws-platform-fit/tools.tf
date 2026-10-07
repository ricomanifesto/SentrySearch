# Guarded grant, proof and same-database reconciliation jobs (release-tools image,
# docs/release-tools.md). Every value that decides what runs is fixed in the
# per-release task definition: the image digest, the absolute deadline and job
# budget, the tools and SQL digests and the expected database identity. A
# retained release never changes them; a new value is a new release scope.
variable "release_tools" {
  description = "Optional guarded release-tools jobs for one release. Requires release_jobs. Bundles are references only, never secret values."
  type = object({
    release_id     = string
    image          = string
    not_after      = string
    budget_seconds = number
    tools_sha256   = string
    sql_sha256 = object({
      runtime_grant = string, product_grant = string, runtime_proof = string, product_proof = string, reconcile = string
    })
    runtime = object({ database = string, owner = string, service = string, proof_bundle = object({ arn = string, version_id = string }) })
    product = object({ database = string, owner = string, service = string, proof_bundle = object({ arn = string, version_id = string }) })
  })
  default = null
  validation {
    condition     = var.release_tools == null || var.release_jobs != null
    error_message = "Release-tools jobs need the owner release jobs: grants follow migrations and share their owner bundle and CA material."
  }
  validation {
    condition = var.release_tools == null ? true : try(
      can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", var.release_tools.release_id)) &&
      can(regex("^${var.account_id}\\.dkr\\.ecr\\.${var.region}\\.amazonaws\\.com/[a-z0-9]+([._/-][a-z0-9]+)*@sha256:[a-f0-9]{64}$", var.release_tools.image)), false
    )
    error_message = "Use the manifest's lowercase release UUID and a same-account, same-region ECR release-tools image pinned by digest."
  }
  validation {
    condition = var.release_tools == null ? true : try(
      can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$", var.release_tools.not_after)) &&
      timeadd(var.release_tools.not_after, "0s") == var.release_tools.not_after &&
      timecmp(var.release_tools.not_after, timeadd(plantimestamp(), "168h")) <= 0 &&
      var.release_tools.budget_seconds == floor(var.release_tools.budget_seconds) &&
      var.release_tools.budget_seconds >= 60 && var.release_tools.budget_seconds <= 3600, false
    )
    error_message = "Fix an absolute UTC deadline (YYYY-MM-DDTHH:MM:SSZ) no more than seven days after this plan (the manifest's maximum validity) and a whole-second job budget of 60-3600 seconds."
  }
  validation {
    condition = var.release_tools == null ? true : try(
      alltrue([for digest in concat([var.release_tools.tools_sha256], values(var.release_tools.sql_sha256)) : can(regex("^[a-f0-9]{64}$", digest))]) &&
      var.release_tools.sql_sha256.runtime_grant == var.release_jobs.runtime_grants.sql_sha256, false
    )
    error_message = "Pin the tools and SQL digests from the image's build report; the Runtime grant digest must equal the reviewed db/roles/service.sql pin."
  }
  validation {
    condition = var.release_tools == null ? true : try(alltrue([for name in ["runtime", "product"] :
      alltrue([for value in [var.release_tools[name].database, var.release_tools[name].owner, var.release_tools[name].service] :
      can(regex("^[a-z_][a-z0-9_]{0,62}$", value))]) &&
      var.release_tools[name].owner != var.release_tools[name].service &&
      !contains(["postgres", "template0", "template1", "rdsadmin"], var.release_tools[name].database)
    ]), false)
    error_message = "Name each dedicated database, its owner and its distinct service login with lowercase PostgreSQL identifiers."
  }
  validation {
    condition = var.release_tools == null ? true : try(
      alltrue([for name in ["runtime", "product"] :
        can(regex("^arn:aws:secretsmanager:${var.region}:${var.account_id}:secret:[A-Za-z0-9/_+=.@-]+-[A-Za-z0-9]{6}$", var.release_tools[name].proof_bundle.arn)) &&
        can(regex("^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$", var.release_tools[name].proof_bundle.version_id))
      ]) &&
      var.release_tools.runtime.proof_bundle.arn != var.release_tools.product.proof_bundle.arn &&
      alltrue([for name in ["runtime", "product"] : !contains(concat(
        [for bundle in values(var.environment_bundles) : bundle.arn], [for bundle in values(var.material_bundles) : bundle.arn],
        flatten([for job in ["runtime", "product"] : [var.release_jobs[job].environment_bundle.arn, var.release_jobs[job].material_bundle.arn]])
      ), var.release_tools[name].proof_bundle.arn)]), false
    )
    error_message = "Each proof bundle holds only its service login at an exact UUID version, distinct from every service, material and owner bundle."
  }
}

locals {
  tools = var.release_tools
  tools_jobs = local.tools == null ? {} : {
    runtime-grant     = { database = "runtime", kind = "grant", role = "grant", sql = "runtime_grant" }
    product-grant     = { database = "product", kind = "grant", role = "grant", sql = "product_grant" }
    runtime-proof     = { database = "runtime", kind = "proof", role = "proof", sql = "runtime_proof" }
    product-proof     = { database = "product", kind = "proof", role = "proof", sql = "product_proof" }
    runtime-reconcile = { database = "runtime", kind = "reconcile", role = "recon", sql = "reconcile" }
    product-reconcile = { database = "product", kind = "reconcile", role = "recon", sql = "reconcile" }
  }
  # Grant and reconciliation run as the database owner; proofs run as the
  # service login they prove, from a bundle that holds only that login.
  tools_principal = { for key, job in local.tools_jobs : key => job.kind == "proof" ? local.tools[job.database].service : local.tools[job.database].owner }
  tools_bundle = { for key, job in local.tools_jobs : key => (
    job.kind == "proof" ? local.tools[job.database].proof_bundle : var.release_jobs[job.database].environment_bundle
  ) }
  tools_secret_keys = { runtime = ["DATABASE_URL"], product = local.db_secret_keys }
  tools_ecr_arn     = local.tools == null ? null : "arn:aws:ecr:${var.region}:${var.account_id}:repository/${split("@", split(".amazonaws.com/", local.tools.image)[1])[0]}"
  tools_environment = { for key, job in local.tools_jobs : key => merge(
    {
      RELEASE_ID                 = local.tools.release_id
      RELEASE_JOB_ID             = key
      RELEASE_DATABASE           = job.database
      RELEASE_NOT_AFTER          = local.tools.not_after
      RELEASE_JOB_BUDGET_SECONDS = tostring(local.tools.budget_seconds)
      RELEASE_TOOLS_SHA256       = local.tools.tools_sha256
      RELEASE_SQL_SHA256         = local.tools.sql_sha256[job.sql]
      RELEASE_EXPECT_DATABASE    = local.tools[job.database].database
      RELEASE_EXPECT_PRINCIPAL   = local.tools_principal[key]
    },
    job.kind == "grant" ? { RELEASE_SERVICE_ROLE = local.tools[job.database].service } : {},
    job.kind == "proof" ? { RELEASE_OWNER_ROLE = local.tools[job.database].owner } : {},
  ) }
  tools_log_configuration = { for key, job in local.tools_jobs : key => {
    logDriver = "awslogs"
    options = {
      awslogs-group         = var.release_jobs[job.database].log_group
      awslogs-region        = var.region
      awslogs-stream-prefix = key
    }
  } }
  tools_task_contracts = { for key, job in local.tools_jobs : key => [
    # The same fail-closed CA-only init as the owner migration job.
    merge(local.release_task_contracts[job.database][0], { logConfiguration = local.tools_log_configuration[key] }),
    {
      name                   = job.kind
      image                  = local.tools.image
      essential              = true
      user                   = local.release_roles[job.database].uid
      workingDirectory       = "/"
      readonlyRootFilesystem = true
      linuxParameters        = { capabilities = { drop = ["ALL"] } }
      dependsOn              = [{ containerName = "init", condition = "SUCCESS" }]
      startTimeout           = 120
      # Above the in-image stop grace, so a stop request lets the job reap psql.
      stopTimeout = 30
      command     = [job.kind]
      environment = [for name, value in local.tools_environment[key] : { name = name, value = value }]
      secrets = [for name in local.tools_secret_keys[job.database] : {
        name      = name
        valueFrom = "${local.tools_bundle[key].arn}:${name}::${local.tools_bundle[key].version_id}"
      }]
      mountPoints      = [{ sourceVolume = "material", containerPath = "/run/material", readOnly = true }]
      portMappings     = []
      logConfiguration = local.tools_log_configuration[key]
    }
  ] }
  tools_execution_policies = { for key, job in local.tools_jobs : key => {
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
        Sid       = "PinnedJobEnvironment", Effect = "Allow", Action = ["secretsmanager:GetSecretValue"]
        Resource  = [local.tools_bundle[key].arn]
        Condition = { StringEquals = { "secretsmanager:VersionId" = local.tools_bundle[key].version_id } }
      },
    ]
  } }
  # The controller reads a job's receipt only from the stream of the exact task
  # it observed: <prefix>/<app container>/<task id>.
  release_receipt_streams = { for name in keys(local.release_roles) : "${name}-migrate" =>
    "arn:aws:logs:${var.region}:${var.account_id}:log-group:${var.release_jobs[name].log_group}:log-stream:${name}-release/migration/*"
  }
  tools_receipt_streams = { for key, job in local.tools_jobs : key =>
    "arn:aws:logs:${var.region}:${var.account_id}:log-group:${var.release_jobs[job.database].log_group}:log-stream:${key}/${job.kind}/*"
  }
}

resource "aws_iam_role" "tools_execution" {
  for_each           = local.tools_jobs
  name               = "${local.identity_prefix}-${each.value.database}-${each.value.role}-execution"
  assume_role_policy = local.assume_task_role
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_role_policy" "tools_execution" {
  for_each = local.tools_jobs
  name     = "bounded-tools-job-${substr(sha256(jsonencode(local.tools_execution_policies[each.key])), 0, 16)}"
  role     = aws_iam_role.tools_execution[each.key].id
  policy   = jsonencode(local.tools_execution_policies[each.key])
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_ecs_task_definition" "tools" {
  for_each                 = local.tools_jobs
  family                   = "${var.name_prefix}-${each.key}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  # The CA-only release task role: the job itself needs no AWS authority.
  task_role_arn         = aws_iam_role.release_task[each.value.database].arn
  execution_role_arn    = aws_iam_role.tools_execution[each.key].arn
  container_definitions = jsonencode(local.tools_task_contracts[each.key])
  skip_destroy          = true
  runtime_platform {
    cpu_architecture        = "ARM64"
    operating_system_family = "LINUX"
  }
  volume { name = "material" }
  depends_on = [aws_iam_role_policy.release_task, aws_iam_role_policy.tools_execution]
  lifecycle {
    prevent_destroy = true
  }
}

output "tools_task_contracts" {
  value = local.tools_task_contracts
}

output "tools_execution_policies" {
  value = local.tools_execution_policies
}

output "receipt_log_streams" {
  description = "Per-job receipt stream ARN patterns (app container only) for the release launcher's read policy."
  value       = merge(local.release_receipt_streams, local.tools_receipt_streams)
}

output "release_tools_bindings" {
  description = "Review values for the release record: the fixed deadline and digests that the plan binds into each revision, and each grant/proof job's exact receipt expectation for the manifest (proof schema equals the migrated revision). The manifest does not repeat the deadline: the reviewed plan hash and exact revisions bind it."
  value = local.tools == null ? null : {
    release_id     = local.tools.release_id
    not_after      = local.tools.not_after
    budget_seconds = local.tools.budget_seconds
    tools_sha256   = local.tools.tools_sha256
    receipt_schema = "sentry.release-tools.job.v1"
    expectations = { for key, job in local.tools_jobs : key => merge(
      { database = local.tools[job.database].database, principal = local.tools_principal[key] },
      job.kind == "grant" ? { service_role = local.tools[job.database].service, sql_digest = local.tools.sql_sha256[job.sql] } : {},
    ) if job.kind != "reconcile" }
  }
}

output "tools_task_roles" {
  description = "Role bindings of each registered guarded-job revision."
  value = { for key, task in aws_ecs_task_definition.tools : key => {
    task_role_arn = task.task_role_arn, execution_role_arn = task.execution_role_arn
  } }
}
