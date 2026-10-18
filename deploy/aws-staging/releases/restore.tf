# Restore verifications (F077): the guarded reconcile and proof jobs that the release
# controller runs against one restored instance under its own verification id
# (docs/release-controller.md, "Restore verification runs"). Each entry names one of
# the current release's databases, pins its own release-tools image and digests and
# reads only its own two restore bundles. Its definitions never belong to a release
# key: every retained release renders exactly what it rendered without them.
#
# An entry exists for one verification only: it is added, the verification runs, the
# attended set is detached, and the entry is removed in its own checked plan (IAM
# refuses to delete an attached policy). The revisions stay registered as evidence. A
# rollback re-plan renders no entry and may remove exactly these resources once the
# attended set is detached; an entry left past its deadline fails validation in every
# plan until it is removed.
variable "restore_verifications" {
  description = "At most one verification per database, keyed by the database. Bundles are references only, never secret values."
  type = map(object({
    database            = string
    instance_identifier = string
    not_after           = string
    budget_seconds      = number
    image               = string
    tools_sha256        = string
    sql_sha256          = object({ reconcile = string, proof = string })
    owner_bundle        = object({ arn = string, version_id = string })
    proof_bundle        = object({ arn = string, version_id = string })
  }))
  default = {}
  validation {
    condition     = alltrue([for key, entry in var.restore_verifications : contains(["runtime", "product"], key) && entry.database == key])
    error_message = "Key each verification by its database, runtime or product."
  }
  validation {
    # The kit's restore label rule: lowercase letters and digits, single inner
    # hyphens, at most 20 characters.
    condition = alltrue([for key, entry in var.restore_verifications :
      can(regex("^${var.name_prefix}-${key}-db-restore-[a-z0-9](-?[a-z0-9])*$", entry.instance_identifier)) &&
      length(entry.instance_identifier) - length("${var.name_prefix}-${key}-db-restore-") <= 20
    ])
    error_message = "Name the restored instance <prefix>-<database>-db-restore-<label>, the identifier the kit's restore created."
  }
  validation {
    condition = alltrue([for entry in values(var.restore_verifications) : try(
      can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$", entry.not_after)) &&
      timeadd(entry.not_after, "0s") == entry.not_after &&
      timecmp(entry.not_after, plantimestamp()) > 0 &&
      timecmp(entry.not_after, timeadd(plantimestamp(), "168h")) <= 0 &&
      entry.budget_seconds == floor(entry.budget_seconds) &&
      entry.budget_seconds >= 60 && entry.budget_seconds <= 3600, false
    )])
    error_message = "Fix an absolute UTC deadline (YYYY-MM-DDTHH:MM:SSZ) after this plan and no more than seven days after it, and a whole-second job budget of 60-3600 seconds."
  }
  validation {
    condition = alltrue([for entry in values(var.restore_verifications) :
      can(regex("^${var.account_id}\\.dkr\\.ecr\\.${var.region}\\.amazonaws\\.com/${var.name_prefix}/release-tools@sha256:[0-9a-f]{64}$", entry.image)) &&
      alltrue([for digest in [entry.tools_sha256, entry.sql_sha256.reconcile, entry.sql_sha256.proof] : can(regex("^[0-9a-f]{64}$", digest))])
    ])
    error_message = "Pin the release-tools image by digest from this environment's release-tools repository, and the tools and SQL digests from its build report."
  }
  validation {
    # The verification proves what the current release proved: the same reconcile
    # and proof programs (the kit refuses a rebuilt image whose programs differ).
    condition = alltrue([for key, entry in var.restore_verifications : try(
      entry.sql_sha256.reconcile == one([for release in values(var.releases) : release.release_tools.sql_sha256.reconcile if release.slot == "current"]) &&
      entry.sql_sha256.proof == one([for release in values(var.releases) : release.release_tools.sql_sha256["${key}_proof"] if release.slot == "current"]), false
    )])
    error_message = "A verification runs the current release's reconcile and proof programs: pin the same SQL digests."
  }
  validation {
    condition = alltrue([for key, entry in var.restore_verifications :
      can(regex("^arn:aws:secretsmanager:${var.region}:${var.account_id}:secret:${var.name_prefix}/restore-owner-environment/${key}-[A-Za-z0-9]{6}$", entry.owner_bundle.arn)) &&
      can(regex("^arn:aws:secretsmanager:${var.region}:${var.account_id}:secret:${var.name_prefix}/restore-proof-environment/${key}-[A-Za-z0-9]{6}$", entry.proof_bundle.arn)) &&
      alltrue([for bundle in [entry.owner_bundle, entry.proof_bundle] : can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", bundle.version_id))])
    ])
    error_message = "Read each verification's owner and proof logins from its own restore-owner-environment/<database> and restore-proof-environment/<database> secrets at exact lowercase UUID VersionIds."
  }
  validation {
    condition = alltrue([for entry in values(var.restore_verifications) : !anytrue([for bundle in [entry.owner_bundle, entry.proof_bundle] :
      contains(flatten([for release in values(var.releases) : concat(
        [for item in values(release.environment_bundles) : item.arn], [for item in values(release.material_bundles) : item.arn],
        [for name in ["runtime", "product"] : [release.release_jobs[name].environment_bundle.arn, release.release_jobs[name].material_bundle.arn, release.release_tools[name].proof_bundle.arn]],
        release.observers == null ? [] : [release.observers.runtime_bundle.arn],
        release.model_provider == null ? [] : [release.model_provider.key_bundle.arn],
        release.bootstrap == null ? [] : flatten([for name in ["runtime", "product"] : [
          release.bootstrap[name].admin_secret.arn, release.bootstrap[name].credentials.arn, release.bootstrap[name].ca_bundle.arn,
        ]]),
      )]), bundle.arn)
    ])])
    error_message = "A restore bundle is never a release's bundle: it names the restored endpoint, not the source instance."
  }
}

locals {
  # The jobs keep the release-tools contract: a job id <database>-<kind> fits the
  # session's application name; the receipt stream is <job id>/<kind>/<task id>.
  restore_jobs = merge([for key, entry in var.restore_verifications : {
    "${key}-rv-recon" = { database = key, kind = "rv-recon", family = "restore-reconcile-${key}", bundle = entry.owner_bundle, sql = entry.sql_sha256.reconcile }
    "${key}-rv-proof" = { database = key, kind = "rv-proof", family = "restore-proof-${key}", bundle = entry.proof_bundle, sql = entry.sql_sha256.proof }
  }]...)
  current_release = var.releases[local.current_key]
  current_tools   = local.current_release.release_tools
  # Reconciliation runs as the owner; the proof as the service login it proves.
  restore_principal = { for key, job in local.restore_jobs : key =>
    job.kind == "rv-proof" ? local.current_tools[job.database].service : local.current_tools[job.database].owner
  }
  restore_environment = { for key, job in local.restore_jobs : key => merge(
    {
      RELEASE_ID                 = local.current_release.release_id
      RELEASE_JOB_ID             = key
      RELEASE_DATABASE           = job.database
      RELEASE_NOT_AFTER          = var.restore_verifications[job.database].not_after
      RELEASE_JOB_BUDGET_SECONDS = tostring(var.restore_verifications[job.database].budget_seconds)
      RELEASE_TOOLS_SHA256       = var.restore_verifications[job.database].tools_sha256
      RELEASE_SQL_SHA256         = job.sql
      RELEASE_EXPECT_DATABASE    = local.current_tools[job.database].database
      RELEASE_EXPECT_PRINCIPAL   = local.restore_principal[key]
    },
    job.kind == "rv-proof" ? { RELEASE_OWNER_ROLE = local.current_tools[job.database].owner } : {},
  ) }
  repositories = { for key, name in module.names.ecr_repositories : key => "arn:aws:ecr:${var.region}:${var.account_id}:repository/${name}" }
  # The current release's CA-only release task role: its init reads that release's
  # pinned CA bundle and nothing else; the job itself needs no AWS authority.
  restore_task_role = { for name in keys(var.restore_verifications) : name => "${local.role_arn}/${local.current.iam_role_names["${name}-release-task"]}" }
}

module "restore_job" {
  source   = "../modules/release-job"
  for_each = local.restore_jobs

  account_id = var.account_id
  region     = var.region
  job_id     = each.key
  kind       = each.value.kind
  image      = var.restore_verifications[each.value.database].image
  # The current release's own reconcile job fixes the init, the user and the keys
  # read from the bundle; the restore bundle supplies the restored endpoint.
  user        = local.current.tools_task_contracts["${each.value.database}-reconcile"][1].user
  init        = local.current.release_task_contracts[each.value.database][0]
  log_group   = module.names.log_groups["${each.value.database}-release"]
  environment = local.restore_environment[each.key]
  secret_keys = [for secret in local.current.tools_task_contracts["${each.value.database}-reconcile"][1].secrets : secret.name]
  bundle      = each.value.bundle
  # The init runs the current release's search image; the job runs the pinned release-tools image.
  pull_repositories = [local.repositories.search, local.repositories.release_tools]
}

resource "aws_iam_role" "restore_execution" {
  for_each           = local.restore_jobs
  name               = "${var.name_prefix}-${each.key}-execution"
  assume_role_policy = local.current.assume_task_role
}

resource "aws_iam_role_policy" "restore_execution" {
  for_each = local.restore_jobs
  name     = "bounded-restore-job-${substr(sha256(jsonencode(module.restore_job[each.key].execution_policy)), 0, 16)}"
  role     = aws_iam_role.restore_execution[each.key].id
  policy   = jsonencode(module.restore_job[each.key].execution_policy)
}

resource "aws_ecs_task_definition" "restore" {
  for_each                 = local.restore_jobs
  family                   = "${var.name_prefix}-${each.value.family}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  task_role_arn            = local.restore_task_role[each.value.database]
  execution_role_arn       = aws_iam_role.restore_execution[each.key].arn
  container_definitions    = jsonencode(module.restore_job[each.key].task_contract)
  # A finished verification's revisions stay registered as evidence; removing the
  # entry removes its roles and its launcher statement, so nothing can launch them.
  skip_destroy = true
  runtime_platform {
    cpu_architecture        = "ARM64"
    operating_system_family = "LINUX"
  }
  volume { name = "material" }
  depends_on = [aws_iam_role_policy.restore_execution]
}

locals {
  # Its own document in the attended set, so the jobs, receipts and tasks documents
  # are the same with or without a verification. Launch tags, stops and task reads
  # come from those documents (restore tasks carry the job tag).
  restore_launcher_policy = length(local.restore_jobs) == 0 ? {} : {
    restore = {
      Version = "2012-10-17"
      Statement = [
        { Sid = "RunRestoreVerifications", Effect = "Allow", Action = ["ecs:RunTask"], Resource = sort([for task in aws_ecs_task_definition.restore : task.arn]), Condition = local.in_cluster },
        {
          Sid      = "PassRestoreRoles", Effect = "Allow", Action = ["iam:PassRole"]
          Resource = sort(distinct(concat([for role in aws_iam_role.restore_execution : role.arn], values(local.restore_task_role)))), Condition = local.pass_to_ecs
        },
        { Sid = "ReadRestoreReceipts", Effect = "Allow", Action = ["logs:GetLogEvents"], Resource = sort([for job in module.restore_job : job.receipt_stream]) },
        { Sid = "DenyExecuteCommandOnRestore", Effect = "Deny", Action = ["ecs:RunTask"], Resource = ["*"], Condition = local.exec_enabled },
      ]
    }
  }
}

output "restore_verifications" {
  description = "Review values for each verification's manifest: its release, revisions, roles and the fixed expectations Terraform knows (the kit adds schema and host)."
  value = { for name, entry in var.restore_verifications : name => {
    release_id          = local.current_release.release_id
    instance_identifier = entry.instance_identifier
    not_after           = entry.not_after
    budget_seconds      = entry.budget_seconds
    image               = entry.image
    tools_sha256        = entry.tools_sha256
    jobs = { for kind in ["rv-recon", "rv-proof"] : "${name}-${kind}" => {
      task_definition = aws_ecs_task_definition.restore["${name}-${kind}"].arn
      task_role       = local.restore_task_role[name]
      execution_role  = aws_iam_role.restore_execution["${name}-${kind}"].arn
      receipt_stream  = module.restore_job["${name}-${kind}"].receipt_stream
      expect = merge(
        { database = local.current_tools[name].database, principal = local.restore_principal["${name}-${kind}"] },
        kind == "rv-proof" ? { sql_digest = entry.sql_sha256.proof } : {},
      )
    } }
  } }
}

output "restore_task_contracts" {
  value = { for key, job in module.restore_job : key => job.task_contract }
}

output "restore_execution_policies" {
  value = { for key, job in module.restore_job : key => job.execution_policy }
}
