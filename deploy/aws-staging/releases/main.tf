module "names" {
  source                = "../modules/naming"
  account_id            = var.account_id
  region                = var.region
  name_prefix           = var.name_prefix
  private_dns_namespace = var.private_dns_namespace
}

# Each retained release is its own keyed instance of the reviewed task/IAM
# module: release-scoped roles with exact-version policies and task revisions
# that are never deregistered by Terraform.
module "release" {
  source   = "../../aws-platform-fit"
  for_each = var.releases

  account_id          = var.account_id
  region              = var.region
  name_prefix         = var.name_prefix
  release_scope       = each.key
  release_id          = each.value.release_id
  runtime_server_name = module.names.runtime_server_name
  artifact_bucket     = module.names.report_bucket
  images              = each.value.images
  log_groups          = { for name in ["runtime", "api", "worker"] : name => module.names.log_groups[name] }
  environment_bundles = each.value.environment_bundles
  material_bundles    = each.value.material_bundles
  release_jobs = {
    runtime        = merge(each.value.release_jobs.runtime, { log_group = module.names.log_groups["runtime-release"] })
    product        = merge(each.value.release_jobs.product, { log_group = module.names.log_groups["product-release"] })
    runtime_grants = each.value.release_jobs.runtime_grants
  }
  release_tools = merge(each.value.release_tools, { release_id = each.value.release_id })
  observers = each.value.observers == null ? null : {
    namespace      = var.private_dns_namespace
    budget_seconds = each.value.observers.budget_seconds
    runtime_bundle = each.value.observers.runtime_bundle
    log_group      = module.names.log_groups["observe"]
  }
  bootstrap = each.value.bootstrap
}

locals {
  current_key   = one([for key, release in var.releases : key if release.slot == "current"])
  rollback_key  = one([for key, release in var.releases : key if release.slot == "rollback"])
  current       = module.release[local.current_key]
  cluster_arn   = module.names.cluster_arn
  task_wildcard = "arn:aws:ecs:${var.region}:${var.account_id}:task/${module.names.cluster_name}/*"
  in_cluster    = { ArnEquals = { "ecs:cluster" = local.cluster_arn } }
  pass_to_ecs   = { StringEquals = { "iam:PassedToService" = "ecs-tasks.amazonaws.com" } }
  exec_enabled  = { StringEqualsIgnoreCase = { "ecs:enable-execute-command" = "true" } }

  # Only the current release runs jobs (migrations, grants, proofs and
  # reconciliation): a rollback never re-runs them. Services may use either
  # retained release's own revision.
  services      = ["runtime", "api", "worker"]
  service_kinds = flatten([for name in local.services : ["${name}-task", "${name}-execution"]])
  role_arn      = "arn:aws:iam::${var.account_id}:role"
  # Database jobs, observers and bootstrap jobs each launch under their own scope.
  current_jobs           = sort(values(local.current.launch_scopes.jobs.task_definitions))
  current_job_roles      = sort([for name in local.current.launch_scopes.jobs.roles : "${local.role_arn}/${name}"])
  current_observers      = sort(values(local.current.launch_scopes.observers.task_definitions))
  current_observer_roles = sort([for name in local.current.launch_scopes.observers.roles : "${local.role_arn}/${name}"])
  service_roles = sort(flatten([for release in module.release : [for kind, name in release.iam_role_names :
    "arn:aws:iam::${var.account_id}:role/${name}" if contains(local.service_kinds, kind)
  ]]))
  service_revisions = { for name in ["runtime", "api", "worker"] : name => sort([for release in module.release : release.task_definition_arns[name]]) }

  # Attended release launcher for release/controller.py, split by concern to
  # stay within IAM's managed-policy size. This is a trusted launcher, not an
  # IAM command sandbox: RunTask overrides remain the controller's to reject.
  release_launcher_policies = {
    jobs = {
      Version = "2012-10-17"
      Statement = [
        { Sid = "RunCurrentReleaseJobs", Effect = "Allow", Action = ["ecs:RunTask"], Resource = local.current_jobs, Condition = local.in_cluster },
        {
          Sid       = "TagReleaseTasksOnLaunch", Effect = "Allow", Action = ["ecs:TagResource"], Resource = [local.task_wildcard]
          Condition = { StringEquals = { "ecs:CreateAction" = "RunTask" } }
        },
        {
          # The controller stops only its own job tasks, which carry its job tag.
          Sid       = "StopReleaseJobTasks", Effect = "Allow", Action = ["ecs:StopTask"], Resource = [local.task_wildcard]
          Condition = merge(local.in_cluster, { Null = { "aws:ResourceTag/sentry:job-id" = "false" } })
        },
        { Sid = "PassCurrentJobRoles", Effect = "Allow", Action = ["iam:PassRole"], Resource = local.current_job_roles, Condition = local.pass_to_ecs },
        { Sid = "DenyExecuteCommandOnLaunch", Effect = "Deny", Action = ["ecs:RunTask"], Resource = ["*"], Condition = local.exec_enabled },
      ]
    }
    services = {
      Version = "2012-10-17"
      Statement = concat(
        # A deploy names the exact revision; scale-to-zero requests carry none.
        [for name, arn in module.names.service_arns : {
          Sid       = "Update${title(name)}Service", Effect = "Allow", Action = ["ecs:UpdateService"], Resource = [arn]
          Condition = merge(local.in_cluster, { ArnEqualsIfExists = { "ecs:task-definition" = local.service_revisions[name] } })
        }],
        [
          { Sid = "DescribePinnedServices", Effect = "Allow", Action = ["ecs:DescribeServices"], Resource = sort(values(module.names.service_arns)), Condition = local.in_cluster },
          { Sid = "PassRetainedServiceRoles", Effect = "Allow", Action = ["iam:PassRole"], Resource = local.service_roles, Condition = local.pass_to_ecs },
          { Sid = "DenyExecuteCommandOnServices", Effect = "Deny", Action = ["ecs:UpdateService"], Resource = ["*"], Condition = local.exec_enabled },
        ],
      )
    }
    # Receipts are read only from each current job's app-container stream and
    # the current release's worker app-container streams (worker/<release-id>/);
    # the controller names the exact stream of the task it observed. Missing,
    # stale or ambiguous receipts hold the release. This still exposes all of the
    # current release's worker application output; attaching it needs approval.
    receipts = {
      Version = "2012-10-17"
      Statement = [
        { Sid = "ReadCurrentJobReceipts", Effect = "Allow", Action = ["logs:GetLogEvents"], Resource = sort(values(local.current.receipt_log_streams)) },
        { Sid = "ReadWorkerReadinessReceipts", Effect = "Allow", Action = ["logs:GetLogEvents"], Resource = [local.current.readiness_log_stream] },
      ]
    }
    tasks = {
      Version = "2012-10-17"
      Statement = [
        # ListTasks has no task-level resource for Fargate; the cluster condition scopes it.
        { Sid = "ListClusterTasks", Effect = "Allow", Action = ["ecs:ListTasks"], Resource = ["*"], Condition = local.in_cluster },
        { Sid = "DescribeClusterTasks", Effect = "Allow", Action = ["ecs:DescribeTasks"], Resource = [local.task_wildcard], Condition = local.in_cluster },
        { Sid = "DenyExecuteCommand", Effect = "Deny", Action = ["ecs:ExecuteCommand"], Resource = ["*"] },
      ]
    }
  }
  # The current release's Runtime and API observers: launch, pass their own
  # roles and read only their observer-container receipt streams. Launch tags
  # and stops come from the jobs policy (observers carry the job tag).
  observer_launcher_policy = length(local.current_observers) == 0 ? {} : {
    observe = {
      Version = "2012-10-17"
      Statement = [
        { Sid = "RunCurrentReleaseObservers", Effect = "Allow", Action = ["ecs:RunTask"], Resource = local.current_observers, Condition = local.in_cluster },
        { Sid = "PassCurrentObserverRoles", Effect = "Allow", Action = ["iam:PassRole"], Resource = local.current_observer_roles, Condition = local.pass_to_ecs },
        { Sid = "ReadCurrentObserverReceipts", Effect = "Allow", Action = ["logs:GetLogEvents"], Resource = sort(values(local.current.observer_receipt_streams)) },
        { Sid = "DenyExecuteCommandOnObservers", Effect = "Deny", Action = ["ecs:RunTask"], Resource = ["*"], Condition = local.exec_enabled },
      ]
    }
  }
  attended_launcher_policies = merge(local.release_launcher_policies, local.observer_launcher_policy)
  # Bootstrap is a separate administrator path: its launcher is never part of
  # the attended set and nothing in this run attaches it.
  bootstrap_launcher_policy = length(local.current.launch_scopes.bootstrap.task_definitions) == 0 ? null : {
    Version = "2012-10-17"
    Statement = [
      { Sid = "RunFirstDeploymentBootstrap", Effect = "Allow", Action = ["ecs:RunTask"], Resource = sort(values(local.current.launch_scopes.bootstrap.task_definitions)), Condition = local.in_cluster },
      { Sid = "PassBootstrapRoles", Effect = "Allow", Action = ["iam:PassRole"], Resource = sort([for name in local.current.launch_scopes.bootstrap.roles : "${local.role_arn}/${name}"]), Condition = local.pass_to_ecs },
      { Sid = "ReadBootstrapReceipts", Effect = "Allow", Action = ["logs:GetLogEvents"], Resource = sort(values(local.current.bootstrap_receipt_streams)) },
      { Sid = "DenyExecuteCommandOnBootstrap", Effect = "Deny", Action = ["ecs:RunTask"], Resource = ["*"], Condition = local.exec_enabled },
    ]
  }
}

# Unattached: attaching them to a short-lived operator session is a separate
# trust/operator approval. Attach the attended set together.
resource "aws_iam_policy" "release_launcher" {
  for_each    = local.attended_launcher_policies
  name        = "${var.name_prefix}-release-launcher-${each.key}"
  description = "Attended release launcher (${each.key}) for retained ${var.name_prefix} releases."
  policy      = jsonencode(each.value)
}

resource "aws_iam_policy" "release_launcher_bootstrap" {
  count       = local.bootstrap_launcher_policy == null ? 0 : 1
  name        = "${var.name_prefix}-release-launcher-bootstrap"
  description = "First-deployment bootstrap launcher for ${var.name_prefix}; separate from the attended set and unattached."
  policy      = jsonencode(local.bootstrap_launcher_policy)
}
