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

  # Only the current release runs owner jobs: a rollback never re-runs
  # migrations. Services may use either retained release's own revision.
  current_jobs = sort([local.current.task_definition_arns["runtime-release"], local.current.task_definition_arns["product-release"]])
  current_job_roles = sort([for kind, name in local.current.iam_role_names :
    "arn:aws:iam::${var.account_id}:role/${name}" if strcontains(kind, "-release-")
  ])
  service_roles = sort(flatten([for release in module.release : [for kind, name in release.iam_role_names :
    "arn:aws:iam::${var.account_id}:role/${name}" if !strcontains(kind, "-release-")
  ]]))
  service_revisions = { for name in ["runtime", "api", "worker"] : name => sort([for release in module.release : release.task_definition_arns[name]]) }

  # Attended release launcher for release/controller.py, split by concern to
  # stay within IAM's managed-policy size. This is a trusted launcher, not an
  # IAM command sandbox: RunTask overrides remain the controller's to reject.
  release_launcher_policies = {
    jobs = {
      Version = "2012-10-17"
      Statement = [
        { Sid = "RunCurrentOwnerJobs", Effect = "Allow", Action = ["ecs:RunTask"], Resource = local.current_jobs, Condition = local.in_cluster },
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
}

# Unattached: attaching them to a short-lived operator session is a separate
# trust/operator approval. Attach all three together.
resource "aws_iam_policy" "release_launcher" {
  for_each    = local.release_launcher_policies
  name        = "${var.name_prefix}-release-launcher-${each.key}"
  description = "Attended release launcher (${each.key}) for retained ${var.name_prefix} releases."
  policy      = jsonencode(each.value)
}
