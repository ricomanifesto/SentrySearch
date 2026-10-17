# Alarm, notification and budget shapes. An alarm exists here only where a metric
# has a producer: AWS's own service and database metrics, and metric filters over
# the worker's readiness receipts. Every other alert the staging requirements name
# has no producer yet and is listed as unwired instead of rendered as an alarm
# that could never fire. Nothing here delivers a notification or enforces a
# budget until a recipient is approved: without one, no topic, subscription or
# budget is rendered.
variable "notifications" {
  description = "Optional alert recipient and monthly review threshold (a review trigger, not a spending cap). Null renders no topic, subscription or budget."
  type = object({
    email              = string
    monthly_budget_usd = number
  })
  default = null
  validation {
    condition = var.notifications == null ? true : try(
      can(regex("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", var.notifications.email)) &&
      var.notifications.monthly_budget_usd > 0 && var.notifications.monthly_budget_usd <= 10000 &&
      floor(var.notifications.monthly_budget_usd) == var.notifications.monthly_budget_usd, false
    )
    error_message = "Name one approved recipient address and a whole-dollar monthly review threshold between 1 and 10000."
  }
  validation {
    condition     = !endswith(var.name_prefix, "-production") || var.notifications != null
    error_message = "A production environment names its alert recipient and monthly budget."
  }
}

locals {
  notify = var.notifications != null
  # Worker readiness receipts (src/execution/readiness_receipts.py) are one line each
  # in the worker's log group: the marker, a space and compact JSON. The ready filter
  # counts lines with the marker and one exact phrase; the error filters count lines
  # with any one of their exact phrases (only receipts carry "error_code").
  worker_namespace = "${var.name_prefix}/worker"
  worker_deadline_codes = [for phase in ["starting", "maintenance", "generation", "evaluation", "idle", "stopped", "drain"] :
  "${phase}_deadline_exceeded"]
  worker_receipt_metrics = {
    WorkerReadyReceipts = "\"SENTRY_WORKER_READINESS\" \"\\\"ready\\\":true\""
    WorkerRuntimeErrors = join(" ", [for code in ["runtime_unavailable", "runtime_access_denied"] :
    "?\"\\\"error_code\\\":\\\"${code}\\\"\""])
    WorkerDeadlineErrors = join(" ", [for code in local.worker_deadline_codes :
    "?\"\\\"error_code\\\":\\\"${code}\\\"\""])
  }
  # Each wired alarm's producer, dimensions, threshold and missing-data handling.
  wired_alarms = merge(
    { for name, service in module.names.service_names : "${name}-missing" => {
      description = "No ${name} task is reporting: ECS publishes service CPU only while a task runs, so silence breaches."
      namespace   = "AWS/ECS", metric = "CPUUtilization", statistic = "SampleCount"
      dimensions  = { ClusterName = module.names.cluster_name, ServiceName = service }
      comparison  = "LessThanThreshold", threshold = 1, period = 300, evaluation_periods = 2
      missing     = "breaching"
    } },
    { for name, identifier in module.names.db_identifiers : "${name}-db-storage" => {
      description = "The ${name} database has less than 10% of its allocated storage free."
      namespace   = "AWS/RDS", metric = "FreeStorageSpace", statistic = "Minimum"
      dimensions  = { DBInstanceIdentifier = identifier }
      comparison  = "LessThanThreshold", threshold = local.db_allocated_storage * 1073741824 / 10, period = 300, evaluation_periods = 1
      missing     = "breaching"
    } },
    {
      worker-unready = {
        description = "No worker reported ready for ten minutes: it is down, unready, or its receipts are not arriving."
        namespace   = local.worker_namespace, metric = "WorkerReadyReceipts", statistic = "Sum", dimensions = {}
        comparison  = "LessThanThreshold", threshold = 1, period = 300, evaluation_periods = 2
        missing     = "breaching"
      }
      worker-runtime-unreachable = {
        description = "A worker reported the Runtime unavailable or its access denied in two consecutive five-minute periods."
        namespace   = local.worker_namespace, metric = "WorkerRuntimeErrors", statistic = "Sum", dimensions = {}
        comparison  = "GreaterThanOrEqualToThreshold", threshold = 1, period = 300, evaluation_periods = 2
        missing     = "notBreaching"
      }
      worker-phase-deadline = {
        description = "A worker phase (starting, maintenance, generation, evaluation, idle, stopped, drain) passed its deadline."
        namespace   = local.worker_namespace, metric = "WorkerDeadlineErrors", statistic = "Sum", dimensions = {}
        comparison  = "GreaterThanOrEqualToThreshold", threshold = 1, period = 300, evaluation_periods = 1
        missing     = "notBreaching"
      }
    },
  )
  # Alerts the staging requirements name that have no metric producer yet. They
  # stay visible here, not as alarms that could never fire.
  unwired_alerts = {
    backlog-age             = "The worker samples the product backlog but writes it to no log line or metric; it needs a producer (an image change)."
    lease-exhaustion        = "Runtime records lease expiry in its ledger and logs nothing about it; it needs a producer."
    retry-exhaustion        = "Runtime records retry exhaustion in its ledger and logs nothing about it; it needs a producer."
    terminal-mismatch       = "The worker's reconciler records Runtime and product mismatches in the product database but writes no log line or metric; it needs a producer."
    release-phase-deadlines = "Release phase deadlines are enforced by the attended controller, which holds and journals; they are not published as metrics."
    certificate-expiry      = "Runtime's private certificate lives in a Secrets Manager bundle; nothing publishes its expiry."
    backup                  = "RDS automated backups publish no success or failure metric; restore is a documented operator check."
  }
}

# No server-side encryption: CloudWatch cannot publish alarm notifications to a
# topic under the AWS-managed SNS key, whose policy cannot grant it, and a
# customer-managed key would need its own policy review. The topic carries only
# alarm state (names, metrics, thresholds), never secrets or report content.
resource "aws_sns_topic" "alerts" {
  count = local.notify ? 1 : 0
  name  = "${var.name_prefix}-alerts"
}

resource "aws_sns_topic_subscription" "alerts" {
  count     = local.notify ? 1 : 0
  topic_arn = aws_sns_topic.alerts[0].arn
  protocol  = "email"
  endpoint  = var.notifications.email
}

resource "aws_cloudwatch_log_metric_filter" "worker" {
  for_each       = local.worker_receipt_metrics
  name           = "${var.name_prefix}-${each.key}"
  log_group_name = aws_cloudwatch_log_group.this["worker"].name
  pattern        = each.value
  metric_transformation {
    name          = each.key
    namespace     = local.worker_namespace
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "this" {
  for_each            = local.wired_alarms
  alarm_name          = "${var.name_prefix}-${each.key}"
  alarm_description   = each.value.description
  namespace           = each.value.namespace
  metric_name         = each.value.metric
  statistic           = each.value.statistic
  dimensions          = each.value.dimensions
  comparison_operator = each.value.comparison
  threshold           = each.value.threshold
  period              = each.value.period
  evaluation_periods  = each.value.evaluation_periods
  treat_missing_data  = each.value.missing
  actions_enabled     = local.notify
  alarm_actions       = local.notify ? [aws_sns_topic.alerts[0].arn] : []
  ok_actions          = local.notify ? [aws_sns_topic.alerts[0].arn] : []
  # A log-derived metric exists only once its filter does.
  depends_on = [aws_cloudwatch_log_metric_filter.worker]
}

resource "aws_budgets_budget" "monthly" {
  count        = local.notify ? 1 : 0
  name         = "${var.name_prefix}-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.notifications.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"
  cost_filter {
    name = "TagKeyValue"
    # Cost Explorer's tag filter format is user:<key>$<value>.
    values = [join("$", ["user:Environment", var.name_prefix])]
  }
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.notifications.email]
  }
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = [var.notifications.email]
  }
}

output "alerts" {
  description = "Every named alert: wired alarms with their producer and missing-data behavior, and unwired alerts with the reason."
  value = merge(
    { for name, alarm in local.wired_alarms : name => {
      wired     = true, producer = "${alarm.namespace}/${alarm.metric}", dimensions = alarm.dimensions
      threshold = alarm.threshold, missing_data = alarm.missing, notifies = local.notify
    } },
    { for name, reason in local.unwired_alerts : name => {
      wired = false, producer = null, dimensions = {}, threshold = null, missing_data = null, notifies = false, reason = reason
    } },
  )
}
