# Alarm, notification and budget shapes. An alarm exists here only where AWS
# itself publishes the metric; every other alert the staging requirements name
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
}

locals {
  notify = var.notifications != null
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
  )
  # Alerts the staging requirements name that have no metric producer yet. They
  # stay visible here, not as alarms that could never fire.
  unwired_alerts = {
    worker-unready     = "Readiness is proven by the attended gate from worker receipts; no metric is published from them."
    backlog-age        = "Neither Runtime nor Search publishes queue or backlog metrics."
    lease-exhaustion   = "Runtime records lease expiry in its ledger; no metric is published."
    retry-exhaustion   = "Runtime records retry exhaustion in its ledger; no metric is published."
    phase-deadlines    = "Release phase deadlines are enforced by the attended controller and journaled, not published as metrics."
    certificate-expiry = "Runtime's private certificate lives in a Secrets Manager bundle; nothing publishes its expiry."
    backup             = "RDS automated backups publish no success or failure metric; restore is a documented operator check."
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
