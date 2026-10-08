# Optional attended operator role. Its trust names exactly one principal,
# requires the external id, and pins both the role session name and the source
# identity to the approved operator, so the session the release CLI matches
# (assumed-role/<role>/<operator>) proves who assumed it. Null creates nothing;
# attaching the launcher policies to this role is a separate approval.
variable "operator_trust" {
  description = "Optional operator role: one approved principal, its external id, a bounded session and the operator name the manifest approves."
  type = object({
    principal_arn   = string
    external_id     = string
    session_seconds = number
    operator        = string
  })
  default = null
  validation {
    condition = var.operator_trust == null ? true : try(
      can(regex("^arn:aws:iam::[0-9]{12}:(user|role)/[A-Za-z0-9+=,.@_/-]{1,512}$", var.operator_trust.principal_arn)) &&
      !strcontains(var.operator_trust.principal_arn, "*"), false
    )
    error_message = "Trust exactly one IAM user or role ARN: no wildcard, no account root and no service principal."
  }
  validation {
    condition = var.operator_trust == null ? true : try(
      length(var.operator_trust.external_id) >= 16 && length(var.operator_trust.external_id) <= 1224 &&
      can(regex("^[A-Za-z0-9+=,.@:/-]+$", var.operator_trust.external_id)) &&
      can(regex("^[A-Za-z0-9+=,.@-]{2,64}$", var.operator_trust.operator)), false
    )
    error_message = "Use an external id of 16-1224 allowed characters and the manifest's operator as a valid session name."
  }
  validation {
    condition = var.operator_trust == null ? true : try(
      var.operator_trust.session_seconds == floor(var.operator_trust.session_seconds) &&
      var.operator_trust.session_seconds >= 3600 && var.operator_trust.session_seconds <= 43200, false
    )
    error_message = "A role session lasts a whole number of seconds from one to twelve hours."
  }
}

locals {
  operator_trust_policy = var.operator_trust == null ? null : {
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AttendedOperator", Effect = "Allow", Principal = { AWS = var.operator_trust.principal_arn }
      Action = ["sts:AssumeRole", "sts:SetSourceIdentity"]
      Condition = {
        StringEquals = {
          "sts:ExternalId"      = var.operator_trust.external_id
          "sts:RoleSessionName" = var.operator_trust.operator
          "sts:SourceIdentity"  = var.operator_trust.operator
        }
      }
    }]
  }
}

resource "aws_iam_role" "operator" {
  count                = var.operator_trust == null ? 0 : 1
  name                 = "${var.name_prefix}-operator"
  description          = "Attended release operator for ${var.name_prefix}. No policy is attached here."
  max_session_duration = var.operator_trust.session_seconds
  assume_role_policy   = jsonencode(local.operator_trust_policy)
}

output "operator_role_arn" {
  description = "The manifest's operator_role when the optional operator role exists."
  value       = var.operator_trust == null ? null : "arn:aws:iam::${var.account_id}:role/${var.name_prefix}-operator"
}

output "operator_trust_policy" {
  value = local.operator_trust_policy
}
