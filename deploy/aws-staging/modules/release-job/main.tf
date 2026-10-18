# Resource-free rendering of one guarded release-tools job (docs/release-tools.md):
# the fail-closed CA-only init and the job container, their log configuration, the
# job's environment and its execution-policy document. The caller registers the task
# definition and its roles; every value that decides what runs is an input here, so
# the same inputs always render the same bytes.
terraform {
  required_version = ">= 1.9.8, < 2.0.0"
}

variable "account_id" {
  type = string
}

variable "region" {
  type = string
}

variable "job_id" {
  description = "RELEASE_JOB_ID: <database>-<kind>. It is also the awslogs stream prefix."
  type        = string
}

variable "kind" {
  description = "The release-tools command; the job container is named for it."
  type        = string
}

variable "image" {
  description = "The release-tools image, pinned by digest."
  type        = string
}

variable "user" {
  description = "The job container's uid:gid."
  type        = string
}

variable "init" {
  description = "The CA-only init container contract. Its log configuration is replaced by the job's."
  type        = any
}

variable "log_group" {
  type = string
}

variable "environment" {
  description = "The job's fixed environment (RELEASE_* names)."
  type        = map(string)
}

variable "secret_keys" {
  description = "Keys read from the job's bundle, in order."
  type        = list(string)
}

variable "bundle" {
  description = "The one secret version the job reads its connection from."
  type        = object({ arn = string, version_id = string })
}

variable "pull_repositories" {
  description = "ECR repository ARNs the execution role pulls from: the init's and the job's."
  type        = list(string)
}

locals {
  log_configuration = {
    logDriver = "awslogs"
    options = {
      awslogs-group         = var.log_group
      awslogs-region        = var.region
      awslogs-stream-prefix = var.job_id
    }
  }
  task_contract = [
    merge(var.init, { logConfiguration = local.log_configuration }),
    {
      name                   = var.kind
      image                  = var.image
      essential              = true
      user                   = var.user
      workingDirectory       = "/"
      readonlyRootFilesystem = true
      linuxParameters        = { capabilities = { drop = ["ALL"] } }
      dependsOn              = [{ containerName = "init", condition = "SUCCESS" }]
      startTimeout           = 120
      # Above the in-image stop grace, so a stop request lets the job reap psql.
      stopTimeout = 30
      command     = [var.kind]
      environment = [for name, value in var.environment : { name = name, value = value }]
      secrets = [for name in var.secret_keys : {
        name      = name
        valueFrom = "${var.bundle.arn}:${name}::${var.bundle.version_id}"
      }]
      mountPoints      = [{ sourceVolume = "material", containerPath = "/run/material", readOnly = true }]
      portMappings     = []
      logConfiguration = local.log_configuration
    }
  ]
  execution_policy = {
    Version = "2012-10-17"
    Statement = [
      { Sid = "RegistryToken", Effect = "Allow", Action = ["ecr:GetAuthorizationToken"], Resource = ["*"] },
      {
        Sid      = "PullImages", Effect = "Allow", Action = ["ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"]
        Resource = var.pull_repositories
      },
      {
        Sid      = "TaskLogs", Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = ["arn:aws:logs:${var.region}:${var.account_id}:log-group:${var.log_group}:log-stream:${var.job_id}/*"]
      },
      {
        Sid       = "PinnedJobEnvironment", Effect = "Allow", Action = ["secretsmanager:GetSecretValue"]
        Resource  = [var.bundle.arn]
        Condition = { StringEquals = { "secretsmanager:VersionId" = var.bundle.version_id } }
      },
    ]
  }
}

output "log_configuration" {
  value = local.log_configuration
}

output "task_contract" {
  description = "The init and job containers, in launch order."
  value       = local.task_contract
}

output "execution_policy" {
  value = local.execution_policy
}

output "receipt_stream" {
  description = "The receipt stream ARN pattern: the job container's streams only (<job id>/<kind>/<task id>)."
  value       = "arn:aws:logs:${var.region}:${var.account_id}:log-group:${var.log_group}:log-stream:${var.job_id}/${var.kind}/*"
}
