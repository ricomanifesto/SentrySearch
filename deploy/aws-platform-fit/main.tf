locals {
  # Release-scoped identities let a retained rollback release keep its own
  # exact-version policies; unscoped names are unchanged.
  identity_prefix = var.release_scope == null ? var.name_prefix : "${var.name_prefix}-${var.release_scope}"
  roles = {
    runtime = { uid = "65532:65532", profile = "runtime", cpu = "256", memory = "512", stop = 30, image = var.images.runtime, command = ["/app/sentryruntime"] }
    api     = { uid = "10001:10001", profile = "search", cpu = "256", memory = "1024", stop = 60, image = var.images.search, command = ["python", "/app/run_api.py"] }
    worker  = { uid = "10001:10001", profile = "search", cpu = "512", memory = "2048", stop = 60, image = var.images.search, command = ["python", "-m", "dev.run_runtime_worker", "--health-port", "8081", "--drain-seconds", "30"] }
  }
  # Fargate cannot add CHOWN. Retain it from the default capability set by
  # explicitly dropping every other Docker default; applications drop ALL.
  init_drop_capabilities = [
    "AUDIT_WRITE", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "MKNOD",
    "NET_BIND_SERVICE", "NET_RAW", "SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYS_CHROOT"
  ]
  db_secret_keys = ["DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD"]
  secret_keys = {
    runtime = ["DATABASE_URL", "SENTRYRUNTIME_AUTH_CREDENTIALS"]
    api     = local.db_secret_keys
    worker  = concat(local.db_secret_keys, ["SENTRYRUNTIME_PRODUCER_TOKEN", "SENTRYRUNTIME_WORKER_TOKEN"])
  }
  search_environment = {
    ENVIRONMENT            = "staging"
    AWS_REGION             = var.region
    AWS_S3_BUCKET          = var.artifact_bucket
    DB_SSLMODE             = "verify-full"
    DB_SSLROOTCERT         = "/run/material/postgres-ca.pem"
    DB_DEBUG               = "false"
    PYTHON_DOTENV_DISABLED = "1"
  }
  environments = {
    runtime = {
      SENTRYRUNTIME_LISTEN_ADDRESS    = "0.0.0.0:8443"
      SENTRYRUNTIME_AUTH_MODE         = "token"
      SENTRYRUNTIME_TLS_CERT_FILE     = "/run/material/server-cert.pem"
      SENTRYRUNTIME_TLS_KEY_FILE      = "/run/material/server-key.pem"
      SENTRYRUNTIME_PROBE_ADDRESS     = "127.0.0.1:8443"
      SENTRYRUNTIME_PROBE_SERVER_NAME = var.runtime_server_name
      SENTRYRUNTIME_PROBE_CA_FILE     = "/run/material/runtime-ca.pem"
      SENTRYRUNTIME_PROBE_TOKEN_FILE  = "/run/material/probe-token"
    }
    api = merge(local.search_environment, { PORT = "8001", SENTRYSEARCH_EXECUTION_MODE = "paused" })
    worker = merge(local.search_environment, {
      SENTRYRUNTIME_URL     = "https://${var.runtime_server_name}:8443"
      SENTRYRUNTIME_CA_FILE = "/run/material/runtime-ca.pem"
      # Disabled generation scaffold: a reserved local discard port, no live key.
      OPENROUTER_BASE_URL = "http://127.0.0.1:9"
      OPENROUTER_API_KEY  = "disabled-local-platform-fit"
    }, var.release_id == null ? {} : { SENTRYSEARCH_RELEASE_ID = var.release_id })
  }
  mounts = {
    runtime = [{ sourceVolume = "material", containerPath = "/run/material", readOnly = true }]
    api = [
      { sourceVolume = "material", containerPath = "/run/material", readOnly = true },
      { sourceVolume = "tmp", containerPath = "/tmp", readOnly = false },
      { sourceVolume = "work", containerPath = "/var/lib/sentrysearch", readOnly = false }
    ]
    worker = [
      { sourceVolume = "material", containerPath = "/run/material", readOnly = true },
      { sourceVolume = "tmp", containerPath = "/tmp", readOnly = false },
      { sourceVolume = "work", containerPath = "/var/lib/sentrysearch", readOnly = false }
    ]
  }
  health_commands = {
    runtime = ["CMD", "/app/probe", "healthz"]
    api     = ["CMD", "python", "-c", "import http.client as h;c=h.HTTPConnection('127.0.0.1',8001,timeout=2);c.request('GET','/');raise SystemExit(c.getresponse().status!=200)"]
    worker  = ["CMD", "python", "-c", "import http.client as h;c=h.HTTPConnection('127.0.0.1',8081,timeout=2);c.request('GET','/healthz');raise SystemExit(c.getresponse().status!=200)"]
  }
  ports = {
    runtime = [{ containerPort = 8443, protocol = "tcp" }]
    api     = [{ containerPort = 8001, protocol = "tcp" }]
    worker  = []
  }
  # Explicit non-blocking delivery, so the account default cannot make worker
  # output block; overflow drops lines, which the observer sees as sequence gaps.
  # 4 MiB holds about 18 hours of locally measured receipt output; application
  # log volume and Fargate behavior are unmeasured (docs/runtime-consistency.md).
  # Runtime and API modes await their own budget.
  worker_log_options = { mode = "non-blocking", max-buffer-size = "4m" }
  log_configuration = { for name in keys(local.roles) : name => {
    logDriver = "awslogs"
    options = merge({
      awslogs-group         = var.log_groups[name]
      awslogs-region        = var.region
      awslogs-stream-prefix = name
    }, name == "worker" ? local.worker_log_options : {})
  } }
  task_contracts = { for name, role in local.roles : name => [
    {
      name                   = "init"
      image                  = var.images.search
      essential              = false
      startTimeout           = 120
      user                   = "0:0"
      workingDirectory       = "/"
      readonlyRootFilesystem = true
      linuxParameters        = { capabilities = { drop = local.init_drop_capabilities } }
      command = concat([
        "python", "-m", "dev.prepare_service_volumes", "--profile", role.profile,
        "--material-dir", "/run/material", "--secret-id", var.material_bundles[name].arn,
        "--version-id", var.material_bundles[name].version_id, "--region", var.region
      ], name == "runtime" ? [] : ["--tmp-dir", "/tmp", "--work-dir", "/var/lib/sentrysearch"])
      mountPoints      = [for mount in local.mounts[name] : merge(mount, { readOnly = false })]
      logConfiguration = local.log_configuration[name]
    },
    {
      name                   = "app"
      image                  = role.image
      essential              = true
      user                   = role.uid
      readonlyRootFilesystem = true
      linuxParameters        = { capabilities = { drop = ["ALL"] } }
      dependsOn              = [{ containerName = "init", condition = "SUCCESS" }]
      startTimeout           = 120
      stopTimeout            = role.stop
      command                = role.command
      environment            = [for key, value in local.environments[name] : { name = key, value = value }]
      secrets = [for key in local.secret_keys[name] : {
        name      = key
        valueFrom = "${var.environment_bundles[name].arn}:${key}::${var.environment_bundles[name].version_id}"
      }]
      healthCheck      = { command = local.health_commands[name], interval = 30, timeout = 5, retries = 3, startPeriod = 90 }
      mountPoints      = local.mounts[name]
      portMappings     = local.ports[name]
      logConfiguration = local.log_configuration[name]
    }
  ] }
  assume_task_role = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow", Action = "sts:AssumeRole", Principal = { Service = "ecs-tasks.amazonaws.com" }
      Condition = {
        StringEquals = { "aws:SourceAccount" = var.account_id }
        ArnLike      = { "aws:SourceArn" = "arn:aws:ecs:${var.region}:${var.account_id}:*" }
      }
    }]
  })
  ecr_arns = { for name, image in var.images : name => "arn:aws:ecr:${var.region}:${var.account_id}:repository/${split("@", split(".amazonaws.com/", image)[1])[0]}" }
  task_policies = { for name in keys(local.roles) : name => {
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid       = "PinnedMaterial", Effect = "Allow", Action = ["secretsmanager:GetSecretValue"]
        Resource  = [var.material_bundles[name].arn]
        Condition = { StringEquals = { "secretsmanager:VersionId" = var.material_bundles[name].version_id } }
      }
      ], name == "runtime" ? [] : [
      {
        Sid      = "ReportObjects", Effect = "Allow"
        Action   = name == "api" ? ["s3:GetObject", "s3:DeleteObject"] : ["s3:GetObject", "s3:PutObject"]
        Resource = ["arn:aws:s3:::${var.artifact_bucket}/reports/*"]
      }
      ], name != "api" ? [] : [
      {
        Sid       = "ListReports", Effect = "Allow", Action = ["s3:ListBucket"]
        Resource  = ["arn:aws:s3:::${var.artifact_bucket}"]
        Condition = { StringLike = { "s3:prefix" = ["reports/*"] } }
      }
    ])
  } }
  execution_policies = { for name in keys(local.roles) : name => {
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "RegistryToken", Effect = "Allow", Action = ["ecr:GetAuthorizationToken"], Resource = ["*"]
      },
      {
        Sid      = "PullImages", Effect = "Allow", Action = ["ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"]
        Resource = name == "runtime" ? [local.ecr_arns.runtime, local.ecr_arns.search] : [local.ecr_arns.search]
      },
      {
        Sid      = "TaskLogs", Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = ["arn:aws:logs:${var.region}:${var.account_id}:log-group:${var.log_groups[name]}:log-stream:${name}/*"]
      },
      {
        Sid       = "PinnedEnvironment", Effect = "Allow", Action = ["secretsmanager:GetSecretValue"]
        Resource  = [var.environment_bundles[name].arn]
        Condition = { StringEquals = { "secretsmanager:VersionId" = var.environment_bundles[name].version_id } }
      }
    ]
  } }
}

resource "aws_iam_role" "task" {
  for_each           = local.roles
  name               = "${local.identity_prefix}-${each.key}-task"
  assume_role_policy = local.assume_task_role
  lifecycle {
    prevent_destroy = true
  }
}

# A retained release is immutable: policy names bind their exact content, so a
# changed grant is a replacement, and prevent_destroy rejects replacing or
# removing any role, policy or revision. New versions are a new release scope.
resource "aws_iam_role_policy" "task" {
  for_each = local.roles
  name     = "bounded-task-access-${substr(sha256(jsonencode(local.task_policies[each.key])), 0, 16)}"
  role     = aws_iam_role.task[each.key].id
  policy   = jsonencode(local.task_policies[each.key])
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_role" "execution" {
  for_each           = local.roles
  name               = "${local.identity_prefix}-${each.key}-execution"
  assume_role_policy = local.assume_task_role
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_role_policy" "execution" {
  for_each = local.roles
  name     = "bounded-bootstrap-access-${substr(sha256(jsonencode(local.execution_policies[each.key])), 0, 16)}"
  role     = aws_iam_role.execution[each.key].id
  policy   = jsonencode(local.execution_policies[each.key])
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_ecs_task_definition" "service" {
  for_each                 = local.roles
  family                   = "${var.name_prefix}-${each.key}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = each.value.cpu
  memory                   = each.value.memory
  task_role_arn            = aws_iam_role.task[each.key].arn
  execution_role_arn       = aws_iam_role.execution[each.key].arn
  container_definitions    = jsonencode(local.task_contracts[each.key])
  # Keep superseded revisions registered for compatible rollback.
  skip_destroy = true
  runtime_platform {
    cpu_architecture        = "ARM64"
    operating_system_family = "LINUX"
  }
  dynamic "volume" {
    for_each = local.mounts[each.key]
    content {
      name = volume.value.sourceVolume
    }
  }
  depends_on = [aws_iam_role_policy.task, aws_iam_role_policy.execution]
  lifecycle {
    prevent_destroy = true
  }
}

output "task_contracts" {
  value = local.task_contracts
}

output "readiness_log_stream" {
  description = "The worker app container's configured stream ARN pattern: the only place the attended gate reads readiness receipts (release.readiness.worker_stream)."
  value       = "arn:aws:logs:${var.region}:${var.account_id}:log-group:${var.log_groups.worker}:log-stream:${local.log_configuration.worker.options["awslogs-stream-prefix"]}/${local.task_contracts.worker[1].name}/*"
}

output "task_policies" {
  value = local.task_policies
}

output "execution_policies" {
  value = local.execution_policies
}

output "iam_role_names" {
  description = "Every task and execution role this module creates, keyed by task and role kind."
  value = merge(
    { for name, role in aws_iam_role.task : "${name}-task" => role.name },
    { for name, role in aws_iam_role.execution : "${name}-execution" => role.name },
    { for name, role in aws_iam_role.release_task : "${name}-release-task" => role.name },
    { for name, role in aws_iam_role.release_execution : "${name}-release-execution" => role.name },
    { for key, role in aws_iam_role.tools_execution : "${local.tools_jobs[key].database}-${local.tools_jobs[key].role}-execution" => role.name },
  )
}

output "task_definition_arns" {
  description = "Exact registered revisions, keyed like the task families."
  value = merge(
    { for name, task in aws_ecs_task_definition.service : name => task.arn },
    { for name, task in aws_ecs_task_definition.release : "${name}-release" => task.arn },
    { for key, task in aws_ecs_task_definition.tools : key => task.arn },
  )
}
