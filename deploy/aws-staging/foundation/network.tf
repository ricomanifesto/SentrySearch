module "names" {
  source                = "../modules/naming"
  account_id            = var.account_id
  region                = var.region
  name_prefix           = var.name_prefix
  private_dns_namespace = var.private_dns_namespace
}

locals {
  zones = { for index, zone in var.availability_zones : zone => index }
  # Four equal subnets: two task subnets, then two DB subnets.
  task_cidrs = { for zone, index in local.zones : zone => cidrsubnet(var.vpc_cidr, 2, index) }
  db_cidrs   = { for zone, index in local.zones : zone => cidrsubnet(var.vpc_cidr, 2, index + 2) }

  # Task and job security groups. Fargate 1.4.0 pulls images, fetches secrets
  # and ships logs through the task ENI, so each needs the endpoint tier and
  # the S3 gateway for ECR layers.
  workloads = ["runtime", "api", "worker", "runtime_db_jobs", "product_db_jobs", "runtime_transport_proof", "api_proof", "storage_proof"]
  security_groups = {
    runtime                 = "Runtime service tasks"
    api                     = "Search API service tasks"
    worker                  = "Search worker service tasks; no ingress"
    runtime_db_jobs         = "Runtime owner, bootstrap and proof jobs"
    product_db_jobs         = "Product owner, bootstrap and proof jobs"
    runtime_transport_proof = "Fixed Runtime transport-proof task"
    api_proof               = "Fixed operational API-proof task"
    storage_proof           = "Credentialed report-storage proof tasks"
    runtime_db              = "Runtime PostgreSQL"
    product_db              = "Product PostgreSQL"
    endpoints               = "ECR, Secrets Manager and Logs interface endpoints"
  }
  # The only security-group-to-security-group paths. Each produces a source
  # egress rule and a matching destination ingress rule.
  peer_rules = merge(
    {
      runtime-to-runtime-db         = { source = "runtime", destination = "runtime_db", port = 5432 }
      runtime-jobs-to-runtime-db    = { source = "runtime_db_jobs", destination = "runtime_db", port = 5432 }
      api-to-product-db             = { source = "api", destination = "product_db", port = 5432 }
      worker-to-product-db          = { source = "worker", destination = "product_db", port = 5432 }
      product-jobs-to-product-db    = { source = "product_db_jobs", destination = "product_db", port = 5432 }
      worker-to-runtime             = { source = "worker", destination = "runtime", port = 8443 }
      runtime-transport-proof-to-rt = { source = "runtime_transport_proof", destination = "runtime", port = 8443 }
      api-proof-to-api              = { source = "api_proof", destination = "api", port = 8001 }
    },
    { for source in local.workloads : "${replace(source, "_", "-")}-to-endpoints" => { source = source, destination = "endpoints", port = 443 } },
  )

  principal_account = { StringEquals = { "aws:PrincipalAccount" = var.account_id } }
  report_bucket_arn = "arn:aws:s3:::${module.names.report_bucket}"
  ecr_policy = {
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "RegistryToken", Effect = "Allow", Principal = "*", Action = ["ecr:GetAuthorizationToken"], Resource = ["*"]
        Condition = local.principal_account
      },
      {
        Sid       = "PullEnvironmentImages", Effect = "Allow", Principal = "*"
        Action    = ["ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"]
        Resource  = [for name in values(module.names.ecr_repositories) : "arn:aws:ecr:${var.region}:${var.account_id}:repository/${name}"]
        Condition = local.principal_account
      },
    ]
  }
  endpoint_policies = {
    ecr_api = local.ecr_policy
    ecr_dkr = local.ecr_policy
    secretsmanager = {
      Version = "2012-10-17"
      Statement = [
        {
          Sid       = "EnvironmentSecrets", Effect = "Allow", Principal = "*", Action = ["secretsmanager:GetSecretValue"]
          Resource  = ["arn:aws:secretsmanager:${var.region}:${var.account_id}:secret:${module.names.secret_name_prefix}*"]
          Condition = local.principal_account
        },
        {
          # Exact RDS-managed administrator secrets for in-VPC bootstrap jobs.
          Sid       = "RdsManagedAdministratorSecrets", Effect = "Allow", Principal = "*", Action = ["secretsmanager:GetSecretValue"]
          Resource  = sort([for db in aws_db_instance.this : db.master_user_secret[0].secret_arn])
          Condition = local.principal_account
        },
      ]
    }
    logs = {
      Version = "2012-10-17"
      Statement = [{
        Sid       = "EnvironmentLogStreams", Effect = "Allow", Principal = "*", Action = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource  = [for name in values(module.names.log_groups) : "arn:aws:logs:${var.region}:${var.account_id}:log-group:${name}:log-stream:*"]
        Condition = local.principal_account
      }]
    }
    s3 = {
      Version = "2012-10-17"
      Statement = [
        # Layer downloads use ECR-presigned URLs, so this statement is not
        # restricted to the caller's account.
        { Sid = "EcrImageLayers", Effect = "Allow", Principal = "*", Action = ["s3:GetObject"], Resource = ["arn:aws:s3:::prod-${var.region}-starport-layer-bucket/*"] },
        {
          Sid      = "ReportObjects", Effect = "Allow", Principal = "*", Action = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
          Resource = ["${local.report_bucket_arn}/reports/*"], Condition = local.principal_account
        },
        {
          Sid       = "ListReports", Effect = "Allow", Principal = "*", Action = ["s3:ListBucket"], Resource = [local.report_bucket_arn]
          Condition = merge(local.principal_account, { StringLike = { "s3:prefix" = ["reports/*"] } })
        },
      ]
    }
  }
  interface_services = { ecr_api = "ecr.api", ecr_dkr = "ecr.dkr", secretsmanager = "secretsmanager", logs = "logs" }
}

resource "aws_vpc" "this" {
  cidr_block                       = var.vpc_cidr
  enable_dns_support               = true
  enable_dns_hostnames             = true
  assign_generated_ipv6_cidr_block = false
  tags                             = { Name = var.name_prefix }
}

resource "aws_subnet" "task" {
  for_each                        = local.task_cidrs
  vpc_id                          = aws_vpc.this.id
  availability_zone               = each.key
  cidr_block                      = each.value
  map_public_ip_on_launch         = false
  assign_ipv6_address_on_creation = false
  enable_dns64                    = false
  ipv6_native                     = false
  tags                            = { Name = "${var.name_prefix}-task-${each.key}" }
}

resource "aws_subnet" "db" {
  for_each                        = local.db_cidrs
  vpc_id                          = aws_vpc.this.id
  availability_zone               = each.key
  cidr_block                      = each.value
  map_public_ip_on_launch         = false
  assign_ipv6_address_on_creation = false
  enable_dns64                    = false
  ipv6_native                     = false
  tags                            = { Name = "${var.name_prefix}-db-${each.key}" }
}

# Explicit empty route sets and no route propagation: only the implicit local
# route and the S3 gateway endpoint route exist. Static and propagated routes
# added out of band are removed on apply.
resource "aws_default_route_table" "this" {
  default_route_table_id = aws_vpc.this.default_route_table_id
  route                  = []
  propagating_vgws       = []
  tags                   = { Name = "${var.name_prefix}-unused-main" }
}

resource "aws_route_table" "task" {
  vpc_id           = aws_vpc.this.id
  route            = []
  propagating_vgws = []
  tags             = { Name = "${var.name_prefix}-task" }
}

resource "aws_route_table" "db" {
  vpc_id           = aws_vpc.this.id
  route            = []
  propagating_vgws = []
  tags             = { Name = "${var.name_prefix}-db" }
}

resource "aws_route_table_association" "task" {
  for_each       = aws_subnet.task
  subnet_id      = each.value.id
  route_table_id = aws_route_table.task.id
}

resource "aws_route_table_association" "db" {
  for_each       = aws_subnet.db
  subnet_id      = each.value.id
  route_table_id = aws_route_table.db.id
}

resource "aws_default_security_group" "this" {
  vpc_id  = aws_vpc.this.id
  ingress = []
  egress  = []
  tags    = { Name = "${var.name_prefix}-unused-default" }
}

# No inline rules: the provider removes AWS's default allow-all egress when it
# creates each group, and every permitted path is a separate rule below.
resource "aws_security_group" "this" {
  for_each               = local.security_groups
  name                   = "${var.name_prefix}-${replace(each.key, "_", "-")}"
  description            = each.value
  vpc_id                 = aws_vpc.this.id
  revoke_rules_on_delete = true
  tags                   = { Name = "${var.name_prefix}-${replace(each.key, "_", "-")}" }
}

resource "aws_vpc_security_group_egress_rule" "peer" {
  for_each                     = local.peer_rules
  security_group_id            = aws_security_group.this[each.value.source].id
  referenced_security_group_id = aws_security_group.this[each.value.destination].id
  ip_protocol                  = "tcp"
  from_port                    = each.value.port
  to_port                      = each.value.port
  description                  = "${each.value.source} to ${each.value.destination}"
}

resource "aws_vpc_security_group_ingress_rule" "peer" {
  for_each                     = local.peer_rules
  security_group_id            = aws_security_group.this[each.value.destination].id
  referenced_security_group_id = aws_security_group.this[each.value.source].id
  ip_protocol                  = "tcp"
  from_port                    = each.value.port
  to_port                      = each.value.port
  description                  = "${each.value.source} to ${each.value.destination}"
}

resource "aws_vpc_security_group_egress_rule" "s3" {
  for_each          = toset(local.workloads)
  security_group_id = aws_security_group.this[each.key].id
  prefix_list_id    = aws_vpc_endpoint.s3.prefix_list_id
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  description       = "${each.key} to the S3 gateway"
}

resource "aws_vpc_endpoint" "interface" {
  for_each            = local.interface_services
  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${var.region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  ip_address_type     = "ipv4"
  private_dns_enabled = true
  subnet_ids          = [for subnet in aws_subnet.task : subnet.id]
  security_group_ids  = [aws_security_group.this["endpoints"].id]
  policy              = jsonencode(local.endpoint_policies[each.key])
  tags                = { Name = "${var.name_prefix}-${replace(each.key, "_", "-")}" }
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.task.id]
  policy            = jsonencode(local.endpoint_policies.s3)
  tags              = { Name = "${var.name_prefix}-s3" }
}
