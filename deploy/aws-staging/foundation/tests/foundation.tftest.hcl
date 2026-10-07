mock_provider "aws" {}

# Plan-time identities for computed IDs so references can be compared. These
# are fake identifiers; no AWS API is called.
override_resource {
  target          = aws_vpc.this
  values          = { id = "vpc-0f00000000000000a", default_route_table_id = "rtb-0default000000000", default_security_group_id = "sg-0default0000000000" }
  override_during = plan
}
override_resource {
  target          = aws_subnet.task["us-east-1a"]
  values          = { id = "subnet-0task0000000000a" }
  override_during = plan
}
override_resource {
  target          = aws_subnet.task["us-east-1b"]
  values          = { id = "subnet-0task0000000000b" }
  override_during = plan
}
override_resource {
  target          = aws_subnet.db["us-east-1a"]
  values          = { id = "subnet-0db000000000000a" }
  override_during = plan
}
override_resource {
  target          = aws_subnet.db["us-east-1b"]
  values          = { id = "subnet-0db000000000000b" }
  override_during = plan
}
override_resource {
  target          = aws_route_table.task
  values          = { id = "rtb-0task00000000000" }
  override_during = plan
}
override_resource {
  target          = aws_route_table.db
  values          = { id = "rtb-0db0000000000000" }
  override_during = plan
}
override_resource {
  target          = aws_vpc_endpoint.s3
  values          = { id = "vpce-0s3000000000000", prefix_list_id = "pl-0s30000000000000" }
  override_during = plan
}
override_resource {
  target          = aws_service_discovery_private_dns_namespace.this
  values          = { id = "ns-staging000000000" }
  override_during = plan
}
override_resource {
  target          = aws_security_group.this["runtime"]
  values          = { id = "sg-runtime" }
  override_during = plan
}
override_resource {
  target          = aws_security_group.this["api"]
  values          = { id = "sg-api" }
  override_during = plan
}
override_resource {
  target          = aws_security_group.this["worker"]
  values          = { id = "sg-worker" }
  override_during = plan
}
override_resource {
  target          = aws_security_group.this["runtime_db_jobs"]
  values          = { id = "sg-runtime-db-jobs" }
  override_during = plan
}
override_resource {
  target          = aws_security_group.this["product_db_jobs"]
  values          = { id = "sg-product-db-jobs" }
  override_during = plan
}
override_resource {
  target          = aws_security_group.this["runtime_transport_proof"]
  values          = { id = "sg-runtime-transport-proof" }
  override_during = plan
}
override_resource {
  target          = aws_security_group.this["api_proof"]
  values          = { id = "sg-api-proof" }
  override_during = plan
}
override_resource {
  target          = aws_security_group.this["storage_proof"]
  values          = { id = "sg-storage-proof" }
  override_during = plan
}
override_resource {
  target          = aws_security_group.this["runtime_db"]
  values          = { id = "sg-runtime-db" }
  override_during = plan
}
override_resource {
  target          = aws_security_group.this["product_db"]
  values          = { id = "sg-product-db" }
  override_during = plan
}
override_resource {
  target          = aws_security_group.this["endpoints"]
  values          = { id = "sg-endpoints" }
  override_during = plan
}

override_resource {
  target          = aws_db_instance.this["runtime"]
  values          = { master_user_secret = [{ kms_key_id = "alias/aws/secretsmanager", secret_arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:rds!db-11111111-aaaa-4aaa-8aaa-111111111111-AbCdEf", secret_status = "active" }] }
  override_during = plan
}
override_resource {
  target          = aws_db_instance.this["product"]
  values          = { master_user_secret = [{ kms_key_id = "alias/aws/secretsmanager", secret_arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:rds!db-22222222-bbbb-4bbb-8bbb-222222222222-GhIjKl", secret_status = "active" }] }
  override_during = plan
}

variables {
  account_id              = "111122223333"
  region                  = "us-east-1"
  name_prefix             = "sentry-staging"
  availability_zones      = ["us-east-1a", "us-east-1b"]
  vpc_cidr                = "10.80.0.0/20"
  private_dns_namespace   = "sentry-staging.internal.example"
  postgres_engine_version = "16.6"
}

run "private_two_az_network_without_internet_paths" {
  command = plan
  assert {
    condition = (aws_vpc.this.cidr_block == "10.80.0.0/20" && aws_vpc.this.enable_dns_support && aws_vpc.this.enable_dns_hostnames &&
      aws_vpc.this.assign_generated_ipv6_cidr_block == false && aws_vpc.this.ipv6_ipam_pool_id == null && aws_vpc.this.ipv6_netmask_length == null &&
      { for az, subnet in aws_subnet.task : az => subnet.cidr_block } == { "us-east-1a" = "10.80.0.0/22", "us-east-1b" = "10.80.4.0/22" } &&
      { for az, subnet in aws_subnet.db : az => subnet.cidr_block } == { "us-east-1a" = "10.80.8.0/22", "us-east-1b" = "10.80.12.0/22" } &&
      alltrue([for az, subnet in merge({ for k, v in aws_subnet.task : "task-${k}" => v }, { for k, v in aws_subnet.db : "db-${k}" => v }) :
        subnet.vpc_id == aws_vpc.this.id && subnet.map_public_ip_on_launch == false && subnet.assign_ipv6_address_on_creation == false &&
        subnet.ipv6_ipam_pool_id == null && subnet.ipv6_netmask_length == null && subnet.enable_dns64 == false && subnet.ipv6_native == false && subnet.availability_zone == trimprefix(trimprefix(az, "task-"), "db-")
    ]))
    error_message = "Use one dedicated VPC with two task and two DB subnets across two AZs, with no public or IPv6 addressing."
  }
  assert {
    condition = (length(aws_route_table.task.route) == 0 && length(aws_route_table.db.route) == 0 && length(aws_default_route_table.this.route) == 0 &&
      length(aws_route_table.task.propagating_vgws) == 0 && length(aws_route_table.db.propagating_vgws) == 0 && length(aws_default_route_table.this.propagating_vgws) == 0 &&
      aws_default_route_table.this.default_route_table_id == aws_vpc.this.default_route_table_id &&
      { for az, association in aws_route_table_association.task : az => [association.subnet_id, association.route_table_id] } == {
        "us-east-1a" = ["subnet-0task0000000000a", "rtb-0task00000000000"], "us-east-1b" = ["subnet-0task0000000000b", "rtb-0task00000000000"]
      } &&
      { for az, association in aws_route_table_association.db : az => [association.subnet_id, association.route_table_id] } == {
        "us-east-1a" = ["subnet-0db000000000000a", "rtb-0db0000000000000"], "us-east-1b" = ["subnet-0db000000000000b", "rtb-0db0000000000000"]
    })
    error_message = "Route tables keep only implicit local and S3-gateway routes; Terraform removes any default or out-of-band route."
  }
  assert {
    condition = (aws_default_security_group.this.vpc_id == aws_vpc.this.id &&
    length(aws_default_security_group.this.ingress) == 0 && length(aws_default_security_group.this.egress) == 0)
    error_message = "The VPC default security group must have no rules."
  }
}

run "endpoints_cover_bootstrap_services_in_both_task_azs" {
  command = plan
  assert {
    condition = ({ for name, endpoint in aws_vpc_endpoint.interface : name => endpoint.service_name } == {
      ecr_api = "com.amazonaws.us-east-1.ecr.api", ecr_dkr = "com.amazonaws.us-east-1.ecr.dkr"
      logs    = "com.amazonaws.us-east-1.logs", secretsmanager = "com.amazonaws.us-east-1.secretsmanager"
      } && alltrue([for name, endpoint in aws_vpc_endpoint.interface :
        endpoint.vpc_endpoint_type == "Interface" && endpoint.private_dns_enabled && endpoint.vpc_id == aws_vpc.this.id &&
        endpoint.ip_address_type == "ipv4" &&
        endpoint.subnet_ids == toset(["subnet-0task0000000000a", "subnet-0task0000000000b"]) &&
        endpoint.security_group_ids == toset(["sg-endpoints"]) &&
        jsondecode(endpoint.policy) == jsondecode(jsonencode(output.endpoint_policies[name]))
    ]))
    error_message = "ECR API/DKR, Secrets Manager and Logs need private-DNS interface endpoints in both task subnets behind the endpoint SG."
  }
  assert {
    condition = (aws_vpc_endpoint.s3.service_name == "com.amazonaws.us-east-1.s3" && aws_vpc_endpoint.s3.vpc_endpoint_type == "Gateway" &&
      aws_vpc_endpoint.s3.route_table_ids == toset(["rtb-0task00000000000"]) &&
      jsondecode(aws_vpc_endpoint.s3.policy) == jsondecode(jsonencode(output.endpoint_policies.s3)) &&
      output.endpoint_policies.s3.Statement == [
        { Sid = "EcrImageLayers", Effect = "Allow", Principal = "*", Action = ["s3:GetObject"], Resource = ["arn:aws:s3:::prod-us-east-1-starport-layer-bucket/*"] },
        {
          Sid      = "ReportObjects", Effect = "Allow", Principal = "*", Action = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
          Resource = ["arn:aws:s3:::sentry-staging-111122223333-reports/reports/*"], Condition = { StringEquals = { "aws:PrincipalAccount" = "111122223333" } }
        },
        {
          Sid       = "ListReports", Effect = "Allow", Principal = "*", Action = ["s3:ListBucket"], Resource = ["arn:aws:s3:::sentry-staging-111122223333-reports"]
          Condition = { StringEquals = { "aws:PrincipalAccount" = "111122223333" }, StringLike = { "s3:prefix" = ["reports/*"] } }
        },
    ])
    error_message = "The S3 gateway serves only task route tables, the regional ECR layer bucket and report-prefix operations; no general S3 allow."
  }
  assert {
    condition = (output.endpoint_policies.ecr_api == output.endpoint_policies.ecr_dkr &&
      output.endpoint_policies.ecr_api.Statement == [
        {
          Sid       = "RegistryToken", Effect = "Allow", Principal = "*", Action = ["ecr:GetAuthorizationToken"], Resource = ["*"]
          Condition = { StringEquals = { "aws:PrincipalAccount" = "111122223333" } }
        },
        {
          Sid = "PullEnvironmentImages", Effect = "Allow", Principal = "*", Action = ["ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"]
          Resource = [
            "arn:aws:ecr:us-east-1:111122223333:repository/sentry-staging/release-tools",
            "arn:aws:ecr:us-east-1:111122223333:repository/sentry-staging/runtime",
            "arn:aws:ecr:us-east-1:111122223333:repository/sentry-staging/search",
          ]
          Condition = { StringEquals = { "aws:PrincipalAccount" = "111122223333" } }
        },
      ] &&
      jsonencode(output.endpoint_policies.secretsmanager.Statement) == jsonencode([
        {
          Sid      = "EnvironmentSecrets", Effect = "Allow", Principal = "*", Action = ["secretsmanager:GetSecretValue"]
          Resource = ["arn:aws:secretsmanager:us-east-1:111122223333:secret:sentry-staging/*"], Condition = { StringEquals = { "aws:PrincipalAccount" = "111122223333" } }
        },
        {
          # Exact RDS-managed administrator secrets for future in-VPC bootstrap jobs.
          Sid = "RdsManagedAdministratorSecrets", Effect = "Allow", Principal = "*", Action = ["secretsmanager:GetSecretValue"]
          Resource = [
            "arn:aws:secretsmanager:us-east-1:111122223333:secret:rds!db-11111111-aaaa-4aaa-8aaa-111111111111-AbCdEf",
            "arn:aws:secretsmanager:us-east-1:111122223333:secret:rds!db-22222222-bbbb-4bbb-8bbb-222222222222-GhIjKl",
          ]
          Condition = { StringEquals = { "aws:PrincipalAccount" = "111122223333" } }
        },
      ]) &&
      output.endpoint_policies.logs.Statement == [{
        Sid       = "EnvironmentLogStreams", Effect = "Allow", Principal = "*", Action = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource  = [for name in ["api", "product-release", "runtime", "runtime-release", "worker"] : "arn:aws:logs:us-east-1:111122223333:log-group:/sentry-staging/${name}:log-stream:*"]
        Condition = { StringEquals = { "aws:PrincipalAccount" = "111122223333" } }
    }])
    error_message = "Interface endpoint policies admit only same-account callers for this environment's repositories, secret prefix and log groups."
  }
  assert {
    condition = alltrue(flatten([for name, document in output.endpoint_policies : [for statement in document.Statement : [for resource in statement.Resource :
      (resource != "*" || statement.Action == ["ecr:GetAuthorizationToken"]) &&
      (startswith(resource, "arn:aws:s3:::") || resource == "*" || strcontains(resource, ":us-east-1:111122223333:"))
    ]]]))
    error_message = "The ECR token is the only bare wildcard resource; every regional ARN is in the selected account and region."
  }
}

run "security_groups_are_explicit_pairs" {
  command = plan
  assert {
    condition = (toset(keys(aws_security_group.this)) == toset([
      "runtime", "api", "worker", "runtime_db_jobs", "product_db_jobs", "runtime_transport_proof", "api_proof", "storage_proof",
      "runtime_db", "product_db", "endpoints",
      ]) && alltrue([for name, group in aws_security_group.this :
      group.vpc_id == aws_vpc.this.id && group.name == "sentry-staging-${replace(name, "_", "-")}" && group.revoke_rules_on_delete
    ]))
    error_message = "Each service, job class, database and the endpoint tier needs its own named security group."
  }
  assert {
    condition = toset([for rule in aws_vpc_security_group_egress_rule.peer :
      "${ { for name, group in aws_security_group.this : group.id => name }[rule.security_group_id]}>${ { for name, group in aws_security_group.this : group.id => name }[rule.referenced_security_group_id]}:${rule.ip_protocol}/${rule.from_port}-${rule.to_port}"
      if rule.cidr_ipv4 == null && rule.cidr_ipv6 == null && rule.prefix_list_id == null
      ]) == toset(concat([
        "runtime>runtime_db:tcp/5432-5432", "runtime_db_jobs>runtime_db:tcp/5432-5432",
        "api>product_db:tcp/5432-5432", "worker>product_db:tcp/5432-5432", "product_db_jobs>product_db:tcp/5432-5432",
        "worker>runtime:tcp/8443-8443", "runtime_transport_proof>runtime:tcp/8443-8443", "api_proof>api:tcp/8001-8001",
        ], [for source in ["runtime", "api", "worker", "runtime_db_jobs", "product_db_jobs", "runtime_transport_proof", "api_proof", "storage_proof"] :
        "${source}>endpoints:tcp/443-443"
    ])) && length(aws_vpc_security_group_egress_rule.peer) == 16
    error_message = "Security-group egress must be exactly the designed source/destination pairs."
  }
  assert {
    condition = toset([for rule in aws_vpc_security_group_ingress_rule.peer :
      "${ { for name, group in aws_security_group.this : group.id => name }[rule.referenced_security_group_id]}>${ { for name, group in aws_security_group.this : group.id => name }[rule.security_group_id]}:${rule.ip_protocol}/${rule.from_port}-${rule.to_port}"
      if rule.cidr_ipv4 == null && rule.cidr_ipv6 == null && rule.prefix_list_id == null
    ]) == toset([for rule in aws_vpc_security_group_egress_rule.peer : "${ { for name, group in aws_security_group.this : group.id => name }[rule.security_group_id]}>${ { for name, group in aws_security_group.this : group.id => name }[rule.referenced_security_group_id]}:${rule.ip_protocol}/${rule.from_port}-${rule.to_port}"]) && length(aws_vpc_security_group_ingress_rule.peer) == 16
    error_message = "Every destination admits exactly its paired sources; the worker and DB tiers have no other ingress."
  }
  assert {
    condition = (length(aws_vpc_security_group_egress_rule.s3) == 8 && alltrue([for rule in aws_vpc_security_group_egress_rule.s3 :
      rule.prefix_list_id == "pl-0s30000000000000" && rule.ip_protocol == "tcp" && rule.from_port == 443 && rule.to_port == 443 &&
      rule.cidr_ipv4 == null && rule.cidr_ipv6 == null && rule.referenced_security_group_id == null
      ]) && toset([for rule in aws_vpc_security_group_egress_rule.s3 : rule.security_group_id]) == toset([
      "sg-runtime", "sg-api", "sg-worker", "sg-runtime-db-jobs", "sg-product-db-jobs", "sg-runtime-transport-proof", "sg-api-proof", "sg-storage-proof",
    ]))
    error_message = "Task and job groups reach S3 only through the gateway prefix list on 443, for ECR layers and policy-bounded report access."
  }
}

run "databases_are_private_encrypted_tls_and_protected" {
  command = plan
  assert {
    condition = (toset(keys(aws_db_instance.this)) == toset(["runtime", "product"]) && alltrue([for name, db in aws_db_instance.this :
      db.identifier == "sentry-staging-${name}-db" && db.engine == "postgres" && db.engine_version == "16.6" &&
      db.instance_class == "db.t4g.micro" && db.allocated_storage == 20 && db.storage_type == "gp3" && db.max_allocated_storage == null &&
      db.storage_encrypted && db.publicly_accessible == false && db.multi_az == false && db.network_type == "IPV4" && db.port == 5432 &&
      db.db_subnet_group_name == aws_db_subnet_group.this.name && db.parameter_group_name == aws_db_parameter_group.postgres16.name &&
      db.vpc_security_group_ids == toset(["sg-${name}-db"]) && db.ca_cert_identifier == "rds-ca-rsa2048-g1" &&
      db.backup_retention_period == 7 && db.deletion_protection && db.skip_final_snapshot == false &&
      db.final_snapshot_identifier == "sentry-staging-${name}-db-final" && db.copy_tags_to_snapshot && db.delete_automated_backups == false &&
      db.manage_master_user_password && db.password == null && db.password_wo == null && db.username == "${name}_admin" &&
      db.iam_database_authentication_enabled == false && db.auto_minor_version_upgrade == false && db.allow_major_version_upgrade == false &&
      db.apply_immediately == false && db.performance_insights_enabled == false && db.monitoring_interval == 0 &&
      db.engine_lifecycle_support == "open-source-rds-extended-support-disabled"
    ]))
    error_message = "Two private PostgreSQL 16 instances need encryption, TLS parameters, 7-day PITR, deletion protection, final snapshots and RDS-managed admin secrets."
  }
  assert {
    condition = (aws_db_subnet_group.this.subnet_ids == toset(["subnet-0db000000000000a", "subnet-0db000000000000b"]) &&
      aws_db_parameter_group.postgres16.family == "postgres16" &&
    { for parameter in aws_db_parameter_group.postgres16.parameter : parameter.name => parameter.value } == { "rds.force_ssl" = "1", "ssl_min_protocol_version" = "TLSv1.2" })
    error_message = "Databases live only in DB subnets and reject non-TLS or pre-TLS1.2 connections."
  }
}

run "report_bucket_is_private_versioned_and_bounded" {
  command = plan
  assert {
    condition = (aws_s3_bucket.reports.bucket == "sentry-staging-111122223333-reports" && aws_s3_bucket.reports.force_destroy == false &&
      one(aws_s3_bucket_ownership_controls.reports.rule).object_ownership == "BucketOwnerEnforced" &&
      aws_s3_bucket_public_access_block.reports.block_public_acls && aws_s3_bucket_public_access_block.reports.block_public_policy &&
      aws_s3_bucket_public_access_block.reports.ignore_public_acls && aws_s3_bucket_public_access_block.reports.restrict_public_buckets &&
      one(aws_s3_bucket_versioning.reports.versioning_configuration).status == "Enabled" &&
      [for rule in aws_s3_bucket_server_side_encryption_configuration.reports.rule : one(rule.apply_server_side_encryption_by_default).sse_algorithm] == ["AES256"] &&
      alltrue([for resource in [aws_s3_bucket_ownership_controls.reports, aws_s3_bucket_public_access_block.reports, aws_s3_bucket_versioning.reports,
        aws_s3_bucket_server_side_encryption_configuration.reports, aws_s3_bucket_lifecycle_configuration.reports, aws_s3_bucket_policy.reports] :
    resource.bucket == aws_s3_bucket.reports.bucket]))
    error_message = "The report bucket must be owner-enforced, public-blocked, versioned, SSE-S3 and force_destroy=false."
  }
  assert {
    condition = (length(aws_s3_bucket_lifecycle_configuration.reports.rule) == 1 &&
      one(one(aws_s3_bucket_lifecycle_configuration.reports.rule).expiration).days == 30 &&
      one(one(aws_s3_bucket_lifecycle_configuration.reports.rule).noncurrent_version_expiration).noncurrent_days == 30 &&
    one(one(aws_s3_bucket_lifecycle_configuration.reports.rule).abort_incomplete_multipart_upload).days_after_initiation == 1)
    error_message = "Report retention is bounded: 30-day current/noncurrent versions and one-day incomplete uploads."
  }
  assert {
    condition = (jsondecode(aws_s3_bucket_policy.reports.policy) == jsondecode(jsonencode(output.report_bucket_policy)) &&
      output.report_bucket_policy.Statement == [
        {
          Sid       = "DenyInsecureTransport", Effect = "Deny", Principal = "*", Action = ["s3:*"]
          Resource  = ["arn:aws:s3:::sentry-staging-111122223333-reports", "arn:aws:s3:::sentry-staging-111122223333-reports/*"]
          Condition = { Bool = { "aws:SecureTransport" = "false" } }
        },
        {
          Sid      = "DenyVersionDeletion", Effect = "Deny", Principal = "*", Action = ["s3:DeleteObjectVersion"]
          Resource = ["arn:aws:s3:::sentry-staging-111122223333-reports", "arn:aws:s3:::sentry-staging-111122223333-reports/*"]
        },
        {
          Sid      = "DenyWorkloadsOutsideEndpoint", Effect = "Deny", Principal = "*", Action = ["s3:*"]
          Resource = ["arn:aws:s3:::sentry-staging-111122223333-reports", "arn:aws:s3:::sentry-staging-111122223333-reports/*"]
          Condition = {
            ArnLike         = { "aws:PrincipalArn" = ["arn:aws:iam::111122223333:role/sentry-staging-*-task", "arn:aws:iam::111122223333:role/sentry-staging-*-execution"] }
            StringNotEquals = { "aws:SourceVpce" = "vpce-0s3000000000000" }
          }
        },
    ])
    error_message = "Reports require TLS, keep object versions and accept workload roles only through this VPC's S3 gateway."
  }
}

run "registries_logs_cluster_and_private_dns" {
  command = plan
  assert {
    condition = ({ for name, repository in aws_ecr_repository.this : name => repository.name } == {
      runtime = "sentry-staging/runtime", search = "sentry-staging/search", release_tools = "sentry-staging/release-tools"
      } && alltrue([for repository in aws_ecr_repository.this :
        repository.image_tag_mutability == "IMMUTABLE" && repository.force_delete == false &&
        one(repository.image_scanning_configuration).scan_on_push && one(repository.encryption_configuration).encryption_type == "AES256"
    ]))
    error_message = "Three immutable private repositories hold Runtime, Search and release-tools digests without force deletion."
  }
  assert {
    condition = ({ for name, group in aws_cloudwatch_log_group.this : name => group.name } == {
      runtime         = "/sentry-staging/runtime", api = "/sentry-staging/api", worker = "/sentry-staging/worker"
      runtime-release = "/sentry-staging/runtime-release", product-release = "/sentry-staging/product-release"
      } && alltrue([for group in aws_cloudwatch_log_group.this :
        group.retention_in_days == 14 && group.skip_destroy && group.deletion_protection_enabled && group.kms_key_id == null && group.log_group_class == "STANDARD"
    ]))
    error_message = "Every service and release-job log group is pre-created with bounded retention and destroy protection."
  }
  assert {
    condition = (aws_ecs_cluster.this.name == "sentry-staging" &&
      [for setting in aws_ecs_cluster.this.setting : "${setting.name}=${setting.value}"] == ["containerInsights=disabled"] &&
    length(aws_ecs_cluster.this.configuration) == 0)
    error_message = "The cluster has no execute-command configuration and no unapproved Container Insights spend."
  }
  assert {
    condition = (aws_service_discovery_private_dns_namespace.this.name == "sentry-staging.internal.example" &&
      aws_service_discovery_private_dns_namespace.this.vpc == aws_vpc.this.id &&
      { for name, service in aws_service_discovery_service.this : name => service.name } == { runtime = "runtime", api = "api" } &&
      alltrue([for service in aws_service_discovery_service.this :
        one(service.dns_config).namespace_id == "ns-staging000000000" && one(service.dns_config).routing_policy == "MULTIVALUE" &&
        [for record in one(service.dns_config).dns_records : "${record.type}/${record.ttl}"] == ["A/10"] &&
        length(service.health_check_custom_config) == 1 && length(service.health_check_config) == 0 && service.force_destroy == false
      ]) &&
    output.runtime_server_name == "runtime.sentry-staging.internal.example" && output.api_server_name == "api.sentry-staging.internal.example")
    error_message = "Runtime and API resolve through private A records with a 10-second TTL; Runtime's name is its certificate SAN."
  }
}

run "reject_public_vpc_cidr" {
  command = plan
  variables { vpc_cidr = "8.8.0.0/20" }
  expect_failures = [var.vpc_cidr]
}

run "reject_unaligned_vpc_cidr" {
  command = plan
  variables { vpc_cidr = "10.80.1.0/20" }
  expect_failures = [var.vpc_cidr]
}

run "reject_oversized_vpc_cidr" {
  command = plan
  variables { vpc_cidr = "10.0.0.0/12" }
  expect_failures = [var.vpc_cidr]
}

run "reject_single_availability_zone" {
  command = plan
  variables { availability_zones = ["us-east-1a", "us-east-1a"] }
  expect_failures = [var.availability_zones]
}

run "reject_foreign_region_availability_zone" {
  command = plan
  variables { availability_zones = ["us-east-1a", "us-west-2b"] }
  expect_failures = [var.availability_zones]
}

run "reject_other_postgres_major" {
  command = plan
  variables { postgres_engine_version = "15.8" }
  expect_failures = [var.postgres_engine_version]
}

run "reject_ip_namespace" {
  command = plan
  variables { private_dns_namespace = "10.0.0.1" }
  expect_failures = [var.private_dns_namespace]
}

run "reject_unbounded_log_retention" {
  command = plan
  variables { log_retention_days = 0 }
  expect_failures = [var.log_retention_days]
}

run "reject_non_staging_prefix" {
  command = plan
  variables { name_prefix = "sentry-prod" }
  expect_failures = [var.name_prefix]
}
