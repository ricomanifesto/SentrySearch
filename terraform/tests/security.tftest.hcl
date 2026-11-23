# Every provider is mocked. These plans use no credentials or live account APIs.
mock_provider "aws" {}
mock_provider "random" {}

variables {
  database_vpc_id              = "vpc-0123456789abcdef0"
  database_subnet_ids          = ["subnet-0123456789abcdef0", "subnet-abcdef01234567890"]
  db_password                  = "offline-test-fixture"
  db_final_snapshot_identifier = "sentrysearch-final-offline-test"
}

run "private_database_defaults" {
  command = plan

  assert {
    condition     = aws_db_instance.sentrysearch.publicly_accessible == false
    error_message = "The database must not have a public endpoint."
  }
  assert {
    condition     = length(aws_security_group.sentrysearch_db.ingress) == 0 && length(aws_security_group.sentrysearch_db.egress) == 0
    error_message = "An empty client allowlist must explicitly manage zero ingress and egress rules."
  }
  assert {
    condition     = aws_security_group.sentrysearch_db.vpc_id == var.database_vpc_id && aws_db_subnet_group.sentrysearch.subnet_ids == var.database_subnet_ids
    error_message = "The database must use the explicitly supplied network."
  }
  assert {
    condition     = aws_db_instance.sentrysearch.deletion_protection && !aws_db_instance.sentrysearch.skip_final_snapshot && aws_db_instance.sentrysearch.final_snapshot_identifier == var.db_final_snapshot_identifier
    error_message = "Default deletion protection and a named final snapshot are required."
  }
}

run "approved_database_client" {
  command = plan
  variables {
    database_client_security_group_ids = ["sg-0123456789abcdef0"]
  }
  assert {
    condition = alltrue([for rule in aws_security_group.sentrysearch_db.ingress :
      rule.from_port == 5432 && rule.to_port == 5432 && rule.protocol == "tcp" &&
      rule.security_groups == toset(["sg-0123456789abcdef0"]) &&
      length(rule.cidr_blocks) == 0 && length(rule.ipv6_cidr_blocks) == 0
    ]) && length(aws_security_group.sentrysearch_db.ingress) == 1
    error_message = "Only the selected application security group may reach PostgreSQL."
  }
}

run "reject_incomplete_subnets" {
  command = plan
  variables {
    database_subnet_ids = ["subnet-0123456789abcdef0"]
  }
  expect_failures = [var.database_subnet_ids]
}

run "reject_snapshot_outside_project" {
  command = plan
  variables {
    db_final_snapshot_identifier = "another-project-final-test"
  }
  expect_failures = [var.db_final_snapshot_identifier]
}
