mock_provider "aws" {}

variables {
  account_id  = "111122223333"
  region      = "us-east-1"
  name_prefix = "sentry-staging"
}

run "control_bucket_is_private_versioned_and_protected" {
  command = plan
  assert {
    condition = (aws_s3_bucket.control.bucket == "sentry-staging-111122223333-control" &&
      aws_s3_bucket.control.force_destroy == false &&
      one(aws_s3_bucket_ownership_controls.control.rule).object_ownership == "BucketOwnerEnforced" &&
      aws_s3_bucket_public_access_block.control.block_public_acls && aws_s3_bucket_public_access_block.control.block_public_policy &&
      aws_s3_bucket_public_access_block.control.ignore_public_acls && aws_s3_bucket_public_access_block.control.restrict_public_buckets &&
      one(aws_s3_bucket_versioning.control.versioning_configuration).status == "Enabled" &&
      [for rule in aws_s3_bucket_server_side_encryption_configuration.control.rule : one(rule.apply_server_side_encryption_by_default).sse_algorithm] == ["AES256"] &&
      alltrue([for resource in [aws_s3_bucket_ownership_controls.control, aws_s3_bucket_public_access_block.control, aws_s3_bucket_versioning.control,
        aws_s3_bucket_server_side_encryption_configuration.control, aws_s3_bucket_lifecycle_configuration.control, aws_s3_bucket_policy.control] :
    resource.bucket == aws_s3_bucket.control.bucket]))
    error_message = "The control bucket must be owner-enforced, public-blocked, versioned, SSE-S3 and force_destroy=false."
  }
  assert {
    condition = (length(aws_s3_bucket_lifecycle_configuration.control.rule) == 1 &&
      one(aws_s3_bucket_lifecycle_configuration.control.rule).status == "Enabled" &&
      one(one(aws_s3_bucket_lifecycle_configuration.control.rule).abort_incomplete_multipart_upload).days_after_initiation == 1 &&
      length(one(aws_s3_bucket_lifecycle_configuration.control.rule).expiration) == 0 &&
    length(one(aws_s3_bucket_lifecycle_configuration.control.rule).noncurrent_version_expiration) == 0)
    error_message = "State, journals and locks never expire; only incomplete multipart uploads are cleaned up."
  }
}

run "control_bucket_policy_denies_insecure_deletion_and_workloads" {
  command = plan
  assert {
    condition     = jsondecode(aws_s3_bucket_policy.control.policy) == jsondecode(jsonencode(output.control_bucket_policy))
    error_message = "The applied bucket policy must be the reviewed output document."
  }
  assert {
    condition = (alltrue([for statement in output.control_bucket_policy.Statement : statement.Effect == "Deny"]) &&
      { for statement in output.control_bucket_policy.Statement : statement.Sid => try(statement.Condition, null) } == {
        DenyInsecureTransport = { Bool = { "aws:SecureTransport" = "false" } }
        DenyVersionDeletion   = null
        DenyWorkloadRoles = { ArnLike = { "aws:PrincipalArn" = [
          "arn:aws:iam::111122223333:role/sentry-staging-*-task",
          "arn:aws:iam::111122223333:role/sentry-staging-*-execution",
        ] } }
      } &&
      [for statement in output.control_bucket_policy.Statement : statement.Action if statement.Sid == "DenyVersionDeletion"] == [["s3:DeleteObjectVersion"]] &&
      alltrue([for statement in output.control_bucket_policy.Statement :
        statement.Resource == ["arn:aws:s3:::sentry-staging-111122223333-control", "arn:aws:s3:::sentry-staging-111122223333-control/*"]
    ]))
    error_message = "The control bucket must reject plaintext transport, permanent version deletion and every app/job task or execution role."
  }
}

run "state_keys_have_narrow_lockfile_permissions" {
  command = plan
  assert {
    condition = (toset(keys(aws_iam_policy.state_access)) == toset(["bootstrap", "foundation", "releases", "services"]) &&
      alltrue([for root, policy in aws_iam_policy.state_access :
        policy.name == "sentry-staging-state-${root}" &&
        jsondecode(policy.policy) == jsondecode(jsonencode(output.state_access_policies[root])) &&
        output.state_access_policies[root].Statement == [
          {
            # Init lists the workspace prefix; S3's 404-versus-403 check needs list access.
            Sid       = "ListStateKey", Effect = "Allow", Action = ["s3:ListBucket"], Resource = ["arn:aws:s3:::sentry-staging-111122223333-control"]
            Condition = { StringEqualsIfExists = { "s3:prefix" = ["state/${root}.tfstate", "env:/"] } }
          },
          { Sid = "ReadWriteState", Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject"], Resource = ["arn:aws:s3:::sentry-staging-111122223333-control/state/${root}.tfstate"] },
          { Sid = "StateLockfile", Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"], Resource = ["arn:aws:s3:::sentry-staging-111122223333-control/state/${root}.tfstate.tflock"] },
        ]
    ]))
    error_message = "Each root's state policy covers exactly its own state object and S3 lockfile, with no DynamoDB or neighbouring keys."
  }
  assert {
    condition = (aws_iam_policy.release_evidence.name == "sentry-staging-release-evidence" &&
      jsondecode(aws_iam_policy.release_evidence.policy) == jsondecode(jsonencode(output.release_evidence_policy)) &&
      output.release_evidence_policy.Statement == [
        {
          # A missing journal or lock must read as 404, which S3 returns only with list access.
          Sid       = "ListEvidence", Effect = "Allow", Action = ["s3:ListBucket"], Resource = ["arn:aws:s3:::sentry-staging-111122223333-control"]
          Condition = { StringLikeIfExists = { "s3:prefix" = ["releases/*", "locks/sentry-staging.json"] } }
        },
        { Sid = "ReleaseJournals", Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject"], Resource = ["arn:aws:s3:::sentry-staging-111122223333-control/releases/*"] },
        { Sid = "EnvironmentLock", Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"], Resource = ["arn:aws:s3:::sentry-staging-111122223333-control/locks/sentry-staging.json"] },
    ])
    error_message = "Release evidence may append journals and hold only this environment's lock; it cannot read or write Terraform state."
  }
  assert {
    condition = alltrue([for document in concat(values(output.state_access_policies), [output.release_evidence_policy], [output.control_bucket_policy]) :
      alltrue([for statement in document.Statement : alltrue([for resource in statement.Resource :
        resource != "*" && startswith(resource, "arn:aws:s3:::sentry-staging-111122223333-control")
      ])])
    ])
    error_message = "Bootstrap policies are confined to the control bucket; no wildcard or foreign resources."
  }
}

run "reject_short_account" {
  command = plan
  variables { account_id = "11112222333" }
  expect_failures = [var.account_id]
}

run "reject_non_staging_prefix" {
  command = plan
  variables { name_prefix = "sentry-production" }
  expect_failures = [var.name_prefix]
}

run "reject_prefix_that_overflows_release_roles" {
  command = plan
  variables { name_prefix = "sentry-search-runtime-staging" }
  expect_failures = [var.name_prefix]
}

run "reject_invalid_region" {
  command = plan
  variables { region = "global" }
  expect_failures = [var.region]
}

run "no_operator_role_by_default" {
  command = plan
  assert {
    condition     = length(aws_iam_role.operator) == 0 && output.operator_role_arn == null && output.operator_trust_policy == null
    error_message = "Without an approved operator trust input this root creates no IAM principal."
  }
}

run "operator_trust_names_one_principal_and_pins_the_session" {
  command = plan
  variables {
    operator_trust = {
      principal_arn   = "arn:aws:iam::444455556666:role/custodian-issuer", external_id = "fixture-external-id-0123456789"
      session_seconds = 14400, operator = "michael"
    }
  }
  assert {
    condition = (aws_iam_role.operator[0].name == "sentry-staging-operator" &&
      aws_iam_role.operator[0].max_session_duration == 14400 &&
      output.operator_role_arn == "arn:aws:iam::111122223333:role/sentry-staging-operator" &&
      jsondecode(aws_iam_role.operator[0].assume_role_policy) == {
        Version = "2012-10-17"
        Statement = [{
          Sid    = "AttendedOperator", Effect = "Allow", Principal = { AWS = "arn:aws:iam::444455556666:role/custodian-issuer" }
          Action = ["sts:AssumeRole", "sts:SetSourceIdentity"]
          Condition = { StringEquals = {
            "sts:ExternalId" = "fixture-external-id-0123456789", "sts:RoleSessionName" = "michael", "sts:SourceIdentity" = "michael"
          } }
        }]
    })
    error_message = "The operator role trusts one principal with its external id, and the session name and source identity must be the approved operator."
  }
}

run "reject_a_trust_policy_with_a_wildcard_principal" {
  command = plan
  variables {
    operator_trust = { principal_arn = "*", external_id = "fixture-external-id-0123456789", session_seconds = 3600, operator = "michael" }
  }
  expect_failures = [var.operator_trust]
}

run "reject_an_account_root_principal" {
  command = plan
  variables {
    operator_trust = { principal_arn = "arn:aws:iam::444455556666:root", external_id = "fixture-external-id-0123456789", session_seconds = 3600, operator = "michael" }
  }
  expect_failures = [var.operator_trust]
}

run "reject_a_wildcard_role_path" {
  command = plan
  variables {
    operator_trust = { principal_arn = "arn:aws:iam::444455556666:role/*", external_id = "fixture-external-id-0123456789", session_seconds = 3600, operator = "michael" }
  }
  expect_failures = [var.operator_trust]
}

run "reject_a_short_external_id" {
  command = plan
  variables {
    operator_trust = { principal_arn = "arn:aws:iam::444455556666:role/custodian-issuer", external_id = "short", session_seconds = 3600, operator = "michael" }
  }
  expect_failures = [var.operator_trust]
}

run "reject_an_unbounded_session" {
  command = plan
  variables {
    operator_trust = { principal_arn = "arn:aws:iam::444455556666:role/custodian-issuer", external_id = "fixture-external-id-0123456789", session_seconds = 86400, operator = "michael" }
  }
  expect_failures = [var.operator_trust]
}
