module "names" {
  source      = "../modules/naming"
  account_id  = var.account_id
  region      = var.region
  name_prefix = var.name_prefix
}

locals {
  bucket_arn = "arn:aws:s3:::${module.names.control_bucket}"
  control_bucket_policy = {
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport", Effect = "Deny", Principal = "*", Action = ["s3:*"]
        Resource  = [local.bucket_arn, "${local.bucket_arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid      = "DenyVersionDeletion", Effect = "Deny", Principal = "*", Action = ["s3:DeleteObjectVersion"]
        Resource = [local.bucket_arn, "${local.bucket_arn}/*"]
      },
      {
        Sid      = "DenyWorkloadRoles", Effect = "Deny", Principal = "*", Action = ["s3:*"]
        Resource = [local.bucket_arn, "${local.bucket_arn}/*"]
        # Workloads never receive control-bucket access, even by mistake.
        Condition = { ArnLike = { "aws:PrincipalArn" = module.names.workload_role_patterns } }
      },
    ]
  }
  state_access_policies = { for root, key in module.names.state_keys : root => {
    Version = "2012-10-17"
    Statement = [
      {
        # Init lists the default workspace prefix, and S3 reports a missing
        # object as 404 rather than 403 only to callers with list access.
        Sid       = "ListStateKey", Effect = "Allow", Action = ["s3:ListBucket"], Resource = [local.bucket_arn]
        Condition = { StringEqualsIfExists = { "s3:prefix" = [key, "env:/"] } }
      },
      { Sid = "ReadWriteState", Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject"], Resource = ["${local.bucket_arn}/${key}"] },
      { Sid = "StateLockfile", Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"], Resource = ["${local.bucket_arn}/${key}.tflock"] },
    ]
  } }
  release_evidence_policy = {
    Version = "2012-10-17"
    Statement = [
      {
        # The controller expects a missing journal or lock to read as absent (404).
        Sid       = "ListEvidence", Effect = "Allow", Action = ["s3:ListBucket"], Resource = [local.bucket_arn]
        Condition = { StringLikeIfExists = { "s3:prefix" = ["releases/*", module.names.release_lock_key] } }
      },
      { Sid = "ReleaseJournals", Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject"], Resource = ["${local.bucket_arn}/releases/*"] },
      { Sid = "EnvironmentLock", Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"], Resource = ["${local.bucket_arn}/${module.names.release_lock_key}"] },
    ]
  }
}

resource "aws_s3_bucket" "control" {
  bucket        = module.names.control_bucket
  force_destroy = false
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_ownership_controls" "control" {
  bucket = aws_s3_bucket.control.bucket
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "control" {
  bucket                  = aws_s3_bucket.control.bucket
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "control" {
  bucket = aws_s3_bucket.control.bucket
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "control" {
  bucket = aws_s3_bucket.control.bucket
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "control" {
  bucket = aws_s3_bucket.control.bucket
  rule {
    id     = "abort-incomplete-uploads"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
  depends_on = [aws_s3_bucket_versioning.control]
}

resource "aws_s3_bucket_policy" "control" {
  bucket     = aws_s3_bucket.control.bucket
  policy     = jsonencode(local.control_bucket_policy)
  depends_on = [aws_s3_bucket_public_access_block.control]
}

# Unattached customer-managed policies. Operator, launcher and trust choices
# remain separate approvals; this root creates no IAM principal.
resource "aws_iam_policy" "state_access" {
  for_each    = local.state_access_policies
  name        = "${var.name_prefix}-state-${each.key}"
  description = "Terraform S3 state and lockfile access for the ${each.key} root only."
  policy      = jsonencode(each.value)
}

resource "aws_iam_policy" "release_evidence" {
  name        = "${var.name_prefix}-release-evidence"
  description = "Release journal append and environment lock access; no Terraform state."
  policy      = jsonencode(local.release_evidence_policy)
}
