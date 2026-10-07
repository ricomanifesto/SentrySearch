terraform {
  # S3 lockfiles need Terraform 1.10+; this root is tested on the 1.16 line.
  required_version = ">= 1.16.5, < 1.17.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.65.0"
    }
  }
  # Partial configuration: supply the bootstrap control bucket and region with
  # -backend-config at an approved init. Native S3 lockfile; no DynamoDB table.
  backend "s3" {
    key          = "state/releases.tfstate"
    encrypt      = true
    use_lockfile = true
  }
}

provider "aws" {
  region              = var.region
  allowed_account_ids = [var.account_id]
  default_tags {
    tags = { Environment = var.name_prefix, ManagedBy = "terraform", Root = "releases" }
  }
}
