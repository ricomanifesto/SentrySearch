terraform {
  # S3 lockfiles need Terraform 1.10+; this root is tested on the 1.16 line.
  required_version = ">= 1.16.5, < 1.17.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.65.0"
    }
  }
  # The bucket that will hold remote state cannot hold its own creation state.
  # Keep this state encrypted on the bootstrap operator's machine until a reviewed
  # migration to state/bootstrap.tfstate. Never destroy this root with the
  # environment.
  backend "local" {}
}

provider "aws" {
  region              = var.region
  allowed_account_ids = [var.account_id]
  default_tags {
    tags = { Environment = var.name_prefix, ManagedBy = "terraform", Root = "bootstrap" }
  }
}
