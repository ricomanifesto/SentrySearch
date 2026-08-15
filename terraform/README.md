# SentrySearch AWS Infrastructure

This Terraform module creates the original AWS storage stack for SentrySearch:

- an RDS PostgreSQL 15.13 instance
- an encrypted, versioned S3 report bucket
- an IAM user and access key for S3
- an RDS monitoring role
- a CloudWatch log group
- a database security group and subnet group in the default VPC

The application can also use PostgreSQL hosted outside this module. Running Terraform is not required for ordinary local development.

## Read This Before Applying

The current module is a prototype, not a safe production baseline:

- PostgreSQL is publicly reachable and port 5432 is open to `0.0.0.0/0`.
- RDS deletion protection is off and final snapshots are skipped.
- Terraform state is local unless you add a backend.
- The module creates a long-lived IAM access key and exposes its secret as a sensitive Terraform output.
- AWS resources incur charges. The cost values in `outputs.tf` are static estimates, not live pricing.

Review and change those defaults before using this module for real data.

## Apply

You need Terraform 1.0 or newer, configured AWS credentials, and a database password of at least eight characters.

```bash
cd terraform
terraform init
terraform fmt -check
terraform validate
terraform plan -var 'db_password=replace-with-a-strong-password'
terraform apply -var 'db_password=replace-with-a-strong-password'
```

Review the plan before applying it. The database, S3 bucket, IAM user, and related resources are billable.

## Effective Inputs

`main.tf` currently reads these variables:

| Variable | Default | Purpose |
|---|---|---|
| `aws_region` | `us-east-1` | AWS region |
| `project_name` | `sentrysearch` | Resource names and tags |
| `db_password` | none | RDS master password |

`variables.tf` also declares sizing, retention, monitoring, and deletion-protection variables, but `main.tf` does not yet use them. Changing those values in `terraform.tfvars` has no effect until the resources are wired to the variables.

## Current Resource Settings

- RDS: `db.t3.micro`, 20 GB initial storage, 100 GB maximum, seven-day backups, Performance Insights, and enhanced monitoring.
- S3: AES-256 server-side encryption, versioning, blocked public access, Standard-IA after 30 days, Glacier after 90 days, and deletion after seven years.
- CloudWatch: 30-day log retention.

## Outputs

```bash
terraform output database_endpoint
terraform output database_name
terraform output s3_bucket_name
terraform output environment_configuration
terraform output -raw aws_secret_access_key
```

Treat the final command as a credential read: do not paste its result into logs, issues, or shell history. Store it in a secret manager and rotate it if exposed.

Useful read-only commands:

```bash
terraform output
terraform show
terraform plan
```
