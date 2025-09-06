# SentrySearch Terraform Infrastructure

Terraform configuration for SentrySearch's AWS infrastructure.

## Resources

- **RDS PostgreSQL Database** - Metadata and fast queries
- **S3 Bucket** - Report content storage
- **IAM User & Policies** - Application access
- **CloudWatch Log Group** - Application logging
- **Security Groups** - Network access control

## Prerequisites

1. AWS CLI installed and configured
2. Terraform installed (version >= 1.0)
3. AWS Account with appropriate permissions

## Deploy

```bash
cd terraform
terraform init
terraform plan
terraform apply
```

Get outputs:
```bash
terraform output
terraform output aws_secret_access_key  # sensitive values
```

## Files

- `main.tf` - Main infrastructure configuration
- `variables.tf` - Variable definitions and validation
- `outputs.tf` - Output definitions
- `terraform.tfvars` - Variable values (excluded from git)

## Resource Details

### RDS PostgreSQL Database
- Instance: db.t3.micro
- Engine: PostgreSQL 15.4
- Storage: 20GB initial, auto-scaling to 100GB
- Backups: 7-day retention
- Performance Insights enabled

### S3 Bucket
- Versioning enabled
- AES-256 encryption
- Lifecycle: 30 days → Standard-IA → 90 days → Glacier
- Public access blocked

### IAM Configuration
- User: sentrysearch-app
- S3 read/write access to reports bucket
- Auto-generated access key

## Customization

Database sizing in `terraform.tfvars`:
```hcl
db_instance_class = "db.t3.small"
db_allocated_storage = 50
```

S3 lifecycle in `terraform.tfvars`:
```hcl
s3_lifecycle_transition_ia_days = 60
s3_lifecycle_expiration_days = 1825
```

Security in `terraform.tfvars`:
```hcl
enable_deletion_protection = true
```

## Costs

| Resource | Monthly Cost (USD) |
|----------|-------------------|
| RDS db.t3.micro | ~$15-20 |
| RDS Storage (20GB) | ~$2-3 |
| S3 Storage | ~$1-5 |
| CloudWatch Logs | ~$0.50 |
| **Total** | **~$18-30** |

## Outputs

```bash
terraform output database_endpoint
terraform output database_name
terraform output s3_bucket_name
terraform output aws_access_key_id
terraform output aws_secret_access_key  # sensitive
```

Use outputs to configure `.env`:
```bash
terraform output environment_configuration
```

## Management

View state:
```bash
terraform show
```

Update infrastructure:
```bash
terraform plan
terraform apply
```

Destroy infrastructure:
```bash
terraform destroy
```

## Troubleshooting

**AWS Credentials Not Found**
```bash
aws configure
# or
export AWS_ACCESS_KEY_ID="your-key"
export AWS_SECRET_ACCESS_KEY="your-secret"
```

**Region Issues**
```bash
aws configure set region us-east-1
```

**RDS Subnet Group Issues**
```bash
aws ec2 describe-subnets --filters "Name=vpc-id,Values=vpc-xxxxx"
```

**Debug Mode**
```bash
export TF_LOG=DEBUG
terraform apply
```

## Security

1. Never commit `terraform.tfvars` - contains sensitive data
2. Use least privilege IAM policies
3. Enable deletion protection in production
4. Regular security audits of IAM policies
5. Monitor CloudWatch logs

## State Management

Current: Local state in `terraform.tfstate` (excluded from git)

Production: Remote state in S3
```hcl
terraform {
  backend "s3" {
    bucket = "your-terraform-state-bucket"
    key    = "sentrysearch/terraform.tfstate"
    region = "us-east-1"
  }
}
```

## Maintenance

- Update Terraform and AWS provider versions
- Rotate IAM access keys
- Monitor costs and usage
- Review security group rules

Update providers:
```bash
terraform init -upgrade
```

---

This infrastructure incurs AWS costs. Monitor usage regularly.