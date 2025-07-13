# SentrySearch Terraform Infrastructure

This directory contains Terraform configuration files for deploying SentrySearch's AWS infrastructure.

## Overview

This Terraform configuration deploys:
- **RDS PostgreSQL Database** - For metadata and fast queries
- **S3 Bucket** - For report content storage
- **IAM User & Policies** - For application access
- **CloudWatch Log Group** - For application logging
- **Security Groups** - For network access control

## Prerequisites

1. **AWS CLI** installed and configured
2. **Terraform** installed (version >= 1.0)
3. **AWS Account** with appropriate permissions

## Quick Start

### 1. Initialize Terraform

```bash
cd terraform
terraform init
```

### 2. Review Configuration

```bash
# Review the planned changes
terraform plan
```

### 3. Deploy Infrastructure

```bash
# Deploy the infrastructure
terraform apply
```

### 4. Get Outputs

```bash
# View all outputs
terraform output

# Get sensitive values
terraform output aws_secret_access_key
```

## Configuration Files

### Core Files
- `main.tf` - Main infrastructure configuration
- `variables.tf` - Variable definitions and validation
- `outputs.tf` - Output definitions
- `terraform.tfvars` - **Variable values (DO NOT COMMIT)**

### Security Notes
- `terraform.tfvars` is excluded from git via `.gitignore`
- Database password is stored securely in `terraform.tfvars`
- AWS credentials are managed via IAM user

## Resource Details

### RDS PostgreSQL Database
- **Instance Class**: db.t3.micro
- **Engine**: PostgreSQL 15.4
- **Storage**: 20GB initial, auto-scaling to 100GB
- **Backups**: 7-day retention
- **Monitoring**: Performance Insights enabled

### S3 Bucket
- **Versioning**: Enabled
- **Encryption**: AES-256
- **Lifecycle**: 30 days → Standard-IA → 90 days → Glacier
- **Public Access**: Blocked

### IAM Configuration
- **User**: sentrysearch-app
- **Permissions**: S3 read/write access to reports bucket
- **Access Key**: Generated automatically

## Customization

### Database Sizing
```hcl
# In terraform.tfvars
db_instance_class = "db.t3.small"  # Upgrade for better performance
db_allocated_storage = 50          # Increase initial storage
```

### S3 Lifecycle
```hcl
# In terraform.tfvars
s3_lifecycle_transition_ia_days = 60    # Longer before archiving
s3_lifecycle_expiration_days = 1825     # 5 years instead of 7
```

### Security
```hcl
# In terraform.tfvars
enable_deletion_protection = true  # Protect against accidental deletion
```

## Estimated Costs

| Resource | Monthly Cost (USD) |
|----------|-------------------|
| RDS db.t3.micro | ~$15-20 |
| RDS Storage (20GB) | ~$2-3 |
| S3 Storage | ~$1-5 |
| CloudWatch Logs | ~$0.50 |
| **Total** | **~$18-30** |

*Costs may vary based on usage patterns and data transfer*

## Outputs

After deployment, the following outputs are available:

```bash
# Database connection details
terraform output database_endpoint
terraform output database_name

# S3 bucket details
terraform output s3_bucket_name

# AWS credentials
terraform output aws_access_key_id
terraform output aws_secret_access_key  # Sensitive
```

## Environment Configuration

Use the Terraform outputs to configure your `.env` file:

```bash
# Get environment configuration
terraform output environment_configuration
```

## Management Commands

### View Current State
```bash
terraform show
```

### Update Infrastructure
```bash
terraform plan
terraform apply
```

### Destroy Infrastructure
```bash
terraform destroy  # Use with caution!
```

### Import Existing Resources
```bash
# If you have existing resources
terraform import aws_s3_bucket.example bucket-name
```

## Troubleshooting

### Common Issues

1. **AWS Credentials Not Found**
   ```bash
   aws configure
   # or
   export AWS_ACCESS_KEY_ID="your-key"
   export AWS_SECRET_ACCESS_KEY="your-secret"
   ```

2. **Region Issues**
   ```bash
   # Ensure consistent region configuration
   aws configure set region us-east-1
   ```

3. **RDS Subnet Group Issues**
   ```bash
   # Ensure you have subnets in multiple AZs
   aws ec2 describe-subnets --filters "Name=vpc-id,Values=vpc-xxxxx"
   ```

4. **IAM Permissions**
   ```bash
   # Ensure your AWS user has permissions for:
   # - RDS (create, modify, delete)
   # - S3 (create, manage buckets)
   # - IAM (create users, policies)
   # - CloudWatch (create log groups)
   ```

### Debugging
```bash
# Enable detailed logging
export TF_LOG=DEBUG
terraform apply

# Validate configuration
terraform validate

# Format code
terraform fmt
```

## Security Best Practices

1. **Never commit `terraform.tfvars`** - Contains sensitive data
2. **Use least privilege IAM policies** - Only required permissions
3. **Enable deletion protection** in production
4. **Regular security audits** of IAM policies
5. **Monitor CloudWatch logs** for suspicious activity

## State Management

### Local State (Current)
- State is stored locally in `terraform.tfstate`
- **Do not commit state files** to version control

### Remote State (Recommended for Production)
```hcl
# Add to main.tf for remote state
terraform {
  backend "s3" {
    bucket = "your-terraform-state-bucket"
    key    = "sentrysearch/terraform.tfstate"
    region = "us-east-1"
  }
}
```

## Maintenance

### Regular Tasks
- Review and update Terraform version
- Update AWS provider version
- Review and rotate IAM access keys
- Monitor costs and usage
- Update security group rules as needed

### Upgrades
```bash
# Update Terraform
terraform version
# Download latest from https://terraform.io

# Update providers
terraform init -upgrade
```

## Support

For issues with this Terraform configuration:
1. Check the troubleshooting section above
2. Review Terraform and AWS documentation
3. Check AWS CloudTrail for detailed error messages
4. Verify IAM permissions and resource limits

---

**Remember**: This infrastructure will incur AWS costs. Monitor your usage and costs regularly.