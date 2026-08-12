#!/bin/bash

# SentrySearch Terraform Deployment Script
# This script helps deploy and configure the AWS infrastructure for SentrySearch

set -e

echo "SentrySearch Terraform Deployment"
echo "===================================="

# Check if AWS CLI is configured
if ! aws sts get-caller-identity > /dev/null 2>&1; then
    echo "AWS CLI not configured. Please run 'aws configure' first."
    exit 1
fi

# Check if terraform.tfvars exists
if [[ ! -f "terraform.tfvars" ]]; then
    echo "terraform.tfvars not found. Please create it with your configuration."
    echo "   You can copy from the README.md example or check the variables.tf file."
    exit 1
fi

# Display current AWS identity
echo "Current AWS Identity:"
aws sts get-caller-identity

echo ""
echo "Current Configuration:"
echo "  Region: $(grep 'aws_region' terraform.tfvars | cut -d'=' -f2 | tr -d ' "' || echo 'Not set')"
echo "  Project: $(grep 'project_name' terraform.tfvars | cut -d'=' -f2 | tr -d ' "' || echo 'Not set')"

# Ask for confirmation
echo ""
read -p "This will create AWS resources that incur costs (~$18-30/month). Continue? (y/N): " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Deployment cancelled."
    exit 1
fi

# Initialize Terraform
echo "Initializing Terraform..."
terraform init

# Validate configuration
echo "Validating configuration..."
terraform validate

# Plan deployment
echo "Planning deployment..."
terraform plan -out=tfplan

# Apply deployment
echo "Applying deployment..."
terraform apply tfplan

# Clean up plan file
rm -f tfplan

echo ""
echo "Deployment Complete!"
echo "======================="

# Display outputs
echo ""
echo "Deployment Summary:"
terraform output deployment_summary

echo ""
echo "Environment Configuration:"
echo "Copy these values to your .env file:"
echo ""
terraform output environment_configuration

echo ""
echo "AWS Secret Access Key (copy securely):"
terraform output aws_secret_access_key

echo ""
echo "Estimated Monthly Cost:"
terraform output estimated_monthly_cost

echo ""
echo "Next Steps:"
echo "1. Copy the AWS Secret Access Key to your .env file"
echo "2. Update your .env file with the database endpoint and other values"
echo "3. Test the database connection"
echo "4. Deploy your application"

echo ""
echo "Useful commands:"
echo "  terraform output                     # View all outputs"
echo "  terraform show                       # View current state"
echo "  terraform destroy                    # Delete all resources (careful!)"