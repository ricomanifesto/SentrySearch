#!/bin/bash

# Review and deploy the original AWS stack only after its prerequisites are met.
# Disable tracing before handling credentials, including when invoked with bash -x.
set +x
set -euo pipefail
umask 077
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

echo "SentrySearch Terraform Deployment"
echo "Review the private network, migration, and state prerequisites in README.md first."

if ! aws sts get-caller-identity > /dev/null 2>&1; then
    echo "AWS CLI credentials are unavailable. Configure your approved AWS profile first."
    exit 1
fi

echo "Current AWS Identity:"
aws sts get-caller-identity

# Keep the password out of command arguments, shell history, and tfvars files.
# Terraform still stores it in state and saved plans; protect the state backend.
if [[ -z ${TF_VAR_db_password:-} ]]; then
    read -r -s -p "RDS master password: " TF_VAR_db_password
    printf '\n'
fi
export TF_VAR_db_password

plan_dir=$(mktemp -d "${TMPDIR:-/tmp}/sentrysearch-tfplan.XXXXXXXX")
cleanup() {
    rm -f -- "$plan_dir/tfplan"
    rmdir -- "$plan_dir"
    unset TF_VAR_db_password
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "Initializing Terraform..."
terraform init

echo "Validating configuration..."
terraform validate

echo "Planning deployment..."
terraform plan -input=false -out="$plan_dir/tfplan"

# Approval applies to the actual saved plan, after its changes have been displayed.
printf 'Apply this reviewed plan and incur AWS charges? (y/N): '
read -r reply
if [[ ! $reply =~ ^[Yy]$ ]]; then
    echo "Deployment cancelled."
    exit 1
fi

terraform apply -input=false "$plan_dir/tfplan"

echo "Deployment complete. Non-secret resource summary:"
terraform output deployment_summary
terraform output environment_configuration
echo "Provision application credentials through the approved secret store."
echo "This script does not print access keys. Terraform state and saved backups remain sensitive."
