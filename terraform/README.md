# SentrySearch AWS Infrastructure

This module defines the original AWS storage stack: PostgreSQL 15.13 on RDS,
an encrypted and versioned S3 report bucket, an application IAM user/access key,
an RDS monitoring role, and a CloudWatch log group. The application can use
PostgreSQL outside this module; Terraform is not required for local development.
This source does not establish whether any matching resources still exist.

## Before any deployment

Confirm ownership, the intended account/region, the current state backend, and
whether this stack is still needed. Do not recreate a retired stack merely to
update this configuration. Resource creation, migration, and deletion each need
an approved environment-specific plan.

The database now has these safeguards:

- `publicly_accessible = false`.
- No default VPC/subnet discovery. Supply an existing VPC and private database
  subnets spanning at least two Availability Zones.
- No database client ingress by default. Explicitly allow approved application
  security group IDs on TCP 5432. No public CIDR option is provided.
- No security group egress rules. PostgreSQL replies use stateful ingress rules.
- Deletion protection defaults to enabled. Deletion/replacement requires an
  explicit protection change and a unique, named final snapshot; snapshot
  skipping is disabled.

VPC IDs, subnet IDs, and security group IDs are checked for shape, not routing or
ownership. Before applying, verify the subnets belong to the selected VPC and
region, have the required Availability Zone coverage, and use private routes.
Verify supported security group references and private reachability from the API,
worker, migration runner, and operator. An internet-hosted backend cannot reach
this RDS instance through its old public path. Establish the approved private
network path or use a different database before removing that path from an
existing deployment. This module does not create a VPN, peering connection,
PrivateLink service, NAT gateway, or VPC endpoints.

If moving application compute into the VPC, separately review its outbound
requirements: S3, authentication, model APIs, logging, and any durable execution
service. Those application dependencies and routes are outside this module.

## Inputs

Terraform 1.9 or newer is required (the existing storage validation references
another input). Use an approved AWS profile/role and a protected, access-controlled
state backend. Without an explicit backend, Terraform stores state locally.

Put **non-secret** inputs in an ignored `terraform.tfvars`, for example:

```hcl
aws_region                         = "us-east-1"
project_name                       = "sentrysearch"
database_vpc_id                    = "vpc-0123456789abcdef0"
database_subnet_ids                = ["subnet-0123456789abcdef0", "subnet-abcdef01234567890"]
database_client_security_group_ids = ["sg-0123456789abcdef0"]
db_final_snapshot_identifier       = "sentrysearch-final-unique-change-reference"
```

The IDs above are placeholders. `database_vpc_id`, `database_subnet_ids`,
`db_password`, and `db_final_snapshot_identifier` have no defaults.
`database_client_security_group_ids` defaults to an empty set, which denies all
clients. Choose a final snapshot name not already used in the target region and
account, starting with `<project_name>-final-`. Use a new name for each authorized
deletion/replacement; a name collision blocks deletion rather than overwriting a
snapshot.

`enable_deletion_protection` is now effective and defaults to `true`. Other
previously declared sizing, lifecycle, monitoring, and retention variables remain
unwired; their effective values are still the constants in `main.tf`.

## Credentials and saved plans

Run `./deploy.sh` from this directory or by its path. It accepts the database
password through a hidden prompt or an existing `TF_VAR_db_password` supplied by
your approved secret workflow. Do not put passwords in command arguments, shell
history, committed files, or plaintext tfvars. The script disables shell tracing,
creates its saved plan with private file/directory permissions, shows the plan,
asks before applying that exact plan, and removes the temporary plan on success,
failure, or handled interruption. Forced termination or host failure can still
leave temporary files that need secure cleanup.

Terraform state, state backups, and saved plans contain the RDS password and
application access-key secret in plaintext even when outputs are marked
`sensitive`. Protect existing files as well as newly created files; use encrypted,
access-controlled state storage. Do not upload state, plans, full `terraform show`
output, or secret output values to logs or issue trackers.

The script prints only non-secret resource summaries. It does not retrieve or
print application access keys. Provision credentials to the application through
an approved secret store and use the SDK credential chain. The legacy IAM
user/access-key resource remains declared to avoid an implicit credential deletion
in this source repair. Replacing it with workload credentials requires its own
migration and rotation plan. Marking an output sensitive does not rotate a key
that was previously exposed.

## Existing stack migration and deletion

Before applying to an existing database, review the exact resource addresses and
state, make a recoverable backup, verify restore access, and rehearse the private
connection path. Changing VPC/subnets/security groups can require replacement or
an outage. A plan proposing a database replacement needs a separate data migration
and cutover plan; do not disable safeguards just to make it proceed. Preserve the
current working connection until the replacement path is verified. Review engine
15.13 and instance-class availability for the target region before any new build.

For an authorized deletion, first apply a reviewed change setting
`enable_deletion_protection = false` while keeping a unique final snapshot name.
Then review the deletion plan and retain the final snapshot according to the data
owner's policy. Do not remove the resource declaration or change the state to
bypass protection. Final snapshots are backups, not proof of a successful restore.

## Deployment policy example

`terraform-permissions.json` is a reviewable template. Replace `<ACCOUNT_ID>`,
`<REGION>`, and `<VPC_ID>` with the exact approved deployment scope before use;
replace `sentrysearch` resource names if changing `project_name`. Do not attach the
unrendered template or broaden it to fix an access error.

Only read-only discovery uses `Resource: "*"`. RDS and log writes use named
resources; IAM writes use the named application user and monitoring role.
Security group creation requires the project tag in the selected VPC, and later
writes require that existing tag. For a pre-existing untagged group, first
reconcile the exact group ID and its Terraform resource address without changing either. If already managed, retain
that address and do not re-import or recreate it. Bootstrap the `Project` tag only
through a separately approved, temporary `ec2:CreateTags` grant scoped to that
exact security group ARN, then remove the bootstrap grant. Review a subsequent
plan for unexpected replacement before using this policy. An unmanaged group
needs an approved import/state reconciliation before any apply. `iam:PassRole`
allows only the monitoring role and `monitoring.rds.amazonaws.com`; managed-policy attachment is
limited to the RDS enhanced monitoring policy. The role-scoped
`iam:ListInstanceProfilesForRole` read supports the [provider's deletion preflight](https://github.com/hashicorp/terraform-provider-aws/blob/v5.100.0/internal/service/iam/role.go#L520-L580);
no instance-profile mutations are granted. Bucket administration uses the
project's generated bucket-name prefix and does not grant report-object access.
Narrow that prefix to the exact bucket when known. The bucket-scoped reads also
cover ACL, CORS, website, acceleration, request payment, logging, replication, and
object-lock configuration because [AWS provider 5.100.0 refreshes those settings](https://github.com/hashicorp/terraform-provider-aws/blob/v5.100.0/internal/service/s3/bucket.go#L783-L1141)
even when this module does not configure them.

This example is not an account permission boundary or proof of deployment
readiness. SCPs, permission boundaries, service-linked-role prerequisites, and
existing resource ownership still need review. Validate the rendered policy with
the owning account's approved tools before any deployment; no account-side IAM
simulation is included in the offline checks.

## Local validation

These checks do not create, plan, refresh, or change live account resources:

```bash
terraform init -backend=false -input=false
terraform fmt -check
terraform validate
terraform test # providers are mocked; plans do not call AWS
shellcheck deploy.sh
cd ..
python3 -m unittest discover -s tests -p test_infrastructure_security.py -v
actionlint .github/workflows/ci.yml
```

Provider initialization downloads provider packages and verifies their signatures;
validation checks configuration/schema only. Terraform tests use mocked providers
for private defaults, explicit client ingress, required subnet coverage, and
snapshot naming. Offline script tests use fake AWS and Terraform executables.
These checks do not prove live connectivity, IAM sufficiency, snapshot creation, restore behavior, or a deployed security posture.

References: [RDS provider arguments](https://registry.terraform.io/providers/hashicorp/aws/5.100.0/docs/resources/db_instance),
[RDS permissions](https://docs.aws.amazon.com/service-authorization/latest/reference/list_rds.html),
[EC2 permissions](https://docs.aws.amazon.com/service-authorization/latest/reference/list_ec2.html),
[CloudWatch Logs permissions](https://docs.aws.amazon.com/service-authorization/latest/reference/list_logs.html),
[S3 permissions](https://docs.aws.amazon.com/service-authorization/latest/reference/list_s3.html),
[IAM condition keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html).
