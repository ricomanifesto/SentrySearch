# Private AWS staging roots

These Terraform roots describe an isolated, attended staging environment for the
Runtime, Search API and worker services. They are **mock-tested source only**:
nothing here has been applied, planned against an account, initialized against a
real backend or used to publish an image. Every test uses `mock_provider "aws"`
with `command = plan` and fake identifiers. A green run is not IAM evaluation,
an account-specific plan, a reachability proof or deployment approval.

## Roots and ownership

| Directory | State | Owns |
| --- | --- | --- |
| `bootstrap/` | Local and encrypted on the bootstrap operator's machine until a reviewed migration to `state/bootstrap.tfstate` | Private versioned control bucket (`state/`, `releases/`, `locks/`); unattached per-root state policies and the release-evidence policy |
| `foundation/` | `state/foundation.tfstate` | Two-AZ private VPC, routes, endpoints, security groups, both PostgreSQL 16 instances, report bucket, three ECR repositories, log groups, ECS cluster, private DNS |
| `releases/` | `state/releases.tfstate` | The current release and at most one compatible rollback, each a keyed instance of [`../aws-platform-fit`](../aws-platform-fit/README.md) with its guarded release-tools jobs; four unattached release-launcher policies |
| `services/` | `state/services.tfstate` | The three ECS services, created at desired count zero |
| `modules/naming/` | none | Shared names derived from account, region and prefix |

Each environment root declares an S3 backend with `use_lockfile = true` and
`encrypt = true`, and no DynamoDB table. The bucket and region are supplied at
an approved `terraform init` with `-backend-config`; nothing in this repository
selects a real account. Every root pins Terraform `>= 1.16.5, < 1.17.0` (S3
lockfiles need 1.10 or later; 1.16.5 is the tested release) and provider
`hashicorp/aws` 6.65.0, with lock-file hashes for Linux and macOS on amd64 and arm64.
Provider blocks set `allowed_account_ids = [var.account_id]`.

Roots never read one another's state. Reviewed outputs become explicit, validated
inputs: the foundation's subnets, service security groups and Cloud Map service
ARNs feed `services/`; its DNS namespace feeds `releases/`; `releases/` reports
`current_service_task_definitions` for the initial `services/` apply. Names such
as the cluster, log groups, buckets and repositories are derived identically in
every root from `account_id`, `region` and `name_prefix`.

### Terraform and release-controller boundary

Terraform owns networking, discovery, deployment settings and every other service
attribute. The [release controller](../../docs/release-controller.md) changes only
each service's task definition and desired count: `services/` creates services at
zero and ignores exactly `task_definition` and `desired_count`. Applying Terraform
never starts a service, resumes traffic or reverts a controller release. The
controller's deploy request also re-sends Exec disabled and the circuit breaker
without rollback, matching Terraform. Whether a partial `deploymentConfiguration`
resets Terraform's minimum/maximum percent is unverified; a deploy from desired
zero cannot overlap writers either way, and the next plan would show the drift.
Settling that ownership is a gate before any AWS adapter is built.

### Retained releases

`releases/` registers task definitions but never runs them. Each release key is
`r` plus the first eight hex digits of its manifest UUID and scopes its
task/execution role names. A first deployment holds only the current release
(`empty_hold`); an upgrade retains exactly one explicitly compatible rollback.
A secret can hold several releases' versions, but always for the same task and
purpose. Each release also fixes its `release_tools` inputs: the release-tools
image from this environment's repository, the absolute deadline and budget, the
tools and SQL digests, database identities and two proof bundles (twelve distinct
bundles per release). See [release tools](../../docs/release-tools.md).

A retained release is immutable. Revisions use `skip_destroy`; roles, inline
policies and revisions use `prevent_destroy`; and each inline policy's name binds
a hash of its content. Any change that would replace a retained release's role,
grant or revision, or remove a release, therefore fails the plan. New images or
secret versions are a new release key. To retire a release after its rollback
window closes and nothing references it, an operator explicitly removes that key
from state (`terraform state rm 'module.release["<key>"]'`) and from the inputs,
then deletes its roles and deregisters its revisions as a separate, approved step.

### Release launcher

Four unattached policies, `release-launcher-jobs`, `-services`, `-tasks` and
`-receipts`, are attached together to the attended launcher session; that trust
choice is a separate approval. They allow:

- `RunTask` on the **current** release's job revisions (migrations, grants,
  proofs and reconciliation) in this cluster, with `TagResource` only during
  `RunTask`. A rollback never re-runs migrations or grants;
- `StopTask` only on cluster tasks that carry the controller's `sentry:job-id`
  tag;
- `UpdateService` per service, limited to that service's own retained revisions
  when a request names a task definition (`ArnEqualsIfExists`). Scale-to-zero
  requests carry none; the controller always sends the exact ARN when it deploys;
- `DescribeServices` on the three services, `DescribeTasks` within the cluster,
  and `ListTasks` (`*`, conditioned on this cluster, because Fargate tasks have no
  listable resource);
- `iam:PassRole` for exactly the current release's job roles and both retained
  releases' service roles, with `iam:PassedToService = ecs-tasks.amazonaws.com`;
- `logs:GetLogEvents` only on the current jobs' app-container streams
  (`<job>/<container>/*`) in the two release log groups, to read receipts. The log
  groups are shared by releases, so the controller reads the exact stream of the
  task it observed and rejects any receipt whose release, job or task differs;
- `logs:GetLogEvents` only on the **current** release's worker app-container
  streams (`/<name_prefix>/worker`, `worker/<release-id>/app/*`) for the worker
  readiness gate. Each release's worker revision fixes its `release_id` as
  `SENTRYSEARCH_RELEASE_ID` and as an immutable stream prefix
  (`worker/<release-id>`), and its execution role writes only under that prefix,
  so a retained rollback release's streams are outside the read. The controller
  derives the recorded task's exact stream from the approved manifest and the
  ECS task. Worker logs use explicit non-blocking delivery and a 4 MiB buffer.
  **This read still exposes all application output of the current release's
  worker tasks** (report identifiers, request lines, exception text) within log
  retention, which the launcher could not read before. It is neither
  receipt-only nor exact-task authority: exact-task access would need trusted
  per-task credential issuance, and receipt-only access a separate sanitized
  destination. Michael must choose attended whole-release log access or a
  separate receipt destination before these policies are attached.

They deny `ExecuteCommand` and any `RunTask`/`UpdateService` that enables Exec, on
every resource. They grant no secret read, image push, log write, IAM change or
task-definition registration. A test bounds each document within IAM's 6,144
character limit at the longest allowed names. RunTask overrides cannot be fully
constrained by IAM: this is a trusted launcher whose controller rejects overrides,
not a command sandbox.

**A release cannot complete yet.** The grant, proof and reconciliation jobs, the
worker readiness gate, their roles and receipt reads now exist (mock-tested), but
there is no AWS adapter or log reader, the migration images emit no receipts, and
the Runtime and API operational observers do not exist. Missing, stale or
ambiguous receipts hold the release.

The release journal and environment lock use the separate `release-evidence`
policy from `bootstrap/`, which requires the manifest's environment name to equal
`name_prefix`. It includes `ListBucket` (object names only) because S3 reports a
missing journal or lock as 404 rather than 403 only to callers with list access.

## Network and access

The VPC has two task subnets and two DB subnets in two explicit zones, carved
from one aligned RFC 1918 range. There is no internet, NAT or egress-only
gateway, no peering or transit attachment, no IPv6 and no public addressing.
Route tables, including the unused main table, declare empty route sets and no
route propagation: only the implicit local route and the S3 gateway route remain,
and static or propagated routes added out of band are removed on apply. The
default security group has no rules.

| Source group | Destination | Port |
| --- | --- | --- |
| `runtime`, `runtime_db_jobs` | `runtime_db` | 5432 |
| `api`, `worker`, `product_db_jobs` | `product_db` | 5432 |
| `worker`, `runtime_transport_proof` | `runtime` | 8443 |
| `api_proof` | `api` | 8001 |
| Every task and job group | `endpoints` | 443 |
| Every task and job group | S3 gateway prefix list | 443 |

Each pair is an egress rule on the source and an ingress rule on the destination.
Groups have no inline rules; the provider removes AWS's default allow-all egress
rule when it creates each group. Fargate platform 1.4.0 pulls images, fetches
secrets and ships logs through the task network interface, which is why every
task and job group reaches the endpoints and the S3 gateway.

Interface endpoints for ECR API, ECR DKR, Secrets Manager and CloudWatch Logs
use private DNS in both task subnets. Their policies admit only same-account
principals for this environment's repositories, secret-name prefix
(`<name_prefix>/`), the two exact RDS-managed administrator secrets and log groups. The S3 gateway, attached only to the task route
table, permits regional ECR layer reads from `prod-<region>-starport-layer-bucket`
(not restricted by caller account, because layer downloads use presigned URLs)
and report-prefix object and list operations. The report bucket additionally
denies workload roles that do not arrive through this gateway.

Cloud Map provides private `runtime.<namespace>` and `api.<namespace>` A records
with a 10-second TTL. `runtime.<namespace>` must be the Runtime certificate SAN.
DNS can return unhealthy records when none are healthy; it is not a readiness gate.

## Data and destroy protection

| Resource | Protection |
| --- | --- |
| Control bucket | `prevent_destroy`, no `force_destroy`, versioned, SSE-S3, public access blocked, owner-enforced; denies plaintext transport, version deletion and every workload role. Only incomplete uploads expire |
| Report bucket | Same baseline; current/noncurrent versions expire after `report_retention_days` (default 30, subject to deletion-policy approval) and incomplete uploads after one day. Physical removal can take up to twice that period; expired delete markers are not cleaned up |
| PostgreSQL | `prevent_destroy`, deletion protection, final snapshot, retained automated backups, seven-day PITR, `rds.force_ssl=1`, TLS 1.2 minimum, storage encryption, RDS-managed administrator secrets and no Extended Support enrolment |
| ECR | `prevent_destroy`, no `force_delete`, immutable tags, no lifecycle policy |
| Log groups | Deletion protection and `skip_destroy`; bounded retention (default 14 days) |
| Release roles, policies and revisions | `prevent_destroy`; revisions also `skip_destroy`; content-bound policy names |

Terraform holds no secret values, passwords, password hashes or secret data
sources. Bundles are full secret ARNs plus exact VersionIds; moving labels such as
`AWSCURRENT` are rejected. The credential owner creates and versions secrets under
the environment prefix outside Terraform.

## Local validation

From each root directory (`bootstrap`, `foundation`, `releases`, `services`), with
every `AWS_*` variable removed from the environment:

```sh
terraform init -backend=false -input=false -lockfile=readonly
terraform fmt -check -recursive
terraform validate
terraform test
```

`-backend=false` never contacts a backend; init only installs the pinned provider.
From the repository root, `uv run python -m pytest tests/test_staging_infrastructure.py`
(also part of `dev/check_local_setup.py`) checks what plans cannot show: backend
settings, provider guards, `prevent_destroy`, the exact `ignore_changes`, absent
data sources and internet paths, the security-group rule set and plan-only tests.
It also maps every controller ECS call to the IAM actions it needs and checks
that set against the Allow actions the mocked plan asserts on the rendered
launcher policies.

The tests assert rendered resources and policies: network posture, endpoint
coverage and policies, the exact security-group graph, database, bucket, registry,
log and DNS settings, retained releases and their roles, the launcher policies
and their size, and paused services. They reject public or unaligned CIDRs, a single zone, other
PostgreSQL majors, unbounded log retention, foreign or wildcard secrets, moving
secret labels, shared or role-swapped bundles, foreign or tag-pinned images,
unbound release keys, missing or extra current/rollback releases, unpinned task
definitions and grant sources, and shared security groups.

## Not proven or not built

Mocks do not evaluate IAM, endpoint or bucket policies, condition keys (including
`ecs:task-definition` with `IfExists`, `ecs:CreateAction` and
`ecs:enable-execute-command`, `aws:ResourceTag` on `StopTask`), S3 backend init
and the 404 behaviour with the narrowed list permissions, Fargate image pulls
through the gateway, the provider's default-egress removal, RDS TLS parameters,
Cloud Map health reporting, quotas or prices. Those need
approved read-only account inspection, an exact reviewed plan and, separately,
an approved apply.

Not implemented here: secret containers (created by the credential owner),
alarms, SNS, budgets and VPC flow logs (recipient, cost and retention approvals),
DNS Firewall, the bootstrap job definition and its administrator path, a
published and scanned release-tools image, measured log buffers for Runtime and
API (the worker's is [set](../../docs/runtime-consistency.md#readiness-receipts)),
and any operator trust policy or role. Release journals, lockfile versions and the proposed 90-day
evidence retention have no lifecycle rule: evidence is kept until a reviewed
retention decision.
