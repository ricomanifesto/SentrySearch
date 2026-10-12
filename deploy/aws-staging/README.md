# Private AWS staging roots

These Terraform roots describe an isolated, attended staging environment for the
Runtime, Search API and worker services. They are **mock-tested source only**:
nothing here has been applied, planned against an account, initialized against a
real backend or used to publish an image. Every test uses `mock_provider "aws"`
with `command = plan` and fake identifiers. One file,
`releases/tests/releases_bootstrap_retention.tftest.hcl`, uses `command = apply`
against that same mocked provider, because a catalog transition needs state
carried from one run to the next; no test configures a real provider. A green run is not IAM evaluation,
an account-specific plan, a reachability proof or deployment approval.

## Roots and ownership

| Directory | State | Owns |
| --- | --- | --- |
| `bootstrap/` | Local and encrypted on the bootstrap operator's machine until a reviewed migration to `state/bootstrap.tfstate` | Private versioned control bucket (`state/`, `releases/`, `locks/`); unattached per-root state policies and the release-evidence policy; an optional attended operator role (none by default) |
| `foundation/` | `state/foundation.tfstate` | Two-AZ private VPC, routes, endpoints, security groups, both PostgreSQL 16 instances, report bucket, three ECR repositories, log groups (including the observers'), ECS cluster, private DNS; alarms for published metrics and, with an approved recipient, notifications and a monthly budget |
| `releases/` | `state/releases.tfstate` | The current release and at most one compatible rollback, each a keyed instance of [`../aws-platform-fit`](../aws-platform-fit/README.md) with its guarded release-tools jobs, optional observers and (first deployment only) bootstrap jobs; the unattached attended release-launcher set and a separate bootstrap launcher |
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
never starts a service, resumes traffic or reverts a controller release.
Deployment settings and Exec have exactly one writer, Terraform. The controller's
deploy request carries only cluster, service, task definition, desired count and
a forced new deployment. It never sends `deploymentConfiguration` or
`enableExecuteCommand`, so it cannot reset omitted percentages. It holds with
`service_settings_drift` before any forward action unless ECS reports this root's
values for every described service. It checks before each deploy, on every
forward deploy response (identical resends included), while reconciling a lost
deploy (including just before an identical resend), and on every later
observation of a started service (that service only). Scale-to-zero
reconciliation is never blocked.
The values are:
- minimum 0% and maximum 100%;
- circuit breaker on, rollback off;
- no alarm rollback;
- the rolling strategy;
- the ECS controller;
- Exec off.

A static test ties those expected values to this file.

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

The attended set is four unattached policies, `release-launcher-jobs`,
`-services`, `-tasks` and `-receipts`, plus `-observe` when the current release
has observers. They are attached together to the attended launcher session; that
trust choice is a separate approval. They allow:

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
- `RunTask` on the **current** release's two observer revisions only (never a
  retained release's), `iam:PassRole` for exactly their roles and
  `logs:GetLogEvents` only on their observer-container streams
  (`/<name_prefix>/observe`, `<check>/observer/*`), in the `-observe` policy.
  Observer tasks carry the job tag, so the jobs policy's tagging and stops cover
  them;
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
  destination. Attended whole-release access is the selected design: no other
  release, no `logs:Unmask` and no sharing outside the attended session.
  Attaching these policies remains a separate approval.

They deny `ExecuteCommand` and any `RunTask`/`UpdateService` that enables Exec, on
every resource. They grant no secret read, image push, log write, IAM change or
task-definition registration. A test bounds each document within IAM's 6,144
character limit at the longest allowed names. RunTask overrides cannot be fully
constrained by IAM: this is a trusted launcher whose controller rejects overrides,
not a command sandbox.

Bootstrap jobs launch through `release-launcher-bootstrap`, a separate
unattached policy outside the attended set: `RunTask` on the two bootstrap
revisions, `PassRole` for their roles and `GetLogEvents` on their receipt
streams. Nothing in this run attaches it; the live administrator path is a
separate approval.

Bootstrap definitions and bootstrap launch authority are separate things:

- **Definitions** (the two bootstrap revisions, their four roles and inline
  policies) belong to the environment's first release, the only one that may
  carry a `bootstrap` input. They are immutable and `prevent_destroy` like the
  rest of that release, so it keeps the input unchanged when it becomes the
  retained rollback release at the first upgrade, and when it is made
  `current` again for a rollback run. Dropping the input from a retained
  release fails the plan, as removing any other part of it does. They go when
  that release is retired, by the explicit procedure above.
- **Launch authority** is the `release-launcher-bootstrap` policy alone. It is
  rendered only for a first deployment: one current release and nothing
  retained beside it. The first upgrade's plan removes the policy (detach it
  first; the first-deployment sequence already does). From then on no policy
  in this root names a bootstrap revision, role or stream, whichever slot the
  first release is in. The controller refuses bootstrap jobs in anything but a
  first deployment as well (`bootstrap_requires_empty_hold`), and a rollback
  run never launches one.

A test applies that whole sequence against one mocked state: first deployment,
upgrade with the first release retained, then a rollback re-plan.

Every evidence producer now has a definition: migrations in their release-job
mode, grants, proofs, reconciliation, observers and the worker gate. Local
Runtime, Search and release-tools images carry these producers; the container
suites and the [integrated canary](../../docs/release-canary.md) run them, and
the [image ledger](../../docs/image-risk-dispositions.md) records their scans.
That is local evidence only. The images are not published to this environment's
repositories, their retained findings are not accepted, these roots are not
applied and nothing has run on AWS, so no release can run against these roots
yet. Missing, stale or ambiguous receipts hold the release.

A rollback run (docs/release-controller.md) restores the retained prior pair.
The attended scope stays the **current** release's: the operator re-plans
`releases/` with the prior release as `current` before the run. Its reconcile,
proof and observer revisions keep the deadline fixed when it was first planned,
so a rollback after that deadline holds at its first job and needs a new release
key planned from the prior pair's images, a separate approval.

### Monitoring

`foundation/` renders an alarm only where AWS itself publishes the metric: one
per service when no task reports ECS service CPU (silence breaches), and one per
database when free storage drops below 10% of the allocation (missing data
breaches). The `alerts` output lists those with their producer and missing-data
behaviour, and every other named alert (worker readiness, backlog age, lease and
retry exhaustion, phase deadlines, certificate expiry, backup) as unwired with the
reason: nothing publishes a metric for them yet. Without the optional
`notifications` input (an approved recipient and a monthly review threshold, not
a cap) there is no SNS topic, subscription or budget, and alarms have no actions.
The topic has no server-side encryption: CloudWatch cannot publish to a topic
under the AWS-managed SNS key, and a customer-managed key needs its own policy
review. It carries alarm state only.

### Operator role

`bootstrap/` can create the attended operator role (`operator_trust`, default
`null`). Its trust names exactly one IAM user or role, requires the external id,
bounds the session to 1–12 hours and requires the role session name and the
source identity to equal the manifest's operator, so the session the release CLI
matches proves who assumed it. Wildcards and account-root principals are
rejected. No policy is attached by Terraform.

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
definitions and grant sources, and shared security groups. They also cover the
observe policy (current revisions only), the separate bootstrap launcher,
bootstrap only on a first deployment with RDS-managed administrator secrets,
observer bundle aliasing and purpose changes, the wired and unwired alerts,
recipient-gated notifications and budget, and the operator trust policy
(rejecting wildcard or account-root principals, short external ids and unbounded
sessions).

## Account inspection

[`inspect/`](inspect/README.md) holds the only step that touches an account
before an apply: a read-only script the account's owner runs with a profile they
authenticated, and an offline assembler that turns its bundle and the chosen
environment values into each root's account inputs, a manifest skeleton, a
refreshed price table and the inspection checklist. Neither has run against an
AWS account.

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
VPC flow logs (retention approval), producers for the unwired alerts, DNS
Firewall, the live bootstrap administrator path, published and scanned images
carrying the observers and migration release jobs, the Runtime and API log
buffers' behavior on Fargate (their sizes come from a
[local measurement](../../docs/service-images.md#log-buffers)), and any attachment of launcher policies. Notification delivery and budget
enforcement are not proven by mocks. Release journals, lockfile versions and the proposed 90-day
evidence retention have no lifecycle rule: evidence is kept until a reviewed
retention decision.
