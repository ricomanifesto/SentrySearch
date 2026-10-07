# Local AWS platform-fit draft

This directory models three independent ARM64 Fargate service task definitions,
an optional pair of separate one-shot owner migration task definitions and,
optionally, six guarded release-tools job definitions, each with distinct
task/execution IAM roles. It is a **local, disabled-generation
scaffold**, not a deployed environment, release orchestrator or completed
application canary. `release_jobs = null` is the default: existing callers retain
exactly the three service definitions and no owner-job identities or definitions.
The existing `terraform/` topology is not reused or modified.

The [staging roots](../aws-staging/README.md) use this directory as a module:
`aws-staging/releases` instantiates it once per retained release with a
`release_scope`. The module therefore declares no provider configuration; its
callers supply the region and `allowed_account_ids` guard.

Only task definitions, IAM roles and inline policies are declared. There are no
services, clusters, networks, databases, buckets, registries, secrets, log groups,
DNS, load balancers or schedulers. References to those dependencies require
pre-existing, separately approved **staging** resources. Applying even this
limited module would mutate AWS; no apply or unmocked plan is part of local proof.

## Local validation

From this directory, with Terraform 1.9.8 or newer (tested with 1.9.8 and 1.16.5):

```sh
terraform init -backend=false -input=false -lockfile=readonly
terraform fmt -check -recursive
terraform validate
terraform test
```

The provider is pinned to `hashicorp/aws` 6.65.0 and its generated lock file is
tracked, with package hashes for Linux and macOS on amd64 and arm64. Init
downloads the signed provider package; it does not query an AWS account. Every
test uses `mock_provider "aws"` with `command = plan`, fake identifiers and no
credentials. Do not substitute a real provider or use these fixtures as staging
configuration.

Tests inspect the actual task-definition and IAM-resource attributes, plus
rendered container and policy contracts. They cover process ordering, UID and
mount boundaries, liveness/grace, paused admission, secret versions, IAM scoping,
and rejection of mutable image tags, cross-account secrets, shared bundles, moving
secret stages and non-DNS TLS identity. Release tests also cover opt-in,
owner/service and material/environment separation, DB-only commands, fixed
operator grant provenance, and invalid release refs/log groups. Release-tools
tests cover opt-in, the six job contracts, fixed deadline/digest/identity values,
per-job execution roles and receipt streams, and rejection of tags, foreign
images, non-UTC, impossible or far-future deadlines, out-of-range budgets, unpinned digests,
a Runtime grant digest differing from its pin and aliased proof bundles. Retention tests
cover unchanged unscoped role names, release-scoped roles, stable families,
retained revisions and content-bound policy names. They do not execute IAM policy
evaluation, fetch real secrets, run Fargate or verify network reachability.

## Release scope and retained revisions

`release_scope` is optional and defaults to `null`, which keeps every existing
role name. When set (2–12 lowercase letters or digits, starting with a letter),
task and execution roles become `<name_prefix>-<release_scope>-<task>-task` and
`...-execution`, so a retained rollback keeps its own exact-version policies while
a newer release uses new secret versions. Task families do not change: each
release registers a revision of the same family. Validation rejects a scope whose
longest role name would exceed IAM's 64 characters.

A retained release is immutable. Task definitions set `skip_destroy`, and roles,
inline policies and task definitions set `prevent_destroy`. Each inline policy's
name ends in a hash of its content, so changing a grant is a replacement. Any
change that would replace a role, grant or revision, or remove the release, fails
the plan instead of silently breaking a launchable rollback; new images or secret
versions belong to a new scope. Retirement is an explicit state removal followed
by an approved deletion. `iam_role_names` and `task_definition_arns` report the
exact roles and registered revisions.

## Tasks and process ownership

| Task | Application command | CPU / memory | Liveness | Stop budget |
| --- | --- | --- | --- | --- |
| Runtime | `/app/sentryruntime` | 0.25 vCPU / 512 MiB | `/app/probe healthz` | 30 s, above runtime's 10 s shutdown |
| API | `python /app/run_api.py` | 0.25 vCPU / 1024 MiB | Python HTTP check of loopback `GET /` | 60 s |
| Worker | `python -m dev.run_runtime_worker --health-port 8081 --drain-seconds 30` | 0.5 vCPU / 2048 MiB | Python HTTP check of loopback `/healthz` | 60 s, above 30 s drain |

Each task first runs the Search image's
`python -m dev.prepare_service_volumes`. This `init` container is nonessential and
root, with a 120-second dependency-start timeout. The app requires init `SUCCESS`;
failure must not start the service. The app also has a 120-second dependency
timeout. Both containers have read-only roots. Init retains only `CHOWN` from the
default Linux capability set; every other Docker default is explicitly dropped.
Fargate permits adding only `SYS_PTRACE`, so `drop ALL` plus `add CHOWN` is **not**
a valid Fargate translation. App containers drop `ALL` and run as runtime UID
65532 or Search UID 10001. Their images remain pinned ECR digest inputs.

Fresh task-local bind volumes, not Fargate-unsupported `tmpfs`, hold material and
Search `/tmp` plus `/var/lib/sentrysearch`. Init gets writable mounts and establishes
ownership; apps mount material read-only and Search scratch read/write. No host
path, persistent volume or shared filesystem is configured. Scratch may contain
report material and must never become durable product storage. Platform behavior
for these permissions and ephemeral cleanup still needs a deployed proof.

The runtime probe connects only to `127.0.0.1:8443` while verifying the supplied
DNS SAN and mounted CA, with a token read from a file. It cannot accidentally
probe another service-discovery replica. Native TLS and token auth remain on.
Worker health has no exposed task port. API `GET /` is DB-independent process
liveness; `/api/health` can perform DB work and return a degraded HTTP 200, so it
is not used here. Runtime/worker `/readyz` and API `/api/ready` are **separate
release gates**, not replacement probes. Readiness evaluation/promotion is not
implemented by these task definitions.

The worker image also provides a bounded readiness command:
`python -m dev.check_worker_readiness --address 127.0.0.1:8081 --deadline-seconds 2`.
It checks `/readyz`, not liveness, and returns 0 only when ready, 1 on an unready
or failed check, and 2 for invalid invocation. It must run in that worker's
network namespace. This module does not schedule it, expose its loopback port or
add a sidecar. An ECS container health command is not ECS Exec: ECS Exec requires
a writable root filesystem and is not a valid promotion mechanism for these
read-only task definitions. A managed readiness/promotion observation path is
still a deployment gate; local Docker execution is not evidence of that path.

For the attended release gate, `release_id` (the manifest's release UUID; it must
equal `release_tools.release_id` when jobs are set) is fixed in the worker
revision as `SENTRYSEARCH_RELEASE_ID`. The supervisor then writes
[readiness receipts](../../docs/runtime-consistency.md#readiness-receipts) to its
app container's stream, which `readiness_log_stream` names for the launcher's
read policy. That stream also carries the worker's other output. The worker's
awslogs configuration sets `mode = non-blocking` and `max-buffer-size = 4m`
explicitly instead of relying on the account default; overflow drops lines,
which the observer sees as gaps. Non-blocking delivery on Fargate and the
buffer's real headroom are not yet measured. Runtime and API logging is unchanged.
Without `release_id` the worker emits no receipts.

## Version-pinned secret bundles

Only full secret ARNs and exact lowercase UUID VersionIds are inputs, never
secret values. Bundles must be distinct, in the selected account and region.
There are no secret-value data sources or free-form plaintext environment inputs.
Changing a bundle version requires an intentional task-definition revision and
future approved rollout; modifying `AWSCURRENT` cannot change this draft silently.

| Role | Environment bundle JSON keys | File-material bundle JSON keys |
| --- | --- | --- |
| Runtime | `DATABASE_URL`, `SENTRYRUNTIME_AUTH_CREDENTIALS` | `server-cert.pem`, `server-key.pem`, `runtime-ca.pem`, `postgres-ca.pem`, `probe-token` |
| API | `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD` | `runtime-ca.pem`, `postgres-ca.pem` |
| Worker | API DB keys plus `SENTRYRUNTIME_PRODUCER_TOKEN`, `SENTRYRUNTIME_WORKER_TOKEN` | `runtime-ca.pem`, `postgres-ca.pem` |
| Optional Runtime release | owner `DATABASE_URL` only | `postgres-ca.pem` only |
| Optional product release | owner `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD` only | `postgres-ca.pem` only |

The default has six bundles; opting into both release jobs requires four more.
All ten ARNs must be distinct. Separate ARNs enforce IAM resource boundaries,
not the plaintext's DB identity or privileges: an operator must independently
verify owner versus service principal, database target, TLS and actual grants.
Owner bundles must contain only the documented DB keys; Terraform does not read
them and cannot detect extra JSON fields. Release material profiles reject extra
fields, including server keys, Runtime CA and tokens.

ECS environment-secret references use `ARN:JSON_KEY::VERSION_ID`. Execution roles
have `GetSecretValue` for only their environment bundle/version. Init requests
its material bundle/version through the task role. **A task role belongs to the
whole task, not one container**: the app retains authority to retrieve its own
material bundle, whose files it can already read. Init is not an isolated IAM
principal. Neither role is allowed to read another service's bundle.
Likewise a migration process can retrieve its own CA bundle through its release
task role. Its root initializer shares that CA-read authority, but is not injected
with owner environment values and has no permission to retrieve their bundle.
Service task/execution roles cannot read release bundles, and release roles cannot
read service bundles. No release task role has S3 permissions.

The initial contract requires the AWS-managed Secrets Manager encryption key and
SSE-S3 artifact storage. It grants no `kms:Decrypt` and cannot use customer-managed
keys without a separate policy/key-policy review. Task role S3 access is restricted
to `reports/*`: worker Get/Put; API Get/Delete and prefix-conditioned ListBucket.
There is no DeleteObjectVersion, bucket administration or runtime S3 authority.
Execution roles can pull only the specified ECR repositories and write their own
streams in pre-existing log groups, not create groups. ECR authorization-token
acquisition is the one necessary wildcard-resource permission. Log retention is
an external dependency, not implicitly configured here.

## Deliberate disabled behavior

- API execution admission is fixed to `paused`. This does not revoke accepted
  work, disable read/delete paths or bypass authentication.
- No auth URL or service key is supplied. Authenticated API routes return service
  unavailable; successful liveness/readiness is not proof of authentication.
  A future isolated auth configuration must not reuse production credentials.
- Worker OpenRouter configuration is fixed to `http://127.0.0.1:9` with the
  disposable literal `disabled-local-platform-fit`. This is **not a live key or
  functional stub** and cannot run useful generation. There is no provider-key
  secret wired. This does not prove that every research path has no egress; no
  work may be admitted until a complete fake-provider and egress contract exists.
- Source images must contain `/app/probe` and `dev.prepare_service_volumes`; a
  packaging digest from before those helpers cannot satisfy this draft. A digest
  alone does not prove ARM64 support, security scan status or file contents.

## Optional separate release jobs

Supply the complete `release_jobs` object only when preparing reviewed release
inputs. Its `runtime` and `product` entries each require `environment_bundle` and
`material_bundle` objects (`arn`, `version_id`), plus a distinct pre-existing
`log_group`. `runtime_grants` requires `source_commit` (40 lowercase hex) and
`sql_sha256` (64 lowercase hex). See the mock test fixture for the structure;
those identifiers and hashes are deliberately fake, not runnable staging values.
There is no arbitrary command, plaintext DB credential or extra environment input.

| Definition | Immutable image input / command | CA initializer / process UID |
| --- | --- | --- |
| `runtime-release` | `images.runtime` / `/app/migrate` | `runtime-release` / 65532 |
| `product-release` | `images.search` / `python -m dev.migrate_storage` | `search-release` / 10001 |

Both use the pinned Search image for init, 0.25 vCPU / 512 MiB as an unmeasured
initial allocation, and a single task-local CA volume. Both roots are read-only;
the CA is writable only to root init and read-only to the nonroot migration.
There are no scratch volumes, ports, health checks, restart policies or service
schedulers. Successful init is mandatory. Runtime explicitly sets
`SENTRYRUNTIME_MIGRATIONS_DIRECTORY=/app/db/migrations`, independent of the job's
working directory `/`; Search sets `ENVIRONMENT=staging`, `DB_SSLMODE=verify-full`,
`DB_SSLROOTCERT=/run/material/postgres-ca.pem`, `DB_DEBUG=false` and disables dotenv.

Each job has a **separate** execution role for its owner environment bundle,
required ECR repositories and own log streams; a separate task role can only read
its pinned CA bundle. All secret versions and image digests are immutable inputs.
No job receives service credentials, Runtime auth/probe/worker tokens, S3 or model
authority. Source images must actually include the two release-only initializer
profiles. Never use the broad service material profiles for an owner job.

Registering these definitions does not run them. A separately approved operator
or controller must prevent concurrent releases, impose a measured whole-job
deadline, wait for task `STOPPED`, inspect stopped/start-failure reasons, and require
both init and migration exit 0. The [offline release controller](../../docs/release-controller.md)
encodes these rules against fake ports only; it has no AWS adapter. A 30-second `stopTimeout` is termination grace,
**not** a whole-migration deadline. A missing migration exit code, failed init,
killed/timed-out task or incompatible schema is a failed release, even if no
container remains running. No scheduler retry or automatic down-migration is
configured. Preserve failure receipts and verify transaction/schema state before
an intentional rerun; the existing migrators handle idempotent reruns, not generic
infrastructure success detection.

## Optional guarded release-tools jobs

`release_tools` (default `null`; requires `release_jobs`) adds one task definition
per job: `runtime-grant`, `product-grant`, `runtime-proof`, `product-proof`,
`runtime-reconcile` and `product-reconcile`. Each runs the digest-pinned
[release-tools](../../docs/release-tools.md) image after the same CA-only init as
the owner migration, with the job's fixed command, a read-only root, no
capabilities, the database's release UID, no ports, health checks or restart, a
30-second stop timeout above the in-image grace, and logs in that database's
release log group under stream prefix `<job>`.

| Input | Rule |
| --- | --- |
| `release_id` | The manifest's release UUID |
| `image` | Same-account, same-region ECR image by digest |
| `not_after`, `budget_seconds` | Absolute UTC deadline at most seven days after the plan; whole seconds, 60–3600 |
| `tools_sha256`, `sql_sha256` | From the image's `digest` report; `runtime_grant` must equal `release_jobs.runtime_grants.sql_sha256` |
| `runtime`, `product` | Database, owner and distinct service identifiers, and a `proof_bundle` holding only the service login at an exact version |

The release and job ids, deadline, budget, digests and expected identity are
container environment values, so the registered revision binds them; the image
rejects a mismatch before connecting. Changing any of them replaces the revision,
which `prevent_destroy` refuses for a retained release: use a new release scope.

Grant and reconciliation jobs read the owner environment bundle; proofs read only
their `proof_bundle`. Each job has its own execution role (`<db>-grant`,
`<db>-proof` or `<db>-recon`): pull the Search (init) and release-tools
repositories, write its own log streams and read its one bundle version. The task
role is the release's CA-only task role. `receipt_log_streams` lists each job's
app-container stream pattern for the launcher's receipt reads, and
`release_tools_bindings` gives the manifest's grant and proof expectations. The
bootstrap job is not wired: it needs the administrator secret and a separately
approved administrator path.

### Runtime grants: pinned source

`release_grant_contract` is review metadata, not SQL execution or a permission
grant. Its fixed path is `db/roles/service.sql` in the Runtime repository. The
file is deliberately **not** in the Runtime image or Goose migrations. Pin the
matching Runtime source commit and the SHA256 of the exact file, verify both
before execution, and establish source-to-image correspondence from the build
receipt; Terraform validates hash shape, not provenance or file content.

For the currently retained Runtime source, commit
`bb6e523da3c6f4bb186a548f3be696a40798fae9` has grant-file SHA256
`02a2b55161506254b1977f26351ec3bbba4de7c94a54b3b697153d622ae02aa0`.
This is a source receipt, not a claim that a future ECR digest contains that build.
An operator can compare `git show <pinned-commit>:db/roles/service.sql | shasum -a 256`
in the verified Runtime checkout. Review later source changes before changing the
pin; never follow `main` or download SQL inside the migration task.

The release order is explicit:

1. Approve the environment and release window; pause admission and drain all
   writers. Retain a usable backup and compatible rollback plan. Provision/audit
   separate DB owner and unprivileged service principals outside these jobs.
2. Run the Runtime owner migration task against its **dedicated Runtime DB**;
   require successful task/container receipts and the image's exact schema.
3. Run the `runtime-grant` job: it applies the vendored, hash-verified
   `db/roles/service.sql` with `psql -X`, `ON_ERROR_STOP=1` and explicit database
   and service-role parameters, as the owner, over verified TLS. The script
   revokes PUBLIC privileges database-wide; the job refuses the product database
   (the script requires the Runtime tables and database ownership).
4. Run the product owner migration task against its **separate product DB**, then
   the `product-grant` job, which applies the product contract in
   `docs/storage-release.md`. Run `python -m dev.migrate_storage --check` with
   service credentials separately.
5. Run both proof jobs: each service login performs its intended operations and
   fails to perform DDL, own or transfer objects, mutate migration history, change
   roles or reach another database. Start service tasks with service credentials
   only; evaluate readiness and the separately approved synthetic canary before
   any admission decision.

The two DB migrations are independent; this conservative ordered checklist is an
operator contract, not a cross-database transaction. The offline controller
models its ordering and holds but is not a deployed orchestrator.
The module does not create principals, launch jobs, observe readiness, schedule
promotion or provision the enclosing platform; registering the job definitions
runs nothing.

## Release preflight and omitted deployment gates

1. Verify approved account, region, isolated resources, image manifests/scans,
   operator and budget. Provider input validation does not certify any of these.
2. Inspect the runtime's encrypted `DATABASE_URL` through an authorized secret
   path: it must name the restricted service role and include
   `sslmode=verify-full&sslrootcert=/run/material/postgres-ca.pem`. Terraform never
   reads its plaintext, so it **cannot enforce** those URL parameters. Search
   instead fixes its TLS mode/path directly. Verify both remote DB transports.
3. Review/opt into the two owner-job definitions and execute the separate release
   order above only under deployment authorization. Runtime owner `DATABASE_URL`
   also requires `sslmode=verify-full&sslrootcert=/run/material/postgres-ca.pem`;
   its plaintext and DB ownership are not verified by Terraform; the release-tools
   jobs reject any other URL form before connecting. Provisioning, task
   launch/completion and promotion remain omitted gates; job definitions alone do
   not satisfy them.
4. Prove certificate issuance, trusted SAN/CA distribution, token scope and
   rotation. Runtime loads files at startup; secret renewal is not a running
   process rotation. Keep a compatible pinned rollback version.
5. The [staging roots](../aws-staging/README.md) now declare the network, DNS
   and services, mock-tested only. Restart/replacement behavior, health gates,
   startup ownership and task volume lifecycle still need deployed proof. Mocked
   plans cannot establish Fargate secret injection or service operation.
6. Prove bounded S3 Get/Put/Delete permissions, no cross-prefix access, accepted
   encryption, backup/restore, compatible rollback and delivered operator alerts.
7. Build and approve isolated auth/fake-provider canaries. Live provider calls,
   production integration, registry publication and resource creation remain
   separate gates. Existing production auto-deploy hooks are unchanged.

## Primary references

- [Pinned provider task-definition schema](https://github.com/hashicorp/terraform-provider-aws/blob/v6.65.0/website/docs/r/ecs_task_definition.html.markdown)
- [Terraform mocked-provider tests](https://developer.hashicorp.com/terraform/language/tests/mocking)
- [Fargate container definitions and timeouts](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html)
- [Fargate restrictions](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/fargate-tasks-services.html) and [ephemeral bind mounts](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/bind-mounts.html)
- [ECS secret JSON-key/version syntax](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/secrets-envvar-secrets-manager.html)
- [Secrets Manager VersionId IAM condition](https://docs.aws.amazon.com/service-authorization/latest/reference/list_secretsmanager.html)
- [Task execution role permissions](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_execution_IAM_role.html)
- [Task-role authority is shared by the task](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html)
- [ECS Exec filesystem requirements](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-exec.html)
