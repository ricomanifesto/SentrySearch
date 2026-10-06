# Local AWS platform-fit draft

This directory models three independent ARM64 Fargate task definitions and their
task/execution IAM roles. It is a **local, disabled-generation scaffold**, not a
deployed environment, a release pipeline or a completed application canary.
The existing `terraform/` topology is not reused or modified.

Only task definitions, IAM roles and inline policies are declared. There are no
services, clusters, networks, databases, buckets, registries, secrets, log groups,
DNS, load balancers or schedulers. References to those dependencies require
pre-existing, separately approved **staging** resources. Applying even this
limited module would mutate AWS; no apply or unmocked plan is part of local proof.

## Local validation

From this directory, with Terraform 1.9.8 or newer:

```sh
terraform init -backend=false -input=false
terraform fmt -check -recursive
terraform validate
terraform test
```

The provider is pinned to `hashicorp/aws` 6.65.0 and its generated lock file is
tracked. Init downloads a signed provider from its registry; it does not query an
AWS account. Every test uses `mock_provider "aws"` with `command = plan`, fake
identifiers and no credentials. Do not substitute a real provider or use these
fixtures as staging configuration.

Tests inspect the actual task-definition and IAM-resource attributes, plus
rendered container and policy contracts. They cover process ordering, UID and
mount boundaries, liveness/grace, paused admission, secret versions, IAM scoping,
and rejection of mutable image tags, cross-account secrets, shared bundles,
moving secret stages and non-DNS TLS identity. They do not execute IAM policy
evaluation, fetch real secrets, run Fargate or verify network reachability.

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

## Six version-pinned secret bundles

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

ECS environment-secret references use `ARN:JSON_KEY::VERSION_ID`. Execution roles
have `GetSecretValue` for only their environment bundle/version. Init requests
its material bundle/version through the task role. **A task role belongs to the
whole task, not one container**: the app retains authority to retrieve its own
material bundle, whose files it can already read. Init is not an isolated IAM
principal. Neither role is allowed to read another service's bundle.

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

## Release preflight and omitted deployment gates

1. Verify approved account, region, isolated resources, image manifests/scans,
   operator and budget. Provider input validation does not certify any of these.
2. Inspect the runtime's encrypted `DATABASE_URL` through an authorized secret
   path: it must name the restricted service role and include
   `sslmode=verify-full&sslrootcert=/run/material/postgres-ca.pem`. Terraform never
   reads its plaintext, so it **cannot enforce** those URL parameters. Search
   instead fixes its TLS mode/path directly. Verify both remote DB transports.
3. Provision/audit separate DB service and owner grants, apply the appropriate
   schema release, and check readiness. **Release-owner jobs are intentionally
   absent**: their DDL credentials, IAM, material bundles and migration sequence
   are distinct and must be designed before a deployment is complete.
4. Prove certificate issuance, trusted SAN/CA distribution, token scope and
   rotation. Runtime loads files at startup; secret renewal is not a running
   process rotation. Keep a compatible pinned rollback version.
5. Implement the actual network, DNS, services, restart/replacement behavior,
   health gates, startup ownership and task volume lifecycle. Mocked plans cannot
   establish Fargate secret injection or service operation.
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
