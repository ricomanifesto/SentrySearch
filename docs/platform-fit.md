# Local AWS platform-fit proof

This slice validates file-secret initialization, non-root task-local volumes,
and service lifecycle contracts on Docker. It does **not** register tasks, call
AWS APIs, prove an ECS scheduler, publish images, or deploy anything. The existing
Railway build and deployment configuration are unchanged.

## Ownership and startup ordering

Fargate does not support `tmpfs`. Use separate task-scoped ephemeral volumes for
material, `/tmp`, and `/var/lib/sentrysearch`; mount application roots read-only.
Fargate encrypts task volume storage. These local tests use Docker named volumes,
not tmpfs, to exercise ownership and read/write boundaries; they do not prove
Fargate encryption or persistence behavior. See the
[Fargate task differences](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/fargate-tasks-services.html)
and [file-secret sidecar pattern](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/specifying-sensitive-data.html).

`python -m dev.prepare_service_volumes` is an explicit, one-shot root initializer
included in the Search image. It is not an application entrypoint or migration.
The application container must depend on initializer **SUCCESS**, and the
initializer must be nonessential. Applications retain their existing UIDs:
runtime `65532`, Search `10001`. Only the initializer changes ownership.

The initializer needs `CHOWN`. Local Docker tests drop every capability then add
only `CHOWN`; Fargate cannot add that capability after dropping it (it only permits
adding `SYS_PTRACE`). In the task definition retain `CHOWN` while explicitly
dropping the other default capabilities. Applications drop all capabilities.
See [Fargate task definition parameters](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html).

Do not put material and scratch on the same volume, even through distinct mount
paths. The helper rejects equal device/inode roots as well as nested paths,
symlinked paths, nonempty roots, and roots not owned by its effective UID. Mount
fresh roots without copying image contents. The Search serving profile needs all
three independent volumes; runtime and release profiles need material only.
Runtime migrations and Search releases
remain independent one-shot processes with separate database-owner authority.

## File-secret contract

Choose a **specific immutable UUID version** of a Secrets Manager `SecretString`
containing one JSON object. An unversioned `AWSCURRENT` request is not supported.
The helper requests that exact version and verifies the response version before
accepting the body. It requires an explicit same-region `arn:aws:secretsmanager`
ARN and region; SDK access uses the task role, not keys embedded in the image.
Only these exact filenames are accepted:

| Profile | Required JSON keys | Owner |
| --- | --- | --- |
| `runtime` | `server-cert.pem`, `server-key.pem`, `runtime-ca.pem`, `postgres-ca.pem`, `probe-token` | `65532:65532` |
| `search` | `runtime-ca.pem`, `postgres-ca.pem` | `10001:10001` |
| `runtime-release` | `postgres-ca.pem` | `65532:65532` |
| `search-release` | `postgres-ca.pem` | `10001:10001` |

The two release profiles are for database-only migration/check jobs. They reject
runtime TLS keys, runtime CA/probe tokens, and scratch-volume arguments. Each
initializes only its fresh material volume; release jobs do not receive unrelated
application credentials merely to obtain the PostgreSQL CA. All profiles retain
the same strict material validation, ownership and immutable-version rules.

Example command shape (placeholders, not live identifiers):

```text
python -m dev.prepare_service_volumes --profile search \
  --material-dir /run/material --tmp-dir /tmp --work-dir /var/lib/sentrysearch \
  --secret-id <regional-secret-ARN> --version-id <immutable-version-UUID> \
  --region us-east-1
```

On Cloudflare there is no Secrets Manager source: `--environment-source` reads the
same JSON body from `CFINIT_MATERIAL` and refuses it unless its SHA-256 equals the
operator-recorded `CFINIT_MATERIAL_SHA256`. Everything below applies unchanged; the
container entrypoint that calls it is described in `deploy/cloudflare/README.md`.

The JSON body, including overhead, must be at most 65,536 UTF-8 bytes; a selected
CA bundle must fit that bound. Duplicate, extra, missing, empty and malformed
fields fail closed. CA PEMs must parse; runtime certificate and unencrypted key
must match. Encrypted keys are rejected without OpenSSL prompting. The helper
does not certify certificate lifetime, hostname or CA-chain validity; the runtime
probe performs live TLS verification before a task can be considered ready.
See the [GetSecretValue contract](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html).

Material files are `0400`, directories `0700`, and application material mounts
are read-only. Scratch roots are `0700` and writable only by Search's UID. No
secret values, SDK errors, certificate contents, or paths from failed inputs are
printed. A failed initialization produces a fixed error and nonzero exit; discard
that task's volumes, including any partial files. Do not retry on partially
initialized volumes, overwrite old versions or hot-rotate mounted files. A new
task gets a new secret version and new volumes; test probes before retiring the
old task. ACM renewal alone does not update these files.

The runtime's `/app/probe healthz|readyz` reads
`SENTRYRUNTIME_PROBE_CA_FILE=/run/material/runtime-ca.pem` and
`SENTRYRUNTIME_PROBE_TOKEN_FILE=/run/material/probe-token`. Configure its numeric
loopback address and explicit certificate server name separately. The probe token
is an API credential with the configured role's authority, not a health-only
credential. Restrict its access accordingly. Existing application DB credentials,
runtime auth configuration, and worker tokens still use the application's
environment contracts; this helper does not change those APIs.

Task IAM authority is task-scoped, not container-scoped: an init sidecar is **not**
an IAM isolation boundary from the application. Restrict the task role's secret
resource/version permissions and avoid granting a worker access to other tasks'
material. Live IAM, secret acquisition and rotation remain deployment gates.

## Reproducible local proof

```bash
uv run python -m pytest tests/test_prepare_service_volumes.py
uv run python dev/check_platform_fit.py --runtime-repo ../sentryruntime
```

The runner builds both local `image-check` tags. `--skip-build` intentionally uses
existing tags; record their image IDs and ensure they match the source under test.
Build dependency downloads may use the network. Every **test container** uses an
internal Docker network without an outbound route, no host credential mounts,
fixture-only JSON on stdin, disposable TLS/auth/database credentials, and a local
non-answering model stub. AWS SDK unit tests use explicit dummy credentials and
`Stubber`, never a live Secrets Manager call. Containers and named volumes are
removed after the proof.

The suite proves non-root private material consumption, denied root/material
writes, writable Search scratch, duplicate-volume rejection, init-failure ordering,
runtime protected TLS exec probes, API shutdown, worker liveness versus readiness,
and busy-worker drain deadline/restart recovery against real disposable databases.
It reuses the existing service lifecycle assertions on named volumes, proving the
volume substitution through actual application behavior.

Still unproven: ECS registration/ordering/health replacement, runtime task memory
limits, cloud networking, task IAM credential retrieval, secret permissions,
certificate issuance/export/installation, registry provenance, managed backups,
restore drills, real provider calls and production compatibility. This local
proof does not authorize any of those actions.

## Draft task contract and release hold

[The task/IAM module](../deploy/aws-platform-fit/README.md) models three independent
Fargate tasks, pinned images and secret versions, init SUCCESS dependencies,
read-only roots and scoped task/execution policies. It contains no service,
network, database, bucket or release-job provisioning. Mocked Terraform validation
does not establish real IAM enforcement or Fargate acceptance. The separate
[staging roots](../deploy/aws-staging/README.md) now model that environment, also
mock-tested only and never applied.

The original October 6, 2026 local ARM64 Search image was **not release-clean**:
Trivy 0.75.0 reported 4 critical and 64 high package/advisory occurrences,
including 13 critical/high occurrences with listed Python-package fixes.
These counts are not proof of exploitability. Application PyJWT, AnyIO,
cryptography and urllib3, plus base-image packaging dependencies and OS findings,
need a bounded dependency/base review and rescan before publication or deployment.
Do not suppress all OS findings or infer a live service's exposure from this image.

The subsequent [dependency/base remediation and OS minimization](image-security.md)
clears critical and Python-package findings and reduces Debian packages to 29.
The exact rebuilt image retains 7 high OS matches across five advisories, plus
lower/unknown findings. The liblzma UNKNOWN match has an upstream HIGH advisory;
publication/deployment remain held for explicit residual-risk resolution.
Use that newer exact-image receipt when continuing, not the historical counts above.
