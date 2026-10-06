# Backend service images

`container/Dockerfile` builds one backend image for the API, the durable-generation
worker, and the product release job. Each role runs as an independent process
and service. This is a locally proven build and process contract, not a published
image, a deployment, or evidence of a production cutover.

The existing Railway service is unchanged: `railway.json` still selects Railpack
and `python run_api.py`. The image definition lives outside the repository root
so it cannot replace that build implicitly.

## Build

```bash
docker build --file container/Dockerfile --tag sentrysearch:local .
```

Inputs are pinned: the multi-architecture Python 3.11 base image by digest, the
build-only `uv` installer by PyPI wheel hashes, the runtime dependencies by
`uv.lock` (`uv sync --locked --no-dev`), and the static `tini` v0.19.0 init by
SHA-256 for `amd64` and `arm64`. Those checksums match the release's published
`.sha256sum` files. Both release binaries' detached GPG signatures were verified
on October 6, 2026 against the upstream-published signing fingerprint
`595E85A6B1B4779EA4DAAEC70B588DFF0527A9B7`; the verified SHA-256 values match
the Dockerfile pins. Follow [upstream signature verification](https://github.com/krallin/tini#signed-binaries)
when changing either binary. Update a pin deliberately and rerun the proof below.
Image digests are not bit-for-bit
reproducible across builds.

`container/Dockerfile.dockerignore` admits only `pyproject.toml`, `uv.lock`,
`.python-version`, `run_api.py`, `src/`, `certs/`, and the three explicit service
points from `dev/`. Tests, fixtures, the frontend, Terraform, and `.env` files
never enter the build context. Behind a TLS-intercepting build proxy, pass its
complete PEM trust bundle as `--secret id=build_ca,src=<bundle>`; it is used only
while downloading dependencies and is not stored in a layer.

## Roles

The image has no default command. Each service selects exactly one role:

| Role | Command | Database role | Other required settings |
| --- | --- | --- | --- |
| API | `python /app/run_api.py` | application | `PORT` (default 8001), execution admission |
| Worker | `python -m dev.run_runtime_worker --health-port 8081` | application | runtime endpoint, trust, and distinct producer/worker tokens; OpenRouter; S3 |
| Release job | `python -m dev.migrate_storage` | schema owner | none |
| Release check | `python -m dev.migrate_storage --check` | application | none |
| Volume initializer | `python -m dev.prepare_service_volumes ...` | none | explicit material profile/version; root only for fresh-volume ownership |

Application and database release roles use the explicit `DB_*`, `ENVIRONMENT`, and `AWS_*` settings described
in [the storage release contract](storage-release.md), and the admission and
runtime settings in [admission and transport](runtime-admission.md). The image
sets `PYTHON_DOTENV_DISABLED=1`; configuration comes only from the service
environment and mounted files, never from a `.env` file. The image contains no
credentials, endpoints, or bucket names.

Run SentryRuntime's own service and migration job from its image; see that
repository's runtime operations document. Its migration job is separate from
the product release job, and neither runs at service startup.
The cross-service proof also applies the runtime repository's
`db/roles/service.sql` after its migrations. The running runtime uses a separate
restricted login with no DDL, deletion, migration-history writes or event updates;
its database owner is confined to release/setup jobs. Supply a runtime checkout
containing that grant script when running the proof.

### Configuration and privilege matrix

| Setting | API | Worker | Release job | Release check |
| --- | --- | --- | --- | --- |
| Application DB credentials | yes | yes | no | yes |
| Schema-owner DB credentials | no | no | yes | no |
| `SENTRYSEARCH_EXECUTION_MODE` | yes | no | no | no |
| Runtime URL and CA file | in `runtime` mode, validated only | yes | no | no |
| Runtime producer and worker tokens | no | yes, distinct | no | no |
| OpenRouter key | legacy mode only | yes | no | no |
| S3 bucket and SDK credentials | yes; checked at startup in staging/production | yes | no | no |
| Supabase service key | yes | no | no | no |

The API writes dispatch intent to the product database; it never calls the
runtime and must not receive runtime tokens. Release credentials are supplied
only to the one-shot release job. Runtime tokens are credentials with their full
configured authority, so do not reuse them for other services. A runtime health
probe needs its own restricted credential and still has that credential's API
authority; it is not a special health-only role.

## Process contract

`tini` is PID 1. It forwards signals only to the selected role's main process
and reaps orphaned descendants. Application and release containers run as UID/GID `10001` with a
read-only-compatible root filesystem. Application code and dependencies in
`/app` are owned by root and not writable by the service user.

The working directory is the service-owned scratch directory
`/var/lib/sentrysearch`. Generation writes process-local traces and metrics there.
Under a read-only root filesystem, mount `/tmp` and that directory as tmpfs or
ephemeral storage. Treat both as sensitive working data: they can contain report
content. Never share or persist them as product storage; durable report artifacts
belong in S3. `PYTHONSAFEPATH=1` keeps the writable directory off `sys.path`.

| Role | Signal behavior | Exit status |
| --- | --- | --- |
| API | SIGTERM starts Uvicorn graceful shutdown | `143` after a graceful SIGTERM shutdown (Uvicorn re-raises the signal); nonzero if startup fails |
| Worker | The supervisor receives SIGTERM/SIGINT, marks readiness false, and drains its worker child over a control pipe; the child ignores signals directly | `0` clean drain; `1` worker or unresolved runtime error; `124` drain or phase deadline (child killed and reaped; leases left to expire) |
| Release job and check | Run to completion | `0` ready; `1` configuration, privilege, or schema failure |

Configure the platform's termination grace above the worker's `--drain-seconds`
(30 seconds by default) plus a small margin. A deadline exit does not cancel
provider work already accepted or cap its cost; durable leases and product fences
recover or reject the interrupted attempt. Restart the worker through the
platform; the supervisor does not restart itself.

### Probes

- **API:** `GET /api/ready` checks database connectivity and the exact product
  schema revision; it is suitable for an HTTP readiness check. `GET /api/health`
  is a degraded/connected summary, not a readiness gate.
- **Worker:** `/healthz`, `/readyz`, and `/status` listen on loopback only and must
  not be exposed through a service port. Use an exec probe inside the container:

  ```bash
  python -c "import http.client as h;c=h.HTTPConnection('127.0.0.1',8081,timeout=2);c.request('GET','/readyz');raise SystemExit(c.getresponse().status!=200)"
  ```

  Use `/healthz` the same way for liveness. A platform whose only health check is
  the API's web endpoint is not supervising the worker.
- **Release job:** use its exit status. It exposes no probe.

Platform-specific probe, restart, and termination settings belong to the
deployment-target decision; this document does not select a platform.

The [local AWS platform-fit proof](platform-fit.md) adds a root-only one-shot
initializer, strict file-secret profiles, and real named-volume lifecycle tests.
It exercises a Fargate-shaped filesystem contract without deploying anything.
The initializer exits before application startup, which depends on its success.

## Local proof

```bash
uv run python dev/check_service_images.py --runtime-repo ../sentryruntime
```

The command builds this image and the SentryRuntime image, then runs
`tests/service_images.py` against containers on an internal Docker network with
no outbound route. It generates disposable credentials and separate CAs for
PostgreSQL and the runtime, uses verified TLS for both product and runtime
databases and verified HTTPS with scoped tokens to the runtime, and replaces the
model provider with a local stub that accepts connections and never responds.

It proves:

- the image contents match tracked `src/`, `certs/`, and the release entry points;
  application files are root-owned; the image has no default command, baked
  configuration, or `.env` file; and the process tree runs as UID 10001 under
  `tini`;
- the release job succeeds with the schema-owner role, is idempotent, and is
  rejected for the application role; the application role passes the read-only
  check after grants and cannot create tables;
- the runtime serves the worker through a restricted service login, separate
  from its migration owner; that login cannot migrate, delete runs or rewrite
  existing events;
- deployed plaintext database settings, unreleased schemas, untrusted database
  CAs, plaintext non-loopback runtime URLs, and shared runtime tokens fail closed
  without printing generated secrets; an untrusted runtime certificate keeps the
  worker unready;
- the API becomes ready and shuts down gracefully on SIGTERM;
- an idle worker becomes ready, passes the documented exec probe, and drains on
  SIGTERM;
- a worker blocked in generation reports readiness false while draining, is
  stopped at its drain deadline with its child reaped (exit `124`), and a newly
  started worker recovers the same runtime run after lease expiry with a newer
  product fence.

It does not prove a registry, a target platform's probes or grace periods,
resource limits, real provider or S3 behavior, certificate rotation, real
credentials, network policy, or production data migration. Those remain gated
by the deployment, canary, and rollback stages.

### Image release gate

Passing lifecycle tests is not release approval. Generate an SBOM and scan the
exact intended image digest, review dependency/base findings and retain their
dispositions before publishing. The October 6, 2026 local platform-fit candidate
has unresolved critical/high Search-image findings; see
[the platform-fit release hold](platform-fit.md#draft-task-contract-and-release-hold).
No image publication or deployment is established by the local tests.
