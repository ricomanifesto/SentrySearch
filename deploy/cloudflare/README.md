# Cloudflare platform pieces (local only)

This directory holds the Cloudflare Workers, Durable Objects and Containers code
for running SentrySearch and SentryRuntime on Cloudflare, exercised only on a
local machine with `wrangler dev` and Docker. Nothing here deploys, creates an
account resource, publishes an image or reads Cloudflare credentials.

| Path | What it is |
| --- | --- |
| `sentrysearch_cloudflare/cfinit.py` | Container entrypoint for the Search service and release-tools images (`--target cloudflare`) |
| `worker/src/` | Five Worker scripts: `edge`, `api`, `worker`, `runtime`, `jobs` |
| `worker/config/` | Wrangler configuration templates (no account id); `@@NAME@@` values are filled per run |
| `worker/test/` | Unit tests for signed control and receipt intake |
| `harness/harness.py` | Runs all five scripts under `wrangler dev` with containment and drives signed scenarios |
| `harness/check_entrypoint.py` | Proves the Search entrypoint's privilege drop in real containers |
| `harness/fixture/` | One static binary standing in for every service in the harness self-test |

The runtime image has its own entrypoint, `cmd/cfinit` in the sentryruntime
repository.

## Why the containers need an entrypoint

A Durable Object container runs one image with no init container and no secret
volume, and under the `durable_object` scheduling policy every process in a
deployed container has root-equivalent Linux capabilities whatever its user.
The AWS deployment prepares file material in a separate root initializer and
runs services non-root with no capabilities. `cfinit` restores that inside the
container, in two phases:

1. `start` (root): checks the profile and its fixed command, writes the
   profile's material from `CFINIT_MATERIAL` after checking it against
   `CFINIT_MATERIAL_SHA256` (with `dev/prepare_service_volumes.py`, the same
   rules as the AWS initializer), removes every `CFINIT_` variable and executes
   util-linux `setpriv` to clear supplementary groups and the inheritable,
   ambient and bounding capability sets, switch to the profile's user and set
   `no_new_privs`.
2. `continue` (dropped): refuses unless `/proc/self/status` shows every
   capability set empty, `NoNewPrivs: 1` and exactly the profile's identity,
   then executes the command.

`probe` / `continue-probe` do the same for a fixed readiness probe with a
minimal environment. Profiles: `search` (API and worker, user 10001, runtime and
PostgreSQL CA, scratch in `/run/tmp` and `/run/work`), `search-release`
(product jobs, 10001) and `runtime-release` (runtime jobs, 65532). Each image's
`cloudflare` stage ships `setpriv` (with util-linux's package metadata, filtered
to that one file) and the whole `libcap-ng0` package; the default build targets
are unchanged.

## Worker scripts

One script per service keeps bindings and secrets apart. Each service is a
named Durable Object (`api-0`, `worker-0`, `runtime-0`, one `JobRunner` per
job) owning one container:

- **Start.** Before `start()` the object intercepts `http://evidence.internal`
  (and, for the worker, `http://runtime.internal`) with loopback entrypoints
  created with props only it sets: its object id, service and start nonce.
  Interception configured after `start()` broke the container's ingress
  locally, so it always comes first. Containers start with
  `enableInternet: false`, the image's Cloudflare entrypoint and the container
  settings (`CONTAINER_*` bindings, prefix removed).
- **Receipts.** The worker posts its readiness receipts to
  `evidence.internal`; the intake accepts only the current start's receipts for
  the release, in the exact v1 schema, stores at most 512 rows in Durable
  Object SQLite with an eviction watermark, and reports gaps, conflicting
  duplicates and completeness.
- **Runtime transport.** `runtime.internal` accepts only the worker's WebSocket
  and hands it to the runtime object, which connects to the runtime's TLS
  listener with `getTcpPort().connect()` and moves bytes. The Search worker's
  TLS session, private CA check and bearer token stay end to end
  (`src/execution/runtime_tunnel.py`). The API has no runtime interception.
- **Control.** Every control route needs an Ed25519-signed command for the
  object's own name (recomputed from its namespace), an unexpired lifetime of at
  most five minutes, a body matching the signed digest and a command id never
  accepted before. The signed release, session and fence values are carried for
  the release controller's authority protocol.
- **Lifetime.** Alarms keep a running container's object active and re-arm the
  inactivity timeout; a restarted object re-arms it and re-attaches lifecycle
  observation. Stopping sends SIGTERM and destroys only after the drain window.
  `destroy()` or a resolved `monitor()` never counts as success.
- **Jobs.** A `JobRunner` starts one release-tools job, sends SIGTERM at its
  deadline (alarms also cover deadlines beyond the 15-minute `monitor()`
  window) and destroys it after a grace period. It reports `sql_outcome`
  `unknown` unless the job's own completion receipt exists.
- **Logs.** Container logs and SSH are off; Worker invocation logs are on with
  query strings redacted. Receipts are the only evidence channel.

## Local findings that shaped this code

Measured with the pinned Wrangler 4.141.0 and workerd 2026-09-25:

- Local `exec()` always runs `/bin/sh -c 'echo $$ > <pidfile>; exec "$@"'`, so
  it cannot run in these distroless images. A platform `exec()` probe is
  therefore not provable locally.
- With `enableInternet: false` the local egress sidecar
  (`cloudflare/proxy-everything`) blocks the external path for HTTP and TCP but
  still reaches services on the host's loopback through `host.docker.internal`;
  it publishes the container's ingress on all host interfaces and uses public
  DNS servers.
- An idle Durable Object's containers were killed about 30-60 seconds after
  the object went idle.

## Local harness

`harness/harness.py` renders the templates into a run directory outside the
repository and runs the five scripts together under `wrangler dev`:

- **Containment.** The host side runs under `sandbox-exec` with outbound
  traffic allowed only to loopback and the Docker socket, an empty HOME, XDG
  and Docker configuration and poisoned Cloudflare settings. Wrangler's Docker
  calls go through a shim that logs every call and answers a `pull` only for an
  image already present, so a run never contacts a registry. Containers start
  with `enableInternet: false`; an outside canary bound to the Mac's LAN
  address and the run's `lsof` samples record any escape.
- **Scenarios.** Signed starts; the worker becoming ready through receipts and
  a verified TLS request over the runtime relay; API ingress and the API's
  denied runtime and outside access; refusal of unsigned, expired, replayed,
  foreign-release, misdirected and foreign-key commands; two minutes idle
  without the container stopping; drain on stop with exit 0 and a final
  draining receipt; a job that exits and a job past its deadline, both with
  `sql_outcome` `unknown`, and a refused second run.

`--images fixture` runs every service from `harness/fixture` (one static
binary installed at the paths the Durable Objects start), so it proves the
Worker scripts, not the service images or their privilege drop.
`check_entrypoint.py` covers the Search entrypoint's drop separately; the
runtime's is covered by `scripts/cfinit_check.sh` in sentryruntime. Running the
scenarios on the real `--target cloudflare` images is still to do.

## Validation

```sh
cd deploy/cloudflare/worker
npm ci --ignore-scripts
npm run types && npm run check && npm test
```

`tests/test_cloudflare_cfinit.py`, `tests/test_runtime_tunnel.py` and
`tests/test_receipt_http_sink.py` run in the repository gate.

## Not proven here

Anything that needs a deployed container: capability semantics under
`durable_object`, placement, the 15-minute SIGTERM window, version and
deployment APIs, and Cloudflare's own enforcement of `enableInternet`.
