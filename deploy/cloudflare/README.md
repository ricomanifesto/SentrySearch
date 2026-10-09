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
   ambient and bounding capability sets, switch to the profile's user, set
   `no_new_privs` and install a seccomp filter that refuses new user
   namespaces. The filter is generated for the running architecture and handed
   to `setpriv` through an in-memory file, which the dropped phase closes
   before executing the service.
2. `continue` (dropped): refuses unless `/proc/self/status` shows every
   capability set empty, `NoNewPrivs: 1`, exactly one seccomp filter more than
   the root phase saw (passed along as `--filters`; Docker's default profile
   is itself a filter, so `Seccomp: 2` alone proves nothing) and exactly the
   profile's identity, then executes the command.

The user namespace filter matters because a process holds a full capability
set inside a user namespace it creates. With `CAP_SYS_ADMIN` in the container
(as in local `wrangler dev` containers) the dropped service could otherwise
create one and mount or map root inside it. `unshare` and `clone` with
`CLONE_NEWUSER` fail with `EPERM`; `clone3`, whose flags a filter cannot read,
fails with `ENOSYS` so runtimes fall back to `clone`; another architecture or
the x32 ABI kills the process. Both root phases run Python with `-P` (no
script or working directory on the import path) or `-I`.

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
  `enableInternet: false`, the container settings (`CONTAINER_*` bindings,
  prefix removed) and the complete fixed command, beginning with the
  privilege-dropping wrapper. The `cloudflare` image targets set no entrypoint
  or command of their own. `start()` documents `entrypoint` only as the
  command and arguments to run, and local workerd appends it to an image
  entrypoint, so with none set the same argv runs under either reading.
- **Receipts.** The worker posts its readiness receipts to
  `evidence.internal`; the intake accepts only the current start's receipts for
  the release, in the exact v1 schema, stores at most 512 rows and 8 boot ids
  per start in Durable Object SQLite with an eviction watermark, and reports
  gaps, conflicting duplicates, refused boots and completeness. A start that
  has ended is complete only when every boot's last receipt is its terminal
  one (`alive` false, phase `stopped`, carrying the exit's error code); the
  worker reports `stopped` while still alive first, so a lost tail never reads
  as complete. The start nonce reaches the container
  only inside the interception props, never its environment. Each object keeps
  its last 8 starts and their receipts.
- **Runtime transport.** `runtime.internal` accepts only the worker's WebSocket
  and hands it to the runtime object, which connects to the runtime's TLS
  listener with `getTcpPort().connect()` and moves bytes. The Search worker's
  TLS session, private CA check and bearer token stay end to end
  (`src/execution/runtime_tunnel.py`). The relay refuses text messages and
  closes a tunnel with more than 1 MiB waiting for the runtime's socket. The
  API has no runtime interception.
- **Control.** Every control route needs an Ed25519-signed command for the
  object's own name (recomputed from its namespace), an unexpired lifetime of at
  most five minutes, a body matching the signed digest and a command id never
  accepted before. The signed release, session and fence values are carried for
  the release controller's authority protocol.
- **Drain windows.** The worker object waits 45 seconds after SIGTERM, above
  the worker's own 30-second drain budget, so a busy worker ends itself (exit
  124, `drain_deadline_exceeded`) before the object destroys it; the API and
  runtime objects wait 30 seconds.
- **Lifetime.** A start is claimed in storage before its first `await`, so
  concurrent signed starts produce one start; a claim whose interceptions do
  not bind within a minute is abandoned. The current start is the latest row
  inserted, never chosen by clock. A 10-second alarm keeps a
  running container's object active, also through the drain window, and
  re-arms the inactivity timeout. Enforcement follows the container, not a
  recorded state: `monitor()` can settle while the container still runs, so a
  start ends only when `running` is false, and the alarm observes it again
  otherwise. A restarted object re-arms the timeout, re-binds both
  interceptions for the current start and re-attaches observation; a container
  that ended while no instance watched it is recorded as `ended while
  unobserved`. Stopping sends SIGTERM and destroys only after the drain window,
  recording `destroyed` before calling `destroy()`. `destroy()` or a resolved
  `monitor()` never counts as success.
- **Jobs.** A `JobRunner` starts one release-tools job and keeps it alive with
  the same 10-second alarm. It sends SIGTERM at its deadline (alarms also cover
  deadlines beyond the 15-minute `monitor()` window), keeps that SIGTERM in its
  record even if the job then exits 0, and destroys it after a grace period.
  It reports `sql_outcome` `unknown` unless the job's own completion receipt
  exists and it was never signalled.
- **Logs.** Container logs and SSH are off; Worker invocation logs are on with
  query strings redacted. Receipts are the only evidence channel.

## Local findings that shaped this code

Measured with the pinned Wrangler 4.141.0 and workerd 2026-09-25:

- Under amd64 emulation on Apple silicon (Rosetta here; QEMU user mode refuses
  too) an emulated process cannot install a seccomp filter: `prctl` fails with
  `EINVAL`. The `cloudflare` targets built for `linux/amd64` therefore refuse
  to start when run emulated. They run natively: arm64 locally, amd64 on
  Cloudflare. `wrangler dev` always builds `linux/amd64`, so the harness on
  the real images needs a native amd64 host.
- A Durable Object reload (`wrangler dev` reloads every object on a source
  change) drops receipts posted during the reload, about 10 seconds locally;
  they show as gaps and the history stays incomplete.
- Local workerd passes `start({entrypoint})` to Docker as the command, after
  any image entrypoint. The `cloudflare` targets therefore set none: an image
  entrypoint made every real container exit 64, because the wrapper received
  its own argv as the command.
- Local workerd creates containers with Docker's `on-failure` restart policy
  and no retry limit. A service that fails once restarts over its own
  filesystem, and the wrapper then refuses the non-fresh `/run/material` (exit
  78) on every attempt, which hides the first error. The harness keeps each
  container's output for that reason.
- Docker's `HOME=/root` from the root start would follow the service user.
  libpq treats an unreadable `~/.postgresql/postgresql.crt` as fatal, so the
  Search wrapper sets `HOME=/nonexistent`, as both images declare for their
  users, before dropping privileges (release-tools jobs use `psql` too).
- Containers reach a database on the host's loopback as
  `host.docker.internal` (the harness's disposable PostgreSQL); TLS still
  verifies that name.

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
  a verified TLS request over the runtime relay; API ingress (the edge and the
  API object forward `/api/...` paths unchanged, as the Search API serves
  them), the API's denied runtime and outside access, and what `127.0.0.1`
  reverse-resolves to inside the container (H-L4); refusal of unsigned, expired, replayed,
  foreign-release, misdirected and foreign-key commands; two minutes idle
  without the container stopping; a Durable Object restart (a source change
  reloads every object) with the same start still running and new receipts
  arriving through the re-bound interception; drain on stop with exit 0 and a
  final draining receipt; a job that exits and a job past its deadline, both with
  `sql_outcome` `unknown`, and a refused second run.

`--images fixture` runs every service from `harness/fixture` (one static
binary installed at the paths the Durable Objects start), so it proves the
Worker scripts, not the service images or their privilege drop.
`--long-job-seconds 960` adds one job past a 16-minute deadline (H-J1): the
harness stays silent until 30 seconds before it, so only the object's alarms
keep the container alive meanwhile. `check_entrypoint.py` covers the Search
entrypoint's drop separately; the runtime's is covered by
`scripts/cfinit_check.sh` in sentryruntime.

`--images real` runs the api, worker and runtime from locally built
`--target cloudflare` images. Before Wrangler starts, it sets up a disposable
PostgreSQL 16 with TLS on the host's loopback (reached from the containers as
`host.docker.internal`, the one egress a local container keeps) and migrates it
with the default images as `dev/check_service_images.py` does. The material
reaches the containers only as `CFINIT_MATERIAL` with its digest. The run
checks:

- the worker becomes ready through the tunnel;
- the API answers `/api/ready` through the edge;
- every service process has no capabilities, `no_new_privs` and filter-mode
  seccomp, read from `/proc` in each container's PID namespace;
- each service drains on a signed stop.

Wrangler always builds `linux/amd64`, and amd64 emulation on an arm64 Mac
refuses the entrypoints' seccomp filter. `--native-platform linux/arm64`
therefore makes the shim build the image map natively: such a run proves the
real images on arm64, not on amd64.

## Validation

```sh
cd deploy/cloudflare/worker
npm ci --ignore-scripts
npm run types && npm run check && npm test
```

`npm test` covers signed control, receipt intake and the service and job
lifecycles (a fake container and Durable Object state under node).
`tests/test_cloudflare_cfinit.py`, `tests/test_runtime_tunnel.py` and
`tests/test_receipt_http_sink.py` run in the repository gate.

## Not proven here

Anything that needs a deployed container: capability semantics under
`durable_object`, placement, the 15-minute SIGTERM window, version and
deployment APIs, and Cloudflare's own enforcement of `enableInternet`.
