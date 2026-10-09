# Cloudflare release controller (offline)

`release_cloudflare/` runs the [release controller](release-controller.md) on
Cloudflare Workers, Durable Objects and Containers. The controller, journal,
lock, guards and readiness gate are the shared ones in `release/`; this package
supplies:
- the Cloudflare manifest and approval;
- the signed control client;
- the ports;
- `CloudflarePlatform`.

**Offline only.** This page is not evidence that any account, Worker or object
exists:
- no account call, credential or network code;
- no Wrangler run;
- the Cloudflare API ports and the control transport are injected;
- the tests use fakes.

## Manifest and approval

`release_cloudflare/manifest.py` holds the strict schema, version 1, with
`"platform": "cloudflare"`. It uses the same JSON rules, canonical hash, window,
risk, job plan and approval rules as the AWS manifest, through the shared
submodels. It adds:

- **Environment:**
  - the account and zone (32 hex each);
  - the five Worker script names (`edge`, `api`, `worker`, `runtime`, `jobs`);
  - the Durable Object namespaces;
  - the bootstrap versions an empty-hold release may move from;
  - `bootstrap_control_protocol`.
- **The Worker version-id tuple** the release deploys. No version may repeat a
  bootstrap or rollback version.
- **The container applications:**
  - `durable_object` scheduling;
  - the instance type;
  - SSH and container logs off;
  - each application's exact image keys.
- **Images:** repositories in `registry.cloudflare.com/<account>/`,
  `amd64_digest`, and provenance, SBOM and scan hashes.
- **Storage:** the artifacts and control buckets, and the jurisdiction.
- **Placement regions.**
- **Per-Worker secret names and value digests.** A value never repeats across
  Workers or between a service Worker and the jobs Worker.
- **The operator key id.**
- **The minimum Wrangler version.**
- **Jobs**, each with its image (a migration runs its own database's image;
  grant and proof run the tools image with the
  `sentry.release-tools.job.cloudflare.v1` receipt).
- **A compatible rollback** naming its versions, images and `control_protocol`.

The approval kind is `cloudflare-release-approval`. It binds the manifest hash,
release, environment, account and zone. Each loader refuses the other
platform's documents, and an approval never verifies another platform's
manifest.

## Operations

| Step | What the platform does | Identity and proof |
|---|---|---|
| Quiesce | Stops each live service start by its nonce (`stop-<nonce>`). The stop is accepted from the next release too, by objects that implement `sentry.authority.v1`. Then waits until no start is live and every container application's instance listing is complete and empty. | Object status; an incomplete listing holds `instance_listing_incomplete`; code without the protocol holds `prior_protocol_unsupported` |
| Activate | Deploys a Worker's manifest version at 100%, only from exactly its prior version. The jobs Worker goes before the first job; runtime, API, worker and edge go before the first service start. | A fresh deployment read plus application settings; anything else is `deployment_drift` or `application_drift` |
| Jobs | `POST run` to `job-<release>-<job>` with the launch token as command id | Object id, start nonce, command id, Worker version, image and natural `exit 0`; the job's Cloudflare receipt bound to the same object and nonce |
| Start | `POST start` to `<service>-0`, command id `start-<key>-<release>`, naming the release and version | Object, start nonce, release, version and image; exactly one running instance in the application's listing, the object's own; a healthy probe |
| Worker gate | `POST receipts` pages from a cursor | The unchanged gate; eviction past the cursor, conflicts and refused boots make a read incomplete |
| Operational | The probes' receipts | `{schema, release_id, check_id, status, instances}` bound to the recorded runs |

## Authority

- **Commands are signed.** Every command carries the session and its fence:
  the session's takeover ordinal from the journal. The signed expiry is exactly
  the intent's `command_expires_at`. Nothing is transmitted after
  `min(command_expires_at, deadline_at)`.
- **The objects enforce the authority rules** (`deploy/cloudflare/README.md`):
  - a higher fence supersedes an earlier session;
  - another release may only read or stop the start it names;
  - a start or run happens at most once per command id, and a claim abandoned
    before anything started is dropped;
  - a stop names its start nonce, so it is idempotent by itself. Each journaled
    stop send carries its own command id, so a stop that found its start still
    starting can be sent again.
- **A recovered session waits** until every command an earlier session
  journaled has expired, plus a 30-second allowance, before it sends or decides
  anything.
- **Refusals are classified by their machine code:**
  - `superseded` halts `session_superseded`;
  - `replayed` and `already_run` are observed;
  - definitive refusals hold.
- **Residuals:**
  - If fence evidence is wrong and the prior process is still alive, it can act
    at objects the successor has not reached.
  - A Worker deploy request delivered before its expiry but processed late
    cannot be revoked. The next activation or drift read observes it.

## Validation

```bash
uv run python -m pytest tests/test_release_cloudflare_manifest.py \
  tests/test_cloudflare_control_client.py tests/test_release_cloudflare_controller.py \
  tests/test_release_cloudflare_offline.py tests/test_release_platform_neutral.py \
  tests/test_release_tools_cloudflare.py tests/test_release_r2_offline.py
```

- **Controller matrix:** `tests/test_release_cloudflare_controller.py` runs
  every command through the real signed client into `FakeDOControl`, which
  verifies each signature and applies the object rules. `FakeVersions`,
  `FakeDOControl` and `FakeReceipts` are in `tests/cloudflare_fakes.py`.
- **Offline test:** `tests/test_release_cloudflare_offline.py` runs whole
  releases in a separate interpreter with sockets denied and every Cloudflare,
  Wrangler, AWS and proxy variable poisoned.
- **Signature vectors:** `deploy/cloudflare/worker/test/fixtures/control-vectors.json`
  holds signatures made by the Python client; the TypeScript tests verify them.

## Not implemented

- **Real adapters:** for the Cloudflare API ports (versions, deployments,
  applications, instances, uploads) and the control route transport. They are
  specified in DESIGN §13 (R5): one attempt per call, no retries or proxies,
  transmission only within the command's window.
- **Receipt producers for the migration images.** The JobRunner refuses
  `migrate`. A Cloudflare release therefore holds `launch_failed`, with the
  migration `not_started` and the schema `unchanged`, where AWS would run and
  hold `unknown`.
- **Observers for the Runtime and API operational checks.**
- **Rollback execution and teardown.**
