# Integrated release canary

`tests/release_canary.py`, run by `dev/check_release_canary.py`, drives whole
releases through the operator CLI (`release_cli run` and `recover`) and the real
AWS adapters, with every task a real container. It is a local proof of the
release path end to end. It is not an ECS, Fargate or CloudWatch emulation, and it
makes no AWS request: every CLI call runs under a guard that refuses, records and
fails on any lookup or connection beyond loopback.

## What runs, and through what

| Part | Real | Stand-in |
| --- | --- | --- |
| Operator CLI, controller, adapters, isolated SDK clients | yes | — |
| ECS | — | `tests.release_canary_stack.CanaryEcs`: the controller-test fake's bookkeeping (launch tokens, deployments, task records), with every task backed by a real container (below) |
| Job and observer tasks | the Runtime, Search and release-tools images | started on RunTask with the environment `deploy/aws-platform-fit` renders for the revision; secrets resolved from the canary's custodian values |
| Services | the Runtime, API and worker containers | started by a deployment; the task's ENI address is the container's real address. Local differences from the task definitions: material under `/run/trust` and `/run/tls`; no Runtime probe settings; for the API and worker, static local credentials with metadata disabled, plus the Runtime URL and CA (API, ignored while paused) and an execution-mode setting (worker); a held-open provider stub for the worker instead of the discard port; a 30-second API stop timeout. `HEALTHY` comes from each service's readiness line, not the task definitions' health commands. The observers and the worker gate, not health, prove the services |
| CloudWatch Logs | — | GetLogEvents serves each task's actual output with Docker's timestamps, so receipts and worker readiness receipts are the bytes the producers wrote |
| ECS task metadata | — | a stand-in at `169.254.170.2` returning each task's ARN |
| Databases | two PostgreSQL 16 servers, TLS with SCRAM | an RDS-like administrator per instance: CREATEROLE/CREATEDB, owner of `postgres`, `createrole_self_grant = 'set, inherit'` |
| Journal and lock (S3) | the real store adapter and SDK client | an S3-compatible server on loopback; the client uses path-style addressing |

Job, bootstrap, reconcile and observer containers get exactly the environment
`deploy/aws-platform-fit` renders for them. Init containers are not run. The
harness writes the material their profiles would, as the container suites do; the
init profiles have their own suites. The
manifest's expectations come from the images themselves: the release-tools SQL
digests, the Search schema revision, the Runtime migrations and the AWS-05 image
bindings (index, platform manifest, provenance, SBOM and scan hashes).

## S3 stand-in

Pin it and record it. The canary was run with **moto 5.2.3** in server mode. A
probe with the Search lock's botocore showed it enforces what the journal and lock
rely on:

- `If-None-Match: *` refuses a second create (412);
- `If-Match` refuses a stale replace (412) and a stale delete (412, object kept);
- a current conditional delete removes the object, after which a replace gets 404
  and a fresh create succeeds;
- of 16 concurrent conditional creates, exactly one wins and the rest get 412;
- through the real store adapter, concurrent conditional replaces, concurrent
  conditional deletes, and replaces racing deletes each have exactly one winner;
  stale ETags are refused after the object moves or is deleted; and two racing
  recoveries of a held release leave one owner of both the lock and the journal.

Each run records the stand-in it used in `s3-standin.json` under `--artifacts`.

Real S3 consistency, versioning, `409 ConditionalRequestConflict` timing and
bucket-owner checks are not proven by it.

## Cases

- **First deployment:** bootstrap, migrate, grant and proof for both databases;
  the three services; both observers; the worker readiness gate. It ends
  `held_paused` with the lock released and exactly one task per job and observer.
- **Repeatability:** the same first deployment in two fresh environments. Both
  raw journal chains are validated, and their projections must be identical.
  - **Authority:** each journal's manifest and approval hashes must equal the
    hashes of that run's saved `manifest.json` and `approval.json`. The two runs'
    documents must be identical apart from their wall times.
  - **Replaced in the projection:** only these declared nondeterministic fields:
    - wall times;
    - the store's ETags, and the hash chain over them;
    - the manifest and approval hashes, once checked as above;
    - the worker's boot id, its receipt window and its measured stability;
    - the lock-release request hash, which covers the lock's ETag.
  - **Offsets:** deadlines and token expiries are kept as offsets from their own
    event's issue time.

  Everything else is compared as written: task identities, addresses, launch
  tokens and request hashes, receipt hashes, outcomes, holds, worker-gate resets
  and lock release.
- **Faults**, each of which holds with its designed reason or recovers. A held
  release keeps its lock.
  - **Controller crash** after a launch, then `recover`: `held_paused`, one task
    per job.
  - **Lost RunTask or UpdateService response** (applied, response lost): the
    outcome is reconciled. No intent is a retry; ECS received exactly one RunTask
    per client token and one deploy per service.
  - **Migration killed mid-statement:** blocked on its version table, its backend
    frozen, then killed. It exits 137 with no receipt and holds
    `job_container_failed`, requiring a partial-migration reconcile before a
    rerun; the killed session is gone.
  - **Approval expiring mid-window:** the approval expires while the product
    migration is still inside its statement (blocked and frozen). The release
    holds `approval_expired`. The one StopTask is sent and confirmed, the job
    exits 143 on SIGTERM, its session is gone, and nothing is launched after it.
  - **Wall clock stepping back:** the clock adapter refuses the regression and
    stays untrusted, so the release holds `controller_clock_untrusted`.
  - **Drifted service settings:** `service_settings_drift`, before any deploy.
  - **Worker task dying during the gate:** `task_replaced`.
  - **Forged observer receipt:** appended to the observer's stream, it holds
    `observation_ambiguous`. Substituted for the observer's own receipt with
    another peer address, it holds `operational_peer_mismatch`.
- **Rollback:**
  1. A prior first deployment reaches `held_paused`.
  2. An upgrade to new revisions, with the prior pair as its fallback, deploys
     its services and then holds `observation_ambiguous` on a forged observer
     receipt.
  3. A rollback run takes the failed release's lock by fenced handoff,
     reconciles and proves both schemas, and redeploys the prior revisions.
     Observers and the worker gate pass, and it ends `held_paused`.

  Only reconcile, proof and observer tasks are launched for the rollback run.
  Both pairs run the same images; only their task-definition revisions differ.
  So this proves the handoff, sweep, redeploy and evidence binding, not a binary
  downgrade or an older pair's observer and receipt compatibility.

Each case's journal, CLI reports and every task's output are saved under
`--artifacts`, pass or fail.

## Running it

```bash
python -m venv /path/to/s3-standin && /path/to/s3-standin/bin/pip install 'moto[server]==5.2.3'
/path/to/s3-standin/bin/moto_server -H 127.0.0.1 -p 47902 &
uv run python -m dev.check_release_canary --image-bindings verified-image-bindings.json \
  --s3-endpoint http://127.0.0.1:47902 --s3-standin 'moto 5.2.3' --artifacts canary-evidence
```

The cases need Docker, the images named in the bindings, and the
`169.254.170.0/24` subnet free for one internal network at a time. Each takes a
few minutes.

## Not proven

ECS scheduling, Fargate networking and init ordering, secret injection, awslogs
delivery and ingestion latency, IAM and endpoint policies, RDS's real
administrator, and S3's own conditional semantics are not proven. Neither are the
services' exact task-definition environments and health commands (see the table),
nor a rollback to older binaries. The ECS and
Logs request shapes go through the same offline SDK bridge as the adapter tests.
