# Integrated release canary

`tests/release_canary.py`, run by `dev/check_release_canary.py`, drives whole
releases through the operator CLI (`release_cli run` and `recover`) and the real
AWS adapters, with every task a real container. It is a local proof of the
release path end to end. It is not an ECS, Fargate or CloudWatch emulation, and it
makes no AWS request.

## What runs, and through what

| Part | Real | Stand-in |
| --- | --- | --- |
| Operator CLI, controller, adapters, isolated SDK clients | yes | — |
| ECS | — | `tests.release_canary_stack.CanaryEcs`: the controller-test fake's bookkeeping (launch tokens, deployments, task records), with every task backed by a real container (below) |
| Job and observer tasks | the Runtime, Search and release-tools images | started on RunTask with the environment `deploy/aws-platform-fit` renders for the revision; secrets resolved from the canary's custodian values |
| Services | the Runtime, API and worker containers | started by a deployment; the task's ENI address is the container's real address |
| CloudWatch Logs | — | GetLogEvents serves each task's actual output with Docker's timestamps, so receipts and worker readiness receipts are the bytes the producers wrote |
| ECS task metadata | — | a stand-in at `169.254.170.2` returning each task's ARN |
| Databases | two PostgreSQL 16 servers, TLS with SCRAM | an RDS-like administrator per instance: CREATEROLE/CREATEDB, owner of `postgres`, `createrole_self_grant = 'set, inherit'` |
| Journal and lock (S3) | the real store adapter and SDK client | an S3-compatible server on loopback; the client uses path-style addressing |

Init containers are not run. The harness writes the material their profiles
would, as the container suites do; the init profiles have their own suites. The
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
- of 16 concurrent conditional creates, exactly one wins and the rest get 412.

Real S3 consistency, versioning, `409 ConditionalRequestConflict` timing and
bucket-owner checks are not proven by it.

## Cases

- **First deployment:** bootstrap, migrate, grant and proof for both databases;
  the three services; both observers; the worker readiness gate. It ends
  `held_paused` with the lock released and exactly one task per job and observer.
- **Repeatability:** the same first deployment in two fresh environments. Both
  raw journal chains are validated, and their projections must be identical.
  The projection replaces only these declared nondeterministic fields:
  - wall times, and the hash chain and manifest and approval hashes that cover
    them;
  - the worker's boot id, its receipt window and its measured stability.

  Task identities, addresses, launch tokens, receipt hashes, outcomes, holds and
  lock release are compared as written.
- **Faults**, each of which holds with its designed reason or recovers:
  - a controller crash after a launch, then `recover`: `held_paused`, one task
    per job;
  - a lost RunTask or UpdateService response (applied, response lost):
    reconciled, never sent twice;
  - a migration killed mid-statement while blocked on its version table:
    `job_container_failed`, with a partial-migration reconcile required before a
    rerun, and the killed session gone;
  - approval expiring mid-window: `approval_expired`, with the release's own jobs
    stopped;
  - the wall clock stepping back: `controller_clock_untrusted` (the clock adapter
    is anchored to the monotonic clock and refuses the divergence);
  - drifted service settings: `service_settings_drift`, before any deploy;
  - the worker task dying during the gate: `task_replaced`;
  - a forged observer receipt: appended to the observer's stream,
    `observation_ambiguous`; substituted for the observer's own receipt with
    another peer address, `operational_peer_mismatch`.
- **Rollback:**
  1. A prior first deployment reaches `held_paused`.
  2. An upgrade to new revisions, with the prior pair as its fallback, deploys
     its services and then holds on a forged observer receipt.
  3. A rollback run takes the failed release's lock by fenced handoff,
     reconciles and proves both schemas, and redeploys the prior revisions.
     Observers and the worker gate pass, and it ends `held_paused`.

  Only reconcile, proof and observer tasks are launched for the rollback run.

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
administrator, and S3's own conditional semantics are not proven. The ECS and
Logs request shapes go through the same offline SDK bridge as the adapter tests.
