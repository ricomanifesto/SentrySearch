# Offline release controller

`release/` models an attended staging release as a strict manifest, a pure state
machine and a journaled controller behind narrow ports. This slice is **offline
only**: there is no AWS adapter, CLI entry point, credential handling or network
code, and nothing here has launched a task, changed a service or read real logs.
It defines and tests the rules a future adapter must satisfy; it is not evidence
that any environment exists or that a release has run.

## Inputs

**Manifest (schema v1).** One immutable candidate, identified by the SHA-256 of
its canonical JSON (sorted keys, compact separators). Parsing rejects duplicate
keys, non-integer numbers, unknown fields and any key containing `override`.
Required content:

- release UUID, environment name, 12-digit account, region, cluster and the three
  service ARNs; milestone fixed to `operational-paused`; named operator;
  validity window of at most seven days, release budget, poll and start budgets;
- Runtime, Search and release-tools source commits; per-image ECR repository,
  index and ARM64 digests, and provenance/SBOM/scan receipt hashes;
- a named risk decision (hash, owner, expiry covering the window) and reviewed
  plan hash;
- private subnets, `assign_public_ip: DISABLED` and Fargate platform >= 1.4.0;
- per service and per job: revisioned task definition, task/execution roles,
  secret ARNs with exact VersionIds, security groups and container-to-image map;
- jobs in fixed order (Runtime/product migrate, grant, proof), each with a
  deadline, stop grace, receipt schema and exact expected receipt fields.
  Migrations state their schema; grants pin SQL source and hash. The Runtime
  grant must match the reviewed `db/roles/service.sql` pin;
- operational checks and a tagged rollback plan: `empty_hold` for a first
  release, or `compatible_release` with the prior release ID, images, task
  definitions, trust hash, compatible schemas and snapshot ARNs.

Every ARN, role, secret, repository and snapshot must belong to the manifest's
account and region. Floating references fail: image tags, unrevisioned task
definitions, staging labels instead of VersionIds, branch names and `LATEST`.
Service secret bundles are pairwise disjoint and owner jobs never reuse one.
Loaded expectations are defensively copied into immutable mappings: editing
an input document or a serialized copy cannot change the approved candidate.

**Approval receipt.** A separate document binding the manifest hash, release,
environment, account, region, milestone and a validity interval that ends no
later than the manifest. There is no approved flag in the manifest. Test receipts
are fixtures, not approvals.

## State machine

```text
prepared -> locked -> quiesced -> migrated -> grants_verified
         -> services_started -> operational_verified -> held_paused
any uncertain or failed step -> hold (reason, last proven state, rollback plan)
```

Steps advance one at a time and only on complete evidence. `held_paused` keeps
API admission paused; nothing in this package enables admission.

## Journal, lock and recovery

The journal is one object advanced by ETag-conditional replacement. Each event
records its sequence and the hash of its predecessor, so a reordered or edited
journal is rejected. Polling is not journaled; intents, observations and
transitions are. Before every forward mutation the controller re-checks approval and
the release window, then appends an intent (request hash, stable token, deadline)
and only then calls the port. A lost CAS race halts before any mutation.

The environment lock is created with create-if-absent semantics and is never
stolen by age. A different session cannot continue a journal. Recovery is an
explicit break-glass call naming the prior session, the exact lock ETag and a hash
of fencing evidence; it transfers the journal and lock without executing anything.
The next run reconciles outstanding intents before any new action. CAS
coordinates cooperative controllers only; it cannot fence a call a stale process
already sent.

If approval or the release window expires, forward progress stops. Cleanup can
still discover already-launched jobs by the recorded token and stop only tasks
whose token and task definition match. It never retries RunTask, mints a token,
starts a service or promotes a result. Failed or empty observations are recorded
as unknown and require operator reconciliation; stopping a process does not
prove that its SQL stopped. A hold retains the lock.

Successful finalization journals the exact lock ETag before deletion and confirms
release afterwards. A crash on either side of deletion resumes only this cleanup,
even after approval expiry. A different session still needs explicit recovery;
a changed or foreign lock is never deleted. The controller returns successful
`held_paused` only after confirming lock release. A persisted terminal transition
without that observation is incomplete finalization, not an operator success receipt.

## Launch and job completion

Each job launches with `count=1`, the exact task definition, fixed private
networking, Exec disabled, release/job tags and a stable `clientToken` that is
also `startedBy`. There are no overrides. Launch failures, a partial response or
more than one task hold.

After a crash or ambiguous response the controller looks for the task by token.
Only inside the job's deadline and token lifetime (the shorter of 24 hours or
task lifetime plus one hour) does it resend the identical request with the same
token. Otherwise an unseen launch is `launch_outcome_unknown`: an empty,
eventually consistent listing is not proof that nothing ran.

A job succeeds only when its task is `STOPPED` with
`EssentialContainerExited`, the expected task definition, token, container set
and image digests, integer exit code 0 for every container including init, and an
exact sanitized receipt for the same release, job and task. The fixed receipt
envelope contains `schema`, `release_id`, `job_id`, `task_arn`, `status` and
`result`. Its schema is the receipt version; `result.schema` is the migrated
database revision. Manifest expectations cannot replace envelope identity or
control fields. Legacy flat receipts are rejected.

The complete stopped-task evidence and receipt must be observed **before** the
recorded job deadline. These ports do not supply trusted completion timestamps,
so recovery after the deadline holds conservatively even when the task might
have finished earlier. A slow receipt read cannot extend the budget. At the
deadline a live or unseen known task receives a journaled stop and bounded
confirmation; an already stopped task needs no redundant stop. Both paths record
`sql_outcome: unknown` and hold. A waiter return or stopped client alone never
proves success or SQL cancellation. Missing receipts exhaust the same deadline.

## Services and operational evidence

Writers are scaled to zero (journaled) and must drain, and no other task may
remain in the cluster. Services then start in order (Runtime, API, worker) with
a forced new deployment and the deployment circuit breaker enabled but automatic
rollback disabled. A service is ready only when exactly one healthy running task
of that new deployment exists, with exact definition and digests. Tasks from an
older deployment of the same revision never count. Count drift, a failed or
superseded deployment, or timeout holds.

Operational receipts must pass and bind the recorded task ARNs. The task set is
enumerated again before and after the checks; a replacement holds because it
needs a fresh observation window.

## Holds and rollback planning

A hold keeps the lock and records a rollback plan, which is never executed
automatically. For `empty_hold` the plan keeps or returns services to zero and
preserves resources and evidence. Migration outcomes are classified per database:
a successful job proves its schema, an unlaunched job leaves it unchanged, and
any job that ran or may have run without success is `unknown`, because a failed
exit does not prove the SQL rolled back. `compatible_release` plans start the
prior pair only when every actual schema is known and compatible; unknown state
requires reconciliation and incompatible state requires repair forward or
restore into isolated copies.

## Validation

```bash
uv run python -m pytest tests/test_release_manifest.py tests/test_release_machine.py \
  tests/test_release_controller.py tests/test_release_offline.py
```

Fakes in `tests/release_fakes.py` reproduce ECS response shapes, client-token
idempotency, delayed visibility, crashes before and after requests, ambiguous
transport and conditional object writes with a deterministic clock and tokens.
`tests/test_release_offline.py` runs complete releases in a separate interpreter
with poisoned AWS variables and all socket connections denied, and checks that no
AWS SDK or HTTP client module is imported. The fakes do not model IAM, networking,
scheduling or real log ingestion.

## Not implemented

- An AWS adapter, pagination-complete listing, receipt collection from logs and
  an operator CLI.
- Fixed per-job deadline guards in images, a release-tools image, the product
  grant script, bootstrap jobs and session-identity reconciliation jobs.
- Supervisor-emitted worker readiness receipts and the readiness-window observer.
- Rollback execution and teardown.

These remain separate implementation and approval gates. See
[`deploy/aws-platform-fit`](../deploy/aws-platform-fit/README.md) for the owner
task definitions that the manifest references.

## Infrastructure boundary

The mock-tested [staging roots](../deploy/aws-staging/README.md) declare the
environment this controller would operate. Terraform creates the three services at
desired count zero and ignores only their task definition and desired count,
which this controller changes. Its deploy request also re-sends Exec disabled and
the circuit breaker without rollback, matching Terraform's settings. The roots'
unattached launcher policies allow each `EcsPort` call for the definitions that
exist: deploys must name a retained revision of that service, scale-to-zero
requests carry no task definition, only the current release's owner jobs run and
only job-tagged tasks can be stopped. Grant and proof job definitions and the
log reads behind receipt collection do not exist yet, so no release can complete.
The manifest's environment name must equal the roots' `name_prefix` so the lock
key matches the release-evidence policy. These roots are not applied, and mocked
plans do not prove IAM behavior.
