# Offline release controller

`release/` models an attended staging release as a strict manifest, a pure state
machine and a journaled controller behind narrow ports. This slice is **offline
only**: there is no AWS adapter, CLI entry point, credential handling or network
code, and nothing here has launched a task, changed a service or read real logs.
It defines and tests the rules a future adapter must satisfy; it is not evidence
that any environment exists or that a release has run.

The controller's object store has an offline Cloudflare R2 implementation in
`release_cloudflare/`, described in
[the R2 control store](release-cloudflare-r2-store.md), and the controller runs
on Cloudflare through `CloudflarePlatform`, described in
[the Cloudflare release controller](release-cloudflare.md).

## Platform strategy

The controller drives one provider-neutral strategy, `ReleasePlatform`
(`release/ports.py`). The controller owns everything that decides safety:
- the journal, lock and recovery;
- guards, approval and window;
- deadlines, identical-retry limits and visibility polls;
- reconciliation order, the readiness gate, holds and finalization.

A platform only:
- builds requests that can be rebuilt from the recorded intent;
- sends them;
- classifies what it observes.

`EcsPlatform` (`release/controller.py`) is the ECS code that ran before the
extraction, moved without behavior change. The existing `ecs=`, `evidence=` and
`logs=` constructor keywords build it, and its journal names (`run_task`,
`update_service`, `task_arn`, `deployment_id`, …) are the historical ones. A
recorded trace of every call the AWS release tests make on the store, ECS,
evidence, logs and clock ports is identical before and after the extraction.

A different platform is passed as `platform=`. It uses its own journal names, so
no value of one platform is written under another platform's field. The flow
gives it hooks that do nothing on ECS:
- **A session authority** (`SessionAuthority`), derived from the journal:
  - the fence is the session's takeover ordinal, 1 plus the number of
    `recovered` events, each appended by journal CAS while the exact lock is
    transferred;
  - a recovered session sends nothing until every command an earlier session
    journaled (`command_expires_at`) has expired, plus a 30 s clock allowance.
- **Command intent fields** (`command_fields`), written on every command
  intent.
- **Staged activation**, for platforms whose release code is made current
  separately: stage `jobs` before the first job and stage `services` before
  the first service start. A hold after any activation plans
  `restore_prior_platform_versions` first. Only an exact prior state may be moved forward.
  Each reply is screened for drift, and recognition comes from a fresh
  observation.
- **Drift checks:**
  - before a forward deployment is recognized;
  - before every forward send and identical resend, on a fresh observation;
  - on every forward resend's reply, which is never discarded.
- **`PlatformHold(code)`**, which holds, and **`SessionSuperseded`**, which
  halts `session_superseded` without writing again.

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
- grant and proof jobs run only the [release-tools](release-tools.md) image
  (besides init), use receipt schema `sentry.release-tools.job.v1` and job ids
  `<database>-<phase>`, and expect exactly the keys the tools report: grants
  `database`, `principal`, `service_role` and `sql_digest` (equal to the SQL pin),
  proofs `database`, `principal` and `schema`. The product grant is
  `release_tools/sql/product/grants.sql` from the release-tools source, which
  must equal the Search source. Per database, the grant's identity matches the
  migration's, its service role is the proof's principal and the proof's schema
  equals the migrated schema;
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

### Worker readiness gate

The manifest must include the `worker-readiness` check with receipt schema
`sentry.worker-readiness.v1`, no other check may use that schema, and the worker
service's application container must be the Search image named `app`. The
controller proves this check itself from the worker supervisor's own
[readiness receipts](runtime-consistency.md#readiness-receipts) through
`LogPort` (GetLogEvents); Runtime and API checks still use `EvidencePort`.

Identity comes from ECS, never from the worker: the recorded deployment and task,
whose revision and image digests are checked again on every poll, and the fixed
stream `/<environment>/worker`, `worker/<release-id>/app/<task-id>`, derived from
the approved manifest's release id and that task.
The proposed policy (`release.readiness.GatePolicy`), not measured AWS guarantees:

- Each attempt is a new epoch: receipts observed before it never count, and a
  window starts only with a receipt observed more than 5 s (the allowed worker
  clock skew) after it. The gate ends within 600 seconds and the release window;
  a resumed attempt keeps the first attempt's deadline.
- Pass: 60 seconds of consecutive eligible receipts from one boot (alive, ready,
  not draining, no error, a working phase within its budget), measured by both
  the worker's wall clock and its monotonic uptime, adjacent samples at most 15 s
  apart, the last no more than 30 s old by observation time and none more than
  5 s in the future. Every recorded service is enumerated again immediately
  before success, after which the deadline and freshness are checked again. The
  journal records the boot, first and last sequence, stable seconds and the last
  reset reason.
- Reset: a negative or malformed receipt of any shape, a gap, reordering, a
  conflicting replay, a new boot, another release, a future receipt or a clock
  anomaly (time running backwards, or monotonic and wall intervals differing by
  more than 5 s; equal times from a burst of transitions are allowed). Identical
  replays are ignored; past 8,192 distinct receipts a replay resets instead.
- Clear: freshness expiry, a denied, missing or malformed log read, incomplete
  pagination, or ECS health or visibility loss. A clear is dated when the failed
  read returns or ECS was observed, so time spent in a slow failed read never
  counts. A new window needs receipts observed more than 5 s after the clear,
  even when late receipts carry consecutive sequences.
- Reads follow forward tokens from the gate's start to `endTime` = now, at most
  20 pages of 100 events and 1 MiB per poll. A page that returns the caller's own
  token ends the stream; empty pages with a new token do not. Sustained worker
  output above those limits per poll can never pass and holds; worker
  application log volume is unmeasured.
- Hold at once: a failed or superseded deployment, definition or image mismatch,
  a desired count other than one, an extra task, or replacement of the recorded
  task. `controller_clock_rollback` holds when controller time moves backwards,
  against any time already in the journal or within the gate, because deadlines and
  freshness depend on it (see the `Clock` port contract). At the deadline the hold
  is `worker_readiness_not_proven`, with the last reason and receipt count
  journaled.

Success is a bounded observation, not continuing readiness, report completion,
auth or S3 proof, nor proof against a compromised worker. Final readiness and
canary checks remain before any later, separately approved admission change.

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
  tests/test_release_controller.py tests/test_release_offline.py \
  tests/test_release_readiness.py tests/test_worker_readiness_receipts.py \
  tests/test_release_platform_neutral.py
```

`tests/test_release_platform_neutral.py` covers:
- both constructor forms;
- the core's import boundary (no cloud SDK, network or Cloudflare module);
- a rollback plan that depends on the rollback's kind;
- the fence and quiet period after a recovery;
- platform holds and a superseded session.

Fakes in `tests/release_fakes.py` reproduce ECS response shapes, client-token
idempotency, delayed visibility, crashes before and after requests, ambiguous
transport and conditional object writes with a deterministic clock and tokens.
`FakeLogs` pages worker receipts for the observed task's stream and can drop,
edit, duplicate, reorder, delay or stall them, deny reads or never complete.
`tests/test_release_offline.py` runs complete releases in a separate interpreter
with poisoned AWS variables and all socket connections denied, and checks that no
AWS SDK or HTTP client module is imported. The fakes do not model IAM, networking,
scheduling or real log ingestion.

## Not implemented

- An AWS adapter, pagination-complete listing, receipt collection from logs and
  an operator CLI. The adapter must read only the observed task's stream and parse
  it with `release_tools.receipt.extract_receipt`, reporting an ambiguous stream
  as `AmbiguousResponse`. Its `LogPort` must read forward from the head
  (`startFromHead=true`; the API default reads the tail), pass bounds and forward
  tokens through unchanged and never page internally. How GetLogEvents tokens
  behave as `endTime` advances is unverified.
- RunTask override checking beyond the exact request the controller builds.
- In-image deadline guards and receipt producers for the two migration images,
  and wiring of the bootstrap job (the grant, proof and reconciliation jobs are
  [implemented](release-tools.md) and mock-wired).
- Observers for the Runtime and API operational checks.
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
requests carry no task definition, only the current release's jobs (migrations,
grants, proofs and reconciliation) run, only job-tagged tasks can be stopped and
receipts are read only from those jobs' and the current release's worker
app-container log streams. Those worker streams also carry all of the current
release's worker application output, so the read widens the release/app
boundary: Michael must choose attended whole-release log access or a separate
sanitized receipt destination before the policies are attached. Each worker
revision fixes its release's `SENTRYSEARCH_RELEASE_ID`, its
`worker/<release-id>` stream prefix and non-blocking logging. A release still cannot complete: there is no AWS adapter or
log reader, the migration images emit no receipts and the Runtime and API
operational observers do not exist.
The manifest's environment name must equal the roots' `name_prefix` so the lock
key matches the release-evidence policy. These roots are not applied, and mocked
plans do not prove IAM behavior.
