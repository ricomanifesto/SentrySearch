# Offline release controller

`release/` models an attended staging release as a strict manifest, a pure state
machine and a journaled controller behind narrow ports. It contains no SDK,
credential or network code. `release_aws/` adapts those ports to injected AWS SDK
clients ([adapters](release-aws-adapters.md)), tested only against stubs. The
[operator CLI](release-cli.md) is the only composition root: it reads the
custodian's session file, builds isolated clients, proves the operator identity
and Clock reference, then runs the controller. Nothing here has launched a task,
changed a service or read real logs. None of this is evidence that any
environment exists or that a release has run.

## Inputs

**Manifest (schema 2; schema 1 is read-only history).** One immutable candidate,
identified by the SHA-256 of its canonical JSON (sorted keys, compact
separators). Parsing rejects duplicate keys, non-integer numbers, unknown fields
and any key containing `override`.

- **Schema 2** is the format described below and the only one executed. It
  requires an explicit execution `purpose` and the approved `operator_role` (an
  IAM role in the manifest account that the operator's session must have
  assumed; the [CLI](release-cli.md) binds the caller to it).
- **Schema 1** is the earlier accepted format, kept exactly as it was accepted
  in `release/manifest_v1.py`: its own models, constants and rules, which newer
  rules never touch. A schema-1 manifest that was valid then loads now with the
  same hash, and matches its approval offline. It has no `purpose` or
  `operator_role` key (not even as null), its operational checks are plain
  receipt names and not observer tasks, and its migration jobs use their
  original receipt schemas. It always meant a forward run. It is never
  converted and never executed: the controller halts with
  `manifest_schema_not_executable`, and the CLI refuses it with
  `operator_role_unapproved` before reading any credentials. Running an old
  release again needs a new schema-2 manifest and a new approval.
  `tests/fixtures/release-manifest-schema-1.json` and its `-upgrade` variant
  are accepted manifests in canonical encoding; each file's own SHA-256 is the
  hash it was approved under.

Required content (schema 2):

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
  Migrations use the shared migration envelope `sentry.release-migration.v1`
  (written by the Runtime `migrate -release-job` and the Search
  `dev/migrate_storage.py --release-job`), ids `<database>-migrate` and expect
  exactly `database`, `principal` and `schema`. Every job id is the one its task
  definition fixes and fits the producers' `release:<release>:<id>` session name; grants pin SQL source and hash. The Runtime grant
  must match the reviewed `db/roles/service.sql` pin;
- grant and proof jobs run only the [release-tools](release-tools.md) image
  (besides init), use receipt schema `sentry.release-tools.job.v1` and job ids
  `<database>-<phase>`, and expect exactly the keys the tools report: grants
  `database`, `principal`, `service_role` and `sql_digest` (equal to the SQL pin),
  proofs `database`, `principal` and `schema`. The product grant is
  `release_tools/sql/product/grants.sql` from the release-tools source, which
  must equal the Search source. Per database, the grant's identity matches the
  migration's, its service role is the proof's principal and the proof's schema
  equals the migrated schema;
- operational checks: `worker-readiness` (schema `sentry.worker-readiness.v1`,
  proven from the worker's own receipts) and exactly one observer each for the
  Runtime and the API (schema `sentry.operational.v1`), with check ids
  `runtime-observe` and `api-observe` (the ids their task definitions fix). The
  Runtime observer is its own release-tools task (`init` from the Search image,
  `observer` from the release-tools image) whose material is shared with no
  service, job or other observer; the API observer is a single `observer`
  container with no secret and no task role. Each targets the service's private
  name `<target>.<namespace>` (one namespace for both) and fixed port (Runtime
  8443, API 8001), with its own deadline (60 s to one hour) and stop grace.
  Check ids never repeat a job id;
- a tagged rollback plan: `empty_hold` for a first
  release, or `compatible_release` with the prior release ID, images, task
  definitions, trust hash, compatible schemas and snapshot ARNs. This is the
  fallback after a failure, never the run's direction: a forward upgrade with a
  `compatible_release` fallback still migrates.

Schema 2 purposes:

- `{"kind": "forward"}`: the job plan above, optionally preceded by one
  `bootstrap` job per database (Runtime, then product) **only** when the
  fallback is `empty_hold`. A bootstrap job runs the release-tools image with
  id `<database>-bootstrap`, the tools receipt schema and exactly the keys
  `database`, `principal` (the instance administrator), `owner_role` and
  `service_role`. It creates exactly the migration owner and the grant's service
  login on the migrated database, and the administrator is neither of them. It
  names the bundles its Terraform task reads: exactly one RDS-managed
  administrator secret (`rds!db-<instance uuid>`, a name only a bootstrap job
  may use), its bootstrap credentials and its own CA bundle. No service and no
  other job may name any of them. Bootstrap jobs run first, inside the
  `migrated` step.
- `{"kind": "rollback", "failed_release_id", "failed_services", "actual_schemas"}`:
  restore the retained prior pair after a failed release. `failed_services`
  names the Runtime, API and worker task definitions the failed release may have
  deployed, each in the prior service's family. Jobs are exactly `reconcile` then
  `proof` for each database (no migrate, grant or bootstrap). The fallback must be
  `compatible_release`; the manifest's services and Runtime/Search images must
  be that prior release's; the failed release is neither this release nor the
  prior one; both actual schemas are stated and compatible with the prior pair;
  reconcile jobs (owner credentials, never a service bundle) must observe exactly
  those schemas with `release_sessions` and `owner_sessions` of `0`, and proofs
  the same schemas. See [Rollback runs](#rollback-runs).

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
and only then calls the port. A lost CAS race halts before any mutation. The
append and any read that decided it take time, so immediately before each send
(job launch, forward deploy, scale-to-zero, and each identical resend of one) the
controller checks approval and the window again, and with them a launch's
original job deadline and token lifetime or a deploy's original service-start
deadline. Reaching any of these, equality included, holds without sending:
`approval_expired`, `release_window_exceeded`, `launch_outcome_unknown` or
`service_update_unconfirmed`. The journaled intent stays outstanding, so the hold
and its rollback plan count it as possibly sent. Stops of the release's own jobs
and lock release are safety actions: they stay authorized after expiry and are
not gated this way.

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

**Operator abort.** `abort` (the CLI's `cleanup`) stops only this release's own
unfinished job tasks, exactly as expiry cleanup does, then holds with
`operator_abort`. It needs this session's lock (after `recover` for a lost
session) but no current approval, and never launches, deploys or scales. A
finished `held_paused` release is left unchanged.

**Clock trust.** If the Clock raises `ClockUntrusted` before a journal exists,
the run halts (`controller_clock_untrusted`) without writing. Afterwards the
controller latches (it never reads that Clock again) and holds with that reason.
Only safety events (the hold transition, observations and `guard=False` stop or
lock-release intents) are journaled without the Clock, at the latest time already
recorded and marked `clock_untrusted`. Forward intents, every other transition
and session events need the Clock, so a loss even between a guard and its journal
timestamp holds. A restarted or recovered controller whose Clock reads earlier
than the latest journal event holds with `controller_clock_rollback` before
reconciling.

## Launch and job completion

Each job launches with `count=1`, the exact task definition, fixed private
networking, Exec disabled, release/job tags and a stable `clientToken` that is
also `startedBy`. There are no overrides. Each of these holds:
- a launch failure, a partial response or more than one task;
- a task with another definition or token;
- a task that ECS reports with any override or with Exec enabled.

A job whose launch was refused this way is never launched again, even if its
hold was never journaled. A refused task still running under the release's own
token receives a journaled stop rather than continuing under the job's role.

After a crash or ambiguous response the controller looks for the task by token.
A task found that way is described and verified like a direct launch. Only
inside the job's deadline and token lifetime (the shorter of 24 hours or task
lifetime plus one hour) does it resend the identical request with the same
token, and only if both still hold after the resend's intent is journaled.
Otherwise an unseen launch is `launch_outcome_unknown`: an empty,
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

Writers are scaled to zero (journaled) and must drain. Every task in the cluster
that has not finished stopping must then stop before any job runs. One that ECS
still intends to run is an unaccounted writer and holds
(`standalone_writer_present`). Services then start in order (Runtime, API, worker) with
a forced new deployment. The deploy request carries only the controller-owned
fields: cluster, service, task definition, desired count one and the forced
deployment. Terraform alone writes every deployment setting. The controller holds
with `service_settings_drift` unless ECS reports exactly Terraform's values. Before
a forward action the values are checked for every described service, not only the
one being deployed:
- before each deploy;
- on every forward deploy response, the first request's and each identical
  resend's, so a drifted response is neither recognized nor reconciled; once
  that hold is journaled, a later clean read cannot undo it;
- after a lost or crashed deploy, on every observation while the update is
  reconciled and again just before any identical resend, whether or not the
  lost request was applied;
- on every later observation of a started service (that service only; drift elsewhere
  holds at the next forward action or recorded-task check).

A lost or crashed deploy is resent only as the identical request, journaled with
the original deadline and `retry_of`, at most three times per reconciliation;
each authorized recovery reconciles again within the same original deadline. No
forward deploy, first or resent, is sent at or after its recorded service-start
deadline: the deadline is checked after its intent is journaled (with approval
and the window), and for a resend also after the read that decides it.
Otherwise the update holds with `service_update_unconfirmed`. Scale-to-zero
sends, first or resent, keep only the approval and window checks: quiescing
acquires no service-start deadline or settings check.

The values are:
- minimum healthy 0% and maximum 100% (no overlap);
- the circuit breaker enabled with rollback disabled (no automatic return to a
  binary that may not match migrated schemas);
- no alarm rollback;
- the rolling strategy;
- the ECS deployment controller;
- Exec disabled.

A missing value counts as drift. Reconciling a scale-to-zero update is never
blocked by drift: it is the safe direction. A service is ready only when exactly one healthy running task
of that new deployment exists, with exact definition and digests, and that
observation completes before the service's start deadline. Tasks from an older
deployment of the same revision never count. Count drift, a failed or superseded
deployment, or timeout holds.

The task set is enumerated before the checks. Each observer, Runtime then API,
launches like a job (journaled intent, send authorization, exact definition,
token, no overrides, Exec disabled) against the services as recorded; the worker
gate (below) follows:

- Before the launch the recorded service task must report exactly one complete
  attached ENI: one interface id, one subnet among the manifest's subnets and one
  private IPv4 address. Anything less is `service_network_identity_unknown`; the
  run holds and no observer is launched.
- The observer task must stop with the platform evidence a job needs (exact
  definition, token, containers and digests, every exit code 0); a failed or
  unfinished observer holds with the job codes (`job_container_failed`,
  `job_exit_missing`) and its stream is not read.
- Its receipt is read only from that task's own stream and must be exactly the
  `operational` envelope for this release, this check and this observer task,
  `passed`, naming the approved target, host and port, the fixed checks and
  denials for its target and the one address it connected to. Anything else is
  `operational_receipt_mismatch`.
- That address must equal the recorded service task's ENI address; DNS that
  answered from another task is `operational_peer_mismatch`.
- Every recorded service is enumerated again and the target's address re-read
  after the receipt; a replacement holds with `task_replaced` because it needs a
  fresh observation.
- The receipt must be observed before the observer's deadline. At the deadline a
  live observer receives a journaled stop; the check holds with
  `operational_deadline_exceeded`. Observer stops carry no SQL outcome.

The pass records the receipt hash, the peer and the service task. All services
are enumerated once more immediately before `operational_verified`. A recovered
run keeps observer passes already journaled and re-proves the worker gate in a
new epoch.

### Worker readiness gate

The manifest must include the `worker-readiness` check with receipt schema
`sentry.worker-readiness.v1`, no other check may use that schema, and the worker
service's application container must be the Search image named `app`. The
controller proves this check itself from the worker supervisor's own
[readiness receipts](runtime-consistency.md#readiness-receipts) through
`LogPort` (GetLogEvents); Runtime and API observer receipts use `EvidencePort`.

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
exit does not prove the SQL rolled back. A bootstrap job that may have run adds
`reconcile_bootstrap_before_rerun`. `compatible_release` plans start the
prior pair only when every actual schema is known and compatible; unknown state
requires reconciliation and incompatible state requires repair forward or
restore into isolated copies.

## Validation

```bash
uv run python -m pytest tests/test_release_manifest.py tests/test_release_machine.py \
  tests/test_release_controller.py tests/test_release_offline.py \
  tests/test_release_readiness.py tests/test_worker_readiness_receipts.py
```

Fakes in `tests/release_fakes.py` reproduce ECS response shapes, client-token
idempotency, delayed visibility, crashes before and after requests, ambiguous
transport and conditional object writes with a deterministic clock and tokens.
`FakeLogs` pages worker receipts for the observed task's stream and can drop,
edit, duplicate, reorder, delay or stall them, deny reads or never complete.
`tests/test_release_offline.py` runs complete releases in a separate interpreter
with poisoned AWS variables and all socket connections denied, and checks that no
AWS SDK or HTTP client module is imported. The fakes do not model IAM, networking,
scheduling or real log ingestion.

## Rollback runs

A `rollback` purpose restores the retained prior pair after a failed release. It
is its own manifest and approval with its own release ID; it is never automatic.

- **Evidence identity.** The run executes the prior release's own revisions
  (services, reconcile, proof and observer tasks), and each revision fixes its
  release's ID. Every receipt and the worker readiness stream therefore name the
  prior release (`Manifest.evidence_release_id`); a receipt naming the rollback
  run itself is a mismatch. The run's own ID names its journal, lock, approval
  and launch tags.
- **Failed-release handoff.** The run first reads the failed release's journal,
  which must name that release and this environment, otherwise
  `failed_release_unknown`.
  - If the failed release still holds the lock, it moves only by a conditional
    replace of the exact ETag. That needs a handoff naming the failed journal's
    session, that ETag, fence evidence that the old operator session was stopped,
    and who decided; anything less is `handoff_refused` and nothing is written.
  - The handoff is journaled as an intent before the replace. Approval and the
    release window are checked again after that write: a lapse holds with the
    intent outstanding and the lock unmoved. A lock moved by someone else first
    is `handoff_conflict`.
  - After a crash the run settles the intent from the lock it finds:
    - its own lock: `lock_handed_off`, reconciled;
    - the failed lock untouched at the authorized ETag: `handoff_not_applied`,
      after which the same conditional handoff is sent again;
    - anything else: `handoff_conflict`.

    A lost response within the same step holds with `handoff_unconfirmed` unless
    the lock is already the run's.
  - A lock held by any other release is `environment_locked`. A missing lock is
    accepted only when the failed journal recorded its own lock release;
    otherwise `failed_release_lock_missing`.
- **Sweep.** Under the moved lock, before anything else, every launch the failed
  release journaled is accounted for by positive evidence. A launch is one
  token; a retry reuses it.
  - Its tasks are the ones the failed release recorded for it (`launched`,
    `launched_multiple`, `launched_unexpected`) and the ones ECS lists under the
    token. Each task ECS describes must carry that token; one not yet stopped
    gets a journaled safety stop and bounded confirmation (`sql_outcome:
    unknown`).
  - A recorded task that ECS no longer describes counts only if the failed
    release itself recorded seeing it stopped (a job or observer outcome, a
    confirmed stop, or a cleanup that found it stopped). ECS forgets stopped
    tasks; that record does not expire.
  - A launch the provider refused, on record (`launch_failed`), has no task.
  - Everything else is unknown and holds with `failed_release_unreconciled`
    before any reconcile or proof job or service start: a launch whose outcome
    was never learned and for which no task is found, a task that cannot be
    described or does not carry its token, a stop that cannot be confirmed, or a
    journal whose launch records are unclear. The open items are journaled as
    `failed_launches_unresolved`, each with the release, job, token and reason.
    An empty listing, however often repeated, is never evidence that an accepted
    launch has no task: the task may not be listed yet and can still connect and
    write inside its revision's fixed deadline. Tasks that were found are still
    stopped before the hold.

  A stop left outstanding by a crash is sent again, identically, and confirmed
  before anything else, but only while the run still holds its own lock;
  otherwise it holds with `lock_not_held` and sends nothing. The run records the
  failed journal's hash.
- **A rollback of a held rollback.** A rollback run records which release it is
  taking over from (`failed_release_named`) before the lock moves, and
  `failed_release_reconciled` only once the sweep above is complete. A run that
  held in between still owns the lock, so the next attempt names it as the
  failed release. That attempt inherits the open reconciliation: it sweeps the
  held run's own launches and then, from their own journals, the launches of
  each earlier release whose reconciliation was never recorded as complete
  (at most four such releases; a longer chain, a cycle or an unreadable journal
  is `failed_release_unknown`). The earlier journals' hashes are recorded as
  `predecessors`. An unknown launch therefore stays unknown for every later
  attempt until its task is found and stopped; the controller offers no other
  way to clear it, and the operator's own evidence that a request never reached
  ECS is a separate, unimplemented decision.
- **Sequence.** `prepared → locked → quiesced → reconciled → proven →
  services_started → operational_verified → held_paused`: quiesce writers,
  where each service may run the prior revision or its stated failed revision
  (any other is `rollback_service_revision_unknown`);
  reconcile jobs must report exactly the stated schemas with no release or owner
  session left; proof jobs prove the same schemas; the prior pair starts in order;
  both observers and the worker gate run as in a forward release; the lock is
  released at `held_paused`. A migration, grant or bootstrap is never launched.
- **Holds.** A held rollback plans `rollback_hold`: services to zero if started,
  evidence retained, operator review before any retry. Nothing is retried
  automatically. `abort` and `recover` work as for any release. A rollback
  session lost before its handoff never held a lock: `recover` names the failed
  release's lock at its exact ETag and, while the run is still `prepared`,
  leaves it in place; the next `run` hands it off under its own fenced handoff.

**Terraform scope.** The attended launcher may launch only the current
release's revisions, so the operator re-plans the releases root with the prior
release as `current` before a rollback run. That release's job revisions keep
the deadline fixed when it was first planned: a rollback after it expires holds
at its first job, and needs a new release key planned from the prior pair's
images, a separate approval.

## Not implemented

- Any run against AWS. The [operator CLI](release-cli.md), its isolated clients,
  preflight and Clock, and the [adapters](release-aws-adapters.md) have run
  against in-process fakes, and against real containers in the
  [integrated canary](release-canary.md). The canary runs first deployments,
  faults and a rollback run with the real job, observer and service images, the
  journal and lock in an S3-compatible stand-in. Their AWS behavior (IAM,
  `GetLogEvents` tokens as `endTime` advances, stopped-task listing, reported
  overrides, S3's own conditional semantics, the STS `Date` header) is unverified.
- Published images. The local images carry the migration release jobs and the
  observers, and their container suites, scans and SBOMs are recorded: Search and
  release-tools from AWS-05, and the Runtime as rebuilt with Go 1.26.9 in AWS-06.
  No image is in a registry. Their task definitions, log group and launcher policies
  are mock-tested Terraform.
- The live bootstrap administrator path: its task definitions and separate
  launcher exist in mocked Terraform, never attached.
- Teardown, which is a documented operator procedure, not code; a rollback run
  against a real retained pair.

These remain separate implementation and approval gates. See
[`deploy/aws-platform-fit`](../deploy/aws-platform-fit/README.md) for the owner
task definitions that the manifest references.

## Infrastructure boundary

The mock-tested [staging roots](../deploy/aws-staging/README.md) declare the
environment this controller would operate. Terraform creates the three services at
desired count zero and ignores only their task definition and desired count,
which this controller changes. Deployment settings and Exec have one owner,
Terraform: the controller never sends them (a partial `deploymentConfiguration`
could reset the omitted percentages), and it verifies them instead. The roots'
unattached launcher policies allow each `EcsPort` call for the definitions that
exist: deploys must name a retained revision of that service, scale-to-zero
requests carry no task definition, only the current release's jobs (migrations,
grants, proofs and reconciliation) run, only job-tagged tasks can be stopped and
receipts are read only from those jobs' and the current release's worker
app-container log streams. Those worker streams also carry all of the current
release's worker application output, so the read widens the release/app
boundary. The attended whole-release read is the selected design. It covers no
other release, no unmasking and no sharing outside the attended session.
Attaching the policies remains a separate approval. Each worker revision fixes
its release's `SENTRYSEARCH_RELEASE_ID`, its `worker/<release-id>` stream prefix
and non-blocking logging. The roots now define the observer task definitions,
the `/<prefix>/observe` log group and an `-observe` launcher policy for the
current release's observers only, and the migrations' release-job mode; until
images carrying those producers are built, a release against these roots would
hold.
The manifest's environment name must equal the roots' `name_prefix` so the lock
key matches the release-evidence policy. These roots are not applied, and mocked
plans do not prove IAM behavior.
