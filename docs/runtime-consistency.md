# Runtime consistency and recovery

SentryRuntime owns execution state. SentrySearch owns reports, evidence,
evaluation, analyst judgments, and artifact references. The adapter remains
opt-in, with explicit local or verified HTTPS transport; this is not a
deployed-service release. See [admission and transport](runtime-admission.md).

## Publication boundary

After claiming a runtime lease, the worker registers `(run_id, lease_version,
lease_owner)` against the report's dispatch intent. Registration locks the
report before the dispatch row and rejects a different run ID or an older lease.
Every generation progress, failure, and finalization write checks this tuple.

Registration is the **product-side fencing boundary**, not the earlier runtime
claim. The two databases do not share a transaction. If an old attempt publishes
before replacement registration, its completed report stays valid; registration
never reopens it. Once the replacement is registered, older product writes are
rejected. Missing or deleted placeholders cannot be recreated by finalization.
Generation cannot downgrade a completed report, including through the legacy
background path.

Finalization checks ownership, releases locks, uploads content, then reacquires
the locks and checks ownership again before publishing references. Provider calls
and object uploads never hold these product row locks. Markdown and traces use
`reports/{report_id}/artifacts/{sha256(content)}.md` or `.json`; different bytes
cannot overwrite the winning content through these storage methods. Existing
stored keys remain readable. This is content addressing, not S3 Object Lock or
an exactly-once guarantee: rejected uploads can leave unreferenced objects.

## Recovery behavior

The worker polls submitted intents in oldest-check order, including those whose
reports are already complete. Late submission acknowledgments cannot change the
bound run ID or move a terminal dispatch back to submitted.

| Observed state | Product action |
| --- | --- |
| Runtime still queued, running, or retrying | Keep the report state; check other intents next. |
| Runtime failed; report still generating | Mark generation failed without repeating generation. |
| Runtime succeeded; report still generating | Mark a persistence failure and record `runtime_result_missing`; do not invent an artifact. |
| Report already complete; runtime failed | Preserve the report and record `runtime_failed_after_publication`. |
| Runtime unavailable, run missing, or references disagree | Preserve the intent and record an error for operator inspection. Never silently bind another run. |
| Runtime credentials or scope rejected | Stop the worker for operator correction. |

The runtime terminalizes expired, exhausted runs during claim scans. Merely
reading an expired run does not trigger that transition. Product recovery needs
a running worker loop; it is not instantaneous. The supervised worker bounds
individual work phases but does not promise a recovery-time SLA or restart itself.

## Evaluation ownership

Completed runtime-managed reports with pending evaluation are scanned even if
the generation process died before its completion acknowledgment or callback.
The evaluator acquires a product lease before invoking the judge. A database
clock sets its expiry, and a random lease ID fences result and failure writes.
The default lease lasts 15 minutes. Expiry permits takeover; a replacement lease
or terminal evaluation state rejects old results, including uploads in flight.

Only two automatic crash recoveries are allowed per evaluation reservation.
After three interrupted executions, the next recovery scan marks evaluation
failed with `evaluation_recovery_exhausted`. A manual evaluator-only retry can
reserve a new attempt and reset this budget. It does not repeat research or
synthesis. A live, unexpired lease prevents duplicate manual work. Evaluation
attempt numbers retain their role in analyst-judgment versioning.

The automatic scan is limited to reports with runtime dispatch intents. Manual
retries for these reports only reserve pending evaluation for the supervised
worker, even with explicit legacy admission and no API runtime URL. Paused
admission rejects all manual retries before reservation. They do not start another
evaluator inside the API process.

Legacy reports without a runtime intent require explicit legacy admission for
the in-process manual-retry path; runtime admission returns 409 without reserving
evaluation. There is no evaluation heartbeat, and that legacy path has no
whole-job deadline. A replacement lease still fences old result writes. Drain
old API/worker processes before cutover; the supervisor cannot stop an evaluator
already running in another process.

## Worker lifecycle and health

The CLI starts one fresh worker process and keeps health serving in its
supervisor. Application clients, database pools, provider calls, and validator
threads stay in the child. No database or provider request runs in a health
handler. Probe one worker with:

```bash
uv run python -m dev.run_runtime_worker --health-port 8081
curl http://127.0.0.1:8081/healthz
curl http://127.0.0.1:8081/readyz
curl http://127.0.0.1:8081/status
```

The health port defaults to `0`, which selects a free loopback port and logs its
address. It cannot bind a remote interface. This diagnostic server is not a
public, authenticated production endpoint; do not expose or proxy it remotely.

- `/healthz` returns 200 while the owned child is alive. It does not assert that
  dependencies are healthy or that a job is making progress.
- `/readyz` returns 200 after the worker has sampled product state and made a
  successful runtime claim request, including an empty claim. Busy work can stay
  ready within its time budget. Startup, known runtime errors, drain, exceeded
  budgets, and process exit are not ready.
- `/status` returns a cached snapshot: phase, elapsed time and budget, drain
  state, safe error code, and product backlog counts with sample age. It exposes
  no report contents, owner identities, credentials, or raw dependency errors.
- Backlog counts cover pending/submitted dispatches, ready/active runtime-owned
  evaluations, and dispatch records with errors. These are product counts, not
  the runtime's queue totals or a fleet-wide worker registry. Sample age includes
  query/IPC delay and grows during long work; probes do not refresh it.

Send SIGTERM or SIGINT to the **supervisor PID** to drain. Readiness drops as the
supervisor handles the signal; dispatch stops between submissions, and the loop
does not start another work phase. An already in-flight claim can finish its
claimed job. The child ignores direct termination signals and receives drain
through its private control pipe. Signal handlers do not acquire status locks.

| Option | Default | Meaning |
| --- | --- | --- |
| `--startup-seconds` | 60 | Maximum child startup phase. |
| `--maintenance-seconds` | 120 | Maximum reconciliation/backlog phase. |
| `--generation-seconds` | 1800 | Maximum generation/claim phase, including lease heartbeats. |
| `--evaluation-seconds` | 600 | Maximum evaluator phase, including lease acquisition and persistence. Maximum allowed is 840, before the 900-second product lease. |
| `--drain-seconds` | 30 | Grace period for current work before forced termination; zero requests immediate termination. |

An expired phase or drain budget kills and reaps the owned child and exits 124.
Unexpected child failures, rejected runtime credentials, or an unrecovered
runtime error exit 1; clean drain or a successful `--once` cycle exits 0.
The supervisor does not automatically
restart failed work. If the supervisor disappears, its control pipe closes and
the child exits rather than continuing provider work without supervision.

Forced termination leaves durable leases for recovery. Generation becomes
eligible after runtime lease expiry; evaluation becomes eligible after product
lease expiry and still obeys its recovery budget. Open product transactions roll
back on disconnect. A report published before termination remains valid, and
an interrupted upload may leave an unreferenced object.

These are local process deadlines, not hard real-time scheduling, provider-side
cancellation, or dollar-spend guarantees. Work already accepted by a provider
may continue or incur charges after its local connection closes. No new model
route or billing setting is introduced by this worker change.

## Local proof

Run the regular no-services gate first:

```bash
uv sync --locked
uv run python dev/check_local_setup.py
```

With Go, OpenSSL, Homebrew PostgreSQL 16, and a SentryRuntime checkout that
supports native TLS and readiness:

```bash
uv run python dev/check_runtime_consistency.py --runtime-repo ../sentryruntime
uv run python dev/check_runtime_consistency.py --runtime-repo ../sentryruntime --tls
```

The runner builds the real runtime, starts a disposable socket-only PostgreSQL
server and a token-authenticated runtime, and creates an isolated
product database for each integration test. It tests takeover during upload,
reconciliation after runtime failure and lease exhaustion, evaluation takeover,
saved-evidence evaluation recovery, aggregate backlog, and additive migration
backfills. It also kills a supervised evaluator at its deadline, verifies the
report survives, and reclaims evaluation from saved evidence after lease expiry.
The regular gate includes process/HTTP tests for live probes, SIGTERM drain,
forced deadlines, parent death, error redaction, and signal-lock reentrancy.
The HTTPS variant uses disposable certificates and the worker's remote-client
configuration. Both variants prove that API pause reserves nothing and an
accepted intent survives a runtime outage, then drains while admission is paused.
The regular gate also tests real TLS rejection of wrong CA/hostname, expired
certificates, redirects, and ambient trust/proxy overrides.

The storage code uses a fake S3 client; the evaluator is stubbed. These tests do
not call AWS or a model provider and do not prove bucket policy, deployed
transport, provider behavior, production performance, or production recovery.
The runner stops its processes and removes its disposable data after execution.

## Release and rollback gates

- Apply the additive schema before starting upgraded writers. Stop and drain old
  API background jobs and workers: older binaries do not honor these fences.
  Do not run a mixed-version writer fleet or roll back to an unfenced writer
  while durable work is active.
- Prove authenticated protected transport, secret delivery, and least-privilege
  runtime, product-database, and artifact access in the target environment.
- Validate the locally tested health, drain, deadlines, and restart behavior in
  the target platform. Wire alerts for stale backlog samples, missing runs,
  exhausted evaluation recovery, and terminal-state mismatches. Test the actual
  platform's termination grace and provider cost controls.
- Define retention for unreferenced content without deleting any live artifact.
  This slice does not add automatic object cleanup or alter bucket policies.
- Run an explicitly approved controlled canary with rollback receipts before
  enabling remote execution for deployed workloads or removing
  `TODO(sentryruntime-cutover)` legacy paths.
