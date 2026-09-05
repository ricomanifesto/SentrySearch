# Runtime consistency and recovery

SentryRuntime owns execution state. SentrySearch owns reports, evidence,
evaluation, analyst judgments, and artifact references. The adapter remains
opt-in and loopback-only; this is not a deployed-service release.

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
a running worker loop; it is not instantaneous and has no bounded recovery-time
promise while generation or evaluation occupies the process.

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

The automatic scan is limited to reports with runtime dispatch intents. Legacy
in-process reports can still use the manual retry endpoint for pending, unclaimed
or expired evaluation. There is no evaluation heartbeat or whole-job deadline;
work lasting beyond the lease can overlap a replacement, but only its current
owner can publish. Actual provider cost and deadline policy remain release work.

## Local proof

Run the regular no-services gate first:

```bash
uv sync --locked
uv run python dev/check_local_setup.py
```

With Go, Homebrew PostgreSQL 16, and a SentryRuntime checkout available:

```bash
uv run python dev/check_runtime_consistency.py --runtime-repo ../sentryruntime
```

The runner builds the real runtime, starts a disposable socket-only PostgreSQL
server and a token-authenticated loopback runtime, and creates an isolated
product database for each integration test. It tests takeover during upload,
reconciliation after runtime failure and lease exhaustion, evaluation takeover,
saved-evidence evaluation recovery, and additive migration backfills.

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
- Define worker health, shutdown/drain behavior, evaluation deadlines, backlog
  visibility, and alerts for missing runs and terminal-state mismatches.
- Define retention for unreferenced content without deleting any live artifact.
  This slice does not add automatic object cleanup or alter bucket policies.
- Run an explicitly approved controlled canary with rollback receipts before
  enabling remote execution or removing `TODO(sentryruntime-cutover)` fallbacks.
