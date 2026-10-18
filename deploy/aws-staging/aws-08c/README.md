# AWS-08b and AWS-08c: capped provider canary, admission scope and cutover checks

This is the runbook for the pieces the production cutover needs before it can be
authorized. Nothing here has run against a deployment or a provider. Each run is
its own approval: the capped real-provider canary (AWS-08b), each admission-scope
milestone and its rollback (AWS-08c), and the main push that must come first.

## The order

1. `python -m release_kits.cutover pre-cutover --target TARGET.json --work CUTOVER_DIR --deployed ENV_FILE --gate`
   at the head that would be pushed: with explicit legacy admission, no runtime URL
   and no scope, the API behaves as production does today (the local gate, the API
   smoke and the admission tests), and `ENV_FILE` (the deployed API's settings as
   `KEY=VALUE` lines) shows the deployment is set that way. This is what lets the
   main push go first and change nothing.
2. `python -m release_kits.cutover retention ...`: the head still carries every
   legacy path a return to legacy admission needs.
3. The capped provider canary (below), on the isolated environment.
4. Before each scope milestone: `python -m release_kits.cutover drain --database-url-file FILE ...`
   until no legacy writer is running. A report generating in-process for more
   than two hours is counted as abandoned and reported apart; the drain does not
   wait for it.
5. `python -m release_kits.admission_scope expand --work SCOPE_DIR ...` for each
   milestone; you apply the printed settings to the API; `admission_scope verify
   --deployed ENV_FILE` compares the deployed settings with the newest milestone
   and checks that the API itself would accept them.
6. If anything goes wrong: `python -m release_kits.admission_scope rollback ...`,
   then remove exactly the settings it prints (the two scope settings, and under
   a `legacy` base also `SENTRYRUNTIME_URL`, `SENTRYRUNTIME_LOCAL_URL` and
   `SENTRYRUNTIME_CA_FILE`, which legacy admission refuses without a scope), then
   `admission_scope verify`.

Every command writes a hashed receipt chained to the one before and prints its
hash; the next command takes it as `--chain-head`. The cutover kit and the
admission kit keep separate chains: give them separate work directories.

## Admission scope

The API keeps `SENTRYSEARCH_EXECUTION_MODE` and its rules unchanged, and `paused`
stays the default. A scope is two more settings:

- `SENTRYSEARCH_RUNTIME_SCOPE`: the identities (user UUIDs, sorted, comma-separated)
  whose **new reports** are admitted to the runtime;
- `SENTRYSEARCH_RUNTIME_SCOPE_SHA256`: the SHA-256 of that exact text.

A scope needs an explicit `legacy` or `paused` base mode and a valid runtime URL.
Every other identity keeps the base mode. A scope that is not in canonical form,
does not match its hash, or comes without an explicit base mode or a runtime
endpoint fails closed: new work returns 503 for everyone.

Evaluation retries are not scoped; they follow the base mode for everyone. Under
a `legacy` base a runtime-owned report's retry queues to the worker and a legacy
report's retry evaluates in-process. Under a `paused` base every evaluation retry
returns 503, a scoped identity's runtime-owned reports included.

`expand` only ever adds identities; `rollback` records the return to the base
mode. Removing the scope settings never touches admitted work: durable dispatch
ownership keeps every runtime-owned report with the runtime and its worker.

The target is a `sentry.admission-target.v1` document: `environment`, `base_mode`
(`legacy` or `paused`) and `runtime_url` (`https://`). The admission kit's work
directory holds the identity lists; keep it private.

## Orphan retention

An **orphan** is work whose two halves disagree after a scope change or a
rollback: a runtime-owned report whose Runtime run no longer exists, is terminal
while the report is not, or never reached the Runtime; or a Runtime run with no
product report. No cutover step and no rollback deletes anything, orphans
included. What the systems themselves keep:

- product reports and their dispatch intents in the product database, and
  Runtime runs and their event history in the Runtime database, have no
  automatic deletion;
- report objects in S3 expire `report_retention_days` (30 by default) after they
  are written, whatever the scope; an orphan older than that has lost its
  artifacts;
- a report's owner can delete it through the API, which removes the product
  record and its S3 objects but not the Runtime run, leaving a Runtime run with
  no product report;
- the worker's reconciler keeps reconciling runtime-owned reports while any
  worker runs; a mismatch is surfaced by the `terminal-mismatch` alert once it has
  a producer (it is unwired today).

Deleting an orphan is a separate decision with its own receipt.

## Capped real-provider canary (AWS-08b)

With `SENTRYSEARCH_PROVIDER_CANARY` set to a `sentry.provider-canary.v1` manifest,
the worker's model client and source fetcher send through bounded transports:

```json
{"schema": "sentry.provider-canary.v1", "canary_id": "aws-08b-1",
 "not_after": "2026-10-20T18:00:00Z", "budget_usd": 25,
 "providers": {"openrouter": {"hosts": ["openrouter.ai"], "max_requests": 40},
               "sources": {"hosts": ["example.org"], "max_requests": 20}},
 "stop": {"max_consecutive_failures": 3}}
```

A host the manifest does not name, a request past its provider's count, anything
after `not_after`, or anything after the consecutive-failure limit is refused
before it is sent; a refused model request is final (never retried), and a
refused source fetch is recorded unavailable. The source fetcher's public-address
check still looks a source host up in DNS first; no connection is opened to a
refused host. The consecutive-failure limit counts all providers together:
failing source fetches in a row stop model requests too.

**This is not a hard spending cap.** The counts live in one worker process: a
restarted or replaced task starts again from zero, every task counts on its own,
and a request in flight is billed even if its answer is refused. The control for
provider spend is the canary key's own credit limit, set at the provider at or
below `budget_usd` before the canary starts. The account's monthly budget alarm
(the foundation's `notifications`) sees AWS costs only; it cannot see provider
spend.

### What reaching a provider still needs

The canary is the caps and their enforcement. The wiring exists and sets nothing:
`deploy/aws-platform-fit` takes an optional `model_provider` (the base URL, the
canary manifest and its SHA-256, and the `provider-key/worker` bundle at its exact
version) and gives it to the worker alone; null, the default, renders the disabled
generation scaffold (a discard base URL and a placeholder key) byte for byte. The
releases root passes it per release. The 07b kit's `init --provider-canary` fixes
an approved canary (its id, manifest, manifest hash and base URL, for that plan and
those images) into the release record; the custodian step then creates the
`provider-key/worker` secret for that release only, refusing the key file for any
other release and a canary the worker would refuse, and the 7.9 manifest lists the
key among the worker's secrets.

The worker checks its provider settings before it starts. It runs only with the
disabled scaffold (an empty or placeholder key and the discard address) or with an
unexpired canary manifest that names its model host, and a key; anything else, a
live key without a manifest included, stops it with `provider_misconfigured` in its
readiness receipt, so it never reports ready. A disabled worker refuses source
fetches as well as model requests. Before AWS-08b can run, still needed: the
canary's own approval, including whether the 7.9 release approval (milestone
`operational-paused`) must name the canary, which is a release-manifest change; the
provider key with its provider-side credit limit; and a worker image rebuilt from
this series with its scans and suites.

## Proven on the platform only

- The main push itself and the production API's behaviour after it.
- Applying a scope to the deployed API, and a rollback by removing it.
- The drain query against the production database (it is proven against
  PostgreSQL locally).
- The provider canary against a real provider, and the provider key's credit
  limit refusing requests past it.
