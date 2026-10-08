# Release operator CLI

`release_cli/` is the attended operator's command line and the only place release
code builds AWS SDK sessions or clients. It composes the SDK-free
[controller](release-controller.md) with the injected-client
[adapters](release-aws-adapters.md). **Evidence level:** every command has run
only against in-process fakes through the real client constructors, with the
network denied. The production client factory and the live preflight have not
called AWS; nothing here is evidence that an environment exists.

## Commands

```bash
python -m release_cli validate --manifest M.json --approval A.json
python -m release_cli status   --manifest M.json --credentials SESSION.json
python -m release_cli run      --manifest M.json --approval A.json --credentials SESSION.json
python -m release_cli recover  ... --prior-session ID --lock-etag ETAG --fence-evidence-sha256 HASH --authorized-by NAME
python -m release_cli cleanup  ... (same recovery arguments)
```

| Command | Reads | Writes | Notes |
| --- | --- | --- | --- |
| `validate` | the two files | nothing | Strict manifest and approval binding (hash, scope, interval). No clients, credentials, clock reference or network; it does not check the approval against the current time. |
| `status` | journal and lock objects | nothing | Every store write is refused; no ECS request. Reports state, outstanding intents, the lock's session and ETag (the recovery inputs). |
| `run` | everything the controller needs | journal, lock, ECS | Starts a **new** session. A journal owned by another session halts with `session_conflict`. |
| `recover` | as `run` | as `run` | Records the break-glass takeover of the prior session's exact lock ETag with fence evidence, then continues the release under this process's session. |
| `cleanup` | as `run` | journal, StopTask | The same takeover, then stops only the release's own unfinished job tasks (exact token and task definition) and holds with `operator_abort`. Never launches, deploys or scales. |

Each process has a fresh random session id; no command accepts one. Continuing a
lost session always goes through `recover` or `cleanup`, which journal who
authorized the takeover and the evidence that the prior process is fenced.

Output is one JSON document on stdout: no credential, token or provider message;
an unexpected error is reported by its class only. Exit codes: `0` success, `2`
refused before any release action (input, credentials, identity, environment or
clock), `3` the release holds, `4` the controller halted (for example a journal
conflict, a refused recovery or an unexpected error).

Credentialed commands need a schema-2 manifest: its `operator_role` names the IAM
role the operator's session must have assumed. A schema-1 manifest names no role
and is refused (`operator_role_unapproved`) before the credentials file is read.
There is no command-line role: the approved manifest is the only source.

The control bucket is derived as the bootstrap root names it,
`<environment.name>-<account_id>-control`, so the manifest's environment name
must equal the roots' `name_prefix`.

## Execution purpose

Schema 2 manifests state `purpose.kind` explicitly; schema 1 manifests are
forward runs. A forward run may bootstrap both databases first (only with an
`empty_hold` fallback). A forward upgrade whose fallback is `compatible_release`
still migrates: the fallback names what to restore after a failure, not what to
run. A `rollback` purpose is validated (prior pair only, both actual schemas
compatible, reconcile and proof jobs only) but the controller refuses to execute
it (`rollback_execution_unavailable`) until rollback execution is wired.

## Credentials

The credential custodian writes one JSON file for the operator:

```json
{"schema": "sentry.operator-session.v1", "access_key_id": "ASIA…",
 "secret_access_key": "…", "session_token": "…",
 "expires_at": "2026-10-08T20:00:00Z", "session_name": "<manifest operator>"}
```

It must be an absolute path with no symlink anywhere, outside any Git
repository, a regular file owned by the operator with mode exactly `0400`, one
hard link and at most 8 KiB; every parent directory must be owned by the operator
or root and not group- or world-writable (a root-owned sticky directory is
allowed). The file is opened once without following links and checked through
that descriptor. Long-lived `AKIA` keys and missing session tokens are refused.
`expires_at` must cover the release window (the earlier of now plus the
manifest's `total_seconds` plus a 120-second allowance for the journal to be
created, and its `expires_at`) plus ten minutes, and be no more than 36 hours
ahead. It is checked again after the preflight against the referenced clock. On
macOS an extended ACL with any `allow` entry on the file or a parent directory
is refused (mode bits do not show ACLs); `deny`-only entries, such as the
`everyone deny delete` macOS gives home folders, only restrict and pass. These are the custodian's statements, **not proof**:
the file's session name and expiry are unauthenticated, and a key prefix proves
nothing. Identity is proven by the preflight; expiry remains a custodian trust
input because `GetCallerIdentity` reports none. There is no refresh and no
fallback to any ambient source.

## Isolated clients

`release_cli/clients.py` builds every client from a botocore session whose
configuration variables read no environment variable, configuration or
shared-credentials file, customer model directory (`~/.aws/models`) or configured
endpoint URL, with an empty credential provider chain. Each client gets the
file's explicit credentials, the manifest's region, `total_max_attempts` 1 in
standard mode, a 10 s connect and 30 s read timeout, an explicit empty proxy map
(botocore otherwise reads `HTTP(S)_PROXY`), the SDK's locked default CA bundle,
fixed S3 settings (regional `us-east-1` endpoint, no ARN region, no multi-region
access points, accelerate or dual-stack), a constant user agent and no Lambda
recursion-detection header. The SDK still reads a few variables directly; those
settings make `AWS_S3_*`, `AWS_EXECUTION_ENV` and `AWS_LAMBDA_FUNCTION_NAME` with
`_X_AMZN_TRACE_ID` change nothing. It also reads `SSLKEYLOGFILE` when it builds a
TLS context, which would log session secrets: the CLI refuses to run while it is
set (`unsafe_environment`), before any client exists; that is the CLI's only read
of its environment. The adapters still refuse any other client.
`tests/test_release_cli_offline.py` runs the CLI in a subprocess whose
environment poisons credentials, profiles, config and credential files (with a
`credential_process`), model paths, endpoints, FIPS/dual-stack, retry, S3 and
execution-environment settings, CA bundles, proxies, instance/container metadata,
web identity and the Lambda trace id, and records any poisoned file opened,
process started or socket used: none are, and a prepared request carries only the
fixed user agent. A second run with `SSLKEYLOGFILE` set is refused with no client
built and no key log written.

## Preflight and Clock

Before any journal, lock or ECS request, the CLI calls `sts:GetCallerIdentity`
once. Its account, assumed-role ARN and role-session user id must equal the
approved operator: the manifest account, the manifest `operator_role` and the
manifest `operator` as session name, all bound by the approval's manifest hash.
Errors are refusals with no provider text. The session name proves the operator
only as far as the role's trust policy pins it; the operator role and its trust
policy are infrastructure inputs, not facts this code can establish.

The Clock (`release_cli/clock.py`) is monotonic-anchored UTC: wall time sampled
at start plus elapsed monotonic time, so it never moves backwards. Every reading
also samples the wall clock; any backwards wall step, wall and anchored time
more than 5 s apart (a stepped clock, or a host that slept with the monotonic
clock stopped) or an invalid reading makes it permanently untrusted. Its
reference is the preflight response's `Date` header (IMF-fixdate only),
bracketed by the Clock's readings before and after the call. The header has
whole-second resolution, so local minus reference lies in
`[sent - (date + 1 s), received - date]`; the round trip must be at most 2 s and
that whole interval within ±5 s, or the run is refused. `sleep` waits at least
the requested monotonic time (bounded to 60 s) and never moves time or deadlines.

Once untrusted, the Clock raises `ClockUntrusted`, and the controller latches: it
never reads that Clock again in the run. Before a journal exists it halts
(`controller_clock_untrusted`); afterwards it holds with that reason. Only safety
events may be journaled without the Clock (the hold transition, observations, and
`guard=False` intents to stop the release's own jobs or release its lock); they
carry the latest time already recorded and `clock_untrusted`. A forward intent,
any other transition (including `held_paused`) or a session event needs the Clock
and holds instead, even when trust is lost between the guard and the journal
timestamp. A restarted or recovered controller whose clock reads earlier than its
journal holds with `controller_clock_rollback` before reconciling anything.

## Validation

```bash
uv run python -m pytest tests/test_release_cli.py tests/test_release_cli_offline.py
```

## Not proven

- The production client factory, live preflight and every AWS behaviour behind
  them (IAM, STS regional endpoint use, the `Date` header in practice, S3 and ECS
  semantics) have not run against AWS.
- Operator trust, the credential custodian's issuance and the session lifetime
  are approval-time inputs, not facts this code can establish.
- A host whose wall clock is consistently wrong by less than 5 s, or whose
  monotonic and wall clocks drift together, passes these checks.
