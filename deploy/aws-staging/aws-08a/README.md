# AWS-08a: the end-to-end matrix

This is the runbook for `python -m release_kits.aws_08a`. It runs the AWS-08a
matrix against a target description and writes a hashed, chained ledger with
one record per case. The default target is the local canary topology, where every
case that does not need the platform is proven; the platform cases are recorded
`skip` with their reason. Running it against the staging account is a separate
authorization (AWS-08a), after AWS-07b has reached `held_paused`.

```bash
python -m release_kits.aws_08a cases
python -m release_kits.aws_08a run --target TARGET.json --ledger NEW_DIR [--case ID ...]
```

## Targets

A target is a `sentry.aws-08a-target.v1` document. Nothing is resolved from the
environment: every input is named in it.

- **Local** (`"kind": "local"`, `"platform": false`, no endpoint, session or
  identities): `images` (the exact local `search`, `runtime` and `release_tools`
  image IDs) and `runtime_checkout`. The identity is the local test auth double
  (the canary's JWT fixture).
- **Platform** (`"kind": "platform"`, `"platform": true`): `endpoint` (the API,
  `https://`), `endpoint_ca` if the endpoint uses a private authority,
  `deployer_session` (your deployer session file, in the release CLI's format), `identities` (a
  `sentry.aws-08a-identities.v1` file naming the auth `service`, an isolated
  `project`, never a production tenant, and owner-only token files for `owner`,
  `other` and `expired`), `aws_07b_work` (the AWS-07b work directory) and
  `aws_07b_chain_head` (its last receipt's hash; the chain is re-verified
  against the plan and must end there), `plan` and `plan_sha256`, and
  optionally `alert_alarm` (an alarm of this environment). The session must
  belong to the plan's account and must not be the operator role's own session:
  outside an AWS-07b attach window that role holds none of the calls below.

The platform cases' AWS calls, which the deployer session must allow (an access
denial is recorded as `failed (access denied: ...)`, apart from a platform
failure): `sts:GetCallerIdentity`; `iam:SimulatePrincipalPolicy` on the release's
worker and API task roles (`cross-prefix-s3-denial`); `logs:TestMetricFilter` and
`cloudwatch:SetAlarmState` on `alert_alarm` (`alert-delivery`); and
`ecs:ListTasks`, `ecs:DescribeTasks` and `ecs:StopTask` on the worker service's
tasks (the two worker cases). Before any case runs, the AWS-07b chain is checked
against `aws_07b_chain_head`; a mismatch stops the run before anything is sent.

The ledger records which identity was used. Records hold case ids, outcomes,
test node ids, exit codes and log hashes; never a token, credential, report
content or log line. Logs stay in `NEW_DIR/logs/` and only their SHA-256 enters
the ledger.

## The matrix

Local proofs run through five suites, each invoked once (`unit` and
`service-images` select exactly the tests the matrix names; the others run their
whole explicit suite): `unit`: offline pytest; `runtime-consistency`:
`dev/check_runtime_consistency.py`, PostgreSQL 16 and the Runtime binary;
`deterministic-canary`: `dev/check_deterministic_canary.py --skip-build` with the
target's images; `service-images`: the image suites with the target's images;
`runtime-integration`: the Runtime's `go test -tags integration -json`. Each
pytest the suites start writes its outcomes to JUnit XML (`PYTEST_ADDOPTS`), and
the Go suite reports through `-json`; no outcome is read from console text. A
parametrized test passes only when every one of its cases passed. A run refuses
before anything starts if a named test does not exist, and prints the ledger's
last hash when it ends: keep it, as nothing else records the newest entry.

| Case | Local proof | On the platform |
| --- | --- | --- |
| `auth-valid` | deterministic canary | admitted POST with the owner identity |
| `auth-invalid` | deterministic canary | no token and an invalid token are 401 |
| `auth-expired` | deterministic canary | the expired identity is 401 |
| `auth-wrong-owner` | deterministic canary | the other identity reads 404 |
| `outbox-dispatch` | deterministic canary; dispatcher unit test | the report completes |
| `runtime-claim` | deterministic canary; Runtime lease and heartbeat tests | the report completes |
| `artifacts` | deterministic canary; content-addressed key test | the report has its artifact |
| `evaluation` | deterministic canary | evaluation completes |
| `readback` | deterministic canary | the owner reads the evaluated report |
| `duplicate-submission` | deterministic canary redispatch; Runtime idempotent submissions | local proof stands |
| `worker-death-before-publication` | Runtime expired-lease recovery; busy-worker restart; replacement fences the old writer | submits a report, stops the worker task once it has started, and requires the report to complete on a replacement task, the stopped task having exited 124 or 137 (it did not finish the report itself) |
| `worker-death-after-publication` | replay acknowledged without regeneration; terminal observation and upload takeover keep the published object | local proof stands |
| `stale-fence` | Runtime fencing tests; product unfenced-write refusal | local proof stands |
| `evaluation-only-recovery` | saved-evidence recovery, reclaim and crash budget (PostgreSQL) | local proof stands |
| `dependency-outage` | intent survives outage and drains; dispatcher and reconciler keep intents | local proof stands |
| `retry-exhaustion` | Runtime retry policy and budget; product reconciliation | local proof stands |
| `cross-prefix-s3-denial` | platform | `iam:SimulatePrincipalPolicy` on the worker and API task roles' identity policies: each own action allowed under `reports/*` (worker get and put, API get and delete), nothing (read, write or delete) allowed under another prefix; the applied bucket policy holds only Deny statements. Every page of each answer is read; an answer that does not decide each requested action exactly once, with a known decision on the requested resource, fails the case |
| `tls-runtime-hostname` | real TLS refusal; untrusted certificate keeps the worker unready; misnamed certificate refused | the AWS-07b run reached `held_paused`, so the Runtime observer verified `runtime.<namespace>` |
| `secret-rotation` | `tests/aws_08a_local.py`: rotated tokens accepted, retired ones 401, a worker with a retired token stops (exit 1, `runtime_access_denied`) | local proof stands until an upgrade release rotates bundles |
| `certificate-rollover` | `tests/aws_08a_local.py`: renewed certificate trusted only with its authority in the bundle | local proof stands until an upgrade release rotates material |
| `termination-grace-and-replacement` | SIGTERM drain; drain stops between phases; named-volume restart | as above; the stopped task's app container must have exited on its own (0 after a clean drain, 124 at the drain deadline), so before ECS's SIGKILL at the 60-second stop timeout, which would make it 137; the time from STOPPING to the end of execution is recorded |
| `alert-delivery` | platform | first checks each worker metric filter with `logs:TestMetricFilter` against real receipt lines, using the patterns the AWS-07b foundation receipt recorded; then sets `alert_alarm` to ALARM after you type `alert-delivery`, then you type `received` once it arrived; it is set back to OK |
| `pitr-restore` | platform | reads the AWS-07b chain and judges the latest restore attempt in it (of any result) and the latest verification written after that attempt: passes only when that verification is `restore_verified` for the attempt's instance, both jobs reached its endpoint, the proof ran the current release's program (`sql_digest`) and read its schema, and the reconcile saw no foreign session; fails when a restore has no verification or the verification disagrees in any one way; skips only when the chain has neither a restore attempt nor a verification |

Platform steps that act wait for a typed confirmation first: creating the one
report the auth and report cases observe (`submit`; it runs real generation and
evaluation in the isolated project), firing the alarm (`alert-delivery`; it is
set back to OK even if the run is interrupted) and stopping a worker task (the
case id, which also confirms its one fresh report; the task is stopped once that
report has started). Without the `submit` confirmation the case is recorded `skip`,
nothing is sent (not even the denial probes, which come after it) and later auth and
report cases are not asked again. The other platform cases only read: the AWS-07b receipts, IAM's policy
simulation and CloudWatch Logs' metric-filter test.

## Proven on the platform only

- `cross-prefix-s3-denial`: IAM's evaluation of the roles' identity policies
  (IAM simulates a resource policy only for a user caller). The bucket policy is
  checked to hold only Deny statements, so it can only narrow those decisions;
  its conditional denies (insecure transport, outside the endpoint) are proven by
  the platform's own traffic, not by this case.
- `alert-delivery`: SNS email delivery to the named recipient.
- `pitr-restore`: RDS point-in-time restore into a new instance, with the
  reconcile and proof jobs verifying its schema before any login points at it.
  The AWS-07b `restore` and `restore-verify` commands perform both; the restore,
  the restored endpoint, IAM and Fargate are platform facts. The proof covers the
  service login's privileges and denials and the migration state, not data
  content; whether the engine's management sessions run as role OID 10 there is
  not observed locally.
- Fargate behaviour of the worker cases: task stop, ECS replacement timing and
  listing delay.
- Rotation and rollover through Secrets Manager versions in a real upgrade
  release (the local cases prove the services' side).
