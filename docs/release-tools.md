# Guarded release jobs (release-tools image)

`release_tools/` and `container/release-tools.Dockerfile` provide the database
jobs the [release controller](release-controller.md) runs after migrations:
Runtime and product **grants**, least-authority **proofs**, a same-database
**reconciliation** job and a **bootstrap** job for a fresh instance. The image is
local and mock-wired only: ARM64 build, container tests and exact-image scanning
have run, but it has not been published to a registry or run in AWS. Findings
remain unaccepted, and nothing here grants access to a real database.

## Image

| Property | Value |
| --- | --- |
| Base | `gcr.io/distroless/cc-debian13:nonroot` by digest; no shell or package manager |
| Interpreter | CPython 3.11 from the pinned `python:3.11-slim-trixie` digest; installers, headers, the stable-ABI shim, test modules and stdlib extensions without shipped libraries removed |
| Client | `psql` 16.15 and `libpq5` 18.6 from the pinned `postgres:16.15-trixie` digest, preserved as whole Debian packages with status and md5sums; other client programs removed |
| Init | tini v0.19.0 by checksum, PID 1 |
| User | `65532:65532` by default; product jobs run as `10001:10001` |
| Entry point | `tini -- python3.11 -I -B -m release_tools <command>`; no default command |

Base libraries (`libc6`, `libssl3t64`, `zlib1g`, `libzstd1`, and for Python
`libgcc-s1`, `libstdc++6`) must be the exact revisions in the distroless base;
the build fails on drift instead of overlaying them. `-I` ignores `PYTHON*`
variables and the working directory, `-B` never writes bytecode, and the root
filesystem can be read-only. Nothing is downloaded at run time.

`python3.11 -I -B -m release_tools digest` (the image's `digest` command) prints
the build pins: `tools_sha256` over every program and SQL file (relative path,
length, bytes; symlinks rejected) and each SQL file's SHA-256. The Runtime grant
is `db/roles/service.sql` from Runtime `bb6e523` vendored byte-for-byte; a test
requires its SHA-256 to equal the manifest pin
`02a2b55161506254b1977f26351ec3bbba4de7c94a54b3b697153d622ae02aa0`.

## Commands and configuration

Every setting comes from the task definition; anything unexpected fails before a
connection with exit 2.

An omitted URL port defaults to 5432. Explicit ports must be in 1–65535;
port zero is invalid and never selects a different target by falling back.

| Variable | Rule |
| --- | --- |
| `RELEASE_ID` | Manifest release UUID |
| `RELEASE_JOB_ID` | Manifest job id, e.g. `runtime-grant`; `release:<id>:<job>` must fit PostgreSQL's 63-byte `application_name` |
| `RELEASE_DATABASE` | `runtime` or `product` (selects the SQL program) |
| `RELEASE_NOT_AFTER` | Absolute UTC deadline, `YYYY-MM-DDTHH:MM:SSZ` |
| `RELEASE_JOB_BUDGET_SECONDS` | 60–3600 |
| `RELEASE_TOOLS_SHA256`, `RELEASE_SQL_SHA256` | Must equal the image's computed digests |
| `RELEASE_EXPECT_DATABASE`, `RELEASE_EXPECT_PRINCIPAL` | Must equal the connection's database and login |
| `RELEASE_SERVICE_ROLE` | grant, bootstrap |
| `RELEASE_OWNER_ROLE` | proof, bootstrap |
| `RELEASE_TARGET_DATABASE`, `RELEASE_OWNER_PASSWORD`, `RELEASE_SERVICE_PASSWORD` | bootstrap only |
| `DATABASE_URL` or `DB_HOST`/`DB_PORT`/`DB_NAME`/`DB_USER`/`DB_PASSWORD` | From a pinned secret version; exactly one form. A URL may carry only `sslmode=verify-full` and `sslrootcert=/run/material/postgres-ca.pem` |

| Command | Principal | Program |
| --- | --- | --- |
| `grant` (runtime) | database owner | vendored `sql/runtime/service.sql` |
| `grant` (product) | database owner | `sql/product/grants.sql` (implements [storage-release](storage-release.md)) |
| `proof` | service login | `sql/<db>/proof.sql`, then a connection attempt to `postgres` |
| `reconcile` | database owner | `sql/reconcile.sql` (read-only) |
| `bootstrap` | instance administrator, connected to `postgres` | `sql/bootstrap.sql` |

## Guard

Preflight runs in this order, each before any connection: configuration (2),
tools/SQL digests (3), the deadline (4), the ECS task identity from
`ECS_CONTAINER_METADATA_URI_V4` (`169.254.170.2` or loopback only, proxies
disabled; 6) and the CA material (owner-only regular file; 5).

- **Deadline.** The job ends by `min(RELEASE_NOT_AFTER, start + budget)`. psql gets
  that deadline less a 5-second stop grace; too little time left is
  `deadline_expired` without connecting.
- **Watchdog.** psql runs in its own process group with no stdin. At the session
  deadline the group receives SIGTERM, then SIGKILL after the grace, and the job
  reaps it (exit 124). A stop signal through tini does the same at once, even if it
  arrives while psql is starting (exit 143). Output collection after a kill is
  bounded too, so a process that left the group cannot hold the job open.
- **Session.** psql gets a constructed environment: `verify-full` TLS against the
  mounted CA, GSS encryption and client certificates disabled,
  `require_auth=scram-sha-256`, a 5-second connect timeout, the password only in
  `PGPASSWORD`, and `-X -w`, `ON_ERROR_STOP=1`, `VERBOSITY=sqlstate`. `PGOPTIONS`
  sets `statement_timeout` (at most 60 s and at most the remaining budget less a
  2-second reserve), `lock_timeout` (≤3 s), `idle_in_transaction_session_timeout`
  (≤10 s) and `client_connection_check_interval=1000`, so the server abandons a
  running statement within about a second of losing its client.
- **Verification.** `session_check.sql` fails with `RT001`–`RT005` unless the
  session's database, login, encryption (`pg_stat_ssl`), `application_name`
  (`release:<release>:<job>`) and every limit match. `refresh.sql` re-derives the
  limits from the deadline before each phase; the pinned Runtime script is not
  edited, so its few statements share the limit set just before it.
- **Outcomes.** A failure before connecting reports `sql_outcome: none` (exit 10
  for connection errors). Any failure after SQL may have run — SQL error, timeout,
  terminated session, watchdog stop, identity or result mismatch, or a budget
  exhausted after an earlier session — is `sql_outcome: unknown` (exit 11, 124 or
  143). Reasons come from a fixed table of
  SQLSTATEs and connection classes; server text is never logged.

## Receipts and logs

On stdout the job writes one line, `SENTRY_RELEASE_RECEIPT <json>`, in the
controller's fixed envelope: `schema` (`sentry.release-tools.job.v1`),
`release_id`, `job_id`, `task_arn`, `status` and `result`. Successful results:

| Job | `result` |
| --- | --- |
| grant | `database`, `principal`, `service_role`, `sql_digest` (the verified SQL digest) |
| proof | `database`, `principal`, `schema` (`goose:1,2,3` or `sentrysearch:<version>:<checksum16>`) |
| reconcile | `database`, `principal`, `schema`, `release_sessions`, `owner_sessions` |
| bootstrap | `database`, `principal`, `owner_role`, `service_role` |

A failure receipt carries only `reason` and `sql_outcome`, and only once the task
ARN is known; earlier failures write a `job_failed` log event instead. stderr
carries JSON events whose fields and values are allowlisted. The manifest
requires grant/proof jobs to use this schema, the job ids `<database>-<phase>`,
exactly these result keys, `sql_digest` equal to the pinned SQL hash, and proof
identities and schemas that agree with the migration and grant expectations.

`release_tools.receipt.extract_receipt` is the parser `release_aws.evidence` uses
on the exact stream of the observed task (`<job>/<container>/<task id>`). No
marker is a missing receipt. Two markers, a malformed line or extra envelope
fields are `ReceiptAmbiguous`, which the adapter reports as an ambiguous
observation.
Missing, stale (another task or release), ambiguous or failed receipts all hold.

## SQL programs

**Product grants** check that the session owns the dedicated database, the owner
and the service login have no privileged attributes or role memberships, no role
other than an administrator (superuser or `CREATEROLE`) belongs to either of them
(`INHERIT`, `SET` or `ADMIN`), the service login owns nothing, the six
product tables belong to the owner and a revision is recorded. They revoke
database, schema, table and sequence privileges from `PUBLIC` and the service
login, then grant `CONNECT`, schema `USAGE`, `SELECT/INSERT/UPDATE/DELETE` on the
five product tables and `SELECT` on `sentrysearch_schema_migrations`.

**Proofs** run inside a transaction that always rolls back. They require exact
inventories: login attributes, no memberships or owned objects, no `CREATE` or
`TEMPORARY` on the database, `USAGE` on `public` only, no other connectable
database except `template1`, table privileges equal to the grant contract,
column-only privileges equal to the Runtime script's column lists (including
SELECT checks on ordinary/partitioned tables, views and foreign tables, and
system columns), no grant options on database CONNECT, schema USAGE, tables or
columns, no sequence
privileges, no callable function outside the system schemas and no member of the
service login or owner other than an administrator (`RT101`–`RT108`). Intended reads and writes run on fixture rows. Each
forbidden operation must fail with `42501` (`RT110`–`RT131`): history deletion,
update and truncation; migration-history writes; ungranted columns; DDL in
`public`, a new schema, a temporary table, `ALTER`/`DROP` of owned tables; owner
transfer of a table or the database; `SET ROLE`, `GRANT` and `CREATE`/`ALTER ROLE`;
server-side programs and files. A second session to `postgres` must be refused for
lack of `CONNECT`.

**Reconciliation** runs read-only as the owner. It counts other sessions tagged
with this release in the database and the owner's sessions, and logs each one's
`pid`, `backend_start`, database, login, tag and state. Without
`pg_read_all_stats` another role's start time and state read `unknown`. It never cancels or
terminates a session; it informs the decision that an unknown outcome needs.

**Bootstrap** creates the owner and service logins (`NOINHERIT`, no attributes)
and a `template0` UTF-8 database owned by the owner, or verifies existing ones
without escalating them; neither login may belong to a role, and no role other
than the administrator may belong to either (`RT201`–`RT204`). It sets SCRAM
verifiers computed in the job (the plaintext never reaches SQL or logs; statement
logging can still record a verifier), revokes `PUBLIC` access to the target (as
its owner) and to the maintenance database, then fails with `RT205` if `PUBLIC`
can still reach either. It sets the owner's server-side defaults: 60 s
statements, 3 s lock waits, 60 s idle transactions and a 1 s client check, which
also bound migration sessions.

A non-superuser administrator, as on RDS, needs `SET` on the owner role to create
its database, and must own the maintenance database for that revoke; otherwise
bootstrap fails closed. The container suite proves both refusals and the success
once both hold. Grants and proofs reject any non-administrator member of the
owner or service login; still remove the administrator's `SET` membership after
bootstrap, since administrators are exempt from that check.

## Deployment wiring

[`deploy/aws-platform-fit`](../deploy/aws-platform-fit/README.md) defines one task
definition per grant, proof and reconciliation job when `release_tools` is set,
and [`deploy/aws-staging/releases`](../deploy/aws-staging/README.md) supplies it
per retained release. The deadline, budget, release and job ids, digests and
expected identity are task-definition values, so the immutable revision — not
output metadata — binds what runs. Bootstrap is not wired: it needs the
RDS-managed administrator secret and a separately approved administrator path.

## Local proof

```bash
uv run python -m pytest tests/test_release_tools.py
uv run python -m dev.check_release_tools --runtime-repo ../sentryruntime
```

For SQL-only regression coverage without Docker, explicitly run:

```bash
PG_BINDIR=/path/to/postgresql-16/bin SENTRYRUNTIME_REPO=../sentryruntime \
  uv run python -m pytest tests/release_tools_native.py -v
```

This creates a fresh private, Unix-socket-only PostgreSQL 16 cluster, applies the
Runtime migration SQL and product migration code, and stops the cluster in
`finally`. The stopped cluster is retained at the printed path. It never uses an
existing database. Shared native/container cases first demonstrate real excess
read or delegation authority, then require the proof to reject it and pass again
after cleanup. Column grant options are checked even when normal table access
masks the column privilege. This native suite does not prove image packaging,
verified TLS, the migration executable or job lifecycle behavior.

The image runner builds release-tools and both service images and passes their
immutable IDs to the tests. Both actual migration entry points run inside the
internal network: Runtime's `/app/migrate` and Search's
`python -m dev.migrate_storage`. They use separate owner credentials, verified
TLS and private read-only CA volumes. No database port is published and no host
connection to a Docker bridge address is required, including on Docker Desktop.

The unit suite drives real subprocesses (process-group kill of a SIGTERM-ignoring
grandchild, signal forwarding) and a fake psql. The container suite builds the
image and the Runtime image, then uses a disposable TLS PostgreSQL 16 server, a
stand-in metadata endpoint at `169.254.170.2` and an internal network. It covers
bootstrap and grant reruns (privileges unchanged), exact receipts, proofs and
their detection of excess privileges, each service login reaching only its own
database, the Runtime grant refusing the product database even with the product
owner's credentials, wrong password, wrong CA, wrong host name and plaintext
servers, empty or foreign init material, an expired deadline (no connection in the
server log), lock-wait limits, a hung session ended by the in-image deadline with
no controller (its transaction rolled back, then an idempotent rerun), stop
signals, a server query ending within seconds of its client's death (and running
on without the check interval), the statement limit, exact-session
reconciliation (including another role's session), roles able to act as a login,
an RDS-like administrator, no shipped bytecode and redacted output. Pass
`--build-ca-file` behind a
TLS-intercepting proxy.

October 7, 2026 ARM64 acceptance ran all **22 container cases** successfully.
The newly built release-tools local image index is
`sha256:729e62ccc8d68fa93af5b27f72b9c8af114053a38e3daea35b2565fd70e6c40d`;
its ARM64 manifest is
`sha256:78428a0531093b4baa3cd5f5700936ffbf46ddbecf629a5732d2848fcd928d0c`.
The rebuilt Runtime fixture and a retained Search fixture with 51 matching
packaged source files supplied the real migration entry points. Search's image
and dependency inputs were unchanged; this was not a fresh product-image build.
Local image identities are not registry publication receipts.

Trivy 0.75.0 with database updated `2026-10-07T07:38:55Z` reported **54 matches**
across 36 advisory IDs: **0 critical, 1 high, 23 medium, 30 low, 0 unknown**.
All were OS-package matches; none had a scanner-supplied fixed version. No ignore
file, finding suppression or risk acceptance was applied. The rebuilt Runtime
fixture had zero matches in the same database. See [image security](image-security.md#guarded-release-tools)
for the component and inventory limits.

## Not proven

The Terraform module caps the fixed deadline at seven days after the plan. IAM
cannot forbid `RunTask` overrides that would replace a job's environment. The
attended launcher sends none, the ECS adapter refuses to send any, and the
controller holds when an observed task reports one.

- Registry publication, signed provenance, cloud behavior and release approval.
  Docker Hub index pins were independently checked against Docker Hub; local
  build evidence, exported image bytes and SBOMs are retained. Scanner coverage
  does not independently clear the copied interpreter or static init binary.
  Tools-specific findings and the 27 retained Search-image matches remain
  unaccepted. Counts from different images or database dates are not additive.
- RDS behavior: the real administrator's memberships and ownership of `postgres`
  and `template1` (modelled locally by a CREATEROLE/CREATEDB login), `require_auth`
  with RDS authentication, `client_connection_check_interval` and statement
  logging.
- S3 cross-prefix denial (needs the storage-proof task and real IAM) and migration
  jobs' own in-image guards and receipts (Runtime and Search images).
- A task that never reaches its container (pending, image pull, init) is outside
  the in-image guard; the controller's deadline StopTask and the attended operator
  cover it. The 0.25 vCPU / 512 MiB allocation is unmeasured.
- The log and evidence adapters' behavior against real CloudWatch Logs (they are
  stub-tested only), measured log buffering, and any approval or risk decision.
