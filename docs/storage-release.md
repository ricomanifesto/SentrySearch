# Product storage release contract

SentrySearch owns its PostgreSQL report schema, runtime-dispatch outbox, reader
state, and S3 artifacts. SentryRuntime owns a separate execution ledger. This
release does not migrate product data into the runtime or change cloud resources.

## Release order

1. Pause new report/evaluation admission and drain every existing writer,
   including older API versions that ran startup migrations. Retain a backup and
   agree on a maintenance window before touching a deployed database.
2. Supply the schema-owner role to a separate release process through the normal
   `DB_*` settings. Run `uv run python -m dev.migrate_storage`.
3. Supply the restricted application role and run
   `uv run python -m dev.migrate_storage --check`. This command is read-only.
4. Start API and worker with application credentials. Inspect readiness before
   resuming admission. The worker checks storage before claiming any work.

The command supports empty databases, the existing unversioned additive schema,
and databases at any earlier supported revision. Revisions are an ordered list in
`src/storage/schema.py`, one SQL file each under `src/storage/migrations/`, with a
SHA-256 checksum per file. Applied SQL is never edited; changes are appended as a
new revision. The applied revisions must be an exact prefix of the supported list,
otherwise the release refuses to run. DDL for every pending revision, one
reader-state reconciliation, and every revision/checksum marker share one
transaction. A failed step rolls back the release. A concurrent migrator fails immediately on the advisory lock;
database lock waits are limited to 3 seconds and individual statements to 60
seconds. Re-running an applied revision checks it without repeating the backfill.

Backfill reads in batches of 250 and flushes each batch, but commits once. The
transaction's WAL and total duration still scale with retained data. Statement
limits are not a whole-release deadline; measure the dataset and use an operator
deadline before a deployed migration. Never perform the release under live writers.

Readiness requires the exact supported revision/checksum sequence and the ability
to query every column of every mapped table without reading rows. Missing, newer, or changed SQL revisions
and missing columns fail closed. The check uses a read-only transaction, 2-second
statement limits, and a 250-ms lock-wait limit. It is not a full schema, index,
constraint, row-integrity, or backup audit. It does not repair anything.

The application role needs schema USAGE and SELECT/INSERT/UPDATE/DELETE on
`reports`, `report_runtime_dispatches`, `report_disposition_events`,
`report_searches`, `report_tags`, and the revision 2 tables `report_sources`,
`report_claims`, `report_claim_support`, `report_indicator_observations`,
`report_source_observations`, `report_findings`, and `report_artifacts`, plus
SELECT on `sentrysearch_schema_migrations`. Without the revision 2 grants the
read-only check fails closed, because readiness queries every mapped table. It must not own those objects or have schema
CREATE, role-management, or superuser privileges. The schema-owner role is never
an API/worker secret. Actual role provisioning and privilege auditing remain
deployment tasks; the local proof exercises this split in a disposable database.

Rollback means pause, drain, and restore a schema-compatible binary/configuration.
There is no down-migration command. Do not unstamp a revision or restore an older
database over completed work. After a release failure, correct the cause and rerun.

## Revision 2: flat evidence rows and stored reader state

Revision 2 (`002_profile_rows.sql`) is additive. It drops and rewrites nothing,
and the existing JSONB columns stay populated during this transition.

| Object | Contents |
| --- | --- |
| `reports.reader_state_version`, `eligible_for_judgment`, `eligible_for_acceptance`, `eligible_for_handoff` | Derived reader state alongside `review_status` |
| `report_sources` | Cited primary sources: identity, display fields, snapshot fingerprint and capture metadata, source purpose |
| `report_claims` | One row per high-risk claim: stable `claim_id`, class, field, `ordinal` (the legacy `claimIndex`), value, evidence role, and the attribution record's explicit `source_ids` (kept even when a retained schema 2–4 record has no support excerpt) |
| `report_claim_support` | Verbatim support excerpt per claim and source, with snapshot SHA-256 and verification state |
| `report_indicator_observations` | Deterministic infrastructure decisions, linked to a claim when one survives |
| `report_source_observations` | Every researched source's purpose decision, including named exclusions |
| `report_findings` | Blocking gate findings classified as `safety` or `coverage` |
| `report_artifacts` | The current Markdown and trace object per report, with `policy_status` and `policy_version` |

Writers compute reader state with the domain rules in `src/domain/reports.py` in
the same transaction that changes its inputs, on the report row they already
lock. That covers generation finalization, evaluation completion and failure,
generation failure, and analyst dispositions, so a new judgment or a new
evaluation vintage changes handoff eligibility atomically. The evidence rows and
artifact rows are replaced in those same transactions. No provider call or
object upload runs while the row lock is held, and lock scope is unchanged.

The release backfill (`reconcile_reader_state`) fills the new tables from the
stored `threat_data`, `web_sources`, and `evidence_admissibility` JSONB through
the same profile parser the evidence gate uses. Retained schema-4 support keeps an
unknown verification state; nothing is inferred. Retained Markdown is read once to
compute its content policy. The backfill takes no row locks, because the release
runs with writers drained. If the artifact client is unavailable in the release
process, the artifact is recorded as `policy_status = 'unknown'` rather than
failing the release.

The admin categorization endpoint runs the same reconciliation online, while
writers may be active. It never relies on draining. Each report is reread under
its row lock and committed on its own, so a concurrent finalization or evaluation
either commits before the reread or waits for that report's reconciliation; its
rows are never replaced with a projection of older JSONB. A stale Markdown object
is read with no session open, and the result is recorded only if that object is
still the report's current Markdown when the lock is held. A report still locked
after the application's 3-second lock-wait limit is skipped and counted as
`locked_report_skips` in the logged summary; run the endpoint again to cover it.

### Revision 2 privileges

Role provisioning stays a deployment task; the migration does not grant or revoke
anything. In the same maintenance window, after the release command and before the
read-only check, the schema owner grants the application role access to the new
tables. On Supabase, tables the owner creates in `public` also inherit default
privileges for the Data API roles (`anon`, `authenticated`). Only the application
role reads these tables, so revoke those privileges in the same step:

```sql
GRANT SELECT, INSERT, UPDATE, DELETE ON report_sources, report_claims,
  report_claim_support, report_indicator_observations, report_source_observations,
  report_findings, report_artifacts TO <application role>;
REVOKE ALL ON report_sources, report_claims, report_claim_support,
  report_indicator_observations, report_source_observations, report_findings,
  report_artifacts FROM anon, authenticated;
```

Omit the `REVOKE` where those roles do not exist. This read-only query lists any
product table the Data API roles can still read; expect no rows:

```sql
SELECT c.relname, r.rolname
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_roles r ON r.rolname IN ('anon', 'authenticated')
WHERE n.nspname = 'public' AND c.relkind = 'r'
  AND (c.relname LIKE 'report%' OR c.relname = 'sentrysearch_schema_migrations')
  AND has_table_privilege(r.oid, c.oid, 'SELECT');
```

### Content policy versioning

The content policy (the virtual-event promotion marker) is evaluated when an
artifact is written, and the result is stored as `policy_status` (`allowed`,
`excluded`, or `unknown`) with `policy_version` on the artifact row. Reads filter
on the stored value instead of downloading content. This is a behavior change: a
policy change does not take effect on retained artifacts at deploy time. Bump
`ARTIFACT_POLICY_VERSION` in `src/core/report_content_policy.py` and run the
existing reconciliation command (the admin categorization endpoint, or the release
backfill). It recomputes every artifact whose stored version is older, plus any
`unknown` result. Reader-state rule changes work the same way through
`READER_STATE_VERSION` in `src/domain/reports.py`.

### Reads from rows and stored columns

- **Collections:** list, search, count, the analytics and dashboard endpoints, and handoff export filter on the stored columns and on `report_artifacts.policy_status` in SQL. They never download report objects and never recompute review state. A row whose current Markdown has no `allowed` decision is withheld; that includes `excluded`, `unknown`, and a decision recorded for a different object key. Run the release (or the reconciliation command) with artifact credentials so retained Markdown resolves to `allowed` or `excluded` rather than staying `unknown`.
- **`eligible_for_handoff` filter:** reads the stored column. The SQL re-encoding of the eligibility rules is removed.
- **Popular tags:** counted with `GROUP BY` over `report_tags`. Writers keep `report_tags` equal to each report's search tags, and the reconciliation backfills it for retained reports.
- **Quality-score buckets:** computed with `width_bucket` in one aggregate query.
- **Analytics records:** select scalar columns only, including the stored `review_status`.
- **Report detail:** projects the source rail, claim links, and evidence observations and findings from the row tables. A claim's source links come from its stored `source_ids`, so a retained schema 2–4 claim that cites a source without an excerpt keeps that link; support rows supply the excerpts. `threat_data` remains a rendered artifact for the inspection panel. The detail and download paths still read the Markdown object, because they return it.
- **Citations:** the Markdown renderer places each attributed high-risk claim's citation (`[S1](#source-S1)`, or **General practice**) beside the claim. The reader no longer re-attaches citations by text search. Retained Markdown rendered before this change keeps its stored text without inline citations; the source rail and claim ledger are unchanged.

## Database configuration

- `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD` construct a structured
  SQLAlchemy URL; reserved password characters are not URL syntax.
  Ambient `PGHOSTADDR` and `PGSERVICE` routing overrides are rejected.
- Remote hosts and `ENVIRONMENT=staging|production` require
  `DB_SSLMODE=verify-full` and `DB_SSLROOTCERT` pointing to the PEM trust bundle.
  libpq validates both CA and hostname. `prefer`, `require`, and `verify-ca` are
  rejected. GSS encryption is disabled so the explicit TLS contract applies.
- `DB_SSLMODE=disable` is allowed only for loopback or Unix-socket development.
  TCP is required for verified TLS. A remote host cannot inherit plaintext.
- Deployed environments require explicit host, database, user, password, and
  `DB_DEBUG=false`. The application does not choose a production target by default.
- Pool acquisition and connection setup use 5-second limits. Application
  connections use a 10-second statement limit and 3-second lock-wait limit.
  Release and readiness transactions override those statement/lock limits locally.
- Bound SQL parameters are hidden. Connection, readiness, and release diagnostics
  omit raw driver errors. This is not a repository-wide log-redaction audit.

### Railway database TLS

The repository includes the public Supabase production CA at
`certs/supabase-prod-ca-2021.crt`; its [provenance and fingerprints](../certs/README.md)
are recorded alongside it. For a Supabase deployment, include that directory in
the image and set these service variables before starting the new release:

```text
DB_SSLMODE=verify-full
DB_SSLROOTCERT=/app/certs/supabase-prod-ca-2021.crt
```

The absolute path assumes the Railway image's application root is `/app`.
If the build uses a different root, use that root's absolute path or
`certs/supabase-prod-ca-2021.crt` relative to the `python run_api.py` working
directory. Confirm the file exists and is readable in the built image. The
existing connection settings and credentials do not need to change. Other
database providers must use their own reviewed CA bundle.

Approve the deployment and production variable changes through the normal
release process. Rebuild from the revision containing the certificate; an old
image will not acquire the file from a variable change or restart. Do not change
the healthcheck or SSL enforcement to work around a failure. Missing CA paths fail
during configuration; unreadable or malformed PEM files and invalid server
identities fail when libpq connects.

A credential-free preflight with OpenSSL 3 can verify the actual database endpoint
before deployment (substitute its existing host and port):

```bash
openssl s_client -starttls postgres -connect "$DB_HOST:$DB_PORT" \
  -servername "$DB_HOST" -verify_hostname "$DB_HOST" -verify_return_error \
  -no-CAfile -no-CApath -no-CAstore \
  -CAfile certs/supabase-prod-ca-2021.crt </dev/null
```

Require `Verify return code: 0 (ok)`. Disabling the default CA sources ensures the
bundled CA alone validates the endpoint's TLS identity. This does not prove
database authentication, schema compatibility, or application readiness. After
the approved deployment, require Railway `SUCCESS`, no startup TLS errors, and
`/api/ready` returning 200. Handle any subsequent schema or credential error as a
separate release prerequisite; this certificate fix does not perform migrations.

## Artifact credentials

Set `AWS_S3_BUCKET` explicitly in staging/production. `AWS_REGION` defaults to
`us-east-1`. Boto3 resolves credentials from its normal session provider chain:
environment, shared profile, web identity, container/task role, or instance role.
Temporary environment credentials require `AWS_SESSION_TOKEN` along with the
access key and secret. Do not configure partial credentials or put secrets in URLs.

Initialization resolves deferred credentials once, then constructs the client
without passing a frozen credential copy, preserving SDK refresh. Missing or
partial credentials fail visibly; storage is never silently disabled. The worker
always requires artifact initialization. Staging/production API startup does too.
S3 operations use bounded connect/read timeouts and three total SDK attempts.

Credential resolution may contact the configured identity provider or metadata
service. Startup success proves credential availability, not bucket authorization,
region correctness, expiry/rotation recovery, or successful object persistence.
No S3 mutation is performed by startup or schema readiness. The separately approved
canary must prove least-privilege read/write access and rotation with real identities.

## Local proofs

```bash
uv run python dev/check_local_setup.py
uv run python dev/check_runtime_consistency.py --runtime-repo ../sentryruntime
uv run python dev/check_runtime_consistency.py --runtime-repo ../sentryruntime --tls
```

`tests/storage_postgres.py` includes the revision 2 proofs: an empty database
migrates to `[1, 2]`; a revision-1 database upgrades in place and backfills rows,
reader state, and `unknown` artifact policy from retained JSONB; missing, future,
or changed revisions and dropped revision 2 objects fail readiness; and the
writers dual-write rows and reader state, including handoff withdrawal when a new
evaluation vintage begins.

The consistency runner requires PostgreSQL 16 installed through Homebrew and the
companion runtime checkout. It creates disposable databases. The TLS variant also
starts disposable loopback PostgreSQL servers with generated fixture certificates:
trusted succeeds, while wrong CA, wrong hostname, expired certificate, and
plaintext-only servers fail. No cloud, real credentials, or model calls are used.
Local proof is not deployed TLS, IAM, backup, migration-window, or canary evidence.
