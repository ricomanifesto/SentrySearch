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

The command supports empty databases and the existing unversioned additive
schema. Revision 1 freezes the baseline SQL. DDL, reader-state reconciliation,
and the revision/checksum marker share one transaction. A failed step rolls back
the release. A concurrent migrator fails immediately on the advisory lock;
database lock waits are limited to 3 seconds and individual statements to 60
seconds. Re-running an applied revision checks it without repeating the backfill.

Backfill reads in batches of 250 and flushes each batch, but commits once. The
transaction's WAL and total duration still scale with retained data. Statement
limits are not a whole-release deadline; measure the dataset and use an operator
deadline before a deployed migration. Never perform the release under live writers.

Readiness requires the exact supported revision/checksum and the ability to query
every model column without reading rows. Missing, newer, or changed SQL revisions
and missing columns fail closed. The check uses a read-only transaction, 2-second
statement limits, and a 250-ms lock-wait limit. It is not a full schema, index,
constraint, row-integrity, or backup audit. It does not repair anything.

The application role needs schema USAGE and SELECT/INSERT/UPDATE/DELETE on
`reports`, `report_runtime_dispatches`, `report_disposition_events`,
`report_searches`, and `report_tags`, plus SELECT on
`sentrysearch_schema_migrations`. It must not own those objects or have schema
CREATE, role-management, or superuser privileges. The schema-owner role is never
an API/worker secret. Actual role provisioning and privilege auditing remain
deployment tasks; the local proof exercises this split in a disposable database.

Rollback means pause, drain, and restore a schema-compatible binary/configuration.
There is no down-migration command. Do not unstamp a revision or restore an older
database over completed work. After a release failure, correct the cause and rerun.

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

The consistency runner requires PostgreSQL 16 installed through Homebrew and the
companion runtime checkout. It creates disposable databases. The TLS variant also
starts disposable loopback PostgreSQL servers with generated fixture certificates:
trusted succeeds, while wrong CA, wrong hostname, expired certificate, and
plaintext-only servers fail. No cloud, real credentials, or model calls are used.
Local proof is not deployed TLS, IAM, backup, migration-window, or canary evidence.
