# Report artifacts on Cloudflare R2

Report Markdown and trace artifacts can be stored in Cloudflare R2 through its
S3-compatible API. The report service, API and worker use one artifact
protocol, `src.storage.artifact_store.ArtifactStore`. `S3StorageManager`
remains the default backend and behaves exactly as before.

## Selecting the backend

`src.storage.artifacts.artifact_store_from_environment` chooses the backend
when `ReportStorageService` is created:

| `SENTRYSEARCH_PLATFORM` | `ARTIFACT_BACKEND` | Result |
| --- | --- | --- |
| unset | unset or `s3` | the shared `S3StorageManager` (existing behavior) |
| unset | `r2` | `R2ArtifactStore` |
| `cloudflare` | `r2` | `R2ArtifactStore` |
| `cloudflare` | anything else, including unset | startup fails |
| any other value | | startup fails |
| | any other value | startup fails |

A process started by the Cloudflare entrypoint sets
`SENTRYSEARCH_PLATFORM=cloudflare` and never falls back to S3. Existing AWS and
local entrypoints keep their S3 default. Errors name the setting, never its
value.

R2 settings, all required with `ARTIFACT_BACKEND=r2` unless noted:

| Variable | Meaning |
| --- | --- |
| `R2_ACCOUNT_ID` | 32-character lowercase hexadecimal account id |
| `R2_ARTIFACT_BUCKET` | Artifact bucket; separate from any release-control bucket |
| `R2_JURISDICTION` | Optional: `eu`, `fedramp` or `us` for a jurisdictional bucket |
| `R2_ACCESS_KEY_ID` | The bucket-scoped R2 API token's access key id |
| `R2_SECRET_ACCESS_KEY` | The token's secret access key |
| `R2_CA_BUNDLE` | Optional absolute path of a readable CA bundle for TLS verification of the R2 endpoint; empty means the default trust store |

## Behavior

Keys and metadata are identical to the S3 backend:
`reports/<report-id>/artifacts/<sha256>.md` and `.json`. The same bytes map to
the same key, and different bytes never overwrite a published key.

The R2 client is built only from those settings. AWS profiles, shared config
and credential files, `AWS_ENDPOINT_URL*`, `HTTP(S)_PROXY`, `AWS_CA_BUNDLE`,
`REQUESTS_CA_BUNDLE`, extra botocore data directories (`AWS_DATA_PATH` and
`~/.aws/models`, which could replace the S3 endpoint rules or model),
`BOTOCORE_EXPERIMENTAL__PLUGINS` and client-side monitoring (`AWS_CSM_*`,
which would report each call's access key id over UDP) are ignored. It then passes the same
validation as the release-control client:

- region `auto`;
- the exact account (or jurisdictional) endpoint;
- path-style addressing;
- checksums only when an operation requires them, so no `aws-chunked` upload
  bodies or checksum trailers;
- bounded timeouts;
- explicit credentials.

Every request is also checked just before it is sent: its URL must be the
target's endpoint and bucket, without `.` or `..` path segments, or it is
refused. Idempotent calls may be
attempted up to three times.

Differences from the S3 backend:

- **Report ids** must be 1 to 128 characters of letters, digits, `-` and `_`,
  starting with a letter or digit.
- **Keys** must lie under `reports/<report-id>/` without empty, `.` or `..`
  segments.
- **Presigned URLs** are on the R2 S3 API domain and limited to 1 second to 7
  days. A longer lifetime is refused, not shortened.
- **Listing** follows continuation tokens, so reports with more than 1,000
  objects are listed completely. A page that does not state whether it is
  truncated, or a key that is outside the report's prefix or not a valid key,
  is an error, so nothing is deleted from an incomplete or suspect listing.
- **Downloads** read to the end of the body, so the length is checked against
  `Content-Length`, and content-addressed keys are checked against the SHA-256
  in the key. A folder marker or any other key under a report's prefix that is
  not a valid artifact key makes listing and deletion fail; nothing is deleted
  and the objects remain.
- **Deletion** lists the report's prefix and calls `DeleteObject` once per key.
  It does not use `DeleteObjects`, because that operation requires a request
  checksum that R2's documentation does not list. Every key is attempted, and a
  partial failure raises `ArtifactDeletionIncomplete`.

Product semantics are unchanged. Generation still treats artifact uploads as
best-effort, so a completed report does not prove every artifact was stored.
Report deletion still removes the database record when artifact deletion fails,
and logs the failure.

## Validation

All tests are offline and use `tests/r2_fakes.py`, which answers botocore's
`before-send` event.

- `tests/test_r2_artifacts.py`: keys identical to the S3 backend; round trip
  without checksum trailers; refused keys and report ids; presign host and
  limits; paginated deletion that leaves a neighboring report alone; per-key
  failure reporting; bounded retries; isolation from ambient AWS, proxy and CA
  settings, botocore data directories, plugins and client-side monitoring;
  requests refused when they resolve off the target; suspect listings;
  content-address checks; short reads.
- `tests/test_artifact_backend_selection.py`: the selection table above and
  the report service's use of the selected store.
- `tests/test_artifact_r2_offline.py`: an import guard on the new modules, and
  a subprocess that imports the API and worker with
  `SENTRYSEARCH_PLATFORM=cloudflare`, a poisoned environment and every socket
  entry point denied. It records zero attempts and drives the selected store.
- `tests/runtime_postgres_r2.py`: the PostgreSQL consistency suite
  re-collected over the R2 backend. Run it with
  `dev/check_runtime_consistency.py`.

Live R2 behavior (TLS, token scope, request acceptance) is not established by
these tests.
