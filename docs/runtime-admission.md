# Runtime admission and transport

## Explicit admission

The API reads `SENTRYSEARCH_EXECUTION_MODE` before new report creation or manual
evaluation reservation. The default is `paused`, not legacy execution. Existing
installations must choose a mode before new work is accepted.

| Mode | New report | Manual evaluation retry |
| --- | --- | --- |
| `paused` (default) | 503, no reservation | 503, no reservation |
| `runtime` | Report and dispatch intent committed together | Runtime-owned report queues to worker; legacy report returns 409 |
| `legacy` | Explicit in-process background job | Runtime-owned report queues to worker; legacy report runs in-process |

An empty or unknown configured mode, runtime mode without
an endpoint, ambiguous endpoints, and unsafe URLs fail with a generic 503 on
admission. No report or evaluation reservation is made. A missing runtime URL
never enables legacy generation. Legacy admission rejects runtime endpoint or
CA settings in the API environment to catch contradictory configuration.

Authentication still runs before the admission handler. Reads remain available
under their existing authentication and database requirements. Admission pause
does not block report reads, revoke runtime leases, remove dispatch intent,
change evidence/publication rules, or cancel accepted work.

This is process environment configuration, not a live fleet-wide switch.
Change it through controlled API process replacement; drain older API instances
before relying on pause across the fleet. Already-admitted work may finish.
Worker configuration is separate: workers may continue dispatch, reconciliation,
generation, and evaluation of accepted work while API admission is paused.
Use the worker supervisor's SIGTERM drain when execution itself must stop.

The API chooses routing from explicit mode only for **new reports**. Durable
dispatch ownership governs existing runtime-managed evaluation retries, including
when the API has explicit legacy admission and no runtime URL. Runtime admission
never sends a legacy report to the inline evaluator. Legacy-report migration is
not part of this change.

## Worker transport

Configure exactly one endpoint in the worker environment:

- `SENTRYRUNTIME_LOCAL_URL`: HTTP or HTTPS on `127.0.0.1`, `localhost`, or `::1`.
  Both service tokens may be absent for the unauthenticated local demo; if one is
  set, both must be set. Do not forward a local unauthenticated runtime remotely.
- `SENTRYRUNTIME_URL`: explicit HTTPS authority. Requires distinct
  `SENTRYRUNTIME_PRODUCER_TOKEN` and `SENTRYRUNTIME_WORKER_TOKEN`, each matching a
  runtime credential scoped to `sentrysearch/generate_report/v1`. The dispatcher
  uses producer authority; the executor uses worker authority.

For runtime admission, the API needs the same selected endpoint setting to
validate routing configuration. It does not contact the runtime or need worker
tokens, a CA file, or runtime database access. Worker trust configuration is
validated before application jobs and storage/provider clients are initialized.
The CLI loads its local `.env` before spawning the supervised worker; explicit
environment values retain precedence. Set `PYTHON_DOTENV_DISABLED=1` when the
deployment environment must be the only configuration source.

URLs must contain only a scheme and authority, with an optional single trailing
slash. Userinfo, other paths, query/fragment delimiters, whitespace/control
characters, ambiguous/invalid ports, encoded authorities, and plaintext remote
URLs are rejected. The remote client owns its HTTP transport; it cannot be
replaced with an injected client that disables certificate verification.

HTTPS verifies both the certificate chain and server hostname/IP SAN. Optional
`SENTRYRUNTIME_CA_FILE` supplies a PEM CA bundle. When unset/empty in the environment,
HTTPX uses its default CA bundle, with environment trust overrides disabled.
An explicitly selected missing, malformed, or empty bundle fails startup; it
does not fall back to another trust source. Custom contexts require TLS 1.2 or
newer. `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `SSL_CERT_FILE`, and `SSL_CERT_DIR`
do not configure this transport. No verification-off switch is provided.

Requests use a two-second connect and five-second network-operation timeout.
These are HTTPX operation timeouts, not a total generation deadline. Worker
phase/supervisor deadlines remain the outer lifecycle bound. Redirects are never
followed, including same-origin redirects. Rejected credentials, scope, redirects,
or other non-retryable HTTP client errors stop the worker for operator correction.
Network/TLS failures and server errors remain unavailable/retryable under existing
worker phase bounds. Errors do not echo request URLs, bearer values, trust paths,
or raw transport exception chains.

Runtime unavailability after API admission leaves the durable intent pending;
the API does not run a backup inline job. Recovery retries the same report/run
identity. A certificate or token configuration change requires replacing all
affected worker processes; issuance, renewal, expiry alerts, rotation delivery,
and safe fleet replacement remain deployment responsibilities.

## Proof and rollout boundary

`uv run python dev/check_local_setup.py` covers admission, configuration, real
local TLS handshakes, and existing product behavior without external services.
OpenSSL must be available for disposable certificate fixtures.

Run both variants of the PostgreSQL/runtime harness in
[runtime consistency](runtime-consistency.md#local-proof). TLS runs exercise the
real Go server and the product worker's client configuration; S3 and model work
remain fake. Loopback hosting of these proofs does not establish deployed
network isolation, certificate rotation, database TLS, or platform lifecycle.

For rollout or rollback: pause API admissions, drain relevant writers, preserve
databases/outbox/artifacts, replace only compatible binaries/configuration,
reconcile, then explicitly resume. Never use unsetting a URL as a stop switch,
down-migrate active data, or return to an unfenced writer. Keep
`TODO(sentryruntime-cutover)` legacy paths until an approved deployed canary,
legacy-report migration, and compatible rollback are verified.
