# Deterministic local report canary

## Outcome and proof

An authenticated synthetic request must become a completed, evaluated report
through the actual API, product outbox, TLS-authenticated runtime, supervised
worker, generation/evidence gates, product database and artifact client. The
audience is a release reviewer; the demo is an executable test, not a cloud
deployment or a report-quality benchmark.

```sh
uv run python dev/check_deterministic_canary.py --runtime-repo ../sentryruntime
```

For already built local images, add `--skip-build --search-image <local-image>
--runtime-image <local-image>`. The runner resolves immutable local image IDs
before testing, strips inherited provider authority and disables dotenv/shared
AWS credential loading. Builds require at least 3 GiB host headroom. Docker and
both image-build source checkouts are prerequisites. `--build-ca-file` has the
same optional build-only trust-bundle behavior as the service-image runner.

## Real components and fixture boundaries

The suite creates an internal Docker network with no published ports or external
route. Both PostgreSQL databases use verified TLS and distinct owner/app roles;
Runtime uses HTTPS with separate product-scoped producer/worker tokens. Named
material/scratch volumes exercise root initialization followed by non-root,
read-only application containers. Separate release profiles receive only the
PostgreSQL CA, not service identity or scratch volumes.

Only files under `tests/` are mounted read-only for the canary. The release image
allowlist excludes all fixtures and retains the ordinary API/worker entrypoints.
There is no production synthetic-mode switch.

- The auth fixture verifies disposable signed tokens and expiry over the real
  Supabase client's `get_user` HTTP path. It deliberately returns an untrusted
  user-metadata admin claim; normal app-metadata/ownership authorization remains
  unchanged. This is not hosted Supabase/JWKS/revocation proof.
- The real OpenRouter client parses canned HTTP responses from an exact-URL
  `httpx.MockTransport`. Generation and the independent evaluator still run.
  Fixed scores prove evaluator execution and persistence, not model quality.
- Source capture uses its existing fetcher seam, a mock HTTP response and a
  module-local DNS answer. Real public-IP validation, extraction, hashing,
  classification and excerpt gates remain active. The CISA-shaped fixture URL
  is an exact test key, not a fetched CISA source or real intelligence. Negative
  tests reject private DNS, mismatched excerpts and non-operational content.
- The real boto3 client uploads, reads, lists and deletes against an in-memory
  object HTTP fixture. It does not validate SigV4, IAM, encryption, versioning,
  retention or AWS behavior. All data is disposable synthetic data.

The importable test-only worker target installs external-boundary fixtures inside
the spawned child, then calls the unchanged production worker loop. Fixtures
are permanent regression inputs, never a deployable service. Revisit them when
provider/source contracts change; do not promote them into release images as a
shortcut for a cloud canary.

## Assertions and limits

The Docker test checks paused admission without reserving a row, missing/invalid/
expired-token rejection, authenticated creation, durable pending intent,
completed generation and independent evaluation, source SHA, report content and
quality, content-addressed artifact readback, terminal runtime state, and
idempotent redispatch without generation replay. It checks wrong-owner read/
delete denial, owner deletion, database removal and direct artifact absence.
The worker receipt asserts exactly three research, one synthesis, seven section
evaluation, one consistency and one source request.

The same-task `python -m dev.check_worker_readiness` command proves ready state.
The broader service-image suite also proves that a busy draining worker becomes
unready while liveness stays healthy, then times out, cleans up its child and
recovers the same run after restart. Those failure/recovery proofs complement
the successful canary; not every fault is repeated here.

The readiness helper is a bounded POSIX one-shot CLI, not a listener or sidecar.
It returns sanitized JSON and nonzero for unready, malformed, slow or unavailable
peers. Run it in the worker's network namespace. A separate Fargate task cannot
reach that loopback listener. Controlled same-task invocation and release receipt
collection are not implemented; the [offline release controller](release-controller.md)
only defines the receipts it requires. ECS Exec remains disabled and liveness is not
redefined as readiness.

The optional owner-only task definitions and operator grant ordering are in
[`deploy/aws-platform-fit`](../deploy/aws-platform-fit/README.md). Mocks and
local containers do not prove Fargate scheduling, AWS secret delivery, real IAM,
endpoints, identity-service operation, restore, alert delivery or rollout.
Release risk remains held under [the risk ledger](image-risk-dispositions.md).
No application push, publication, deployment or live-provider use is implied.
