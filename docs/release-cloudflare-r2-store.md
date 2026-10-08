# Release control store on Cloudflare R2

`release_cloudflare.r2_store.R2ObjectStore` implements the release controller's
`release.journal.ObjectStore` protocol over R2's S3-compatible API. The
controller, journal and lock code in `release/` are unchanged; this document
describes how the store provides the semantics they already require.

## Why an adapter is needed

The controller needs three conditional operations: create an object only if it
is absent, replace it only if its ETag still matches, and delete it only if its
ETag still matches (exact-owner release of the environment lock). R2 supports
conditional `PutObject` with `If-None-Match: *` and `If-Match`, returning HTTP
412 when the condition fails. R2 documents **no** conditional `DeleteObject`.
A read followed by an unconditional delete is unsafe: if an authorized recovery
transfers the lock between the read and the delete, the delete removes the new
owner's lock and the controller records a successful release.

## Protocol

**Envelope.** Every object the store writes is canonical JSON:

```json
{"body":"<controller bytes as UTF-8>","cf_r2_store":1,"nonce":"<32 hex>","state":"held"}
```

The nonce is random per write, so no two writes have identical bytes and a
content-derived ETag can never repeat for a later incarnation of the same
controller body (an ABA hazard: a stale `If-Match` from an earlier lock must
not match a newer lock). `read` returns the exact controller bytes. A
malformed, foreign or duplicate-keyed object raises `ControlStoreIntegrity`.

**Release by marker.** `delete(key, if_match)` writes a `released` envelope
with an empty body using `If-Match`. If anything changed the object, the write
fails with 412 and the store raises `PreconditionFailed`, which is the same
signal a conditional delete would give. The store never sends `DeleteObject` or
`DeleteObjects`.

**Absent versus released.** `read` reports a released marker as absent.
`create` first tries `If-None-Match: *`; on 412 it reads the object and, only if
it is a released marker, replaces it with `If-Match` set to the marker's ETag.
Two creators racing for one marker produce exactly one owner.

**Superseded journal versions.** Before a release journal
(`releases/<id>/journal.json`) is replaced, the store reads the current head,
confirms it is the committed version carrying the caller's expected ETag, and
writes it to `releases/<id>/journal-versions/<sha256>.json` with
`If-None-Match: *` (an identical existing copy counts as present). Only then is
the head replaced. Copies therefore hold exactly the committed, superseded
versions, the role S3 object versioning plays for noncurrent versions; R2 does
not implement versioning. Copying the new envelope instead would retain
attempts whose conditional write was refused, which would make the evidence
disagree with the committed journal. Retention of copies is a bucket setting,
not enforced by this module.

**Errors.** Only HTTP 412 becomes `PreconditionFailed`. Timeouts, connection
errors, lost responses and every other status raise `ControlStoreUnavailable`
with a fixed message and no provider text. The store never retries; the
controller treats the error as uncertainty and a rerun reloads the journal.

## Client contract

The store never constructs a client. `release_cloudflare.r2_client.validate_client`
rejects an injected botocore client unless it:

- is the `s3` service with region `auto` and the exact endpoint
  `https://<account>.r2.cloudflarestorage.com` (or the `eu`, `fedramp` or `us`
  jurisdictional endpoint) for the target, which also rejects an endpoint taken
  from ambient configuration such as `AWS_ENDPOINT_URL_S3`;
- uses `request_checksum_calculation` and `response_checksum_validation` of
  `when_required`, so no `aws-chunked` body or checksum trailer is sent (R2's
  `PutObject` compatibility does not list them);
- makes exactly one attempt per call (`total_max_attempts=1`), because an SDK
  retry after a lost response can turn an applied write into a false 412;
- has bounded connect (≤ 10 s) and read (≤ 30 s) timeouts, path-style
  addressing and SigV4;
- holds explicit static credentials rather than the SDK credential chain.

## Validation

All tests are offline. `tests/r2_fakes.py` answers botocore's `before-send`
event, so real request serialization and signing run without network access.
It models R2's documented conditional `PutObject`, strongly consistent reads and
missing conditional delete. Where the documentation is silent, it is
pessimistic: ETags derived from content, a `DeleteObject` that ignores
`If-Match`, and refusal of checksum trailers.

- `tests/test_release_r2_store.py`: the store contract, including marker
  release and re-acquisition, racing creators, distinct ETags across
  incarnations, request shapes, superseded-version copies, integrity failures
  and unknown outcomes.
- `tests/test_release_r2_controller.py`: the unchanged controller over the
  store, including the full release, a failed job, a lock transfer racing
  finalization, a crash after the marker write, another release's lock at any
  age, and lost responses on committed journal writes.
- `tests/test_release_r2_guards.py`: deliberately broken store and client
  variants (unconditional delete, `If-Match` delete, no nonce, marker treated
  as held, default checksums, SDK retries, ambient endpoint, head moved before
  its copy, copying the new envelope). Each fails a named check that the real
  store passes.
- `tests/test_release_r2_offline.py`: an AST guard on the R2 modules (no
  sessions, environment reads, dotenv or delete calls, and a restricted import
  set), plus a subprocess release run with poisoned AWS, Cloudflare, Wrangler,
  proxy and dotenv settings and every socket entry point denied. It records zero
  attempts.

## Requires verification against live R2

The offline model cannot establish:

1. Concurrent `If-Match` writes with one ETag yield exactly one success.
2. Concurrent `If-None-Match: *` writes yield exactly one success.
3. R2's response to `DeleteObject` carrying `If-Match`. The store never sends
   one.
4. How R2 derives ETags. The store is independent of it by design.
5. Whether R2 accepts flexible-checksum trailers. The client contract avoids
   them.
6. That a bucket lock rule on `journal-versions/` refuses overwrite and
   deletion.
7. That bucket-scoped tokens cannot cross buckets.
