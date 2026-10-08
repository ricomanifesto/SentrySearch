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

**Envelope.** Every object the store writes is canonical JSON (sorted keys, no
whitespace, ASCII):

```json
{"body":"<controller bytes as UTF-8>","cf_r2_store":1,"nonce":"<32 hex>","state":"held"}
```

The nonce is random per write, so no two writes have identical bytes and a
content-derived ETag can never repeat for a later incarnation of the same
controller body (an ABA hazard: a stale `If-Match` from an earlier lock must
not match a newer lock). The nonce source is not configurable. `read` returns
the exact controller bytes. Anything other than the store's own canonical bytes
(another encoding, a byte-order mark, reformatting, duplicate keys, a body that
is not UTF-8) raises `ControlStoreIntegrity`. Writes larger than the 16 MiB
read bound are refused before any request.

**Release by marker.** `delete(key, if_match)` writes a `released` envelope
with an empty body using `If-Match`. If anything changed the object, the write
fails with 412 and the store raises `PreconditionFailed`, which is the same
signal a conditional delete would give. The store never sends `DeleteObject` or
`DeleteObjects`.

**Absent versus released.** `read` reports a released marker as absent.
`create` first tries `If-None-Match: *`; on 412 it reads the object and, only if
it is a released marker, replaces it with `If-Match` set to the marker's ETag.
Two creators racing for an absent key or for one marker produce exactly one
owner.

**Retained journal versions.** Every committed version of a release journal
(`releases/<id>/journal.json`) is kept as a create-only copy at
`journal-versions/<id>/<sha256>.json`:

- after each write of the journal that R2 confirms with 200;
- whenever the journal head is read, which fills the gap left by a process that
  stopped between a confirmed write and its copy (an identical existing copy
  counts as present).

A write that is refused or whose outcome is unknown is never copied, so the
copies are exactly the committed history, including the newest and terminal
versions. They keep that history if the head is later overwritten by an
unconditional writer, the role S3 object versioning plays; R2 does not
implement versioning. If a copy cannot be confirmed after a committed write,
the store raises `ControlStoreUnavailable`, so the controller stops and a rerun
retains the head when it reads it. Copies live under one top-level prefix that
holds no mutable key, so a single bucket-lock rule on `journal-versions/` can
make them immutable without blocking journal or lock updates. That rule is
bucket configuration, not enforced by this module.

**Errors.** A conditional write's HTTP 412 becomes `PreconditionFailed`, as
does a `create` that finds a held object. A missing object (`NoSuchKey`) reads
as absent. Every other outcome raises `ControlStoreUnavailable` with a fixed
message and no provider text, including a missing bucket, 409, 403, 5xx,
redirects, timeouts and lost responses. The store never retries; the controller
treats the error as uncertainty and a rerun reloads the journal.

## Client contract

The store never constructs a client. `release_cloudflare.r2_client.validate_client`
rejects an injected botocore client unless it:

- is the `s3` service with region `auto` and the exact endpoint
  `https://<account>.r2.cloudflarestorage.com` (or the `eu`, `fedramp` or `us`
  jurisdictional endpoint) for the target, which also rejects an endpoint taken
  from ambient configuration such as `AWS_ENDPOINT_URL_S3`;
- verifies TLS (the default trust store or an explicit CA bundle) and uses no
  proxy, which also rejects proxies picked up from `HTTP(S)_PROXY`;
- uses `request_checksum_calculation` and `response_checksum_validation` of
  `when_required`, so no `aws-chunked` body or checksum trailer is sent (R2's
  `PutObject` compatibility does not list them);
- makes one attempt per call (`total_max_attempts=1`), because an SDK retry
  after a lost response can turn an applied write into a false 412; botocore's
  S3 region redirector can still resend once, but only after a redirect-shaped
  error response, which did not apply the write;
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
  incarnations, canonical-envelope enforcement, request shapes and client
  validation, retention of every committed journal version and its survival of
  an outside head overwrite, integrity failures, and unknown or non-412
  outcomes.
- `tests/test_release_r2_controller.py`: the unchanged controller over the
  store, including the full release, a failed job, a lock transfer racing
  finalization, a crash after the marker write, another release's lock at any
  age, lost responses on committed journal writes, and the terminal journal
  surviving an overwrite of the head.
- `tests/test_release_r2_guards.py`: deliberately broken store and client
  variants (unconditional delete, `If-Match` delete, `DeleteObjects`, constant
  nonce, marker treated as held, superseded-only retention, no read retention,
  copying the new envelope before writing it, default checksums, SDK retries,
  ambient endpoint, disabled TLS verification, a proxy). Each fails a named
  check that the real store passes.
- `tests/test_release_r2_offline.py`: an AST guard over every module in the
  package, with a reviewed per-module import allowlist and forbidden session,
  credential, network, subprocess, dynamic-import, file and delete constructs,
  shown to catch a corpus of violations; plus a subprocess release run with
  poisoned AWS, Cloudflare, Wrangler, proxy and dotenv settings and every socket
  entry point denied. It records zero attempts.

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
8. That the ETag returned by `PutObject` is string-equal to the one a later
   `GetObject` returns.
9. The status for `If-Match` on a missing key: 412, or 404 as S3 returns. The
   store treats 404 on a write as unavailable.
10. Whether R2 ever answers a conditional write with 409.
11. That `If-None-Match: *` on an existing, bucket-locked copy returns 412
    rather than 403 or 409.

Each of items 8 to 11 fails closed if R2 differs, but could stall a release
until the store is adjusted.
