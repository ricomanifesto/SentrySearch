"""Release journal and environment lock store over R2's S3 API.

``release.journal.ObjectStore`` needs create-if-absent, compare-and-swap replace
and an exact-owner delete. R2 supports conditional ``PutObject`` (``If-Match``,
``If-None-Match``) but documents no conditional ``DeleteObject``. This store
therefore never deletes:

* Every object is an envelope ``{"body", "cf_r2_store", "nonce", "state"}``.
  The random nonce makes every write's bytes unique, so a content-derived ETag
  can never repeat for a later incarnation of the same controller body (ABA).
* ``delete(key, if_match)`` is a conditional replace of the owner's object with
  a ``released`` marker. A concurrent owner change moves the ETag, so the
  replace fails with ``PreconditionFailed`` exactly as a conditional delete
  would.
* ``read`` reports a released marker as absent, and ``create`` re-acquires a
  released key by conditionally replacing that marker.
* Before a release journal is replaced, the version being superseded is read,
  confirmed to be the committed head carrying the expected ETag, and stored as
  a create-only copy named by its SHA-256 under ``journal-versions/``. Copies
  therefore only ever hold committed versions, like S3's noncurrent object
  versions, which R2 does not implement; the head holds the current version.
  Copying the new envelope instead would retain attempts that never committed.
  Retention of the copies is enforced by bucket configuration, not here.

Only HTTP 412 is a precondition failure. Every other error, including a lost
response, raises ``ControlStoreUnavailable`` with a fixed message so the
controller stops and a rerun reloads the journal; nothing here retries.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Callable
import uuid

from botocore.exceptions import BotoCoreError, ClientError

from release.journal import PreconditionFailed
from release_cloudflare.r2_client import R2Target, validate_client

ENVELOPE_VERSION = 1
HELD = "held"
RELEASED = "released"
ENVELOPE_KEYS = frozenset({"body", "cf_r2_store", "nonce", "state"})
NONCE = re.compile(r"[0-9a-f]{32}")
JOURNAL_KEY = re.compile(r"releases/(?P<release>[A-Za-z0-9-]{1,64})/journal\.json")
MAX_OBJECT_BYTES = 16 * 1024 * 1024


class ControlStoreIntegrity(Exception):
    """A stored object is not an envelope this store wrote; nothing is trusted."""


class ControlStoreUnavailable(Exception):
    """The request failed or its outcome is unknown; reload before acting again."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ControlStoreIntegrity("duplicate envelope field")
        document[key] = value
    return document


def _status(error: ClientError) -> int | None:
    status = error.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return status if isinstance(status, int) else None


def version_key(key: str, envelope: bytes) -> str | None:
    """The create-only copy key for a superseded journal version, or None."""
    match = JOURNAL_KEY.fullmatch(key)
    if match is None:
        return None
    digest = hashlib.sha256(envelope).hexdigest()
    return f"releases/{match['release']}/journal-versions/{digest}.json"


def parse_envelope(raw: bytes) -> tuple[str, bytes]:
    """Return ``(state, controller body)`` or raise ``ControlStoreIntegrity``."""
    try:
        document = json.loads(raw, object_pairs_hook=_unique_object)
    except (ValueError, UnicodeDecodeError):
        raise ControlStoreIntegrity("envelope is not JSON") from None
    if not isinstance(document, dict) or set(document) != ENVELOPE_KEYS:
        raise ControlStoreIntegrity("envelope fields")
    version = document["cf_r2_store"]
    if type(version) is not int or version != ENVELOPE_VERSION:
        raise ControlStoreIntegrity("envelope version")
    nonce, state, body = document["nonce"], document["state"], document["body"]
    if not isinstance(nonce, str) or not NONCE.fullmatch(nonce):
        raise ControlStoreIntegrity("envelope nonce")
    if state not in (HELD, RELEASED) or not isinstance(body, str):
        raise ControlStoreIntegrity("envelope state")
    if state == RELEASED and body:
        raise ControlStoreIntegrity("released marker carries a body")
    return state, body.encode("utf-8")


class R2ObjectStore:
    """``release.journal.ObjectStore`` over an injected, validated R2 client."""

    def __init__(
        self,
        client: Any,
        target: R2Target,
        *,
        nonce_factory: Callable[[], str] | None = None,
    ) -> None:
        validate_client(client, target)
        self._client = client
        self._bucket = target.bucket
        self._nonce = nonce_factory or (lambda: uuid.uuid4().hex)

    # ObjectStore ---------------------------------------------------------------

    def create(self, key: str, body: bytes) -> str:
        envelope = self._envelope(HELD, body)
        try:
            return self._put(key, envelope, IfNoneMatch="*")
        except PreconditionFailed:
            pass
        current = self._get(key)
        if current is None:
            # Something removed the object between our writes; never guess.
            raise PreconditionFailed(key)
        raw, etag = current
        state, _ = parse_envelope(raw)
        if state != RELEASED:
            raise PreconditionFailed(key)
        return self._put(key, envelope, IfMatch=etag)

    def read(self, key: str) -> tuple[bytes, str] | None:
        current = self._get(key)
        if current is None:
            return None
        raw, etag = current
        state, body = parse_envelope(raw)
        if state == RELEASED:
            return None
        return body, etag

    def replace(self, key: str, body: bytes, *, if_match: str) -> str:
        envelope = self._envelope(HELD, body)
        self._retain_superseded(key, if_match)
        return self._put(key, envelope, IfMatch=if_match)

    def delete(self, key: str, *, if_match: str) -> None:
        """Release exactly the owner's object by conditionally writing a marker."""
        self._put(key, self._envelope(RELEASED, b""), IfMatch=if_match)

    # Wire ------------------------------------------------------------------------

    def _envelope(self, state: str, body: bytes) -> bytes:
        nonce = self._nonce()
        if not isinstance(nonce, str) or not NONCE.fullmatch(nonce):
            raise ControlStoreIntegrity("nonce factory")
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            raise ControlStoreIntegrity("controller body is not UTF-8") from None
        document = {"body": text, "cf_r2_store": ENVELOPE_VERSION, "nonce": nonce, "state": state}
        return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")

    def _retain_superseded(self, key: str, if_match: str) -> None:
        """Copy the committed journal version that ``if_match`` names, or refuse."""
        if JOURNAL_KEY.fullmatch(key) is None:
            return
        current = self._get(key)
        if current is None or current[1] != if_match:
            # The conditional replace would fail; copy nothing uncommitted.
            raise PreconditionFailed(key)
        raw, _ = current
        parse_envelope(raw)
        copy_key = version_key(key, raw)
        if copy_key is None:  # unreachable: the key matched JOURNAL_KEY above
            raise ControlStoreIntegrity("journal key")
        try:
            self._put(copy_key, raw, IfNoneMatch="*")
        except PreconditionFailed:
            existing = self._get(copy_key)
            if existing is None or existing[0] != raw:
                raise ControlStoreIntegrity("journal version copy differs") from None

    def _put(self, key: str, envelope: bytes, **condition: str) -> str:
        try:
            response = self._client.put_object(
                Bucket=self._bucket,
                Key=key,
                Body=envelope,
                ContentType="application/json",
                **condition,
            )
        except ClientError as error:
            if _status(error) == 412:
                raise PreconditionFailed(key) from None
            raise ControlStoreUnavailable(f"put failed (HTTP {_status(error)})") from None
        except BotoCoreError:
            raise ControlStoreUnavailable("put outcome unknown") from None
        etag = response.get("ETag")
        if not isinstance(etag, str) or not etag:
            raise ControlStoreUnavailable("put returned no ETag")
        return etag

    def _get(self, key: str) -> tuple[bytes, str] | None:
        try:
            response = self._client.get_object(Bucket=self._bucket, Key=key)
            raw = response["Body"].read(MAX_OBJECT_BYTES + 1)
        except ClientError as error:
            if _status(error) == 404:
                return None
            raise ControlStoreUnavailable(f"get failed (HTTP {_status(error)})") from None
        except BotoCoreError:
            raise ControlStoreUnavailable("get outcome unknown") from None
        if len(raw) > MAX_OBJECT_BYTES:
            raise ControlStoreIntegrity("object exceeds the size bound")
        etag = response.get("ETag")
        if not isinstance(etag, str) or not etag:
            raise ControlStoreUnavailable("get returned no ETag")
        return raw, etag
