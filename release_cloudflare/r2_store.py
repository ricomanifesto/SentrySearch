"""Release journal and environment lock store over R2's S3 API.

``release.journal.ObjectStore`` needs create-if-absent, compare-and-swap replace
and an exact-owner delete. R2 supports conditional ``PutObject`` (``If-Match``,
``If-None-Match``) but documents no conditional ``DeleteObject``. This store
therefore never deletes:

* Every object is a canonical envelope ``{"body", "cf_r2_store", "nonce",
  "state"}``. The random nonce makes every write's bytes unique, so a
  content-derived ETag can never repeat for a later incarnation of the same
  controller body (ABA).
* ``delete(key, if_match)`` is a conditional replace of the owner's object with
  a ``released`` marker. A concurrent owner change moves the ETag, so the
  replace fails with ``PreconditionFailed`` exactly as a conditional delete
  would.
* ``read`` reports a released marker as absent, and ``create`` re-acquires a
  released key by conditionally replacing that marker.
* Every committed release-journal version is retained as a create-only copy at
  ``journal-versions/<release>/<sha256>.json``: after a confirmed write of
  ``releases/<release>/journal.json``, and whenever the head is read (which
  fills the gap if a process stopped between its write and the copy). Copies
  therefore hold exactly the committed versions, including the newest, the
  role S3 object versioning plays; R2 does not implement versioning. A write
  whose outcome is unknown or refused is never copied. The dedicated top-level
  prefix lets one bucket-lock rule protect every copy without covering the
  mutable heads or locks; retention itself is bucket configuration.

A conditional write's 412 is ``PreconditionFailed``; so is a create that finds
a held object. A missing object (``NoSuchKey``) reads as absent. Every other
error, including a lost response or a copy that cannot be confirmed after a
committed write, raises ``ControlStoreUnavailable`` with a fixed message so the
controller stops and a rerun reloads the journal; nothing here retries.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any
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
VERSIONS_PREFIX = "journal-versions/"
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


def _canonical(document: dict[str, Any]) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")


def _status(error: ClientError) -> int | None:
    status = error.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return status if isinstance(status, int) else None


def version_key(key: str, envelope: bytes) -> str | None:
    """The create-only copy key for a journal version, or None for other keys."""
    match = JOURNAL_KEY.fullmatch(key)
    if match is None:
        return None
    digest = hashlib.sha256(envelope).hexdigest()
    return f"{VERSIONS_PREFIX}{match['release']}/{digest}.json"


def parse_envelope(raw: bytes) -> tuple[str, bytes]:
    """Return ``(state, controller body)`` or raise ``ControlStoreIntegrity``.

    Only the exact canonical ASCII bytes this store writes are accepted, so
    other encodings, byte-order marks and reformatted objects are foreign.
    """
    try:
        text = raw.decode("ascii")
        document = json.loads(text, object_pairs_hook=_unique_object)
    except (ValueError, UnicodeDecodeError):
        raise ControlStoreIntegrity("envelope is not canonical JSON") from None
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
    if _canonical(document) != raw:
        raise ControlStoreIntegrity("envelope is not canonical")
    try:
        return state, body.encode("utf-8")
    except UnicodeEncodeError:
        raise ControlStoreIntegrity("envelope body is not UTF-8") from None


class R2ObjectStore:
    """``release.journal.ObjectStore`` over an injected, validated R2 client."""

    def __init__(self, client: Any, target: R2Target) -> None:
        validate_client(client, target)
        self._client = client
        self._bucket = target.bucket

    # ObjectStore ---------------------------------------------------------------

    def create(self, key: str, body: bytes) -> str:
        envelope = self._envelope(HELD, body)
        try:
            etag = self._put(key, envelope, IfNoneMatch="*")
        except PreconditionFailed:
            current = self._get(key)
            if current is None:
                # Something removed the object between our writes; never guess.
                raise PreconditionFailed(key) from None
            raw, current_etag = current
            if parse_envelope(raw)[0] != RELEASED:
                raise
            etag = self._put(key, envelope, IfMatch=current_etag)
        self._retain(key, envelope)
        return etag

    def read(self, key: str) -> tuple[bytes, str] | None:
        current = self._get(key)
        if current is None:
            return None
        raw, etag = current
        state, body = parse_envelope(raw)
        if state == RELEASED:
            return None
        self._retain(key, raw)
        return body, etag

    def replace(self, key: str, body: bytes, *, if_match: str) -> str:
        envelope = self._envelope(HELD, body)
        etag = self._put(key, envelope, IfMatch=if_match)
        self._retain(key, envelope)
        return etag

    def delete(self, key: str, *, if_match: str) -> None:
        """Release exactly the owner's object by conditionally writing a marker."""
        self._put(key, self._envelope(RELEASED, b""), IfMatch=if_match)

    # Wire ------------------------------------------------------------------------

    def _new_nonce(self) -> str:
        return uuid.uuid4().hex

    def _envelope(self, state: str, body: bytes) -> bytes:
        nonce = self._new_nonce()
        if not isinstance(nonce, str) or not NONCE.fullmatch(nonce):
            raise ControlStoreIntegrity("nonce source")
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            raise ControlStoreIntegrity("controller body is not UTF-8") from None
        document = {"body": text, "cf_r2_store": ENVELOPE_VERSION, "nonce": nonce, "state": state}
        envelope = _canonical(document)
        if len(envelope) > MAX_OBJECT_BYTES:
            # Never commit an object that every later read must refuse.
            raise ControlStoreIntegrity("envelope exceeds the size bound")
        return envelope

    def _retain(self, key: str, envelope: bytes) -> None:
        """Keep a create-only copy of a committed journal version, or stop."""
        copy_key = version_key(key, envelope)
        if copy_key is None:
            return
        try:
            self._put(copy_key, envelope, IfNoneMatch="*")
        except PreconditionFailed:
            existing = self._get(copy_key)
            if existing is None or existing[0] != envelope:
                raise ControlStoreIntegrity("journal version copy differs") from None
        except ControlStoreUnavailable:
            raise ControlStoreUnavailable("journal version retention unconfirmed") from None

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
            if error.response.get("Error", {}).get("Code") == "NoSuchKey":
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
