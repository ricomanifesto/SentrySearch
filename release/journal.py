"""Hash-chained release journal and environment lock over conditional object writes.

The store contract matches S3 conditional writes: create with If-None-Match: *,
replace and delete with If-Match. CAS coordinates cooperative controllers only;
it cannot fence an ECS or SQL call that a stale process already sent. Versioned
objects are recoverable evidence, not tamper-proof attestation.
"""

from __future__ import annotations

import json
from typing import Any, Protocol

from release.manifest import ReleaseRejected, canonical_sha256


class PreconditionFailed(Exception):
    """The object already exists, or its ETag no longer matches."""


class ObjectStore(Protocol):
    def create(self, key: str, body: bytes) -> str: ...

    def read(self, key: str) -> tuple[bytes, str] | None: ...

    def replace(self, key: str, body: bytes, *, if_match: str) -> str: ...

    def delete(self, key: str, *, if_match: str) -> None: ...


def journal_key(release_id: str) -> str:
    return f"releases/{release_id}/journal.json"


def lock_key(environment: str) -> str:
    return f"locks/{environment}.json"


def encode(document: dict[str, Any]) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_chain(document: dict[str, Any]) -> None:
    """Each event names its sequence and the hash of its predecessor."""
    try:
        prior = document["manifest_sha256"]
        if not document["events"]:
            raise ReleaseRejected("journal_integrity")
        for sequence, event in enumerate(document["events"], start=1):
            if event["sequence"] != sequence or event["prior_sha256"] != prior:
                raise ReleaseRejected("journal_integrity")
            prior = canonical_sha256(event)
    except (KeyError, TypeError):
        raise ReleaseRejected("journal_integrity") from None


class Journal:
    """Single-object journal advanced only by ETag-conditional replacement."""

    def __init__(self, store: ObjectStore, key: str) -> None:
        self.store = store
        self.key = key
        self.document: dict[str, Any] = {}
        self.etag = ""

    @property
    def events(self) -> list[dict[str, Any]]:
        return self.document["events"]

    def load(self) -> bool:
        found = self.store.read(self.key)
        if found is None:
            return False
        body, self.etag = found
        try:
            document = json.loads(body)
        except ValueError:
            raise ReleaseRejected("journal_integrity") from None
        if not isinstance(document, dict):
            raise ReleaseRejected("journal_integrity")
        verify_chain(document)
        self.document = document
        return True

    def create(self, header: dict[str, Any], first: dict[str, Any]) -> None:
        """Create the journal and its first event in one conditional write."""
        event = {"sequence": 1, "prior_sha256": header["manifest_sha256"], **first}
        document = {**header, "events": [event]}
        self.etag = self.store.create(self.key, encode(document))
        self.document = document

    def append(self, event: dict[str, Any], **header: Any) -> dict[str, Any]:
        """Append one event (optionally updating header fields) or raise PreconditionFailed."""
        events = self.events
        prior = canonical_sha256(events[-1]) if events else self.document["manifest_sha256"]
        stored = {"sequence": len(events) + 1, "prior_sha256": prior, **event}
        document = {**self.document, **header, "events": [*events, stored]}
        self.etag = self.store.replace(self.key, encode(document), if_match=self.etag)
        self.document = document
        return stored
