"""Deliberately broken R2 store variants; each must fail the check named for it.

Every check runs first against the real store as a positive control, so a
variant that passes a check would mean the check observes nothing. The variants
are the shortcuts an R2 port of an S3-shaped store invites.
"""

from __future__ import annotations

import json
from typing import Any, Callable

import pytest

from release.controller import RecoveryAuthorization, ReleaseHalted
from release.journal import PreconditionFailed, verify_chain
from release_cloudflare.r2_client import R2ClientRejected
from release_cloudflare.r2_store import (
    HELD,
    RELEASED,
    ControlStoreUnavailable,
    R2ObjectStore,
    parse_envelope,
    version_key,
)
from tests.r2_fakes import AMBIENT, CONTROL, Fault, R2Backend, make_client
from tests.release_fakes import SimulatedCrash, sha
from tests.test_release_r2_controller import JOURNAL, LOCK, VERSIONS, R2Rig, r2_rig


class GuardViolation(AssertionError):
    """A named guard did not hold."""


def unvalidated(cls: type, client: Any, **attrs: Any) -> R2ObjectStore:
    """Build a store without client validation, as a careless port would."""
    store = object.__new__(cls)
    store._client = client
    store._bucket = CONTROL.bucket
    store._nonce = attrs.get("nonce_factory") or (lambda: __import__("uuid").uuid4().hex)
    return store


# Broken variants -------------------------------------------------------------------


class UnconditionalDelete(R2ObjectStore):
    """Compare on read, then delete whatever is there."""

    def delete(self, key: str, *, if_match: str) -> None:
        current = self._get(key)
        if current is None or current[1] != if_match:
            raise PreconditionFailed(key)
        self._client.delete_object(Bucket=self._bucket, Key=key)


class IfMatchDelete(R2ObjectStore):
    """Send S3's conditional delete; R2 documents no such condition."""

    def delete(self, key: str, *, if_match: str) -> None:
        self._client.delete_object(Bucket=self._bucket, Key=key, IfMatch=if_match)


class MarkerAsHeld(R2ObjectStore):
    """Treat a released marker as a live lock."""

    def read(self, key: str):
        current = self._get(key)
        if current is None:
            return None
        raw, etag = current
        return parse_envelope(raw)[1], etag

    def create(self, key: str, body: bytes) -> str:
        return self._put(key, self._envelope(HELD, body), IfNoneMatch="*")


class HeadBeforeCopy(R2ObjectStore):
    """Move the journal head first, then copy the superseded version."""

    def replace(self, key: str, body: bytes, *, if_match: str) -> str:
        current = self._get(key)
        etag = self._put(key, self._envelope(HELD, body), IfMatch=if_match)
        if current is not None:
            copy_key = version_key(key, current[0])
            if copy_key is not None:
                self._put(copy_key, current[0], IfNoneMatch="*")
        return etag


class CopyNewEnvelope(R2ObjectStore):
    """Copy the new envelope before the head write: retains uncommitted attempts."""

    def replace(self, key: str, body: bytes, *, if_match: str) -> str:
        envelope = self._envelope(HELD, body)
        copy_key = version_key(key, envelope)
        if copy_key is not None:
            self._put(copy_key, envelope, IfNoneMatch="*")
        return self._put(key, envelope, IfMatch=if_match)


# Checks ----------------------------------------------------------------------------


def rig_with(store_cls: type) -> R2Rig:
    r = r2_rig()
    r.store_cls = store_cls
    return r


def check_transfer_race(store_cls: type) -> None:
    """An authorized lock transfer racing finalization must survive it."""
    r = rig_with(store_cls)
    fired: list[str] = []

    def transfer(method, key, body):
        releasing = method == "DELETE" or (
            method == "PUT" and json.loads(body).get("state") == RELEASED
        )
        if key == LOCK and releasing and not fired:
            fired.append("recovery")
            r.controller("session-b").recover(
                RecoveryAuthorization(
                    prior_session_id="session-a",
                    lock_etag=r.backend.etag(LOCK),
                    fence_evidence_sha256=sha("session-a terminated"),
                    authorized_by="fixture-operator",
                )
            )

    r.backend.before = transfer
    halted = None
    try:
        r.controller().run()
    except ReleaseHalted as error:
        halted = error.code
    if not fired:
        raise GuardViolation("the race was never exercised")
    current = r.backend.get(LOCK)
    if current is None:
        raise GuardViolation("the transferred lock was deleted")
    state, body = parse_envelope(current[0])
    if state != HELD or json.loads(body)["session_id"] != "session-b":
        raise GuardViolation("the transferred lock does not belong to session-b")
    if halted is None:
        raise GuardViolation("finalization reported success after the lock moved")
    if halted != "lock_release_conflict":
        raise GuardViolation(f"unexpected halt {halted}")


def check_no_delete_requests(store_cls: type) -> None:
    r = rig_with(store_cls)
    try:
        r.controller().run()
    except ReleaseHalted:
        pass
    if r.backend.requests("DELETE"):
        raise GuardViolation("DeleteObject was sent to R2")


def check_aba(store: R2ObjectStore) -> None:
    body = b'{"release_id":"r","session_id":"s","acquired_at":"2026-10-08T15:00:00Z"}'
    first = store.create(LOCK, body)
    store.delete(LOCK, if_match=first)
    store.create(LOCK, body)
    try:
        store.replace(LOCK, b"stale writer", if_match=first)
    except PreconditionFailed:
        return
    raise GuardViolation("a stale ETag from an earlier incarnation was accepted")


def check_reacquire(store: R2ObjectStore) -> None:
    store.delete(LOCK, if_match=store.create(LOCK, b"first"))
    try:
        store.create(LOCK, b"second")
    except PreconditionFailed:
        raise GuardViolation("a released key could not be re-acquired") from None


def check_crash_after_marker(store_cls: type) -> None:
    r = rig_with(store_cls)
    r.backend.faults.append(Fault("PUT", LOCK, "crash_after", match_state=RELEASED))
    with pytest.raises(SimulatedCrash):
        r.controller().run()
    try:
        outcome = r.controller().run()
    except ReleaseHalted as error:
        raise GuardViolation(f"finalization not confirmed: {error.code}") from None
    if outcome.state != "held_paused":
        raise GuardViolation(f"finalization not confirmed: {outcome.state}")


def check_client_validated(build: Callable[[], Any]) -> None:
    try:
        R2ObjectStore(build(), CONTROL)
    except R2ClientRejected:
        return
    raise GuardViolation("an unsafe client was accepted")


def check_lost_response_is_unknown(store: R2ObjectStore, backend: R2Backend) -> None:
    etag = store.create(LOCK, b"one")
    backend.faults.append(Fault("PUT", LOCK, "lost_response"))
    try:
        store.replace(LOCK, b"two", if_match=etag)
    except ControlStoreUnavailable:
        return
    except PreconditionFailed:
        raise GuardViolation("a lost response was reported as a definite conflict") from None
    raise GuardViolation("a lost response was reported as success")


def check_versions_complete_after_crash(store_cls: type) -> None:
    """A crash at any journal write never loses a superseded committed version."""
    r = rig_with(store_cls)
    r.backend.faults.append(Fault("PUT", JOURNAL, "crash_after", skip=6))
    with pytest.raises(SimulatedCrash):
        r.controller().run()
    r.controller().run()
    assert_committed_copies(r)


def check_copies_are_committed(store_cls: type) -> None:
    """A refused journal write never leaves a retained copy."""
    r = rig_with(store_cls)
    r.backend.faults.append(Fault("PUT", JOURNAL, "lost_response", skip=9))
    with pytest.raises((ControlStoreUnavailable, ReleaseHalted)):
        r.controller().run()
    r.controller().run()
    assert_committed_copies(r)


def assert_committed_copies(r: R2Rig) -> None:
    head = json.loads(parse_envelope(r.backend.raw(JOURNAL))[1])
    verify_chain(head)
    lengths = []
    for key in r.backend.keys(VERSIONS):
        document = json.loads(parse_envelope(r.backend.raw(key))[1])
        n = len(document["events"])
        if document["events"] != head["events"][:n]:
            raise GuardViolation("a retained copy is not committed history")
        lengths.append(n)
    if sorted(lengths) != list(range(1, len(head["events"]))):
        raise GuardViolation(f"superseded versions missing: {sorted(lengths)}")


# Positive controls and broken variants -----------------------------------------------


def test_real_store_passes_every_check(monkeypatch):
    check_transfer_race(R2ObjectStore)
    check_no_delete_requests(R2ObjectStore)
    backend = R2Backend()
    check_aba(R2ObjectStore(make_client(backend), CONTROL))
    check_reacquire(R2ObjectStore(make_client(R2Backend()), CONTROL))
    check_crash_after_marker(R2ObjectStore)
    backend = R2Backend()
    check_lost_response_is_unknown(R2ObjectStore(make_client(backend), CONTROL), backend)
    check_versions_complete_after_crash(R2ObjectStore)
    check_copies_are_committed(R2ObjectStore)


@pytest.mark.parametrize("variant", [UnconditionalDelete, IfMatchDelete])
def test_delete_shortcuts_lose_a_transferred_lock(variant):
    with pytest.raises(GuardViolation, match="deleted|success"):
        check_transfer_race(variant)
    with pytest.raises(GuardViolation, match="DeleteObject"):
        check_no_delete_requests(variant)


def test_if_match_delete_is_unsafe_when_r2_ignores_the_condition():
    # Whichever way R2 answers, the store must not depend on it.
    with pytest.raises(GuardViolation):
        check_transfer_race(IfMatchDelete)


def test_no_nonce_envelope_accepts_a_stale_etag_under_content_etags():
    store = R2ObjectStore(
        make_client(R2Backend(etags="md5")), CONTROL, nonce_factory=lambda: "0" * 32
    )
    with pytest.raises(GuardViolation, match="stale ETag"):
        check_aba(store)


def test_marker_read_as_held_blocks_reacquire_and_finalization():
    with pytest.raises(GuardViolation, match="re-acquired"):
        check_reacquire(MarkerAsHeld(make_client(R2Backend()), CONTROL))
    with pytest.raises(GuardViolation, match="not confirmed"):
        check_crash_after_marker(MarkerAsHeld)


def test_default_checksum_client_is_rejected_and_its_trailer_is_refused():
    backend = R2Backend()
    check_client_validated(lambda: make_client(backend, request_checksum_calculation=None))
    careless = unvalidated(R2ObjectStore, make_client(backend, request_checksum_calculation=None))
    with pytest.raises(ControlStoreUnavailable):
        careless.create(LOCK, b"x")
    assert backend.log[-1].status == 400 and "x-amz-trailer" in backend.log[-1].headers


def test_retrying_client_is_rejected_and_reports_a_lost_response_as_a_conflict():
    backend = R2Backend()
    check_client_validated(
        lambda: make_client(backend, retries={"mode": "standard", "total_max_attempts": 3})
    )
    careless = unvalidated(
        R2ObjectStore, make_client(backend, retries={"mode": "standard", "total_max_attempts": 3})
    )
    with pytest.raises(GuardViolation, match="definite conflict"):
        check_lost_response_is_unknown(careless, backend)


def test_ambient_endpoint_client_is_rejected(monkeypatch):
    monkeypatch.setenv("AWS_ENDPOINT_URL_S3", "https://ambient-endpoint.invalid")
    backend = R2Backend()
    client = make_client(backend, endpoint=AMBIENT, ignore_configured_endpoint_urls=None)
    assert client.meta.endpoint_url == "https://ambient-endpoint.invalid"
    check_client_validated(lambda: client)


def test_head_moved_before_its_copy_loses_a_committed_version():
    with pytest.raises(GuardViolation, match="superseded versions missing"):
        check_versions_complete_after_crash(HeadBeforeCopy)


def test_copying_the_new_envelope_retains_an_uncommitted_attempt():
    with pytest.raises(GuardViolation, match="not committed history"):
        check_copies_are_committed(CopyNewEnvelope)


def test_every_unsafe_client_is_caught_by_validation():
    backend = R2Backend()
    cases: list[dict[str, Any]] = [
        {"request_checksum_calculation": None},
        {"response_checksum_validation": None},
        {"retries": {"mode": "standard", "total_max_attempts": 2}},
        {"s3": {"addressing_style": "virtual"}},
        {"connect_timeout": None},
    ]
    for overrides in cases:
        check_client_validated(lambda overrides=overrides: make_client(backend, **overrides))
    check_client_validated(lambda: make_client(backend, endpoint="https://example.invalid"))
    with pytest.raises(GuardViolation, match="unsafe client was accepted"):
        check_client_validated(lambda: make_client(backend))
