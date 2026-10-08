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
    JOURNAL_KEY,
    RELEASED,
    ControlStoreUnavailable,
    R2ObjectStore,
    parse_envelope,
    version_key,
)
from tests.r2_fakes import AMBIENT, CONTROL, Fault, R2Backend, make_client
from tests.release_fakes import JobPlan, SimulatedCrash, sha
from tests.test_release_r2_controller import JOURNAL, LOCK, VERSIONS, R2Rig, r2_rig


class GuardViolation(AssertionError):
    """A named guard did not hold."""


def unvalidated(cls: type, client: Any) -> R2ObjectStore:
    """Build a store without client validation, as a careless port would."""
    store = object.__new__(cls)
    store._client = client
    store._bucket = CONTROL.bucket
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


class BatchDelete(R2ObjectStore):
    """Compare on read, then use DeleteObjects, which R2 supports unconditionally."""

    def delete(self, key: str, *, if_match: str) -> None:
        current = self._get(key)
        if current is None or current[1] != if_match:
            raise PreconditionFailed(key)
        self._client.delete_objects(Bucket=self._bucket, Delete={"Objects": [{"Key": key}]})


class ConstantNonce(R2ObjectStore):
    """Drop the per-write nonce."""

    def _new_nonce(self) -> str:
        return "0" * 32


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


class SupersededOnly(R2ObjectStore):
    """Copy only the version being replaced: the newest is never retained."""

    def create(self, key: str, body: bytes) -> str:
        return self._put(key, self._envelope(HELD, body), IfNoneMatch="*")

    def read(self, key: str):
        current = self._get(key)
        if current is None:
            return None
        raw, etag = current
        state, body = parse_envelope(raw)
        return None if state == RELEASED else (body, etag)

    def replace(self, key: str, body: bytes, *, if_match: str) -> str:
        if JOURNAL_KEY.fullmatch(key):
            current = self._get(key)
            if current is None or current[1] != if_match:
                raise PreconditionFailed(key)
            copy_key = version_key(key, current[0])
            if copy_key is not None:
                try:
                    self._put(copy_key, current[0], IfNoneMatch="*")
                except PreconditionFailed:
                    pass
        return self._put(key, self._envelope(HELD, body), IfMatch=if_match)


class NoReadRetention(R2ObjectStore):
    """Copy after each confirmed write, but never fill a gap when reading."""

    def read(self, key: str):
        current = self._get(key)
        if current is None:
            return None
        raw, etag = current
        state, body = parse_envelope(raw)
        return None if state == RELEASED else (body, etag)


class CopyNewEnvelope(R2ObjectStore):
    """Copy the new envelope before writing it: retains attempts that never committed."""

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
        releasing = (
            method in ("DELETE", "POST")
            or (method == "PUT" and json.loads(body).get("state") == RELEASED)
        ) and key in (LOCK, "")
        if releasing and not fired:
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


def check_no_deleting_requests(store_cls: type) -> None:
    r = rig_with(store_cls)
    try:
        r.controller().run()
    except ReleaseHalted:
        pass
    if r.backend.deleting_requests():
        raise GuardViolation("a deleting request was sent to R2")


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


def committed_copies(r: R2Rig) -> list[dict]:
    head = json.loads(parse_envelope(r.backend.raw(JOURNAL))[1])
    verify_chain(head)
    documents = []
    for key in r.backend.keys(VERSIONS):
        document = json.loads(parse_envelope(r.backend.raw(key))[1])
        n = len(document["events"])
        if document["events"] != head["events"][:n]:
            raise GuardViolation("a retained copy is not committed history")
        documents.append(document)
    lengths = sorted(len(document["events"]) for document in documents)
    if lengths != list(range(1, len(head["events"]) + 1)):
        raise GuardViolation(f"committed versions missing: {lengths}")
    return documents


def check_versions_complete_after_crash(store_cls: type) -> None:
    """A crash between a committed head write and its copy loses no version."""
    r = rig_with(store_cls)
    r.backend.faults.append(Fault("PUT", JOURNAL, "crash_after", skip=6))
    with pytest.raises(SimulatedCrash):
        r.controller().run()
    r.controller().run()
    committed_copies(r)


def check_copies_are_committed(store_cls: type) -> None:
    """A refused journal write never leaves a retained copy."""
    r = rig_with(store_cls)
    r.backend.faults.append(Fault("PUT", JOURNAL, "lost_response", skip=9))
    with pytest.raises((ControlStoreUnavailable, ReleaseHalted)):
        r.controller().run()
    r.controller().run()
    committed_copies(r)


def check_terminal_survives_overwrite(store_cls: type) -> None:
    """The final journal of a held release is recoverable after the head is lost."""
    r = rig_with(store_cls)
    r.ecs.plans[r.document["jobs"][2]["task"]["task_definition"]] = JobPlan(exits={"init": 1})
    r.controller().run()
    final = json.loads(parse_envelope(r.backend.raw(JOURNAL))[1])
    r.backend.put_raw(JOURNAL, b"overwritten by an unconditional writer", '"outside"')
    retained = [
        json.loads(parse_envelope(r.backend.raw(key))[1]) for key in r.backend.keys(VERSIONS)
    ]
    if final not in retained:
        raise GuardViolation("the terminal journal was lost with the head")


# Positive controls and broken variants -----------------------------------------------


def test_real_store_passes_every_check():
    check_transfer_race(R2ObjectStore)
    check_no_deleting_requests(R2ObjectStore)
    check_aba(R2ObjectStore(make_client(R2Backend()), CONTROL))
    check_reacquire(R2ObjectStore(make_client(R2Backend()), CONTROL))
    check_crash_after_marker(R2ObjectStore)
    backend = R2Backend()
    check_lost_response_is_unknown(R2ObjectStore(make_client(backend), CONTROL), backend)
    check_versions_complete_after_crash(R2ObjectStore)
    check_copies_are_committed(R2ObjectStore)
    check_terminal_survives_overwrite(R2ObjectStore)


@pytest.mark.parametrize("variant", [UnconditionalDelete, IfMatchDelete, BatchDelete])
def test_delete_shortcuts_lose_a_transferred_lock(variant):
    with pytest.raises(GuardViolation, match="deleted|success"):
        check_transfer_race(variant)
    with pytest.raises(GuardViolation, match="deleting request"):
        check_no_deleting_requests(variant)


def test_constant_nonce_accepts_a_stale_etag_under_content_etags():
    with pytest.raises(GuardViolation, match="stale ETag"):
        check_aba(ConstantNonce(make_client(R2Backend(etags="md5")), CONTROL))


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
    retrying: dict[str, Any] = {"retries": {"mode": "standard", "total_max_attempts": 3}}
    check_client_validated(lambda: make_client(backend, **retrying))
    careless = unvalidated(R2ObjectStore, make_client(backend, **retrying))
    with pytest.raises(GuardViolation, match="definite conflict"):
        check_lost_response_is_unknown(careless, backend)


def test_ambient_endpoint_client_is_rejected(monkeypatch):
    monkeypatch.setenv("AWS_ENDPOINT_URL_S3", "https://ambient-endpoint.invalid")
    backend = R2Backend()
    client = make_client(backend, endpoint=AMBIENT, ignore_configured_endpoint_urls=None)
    assert client.meta.endpoint_url == "https://ambient-endpoint.invalid"
    check_client_validated(lambda: client)


def test_superseded_only_retention_loses_the_newest_and_terminal_versions():
    with pytest.raises(GuardViolation, match="terminal journal was lost"):
        check_terminal_survives_overwrite(SupersededOnly)
    with pytest.raises(GuardViolation, match="committed versions missing"):
        check_versions_complete_after_crash(SupersededOnly)


def test_without_read_retention_a_crash_window_loses_a_committed_version():
    with pytest.raises(GuardViolation, match="committed versions missing"):
        check_versions_complete_after_crash(NoReadRetention)


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
        {"verify": False},
        {"proxies": {"https": "http://192.0.2.1:9"}},
    ]
    for overrides in cases:
        check_client_validated(lambda overrides=overrides: make_client(backend, **overrides))
    check_client_validated(lambda: make_client(backend, endpoint="https://example.invalid"))
    with pytest.raises(GuardViolation, match="unsafe client was accepted"):
        check_client_validated(lambda: make_client(backend))
