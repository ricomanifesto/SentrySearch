"""Contract cases for the R2 release-control store against the offline R2 model."""

from __future__ import annotations

import hashlib
import json

import pytest

from release.journal import PreconditionFailed
from release_cloudflare.r2_client import R2ClientRejected, R2Target, endpoint_for, validate_client
from release_cloudflare.r2_store import (
    ControlStoreIntegrity,
    ControlStoreUnavailable,
    R2ObjectStore,
    parse_envelope,
    version_key,
)
from tests.r2_fakes import CONTROL, Fault, R2Backend, make_client

LOCK = "locks/staging.json"
JOURNAL = "releases/0b9f7c1e-4d2a-4f6b-9a3e-2c1d0e9f8a7b/journal.json"
VERSIONS = "releases/0b9f7c1e-4d2a-4f6b-9a3e-2c1d0e9f8a7b/journal-versions/"


def held(store: R2ObjectStore, key: str) -> tuple[bytes, str]:
    found = store.read(key)
    assert found is not None, f"{key} is not held"
    return found


def copy_key(raw: bytes) -> str:
    key = version_key(JOURNAL, raw)
    assert key is not None
    return key


def store_for(backend: R2Backend, **kwargs) -> R2ObjectStore:
    return R2ObjectStore(make_client(backend), CONTROL, **kwargs)


def raw_envelope(**changes) -> bytes:
    document = {"body": "{}", "cf_r2_store": 1, "nonce": "0" * 32, "state": "held", **changes}
    return json.dumps(document).encode()


# 1. create when absent ----------------------------------------------------------


def test_create_is_conditional_on_absence():
    backend = R2Backend()
    store = store_for(backend)
    etag = store.create(LOCK, b'{"session_id":"a"}')
    assert store.read(LOCK) == (b'{"session_id":"a"}', etag)
    with pytest.raises(PreconditionFailed):
        store.create(LOCK, b'{"session_id":"b"}')
    assert store.read(LOCK) == (b'{"session_id":"a"}', etag)
    first = backend.requests("PUT")[0]
    assert first.headers["if-none-match"] == "*" and "if-match" not in first.headers


# 2. read absent, held, released, malformed ----------------------------------------


def test_read_distinguishes_absent_held_released_and_malformed():
    backend = R2Backend()
    store = store_for(backend)
    assert store.read(LOCK) is None
    etag = store.create(LOCK, b"held")
    assert store.read(LOCK) == (b"held", etag)
    store.delete(LOCK, if_match=etag)
    assert store.read(LOCK) is None
    assert parse_envelope(backend.raw(LOCK))[0] == "released"


@pytest.mark.parametrize(
    "raw",
    [
        b"not json",
        b"[]",
        raw_envelope(cf_r2_store=2),
        raw_envelope(cf_r2_store=True),
        raw_envelope(nonce="short"),
        raw_envelope(state="stolen"),
        raw_envelope(state="released", body="residue"),
        raw_envelope(extra="field"),
        b'{"body":"{}","body":"{}","cf_r2_store":1,"nonce":"' + b"0" * 32 + b'","state":"held"}',
    ],
)
def test_foreign_or_malformed_objects_fail_closed(raw):
    backend = R2Backend()
    backend.objects[(CONTROL.bucket, LOCK)] = (raw, '"foreign"')
    store = store_for(backend)
    with pytest.raises(ControlStoreIntegrity):
        store.read(LOCK)
    with pytest.raises(ControlStoreIntegrity):
        store.create(LOCK, b"x")


# 3. replace with stale and current ETags ------------------------------------------


def test_replace_requires_the_current_etag():
    store = store_for(R2Backend())
    first = store.create(LOCK, b"one")
    second = store.replace(LOCK, b"two", if_match=first)
    assert second != first
    with pytest.raises(PreconditionFailed):
        store.replace(LOCK, b"three", if_match=first)
    assert store.read(LOCK) == (b"two", second)


# 4. exact-owner delete leaves a marker; no DeleteObject ever ------------------------


def test_delete_writes_a_released_marker_and_never_sends_delete_object():
    backend = R2Backend()
    store = store_for(backend)
    etag = store.create(LOCK, b"held")
    with pytest.raises(PreconditionFailed):
        store.delete(LOCK, if_match='"not-the-owner"')
    assert store.read(LOCK) == (b"held", etag)
    store.delete(LOCK, if_match=etag)
    assert store.read(LOCK) is None
    assert backend.get(LOCK) is not None, "the marker remains; nothing is deleted"
    assert backend.requests("DELETE") == []
    release = [
        r for r in backend.requests("PUT") if r.envelope_state == "released" and r.status == 200
    ]
    assert len(release) == 1 and release[0].headers["if-match"] == etag


# 5. re-acquire after release; racing re-acquirers ---------------------------------


def test_released_key_is_reacquired_by_replacing_the_marker():
    backend = R2Backend()
    store = store_for(backend)
    store.delete(LOCK, if_match=store.create(LOCK, b"first"))
    etag = store.create(LOCK, b"second")
    assert store.read(LOCK) == (b"second", etag)
    marker_put = backend.requests("PUT")[-1]
    assert "if-match" in marker_put.headers and marker_put.envelope_state == "held"


def test_two_stores_racing_for_one_marker_produce_exactly_one_owner():
    backend = R2Backend()
    a, b = store_for(backend), store_for(backend)
    a.delete(LOCK, if_match=a.create(LOCK, b"released-owner"))
    outcome: dict[str, object] = {}

    def interleave(method, key, body):
        # Just before A's conditional marker replacement lands, B wins the race.
        if (
            method == "PUT"
            and key == LOCK
            and json.loads(body)["body"] == "a"
            and "b" not in outcome
        ):
            outcome["b"] = b.create(LOCK, b"b")

    backend.before = interleave
    with pytest.raises(PreconditionFailed):
        a.create(LOCK, b"a")
    assert a.read(LOCK) == (b"b", outcome["b"])


# 6. ABA defence under content-derived ETags -----------------------------------------


@pytest.mark.parametrize("etags", ["md5", "random"])
def test_identical_bodies_in_two_incarnations_get_distinct_etags(etags):
    store = store_for(R2Backend(etags=etags))
    body = b'{"release_id":"r","session_id":"s","acquired_at":"2026-10-08T15:00:00Z"}'
    first = store.create(LOCK, body)
    store.delete(LOCK, if_match=first)
    second = store.create(LOCK, body)
    assert second != first
    with pytest.raises(PreconditionFailed):
        store.replace(LOCK, b"stale writer", if_match=first)
    with pytest.raises(PreconditionFailed):
        store.delete(LOCK, if_match=first)
    assert store.read(LOCK) == (body, second)


# 7. request shapes -------------------------------------------------------------------


def test_requests_carry_exact_conditions_and_no_checksum_trailers():
    backend = R2Backend()
    store = store_for(backend)
    store.replace(LOCK, b"b", if_match=store.create(LOCK, b"a"))
    for entry in backend.log:
        assert entry.status in (200, 412), entry
        assert not any(
            name.startswith("x-amz-checksum-")
            or name in ("x-amz-trailer", "x-amz-sdk-checksum-algorithm")
            for name in entry.headers
        ), entry
        assert "aws-chunked" not in entry.headers.get("content-encoding", "")
        assert entry.bucket == CONTROL.bucket
    puts = backend.requests("PUT")
    assert puts[0].headers["if-none-match"] == "*"
    assert puts[1].headers["if-match"].startswith('"')


def test_client_contract_is_validated_before_any_request():
    backend = R2Backend()
    validate_client(make_client(backend), CONTROL)
    assert endpoint_for(R2Target(CONTROL.account_id, "b-1", "eu")) == (
        f"https://{CONTROL.account_id}.eu.r2.cloudflarestorage.com"
    )
    rejected = {
        "endpoint": lambda: make_client(backend, endpoint="https://example.invalid"),
        "request_checksum": lambda: make_client(backend, request_checksum_calculation=None),
        "response_checksum": lambda: make_client(backend, response_checksum_validation=None),
        "retries": lambda: make_client(
            backend, retries={"mode": "standard", "total_max_attempts": 3}
        ),
        "read_timeout": lambda: make_client(backend, read_timeout=600),
        "addressing_style": lambda: make_client(backend, s3={"addressing_style": "virtual"}),
    }
    for reason, build in rejected.items():
        with pytest.raises(R2ClientRejected) as error:
            R2ObjectStore(build(), CONTROL)
        assert error.value.reason == reason
    assert backend.log == []
    for bad in (
        {"account_id": "UPPERCASE0123456789abcdef0123456"},
        {"account_id": "123"},
        {"bucket": "Bad_Bucket"},
        {"jurisdiction": "mars"},
    ):
        with pytest.raises(R2ClientRejected):
            R2Target(**{"account_id": CONTROL.account_id, "bucket": "ok-bucket", **bad})


def test_chain_credentials_are_rejected():
    backend = R2Backend()
    client = make_client(backend)
    client._get_credentials().method = "env"
    with pytest.raises(R2ClientRejected) as error:
        R2ObjectStore(client, CONTROL)
    assert error.value.reason == "credentials"


# 8. superseded journal versions are copied before the head moves ------------------


def test_each_superseded_journal_version_is_copied_before_the_replace():
    backend = R2Backend()
    store = store_for(backend)
    first = store.create(JOURNAL, b'{"events":[1]}')
    v1 = backend.raw(JOURNAL)
    second = store.replace(JOURNAL, b'{"events":[1,2]}', if_match=first)
    v2 = backend.raw(JOURNAL)
    store.replace(JOURNAL, b'{"events":[1,2,3]}', if_match=second)
    order = [entry.key for entry in backend.requests("PUT")]
    assert order == [JOURNAL, version_key(JOURNAL, v1), JOURNAL, version_key(JOURNAL, v2), JOURNAL]
    assert {backend.raw(k) for k in backend.keys(VERSIONS)} == {v1, v2}
    for key in backend.keys(VERSIONS):
        raw = backend.raw(key)
        assert key.endswith(hashlib.sha256(raw).hexdigest() + ".json")
    assert version_key(LOCK, b"x") is None


def test_copy_failure_leaves_the_head_unchanged():
    backend = R2Backend()
    store = store_for(backend)
    etag = store.create(JOURNAL, b'{"events":[1]}')
    backend.faults.append(Fault("PUT", VERSIONS + ".*", "http_500"))
    with pytest.raises(ControlStoreUnavailable):
        store.replace(JOURNAL, b'{"events":[1,2]}', if_match=etag)
    assert store.read(JOURNAL) == (b'{"events":[1]}', etag)


def test_a_stale_replace_copies_nothing_and_a_raced_replace_copies_only_committed():
    backend = R2Backend()
    a, b = store_for(backend), store_for(backend)
    first = a.create(JOURNAL, b'{"events":[1]}')
    second = b.replace(JOURNAL, b'{"events":[1,"b"]}', if_match=first)
    copies = backend.keys(VERSIONS)
    with pytest.raises(PreconditionFailed):
        a.replace(JOURNAL, b'{"events":[1,"a"]}', if_match=first)
    assert backend.keys(VERSIONS) == copies, "a stale writer copied nothing"
    raced: list[str] = []

    def interleave(method, key, body):
        # After A copied the committed head, B commits first; A's replace fails.
        if method == "PUT" and key.startswith(VERSIONS) and not raced:
            raced.append(key)
            b.replace(JOURNAL, b'{"events":[1,"b","b2"]}', if_match=second)

    backend.before = interleave
    with pytest.raises(PreconditionFailed):
        a.replace(JOURNAL, b'{"events":[1,"b","a"]}', if_match=second)
    committed = {b'{"events":[1]}', b'{"events":[1,"b"]}'}
    assert {parse_envelope(backend.raw(k))[1] for k in backend.keys(VERSIONS)} == committed
    assert held(store_for(backend), JOURNAL)[0] == b'{"events":[1,"b","b2"]}'


def test_a_foreign_object_at_a_copy_key_is_an_integrity_failure():
    backend = R2Backend()
    store = store_for(backend)
    etag = store.create(JOURNAL, b"{}")
    raw = backend.raw(JOURNAL)
    backend.put_raw(copy_key(raw), b"tampered", '"x"')
    with pytest.raises(ControlStoreIntegrity):
        store.replace(JOURNAL, b'{"x":1}', if_match=etag)
    assert store.read(JOURNAL) == (b"{}", etag)


def test_an_identical_existing_copy_counts_as_present():
    backend = R2Backend()
    store = store_for(backend)
    etag = store.create(JOURNAL, b"{}")
    raw = backend.raw(JOURNAL)
    backend.put_raw(copy_key(raw), raw, '"earlier"')
    store.replace(JOURNAL, b'{"x":1}', if_match=etag)
    assert held(store, JOURNAL)[0] == b'{"x":1}'


# 9. unknown outcomes never become success ---------------------------------------------


@pytest.mark.parametrize("kind", ["lost_response", "timeout_before", "http_500"])
def test_unknown_outcomes_raise_and_a_rerun_observes_the_truth(kind):
    backend = R2Backend()
    store = store_for(backend)
    etag = store.create(LOCK, b"one")
    backend.faults.append(Fault("PUT", LOCK, kind))
    with pytest.raises(ControlStoreUnavailable) as error:
        store.replace(LOCK, b"two", if_match=etag)
    assert "two" not in str(error.value) and error.value.__cause__ is None
    body, _ = held(store, LOCK)
    assert body == (b"two" if kind == "lost_response" else b"one")


def test_get_errors_other_than_404_are_unavailable():
    backend = R2Backend()
    store = store_for(backend)
    store.create(LOCK, b"x")
    backend.faults.append(Fault("GET", LOCK, "http_500"))
    with pytest.raises(ControlStoreUnavailable):
        store.read(LOCK)


def test_nonce_factory_output_is_validated():
    store = store_for(R2Backend(), nonce_factory=lambda: "predictable")
    with pytest.raises(ControlStoreIntegrity):
        store.create(LOCK, b"x")
