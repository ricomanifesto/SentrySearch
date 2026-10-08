"""Contract cases for the R2 release-control store against the offline R2 model."""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any

import pytest

from release.journal import PreconditionFailed
from release_cloudflare.r2_client import R2ClientRejected, R2Target, endpoint_for, validate_client
from release_cloudflare.r2_store import (
    MAX_OBJECT_BYTES,
    VERSIONS_PREFIX,
    ControlStoreIntegrity,
    ControlStoreUnavailable,
    R2ObjectStore,
    parse_envelope,
    version_key,
)
from tests.r2_fakes import CONTROL, Fault, R2Backend, make_client

LOCK = "locks/staging.json"
RELEASE = "0b9f7c1e-4d2a-4f6b-9a3e-2c1d0e9f8a7b"
JOURNAL = f"releases/{RELEASE}/journal.json"
VERSIONS = f"{VERSIONS_PREFIX}{RELEASE}/"


def held(store: R2ObjectStore, key: str) -> tuple[bytes, str]:
    found = store.read(key)
    assert found is not None, f"{key} is not held"
    return found


def copy_key(raw: bytes) -> str:
    key = version_key(JOURNAL, raw)
    assert key is not None
    return key


def store_for(backend: R2Backend) -> R2ObjectStore:
    return R2ObjectStore(make_client(backend), CONTROL)


def canonical(**changes) -> bytes:
    document = {"body": "{}", "cf_r2_store": 1, "nonce": "0" * 32, "state": "held", **changes}
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")


def copies(backend: R2Backend) -> set[bytes]:
    return {backend.raw(key) for key in backend.keys(VERSIONS)}


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


def test_two_stores_racing_to_create_an_absent_key_produce_one_owner():
    backend = R2Backend()
    a, b = store_for(backend), store_for(backend)
    won: dict[str, str] = {}

    def interleave(method, key, body):
        if method == "PUT" and key == LOCK and json.loads(body)["body"] == "a" and not won:
            won["b"] = b.create(LOCK, b"b")

    backend.before = interleave
    with pytest.raises(PreconditionFailed):
        a.create(LOCK, b"a")
    assert held(a, LOCK) == (b"b", won["b"])


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
        canonical(cf_r2_store=2),
        canonical(cf_r2_store=True),
        canonical(nonce="short"),
        canonical(state="stolen"),
        canonical(state="released", body="residue"),
        canonical(extra="field"),
        b'{"body":"{}","body":"{}","cf_r2_store":1,"nonce":"' + b"0" * 32 + b'","state":"held"}',
        # Not this store's canonical bytes.
        json.dumps(json.loads(canonical())).encode(),
        canonical() + b"\n",
        canonical().decode().encode("utf-16"),
        canonical().decode().encode("utf-32"),
        b"\xef\xbb\xbf" + canonical(),
        # A lone surrogate is well-formed JSON but not UTF-8.
        canonical(body="\ud800"),
    ],
)
def test_foreign_malformed_or_non_canonical_objects_fail_closed(raw):
    backend = R2Backend()
    backend.put_raw(LOCK, raw, '"foreign"')
    store = store_for(backend)
    with pytest.raises(ControlStoreIntegrity):
        store.read(LOCK)
    with pytest.raises(ControlStoreIntegrity):
        store.create(LOCK, b"x")


def test_a_missing_bucket_is_unavailable_not_absent():
    backend = R2Backend()
    other = R2Target(account_id=CONTROL.account_id, bucket="another-bucket")
    store = R2ObjectStore(make_client(backend, other), other)
    with pytest.raises(ControlStoreUnavailable):
        store.read(LOCK)


# 3. replace with stale and current ETags ------------------------------------------


def test_replace_requires_the_current_etag():
    store = store_for(R2Backend())
    first = store.create(LOCK, b"one")
    second = store.replace(LOCK, b"two", if_match=first)
    assert second != first
    with pytest.raises(PreconditionFailed):
        store.replace(LOCK, b"three", if_match=first)
    assert store.read(LOCK) == (b"two", second)


# 4. exact-owner delete leaves a marker; no deleting request ever ---------------------


def test_delete_writes_a_released_marker_and_never_sends_a_deleting_request():
    backend = R2Backend()
    store = store_for(backend)
    etag = store.create(LOCK, b"held")
    with pytest.raises(PreconditionFailed):
        store.delete(LOCK, if_match='"not-the-owner"')
    assert store.read(LOCK) == (b"held", etag)
    store.delete(LOCK, if_match=etag)
    assert store.read(LOCK) is None
    assert backend.get(LOCK) is not None, "the marker remains; nothing is deleted"
    assert backend.deleting_requests() == []
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
    outcome: dict[str, str] = {}

    def interleave(method, key, body):
        # Just before A's first write for "a" lands, B takes the marker.
        if method == "PUT" and key == LOCK and json.loads(body)["body"] == "a" and not outcome:
            outcome["b"] = b.create(LOCK, b"b")

    backend.before = interleave
    with pytest.raises(PreconditionFailed):
        a.create(LOCK, b"a")
    assert held(a, LOCK) == (b"b", outcome["b"])


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


def test_the_nonce_source_is_not_a_constructor_option():
    options: dict = {"nonce_factory": lambda: "0" * 32}
    with pytest.raises(TypeError):
        R2ObjectStore(make_client(R2Backend()), CONTROL, **options)


# 7. request shapes -------------------------------------------------------------------


def test_requests_carry_exact_conditions_and_no_checksum_headers():
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


def test_client_contract_is_validated_before_any_request(monkeypatch):
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
        "tls_verification": lambda: make_client(backend, verify=False),
        "proxies": lambda: make_client(backend, proxies={"https": "http://192.0.2.1:9"}),
    }
    for reason, build in rejected.items():
        with pytest.raises(R2ClientRejected) as error:
            R2ObjectStore(build(), CONTROL)
        assert error.value.reason == reason
    monkeypatch.setenv("HTTPS_PROXY", "http://192.0.2.1:9")
    with pytest.raises(R2ClientRejected) as error:
        R2ObjectStore(make_client(backend, proxies=None), CONTROL)
    assert error.value.reason == "proxies", "an ambient proxy is caught"
    R2ObjectStore(make_client(backend), CONTROL)  # explicit no-proxy wins over the ambient one
    # A CA bundle is accepted only when the caller names exactly that bundle.
    R2ObjectStore(make_client(backend, verify=os.devnull), CONTROL, ca_bundle=os.devnull)
    with pytest.raises(R2ClientRejected):
        R2ObjectStore(make_client(backend, verify=os.devnull), CONTROL)
    with pytest.raises(R2ClientRejected):
        R2ObjectStore(make_client(backend), CONTROL, ca_bundle=os.devnull)
    # A falsy bundle would disable certificate checking in botocore.
    falsy_bundles: tuple[Any, ...] = ("", 0)
    for falsy in falsy_bundles:
        with pytest.raises(R2ClientRejected) as error:
            R2ObjectStore(make_client(backend, verify=falsy), CONTROL, ca_bundle=falsy)
        assert error.value.reason == "tls_verification"
    monkeypatch.setenv("AWS_CA_BUNDLE", os.devnull)
    with pytest.raises(R2ClientRejected) as error:
        R2ObjectStore(make_client(backend, verify=None), CONTROL)
    assert error.value.reason == "tls_verification", "an ambient CA bundle is caught"
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


# 8. every committed journal version is retained -------------------------------------


def test_each_committed_journal_version_is_copied_after_its_write():
    backend = R2Backend()
    store = store_for(backend)
    first = store.create(JOURNAL, b'{"events":[1]}')
    v1 = backend.raw(JOURNAL)
    second = store.replace(JOURNAL, b'{"events":[1,2]}', if_match=first)
    v2 = backend.raw(JOURNAL)
    store.replace(JOURNAL, b'{"events":[1,2,3]}', if_match=second)
    v3 = backend.raw(JOURNAL)
    order = [entry.key for entry in backend.requests("PUT")]
    assert order == [JOURNAL, copy_key(v1), JOURNAL, copy_key(v2), JOURNAL, copy_key(v3)]
    assert copies(backend) == {v1, v2, v3}, "the newest version is retained too"
    for key in backend.keys(VERSIONS):
        assert key.endswith(hashlib.sha256(backend.raw(key)).hexdigest() + ".json")
    assert version_key(LOCK, b"x") is None


def test_copies_live_under_one_prefix_that_holds_no_mutable_key():
    backend = R2Backend()
    store = store_for(backend)
    store.create(JOURNAL, b"{}")
    store.create("releases/1111-2222/journal.json", b"{}")
    store.create(LOCK, b"{}")
    retained = backend.keys(VERSIONS_PREFIX)
    assert len(retained) == 2
    mutable = [key for key in backend.keys() if key not in retained]
    assert mutable and not any(key.startswith(VERSIONS_PREFIX) for key in mutable)


def test_an_unconfirmed_copy_after_a_committed_write_stops_and_a_read_retains_it():
    backend = R2Backend()
    store = store_for(backend)
    etag = store.create(JOURNAL, b'{"events":[1]}')
    backend.faults.append(Fault("PUT", VERSIONS + ".*", "http_500"))
    with pytest.raises(ControlStoreUnavailable):
        store.replace(JOURNAL, b'{"events":[1,2]}', if_match=etag)
    committed = backend.raw(JOURNAL)
    assert parse_envelope(committed)[1] == b'{"events":[1,2]}', "the head write committed"
    assert committed not in copies(backend)
    assert held(store_for(backend), JOURNAL)[0] == b'{"events":[1,2]}'
    assert committed in copies(backend), "reading the head retained it"


def test_a_refused_or_lost_write_is_never_copied():
    backend = R2Backend()
    a, b = store_for(backend), store_for(backend)
    first = a.create(JOURNAL, b'{"events":[1]}')
    b.replace(JOURNAL, b'{"events":[1,"b"]}', if_match=first)
    retained = copies(backend)
    with pytest.raises(PreconditionFailed):
        a.replace(JOURNAL, b'{"events":[1,"a"]}', if_match=first)
    assert copies(backend) == retained, "a refused write left no copy"
    backend.faults.append(Fault("PUT", JOURNAL, "lost_response"))
    with pytest.raises(ControlStoreUnavailable):
        b.replace(JOURNAL, b'{"events":[1,"b","lost"]}', if_match=backend.etag(JOURNAL))
    assert backend.raw(JOURNAL) not in copies(backend), "an unknown outcome is not copied"
    held(b, JOURNAL)
    assert backend.raw(JOURNAL) in copies(backend), "the committed head is retained on read"
    bodies = {parse_envelope(raw)[1] for raw in copies(backend)}
    assert bodies == {b'{"events":[1]}', b'{"events":[1,"b"]}', b'{"events":[1,"b","lost"]}'}


def test_copies_survive_an_outside_overwrite_of_the_head():
    backend = R2Backend()
    store = store_for(backend)
    etag = store.create(JOURNAL, b'{"events":["first"]}')
    store.replace(JOURNAL, b'{"events":["first","terminal"]}', if_match=etag)
    backend.put_raw(JOURNAL, b"overwritten by an unconditional writer", '"outside"')
    bodies = {parse_envelope(raw)[1] for raw in copies(backend)}
    assert b'{"events":["first","terminal"]}' in bodies
    with pytest.raises(ControlStoreIntegrity):
        store.read(JOURNAL)


def test_a_foreign_object_at_a_copy_key_is_an_integrity_failure():
    backend = R2Backend()
    store = store_for(backend)

    class Fixed(R2ObjectStore):
        def _new_nonce(self) -> str:
            return "a" * 32

    fixed = Fixed(make_client(backend), CONTROL)
    expected = canonical(body="{}", nonce="a" * 32)
    backend.put_raw(copy_key(expected), b"tampered", '"x"')
    with pytest.raises(ControlStoreIntegrity):
        fixed.create(JOURNAL, b"{}")
    assert parse_envelope(backend.raw(JOURNAL))[1] == b"{}", "the head committed first"
    with pytest.raises(ControlStoreIntegrity):
        store.read(JOURNAL)


def test_an_identical_existing_copy_counts_as_present():
    backend = R2Backend()
    store = store_for(backend)
    store.create(JOURNAL, b"{}")
    raw = backend.raw(JOURNAL)
    assert held(store, JOURNAL)[0] == b"{}"
    assert held(store, JOURNAL)[0] == b"{}"
    assert copies(backend) == {raw}


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


@pytest.mark.parametrize(
    "status, code",
    [
        (409, "ConditionalRequestConflict"),
        (403, "AccessDenied"),
        (503, "SlowDown"),
        (301, "PermanentRedirect"),
        (400, "InvalidRequest"),
        (404, "NoSuchKey"),
    ],
)
@pytest.mark.parametrize("operation", ["create", "replace", "delete"])
def test_other_statuses_are_unavailable_never_success_or_conflict(status, code, operation):
    backend = R2Backend()
    store = store_for(backend)
    etag = store.create(LOCK, b"one")
    before = dict(backend.objects)
    backend.faults.append(
        Fault("PUT", "locks/.*", "http_status", status=status, code=code, count=5)
    )
    with pytest.raises(ControlStoreUnavailable) as error:
        if operation == "create":
            store.create("locks/other.json", b"x")
        elif operation == "replace":
            store.replace(LOCK, b"two", if_match=etag)
        else:
            store.delete(LOCK, if_match=etag)
    assert code not in str(error.value)
    assert backend.objects == before


def test_get_errors_other_than_no_such_key_are_unavailable():
    backend = R2Backend()
    store = store_for(backend)
    store.create(LOCK, b"x")
    backend.faults.append(Fault("GET", LOCK, "http_500"))
    with pytest.raises(ControlStoreUnavailable):
        store.read(LOCK)
    backend.faults.append(Fault("GET", LOCK, "http_status", status=404, code="NoSuchBucket"))
    with pytest.raises(ControlStoreUnavailable):
        store.read(LOCK)


def test_writes_beyond_the_read_bound_are_refused_before_any_request():
    backend = R2Backend()
    store = store_for(backend)
    with pytest.raises(ControlStoreIntegrity):
        store.create(JOURNAL, b'"' * (MAX_OBJECT_BYTES // 2))
    assert backend.log == []


class LockedCopies(R2Backend):
    """R2 with a bucket lock on copies, answering writes to existing ones with 403."""

    def _put(self, bucket, key, headers, body, url):
        if key.startswith(VERSIONS_PREFIX) and (bucket, key) in self.objects:
            from tests.r2_fakes import _error

            return _error("AccessDenied", 403, url)
        return super()._put(bucket, key, headers, body, url)


def test_reading_a_journal_whose_copy_exists_sends_no_write():
    backend = R2Backend()
    store = store_for(backend)
    store.create(JOURNAL, b'{"events":[1]}')
    backend.log.clear()
    assert held(store, JOURNAL)[0] == b'{"events":[1]}'
    assert backend.requests("PUT") == []


def test_reads_tolerate_locked_copies_and_read_only_access():
    backend = LockedCopies()
    store = store_for(backend)
    store.create(JOURNAL, b'{"events":[1]}')
    assert held(store, JOURNAL)[0] == b'{"events":[1]}'
    backend.faults.append(
        Fault("PUT", ".*", "http_status", status=403, code="AccessDenied", count=99)
    )
    assert held(store_for(backend), JOURNAL)[0] == b'{"events":[1]}', "a read-only reader reads"


def test_a_missing_copy_that_cannot_be_written_still_fails_closed():
    backend = R2Backend()
    store = store_for(backend)
    store.create(JOURNAL, b'{"events":[1]}')
    for key in backend.keys(VERSIONS):
        backend.objects.pop((CONTROL.bucket, key))
    backend.faults.append(
        Fault("PUT", VERSIONS + ".*", "http_status", status=403, code="AccessDenied")
    )
    with pytest.raises(ControlStoreUnavailable):
        store.read(JOURNAL)
