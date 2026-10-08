"""The unchanged release controller over the R2 control store and offline R2 model."""

from __future__ import annotations

from dataclasses import dataclass, field
import json

import pytest

from release.controller import RecoveryAuthorization, ReleaseController, ReleaseHalted
from release.journal import verify_chain
from release.manifest import load_approval, load_manifest
from release_cloudflare.r2_store import ControlStoreUnavailable, R2ObjectStore, parse_envelope
from tests.r2_fakes import CONTROL, Fault, R2Backend, make_client
from tests.release_fakes import (
    FakeClock,
    FakeEcs,
    FakeEvidence,
    FakeLogs,
    JobPlan,
    SimulatedCrash,
    Tokens,
    Trace,
    approval_document,
    encode,
    manifest_document,
    sha,
)

RELEASE = "0b9f7c1e-4d2a-4f6b-9a3e-2c1d0e9f8a7b"
JOURNAL = f"releases/{RELEASE}/journal.json"
VERSIONS = f"journal-versions/{RELEASE}/"
LOCK = "locks/staging.json"


@dataclass
class R2Rig:
    document: dict
    clock: FakeClock
    trace: Trace
    backend: R2Backend
    ecs: FakeEcs
    evidence: FakeEvidence
    logs: FakeLogs
    tokens: Tokens
    approval_raw: bytes
    stores: list = field(default_factory=list)
    store_cls: type = R2ObjectStore

    def store(self) -> R2ObjectStore:
        # Each controller session talks to the bucket through its own client.
        store = self.store_cls(make_client(self.backend), CONTROL)
        self.stores.append(store)
        return store

    def controller(self, session: str = "session-a") -> ReleaseController:
        return ReleaseController(
            load_manifest(encode(self.document)),
            load_approval(self.approval_raw),
            store=self.store(),
            ecs=self.ecs,
            evidence=self.evidence,
            logs=self.logs,
            clock=self.clock,
            tokens=self.tokens,
            session_id=session,
        )

    def head(self, key: str) -> tuple[str, bytes]:
        raw = self.backend.raw(key)
        return parse_envelope(raw)

    def journal(self) -> dict:
        state, body = self.head(JOURNAL)
        assert state == "held"
        return json.loads(body)

    def transitions(self) -> list[str]:
        return [e["to"] for e in self.journal()["events"] if e["kind"] == "transition"]

    def results(self, result: str) -> list[dict]:
        return [
            e
            for e in self.journal()["events"]
            if e["kind"] == "observation" and e["result"] == result
        ]

    def jobs_launched(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for task in self.ecs.tasks.values():
            job = task.tags.get("sentry:job-id")
            if job:
                counts[job] = counts.get(job, 0) + 1
        return counts


def r2_rig(**approval) -> R2Rig:
    document = manifest_document()
    loaded = load_manifest(encode(document))
    clock, trace = FakeClock(), Trace()
    backend = R2Backend(trace=trace)
    ecs = FakeEcs(clock, trace)
    ecs.configure(document)
    return R2Rig(
        document=document,
        clock=clock,
        trace=trace,
        backend=backend,
        ecs=ecs,
        evidence=FakeEvidence(ecs, document),
        logs=FakeLogs(ecs, document),
        tokens=Tokens(),
        approval_raw=encode({**approval_document(loaded.sha256), **approval}),
    )


def assert_intent_precedes_every_mutation(r: R2Rig) -> None:
    last_journal = None
    for entry in r.trace:
        if entry[0] == "store" and entry[1] == JOURNAL:
            last_journal = entry[2]
        elif entry[0] == "ecs":
            assert last_journal is not None, entry
            event = last_journal["events"][-1]
            assert event["kind"] == "intent" and event["action"] == entry[1], (entry, event)


def retained_versions(r: R2Rig) -> list[dict]:
    """Copies as journal documents, shortest first; each must be committed history."""
    documents = []
    for key in r.backend.keys(VERSIONS):
        state, body = parse_envelope(r.backend.raw(key))
        assert state == "held"
        document = json.loads(body)
        verify_chain(document)
        documents.append(document)
    return sorted(documents, key=lambda document: len(document["events"]))


def assert_versions_reproduce_journal(r: R2Rig) -> None:
    """Copies hold exactly the committed versions, the newest included."""
    head = r.journal()
    verify_chain(head)
    documents = retained_versions(r)
    for document in documents:
        n = len(document["events"])
        assert document["events"] == head["events"][:n], "a copy is not committed history"
    lengths = [len(document["events"]) for document in documents]
    assert lengths == list(range(1, len(head["events"]) + 1)), lengths
    assert documents[-1] == head, "the current head is retained"


# 10. happy path ------------------------------------------------------------------


def test_release_reaches_held_paused_and_releases_the_lock_as_a_marker():
    r = r2_rig()
    outcome = r.controller().run()
    assert outcome.state == "held_paused" and outcome.reason is None
    assert r.transitions()[-1] == "held_paused"
    verify_chain(r.journal())
    state, body = r.head(LOCK)
    assert state == "released" and body == b""
    assert r.results("lock_released")
    assert r.backend.deleting_requests() == []
    assert_intent_precedes_every_mutation(r)
    assert_versions_reproduce_journal(r)


# 11. failed job ------------------------------------------------------------------


def test_failed_job_holds_with_the_same_outcome_as_the_reference_store():
    r = r2_rig()
    r.ecs.plans[r.document["jobs"][2]["task"]["task_definition"]] = JobPlan(exits={"init": 1})
    outcome = r.controller().run()
    assert outcome.state == "hold"
    assert outcome.rollback is not None
    assert r.head(LOCK)[0] == "held", "a held release keeps the environment lock"
    assert_intent_precedes_every_mutation(r)
    assert_versions_reproduce_journal(r)


# 12. transfer race at finalization ------------------------------------------------


def test_lock_transferred_between_read_and_marker_write_halts_and_stays_transferred():
    r = r2_rig()
    fired: list[str] = []

    def transfer(method, key, body):
        if (
            method == "PUT"
            and key == LOCK
            and json.loads(body)["state"] == "released"
            and not fired
        ):
            fired.append("recovery")
            r.controller("session-b").recover(
                RecoveryAuthorization(
                    prior_session_id="session-a",
                    lock_etag=r.backend.etag(LOCK),
                    fence_evidence_sha256=sha("session-a process confirmed terminated"),
                    authorized_by="fixture-operator",
                )
            )

    r.backend.before = transfer
    with pytest.raises(ReleaseHalted) as error:
        r.controller().run()
    assert error.value.code == "lock_release_conflict"
    assert fired == ["recovery"]
    state, body = r.head(LOCK)
    assert state == "held" and json.loads(body)["session_id"] == "session-b"
    assert not r.results("lock_released")
    assert r.backend.deleting_requests() == []


# 13. crash after the marker write ---------------------------------------------------


def test_crash_after_marker_write_is_confirmed_by_the_recorded_intent():
    r = r2_rig()
    r.backend.faults.append(Fault("PUT", LOCK, "crash_after", match_state="released"))
    with pytest.raises(SimulatedCrash):
        r.controller().run()
    assert r.head(LOCK)[0] == "released" and not r.results("lock_released")
    markers = len([e for e in r.backend.requests("PUT") if e.envelope_state == "released"])
    outcome = r.controller().run()
    assert outcome.state == "held_paused"
    assert len(r.results("lock_released")) == 1
    assert len([e for e in r.backend.requests("PUT") if e.envelope_state == "released"]) == markers
    assert_versions_reproduce_journal(r)


# 14. no takeover of another release's lock ---------------------------------------------


@pytest.mark.parametrize("acquired_at", ["2020-01-01T00:00:00Z", "2026-10-07T11:59:59Z"])
def test_another_releases_lock_is_never_taken_at_any_age(acquired_at):
    r = r2_rig()
    other = {"release_id": "other", "session_id": "old", "acquired_at": acquired_at}
    owner = R2ObjectStore(make_client(r.backend), CONTROL)
    owner.create(LOCK, json.dumps(other).encode())
    outcome = r.controller().run()
    assert outcome.state == "hold" and outcome.reason == "environment_locked"
    assert outcome.last_proven == "prepared"
    assert json.loads(r.head(LOCK)[1]) == other
    assert r.ecs.mutations == []
    r.clock.advance(days=30)
    assert r.controller().run().state == "hold"
    assert json.loads(r.head(LOCK)[1]) == other


# 15. lost response on a committed journal write ------------------------------------------


@pytest.mark.parametrize("skip", [0, 1, 4, 9, 17, 30])
def test_lost_response_on_a_committed_journal_write_never_forks_or_repeats(skip):
    r = r2_rig()
    r.backend.faults.append(Fault("PUT", JOURNAL, "lost_response", skip=skip))
    # The journal create fails out of the controller; a later append's unknown
    # outcome becomes a hold attempt whose own append meets the committed write.
    with pytest.raises((ControlStoreUnavailable, ReleaseHalted)) as error:
        r.controller().run()
    if isinstance(error.value, ReleaseHalted):
        assert error.value.code == "journal_conflict"
    assert r.transitions()[-1] != "hold", "an unknown outcome is never recorded as progress"
    outcome = r.controller().run()
    assert outcome.state == "held_paused", outcome
    verify_chain(r.journal())
    assert all(count == 1 for count in r.jobs_launched().values()), r.jobs_launched()
    assert_intent_precedes_every_mutation(r)
    assert_versions_reproduce_journal(r)


def test_lost_response_on_the_lock_create_holds_without_losing_the_lock():
    r = r2_rig()
    r.backend.faults.append(Fault("PUT", LOCK, "lost_response", match_state="held"))
    outcome = r.controller().run()
    # The unchanged controller treats any other port error as uncertainty.
    assert outcome.state == "hold" and outcome.reason == "controller_error"
    state, body = r.head(LOCK)
    assert state == "held" and json.loads(body)["session_id"] == "session-a"
    assert r.ecs.mutations == []
    assert r.controller().run().state == "hold"
    assert_versions_reproduce_journal(r)


# Evidence survives an outside overwrite ---------------------------------------------


@pytest.mark.parametrize("outcome", ["held_paused", "hold"])
def test_terminal_journal_survives_an_unconditional_overwrite_of_the_head(outcome):
    r = r2_rig()
    if outcome == "hold":
        r.ecs.plans[r.document["jobs"][2]["task"]["task_definition"]] = JobPlan(exits={"init": 1})
    assert r.controller().run().state == outcome
    final = r.journal()
    r.backend.put_raw(JOURNAL, b"overwritten by an unconditional writer", '"outside"')
    recovered = retained_versions(r)[-1]
    assert recovered == final
    last = recovered["events"][-1]
    if outcome == "held_paused":
        assert last["kind"] == "observation" and last["result"] == "lock_released"
    else:
        assert last["kind"] == "transition" and last["to"] == "hold" and "rollback" in last


class LockedCopies(R2Backend):
    """R2 with a bucket lock on copies, answering writes to existing ones with 403."""

    def _put(self, bucket, key, headers, body, url):
        if key.startswith("journal-versions/") and (bucket, key) in self.objects:
            from tests.r2_fakes import _error

            return _error("AccessDenied", 403, url)
        return super()._put(bucket, key, headers, body, url)


def test_resume_and_recovery_work_when_locked_copies_refuse_writes():
    r = r2_rig()
    r.backend = LockedCopies(trace=r.trace)
    r.ecs.crash[("run_task", "after")] = 1
    with pytest.raises(SimulatedCrash):
        r.controller().run()
    with pytest.raises(ReleaseHalted) as error:
        r.controller("session-b").run()
    assert error.value.code == "session_conflict"
    r.controller("session-b").recover(
        RecoveryAuthorization(
            prior_session_id="session-a",
            lock_etag=r.backend.etag(LOCK),
            fence_evidence_sha256=sha("session-a terminated"),
            authorized_by="fixture-operator",
        )
    )
    assert r.controller("session-b").run().state == "held_paused"
    assert_versions_reproduce_journal(r)
