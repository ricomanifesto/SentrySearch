"""Offline release-controller fault tests against deterministic fake ECS/S3 ports."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json

import pytest

from release.controller import RecoveryAuthorization, ReleaseController, ReleaseHalted
from release.manifest import load_approval, load_manifest
from release.ports import AmbiguousResponse
from tests.release_fakes import (
    PRIOR_RELEASE_ID,
    START,
    FakeClock,
    FakeEcs,
    FakeEvidence,
    FakeLogs,
    FakeStore,
    JobPlan,
    SimulatedCrash,
    Tokens,
    Trace,
    approval_document,
    digest,
    encode,
    iso,
    manifest_document,
    sha,
)

JOURNAL = "releases/0b9f7c1e-4d2a-4f6b-9a3e-2c1d0e9f8a7b/journal.json"
LOCK = "locks/staging.json"
FORWARD = [
    "prepared",
    "locked",
    "quiesced",
    "migrated",
    "grants_verified",
    "services_started",
    "operational_verified",
    "held_paused",
]


@dataclass
class Rig:
    document: dict
    clock: FakeClock
    trace: Trace
    store: FakeStore
    ecs: FakeEcs
    evidence: FakeEvidence
    logs: FakeLogs
    tokens: Tokens
    approval_raw: bytes

    def controller(self, session: str = "session-a") -> ReleaseController:
        return ReleaseController(
            load_manifest(encode(self.document)),
            load_approval(self.approval_raw),
            store=self.store,
            ecs=self.ecs,
            evidence=self.evidence,
            logs=self.logs,
            clock=self.clock,
            tokens=self.tokens,
            session_id=session,
        )

    def journal(self) -> dict:
        return self.store.journal()

    def transitions(self) -> list[str]:
        return [e["to"] for e in self.journal()["events"] if e["kind"] == "transition"]

    def events(self, kind: str, **match) -> list[dict]:
        return [
            e
            for e in self.journal()["events"]
            if e["kind"] == kind and all(e.get(k) == v for k, v in match.items())
        ]

    def calls(self, method: str) -> list[dict]:
        return [request for name, request in self.ecs.mutations if name == method]

    def job_tasks(self, job_id: str) -> list:
        return [t for t in self.ecs.tasks.values() if t.tags.get("sentry:job-id") == job_id]

    def lock_etag(self) -> str:
        return self.store.objects[LOCK][1]

    def recover(self, session: str = "session-b") -> ReleaseController:
        controller = self.controller(session)
        controller.recover(
            RecoveryAuthorization(
                prior_session_id="session-a",
                lock_etag=self.lock_etag(),
                fence_evidence_sha256=sha("prior session process confirmed terminated"),
                authorized_by="fixture-operator",
            )
        )
        return controller


def rig(*, rollback: str = "empty_hold", running_prior: bool = False, **approval) -> Rig:
    document = manifest_document(rollback=rollback)
    loaded = load_manifest(encode(document))
    clock, trace = FakeClock(), Trace()
    store, ecs = FakeStore(trace), FakeEcs(clock, trace)
    ecs.configure(document, running_prior=running_prior)
    return Rig(
        document=document,
        clock=clock,
        trace=trace,
        store=store,
        ecs=ecs,
        evidence=FakeEvidence(ecs, document),
        logs=FakeLogs(ecs, document),
        tokens=Tokens(),
        approval_raw=encode({**approval_document(loaded.sha256), **approval}),
    )


def assert_intent_precedes_every_mutation(r: Rig) -> None:
    last_journal = None
    for entry in r.trace:
        if entry[0] == "store" and entry[1] == JOURNAL:
            last_journal = entry[2]
        elif entry[0] == "ecs":
            assert last_journal is not None, entry
            event = last_journal["events"][-1]
            assert event["kind"] == "intent" and event["action"] == entry[1], (entry, event)


def assert_held(r: Rig, outcome, reason: str, last_proven: str) -> None:
    assert outcome.state == "hold" and outcome.reason == reason, outcome
    assert outcome.last_proven == last_proven
    assert r.transitions()[-1] == "hold"
    assert LOCK in r.store.objects, "a held release keeps the environment lock"
    assert outcome.admission == "paused"
    assert_intent_precedes_every_mutation(r)


# Normal attended release ----------------------------------------------------


def test_first_release_journals_every_step_and_finishes_held_paused():
    r = rig()
    outcome = r.controller().run()
    assert outcome.state == "held_paused" and outcome.reason is None
    assert outcome.admission == "paused"
    assert r.transitions() == FORWARD
    assert LOCK not in r.store.objects, "lock is released only after a complete held-paused finish"
    assert [r["taskDefinition"].split("/")[-1] for r in r.calls("run_task")] == [
        "sentry-staging-runtime-migrate:7",
        "sentry-staging-product-migrate:7",
        "sentry-staging-runtime-grant:7",
        "sentry-staging-product-grant:7",
        "sentry-staging-runtime-proof:7",
        "sentry-staging-product-proof:7",
    ]
    assert [c["service"].rsplit("/", 1)[1] for c in r.calls("update_service")] == [
        "runtime",
        "api",
        "worker",
    ]
    assert r.calls("stop_task") == []
    assert_intent_precedes_every_mutation(r)
    events = r.journal()["events"]
    assert [e["sequence"] for e in events] == list(range(1, len(events) + 1))
    serialized = json.dumps(r.journal())
    assert "fixture-approver" not in serialized and "password" not in serialized


def test_launch_requests_are_exact_and_never_override():
    r = rig()
    r.controller().run()
    first = r.document["jobs"][0]
    request = r.calls("run_task")[0]
    assert request == {
        "cluster": r.document["environment"]["cluster_arn"],
        "taskDefinition": first["task"]["task_definition"],
        "count": 1,
        "launchType": "FARGATE",
        "platformVersion": "1.4.0",
        "networkConfiguration": {
            "awsvpcConfiguration": {
                "subnets": r.document["network"]["subnets"],
                "securityGroups": first["task"]["security_groups"],
                "assignPublicIp": "DISABLED",
            }
        },
        "enableExecuteCommand": False,
        "startedBy": request["clientToken"],
        "clientToken": request["clientToken"],
        "tags": [
            {"key": "sentry:release-id", "value": r.document["release_id"]},
            {"key": "sentry:job-id", "value": "runtime-migrate"},
        ],
    }
    assert len(request["clientToken"]) <= 64
    service = r.calls("update_service")[0]
    assert service == {
        "cluster": r.document["environment"]["cluster_arn"],
        "service": r.document["environment"]["services"]["runtime"],
        "taskDefinition": r.document["services"]["runtime"]["task_definition"],
        "desiredCount": 1,
        "forceNewDeployment": True,
        "enableExecuteCommand": False,
        "deploymentConfiguration": {
            "deploymentCircuitBreaker": {"enable": True, "rollback": False}
        },
    }


# Job completion evidence -----------------------------------------------------


@pytest.mark.parametrize(
    "job_index, plan, reason",
    [
        (0, JobPlan(exits={"init": 1}), "job_container_failed"),
        (0, JobPlan(exits={"migration": 3}), "job_container_failed"),
        (1, JobPlan(exits={"migration": None}), "job_exit_missing"),
        (2, JobPlan(stop_code="TaskFailedToStart"), "job_stopped_abnormally"),
        (3, JobPlan(image_override={"grant": "sha256:" + "e" * 64}), "job_image_mismatch"),
        (0, JobPlan(launch_failure="RESOURCE:MEMORY"), "launch_failed"),
        (4, JobPlan(task_count=2), "launch_task_count"),
    ],
)
def test_job_is_successful_only_with_complete_exact_evidence(job_index, plan, reason):
    r = rig()
    r.ecs.plans[r.document["jobs"][job_index]["task"]["task_definition"]] = plan
    outcome = r.controller().run()
    last = "quiesced" if job_index < 2 else "migrated"
    assert_held(r, outcome, reason, last)
    assert r.calls("update_service") == [], "no service starts after a failed job"


def test_stopped_task_with_zero_exits_but_no_receipt_is_not_success():
    r = rig()
    r.evidence.missing_jobs.add("runtime-proof")
    outcome = r.controller().run()
    assert_held(r, outcome, "job_deadline_exceeded", "migrated")
    assert not r.events("observation", subject="runtime-proof", result="job_succeeded")


@pytest.mark.parametrize(
    "change",
    [
        {"status": "failed"},
        {"task_arn": "arn:aws:ecs:us-east-1:111122223333:task/sentry-staging/forged"},
        {"release_id": "11111111-2222-4333-8444-555555555555"},
        {"result": {"database": "product_db", "principal": "product_owner"}},
        {"schema": "sentry.release.other.v1"},
    ],
)
def test_receipt_must_bind_release_job_task_and_expectations(change):
    r = rig()
    r.evidence.job_changes["product-proof"] = change
    outcome = r.controller().run()
    assert_held(r, outcome, "job_receipt_mismatch", "migrated")


def test_ambiguous_receipt_stream_holds_and_never_counts_as_success(monkeypatch):
    # An adapter that finds two receipts (or a malformed one) in a task's stream
    # reports uncertainty; a grant whose outcome is unknown must hold.
    r = rig()
    original = r.evidence.job_receipt

    def ambiguous(release_id, job_id, task_arn):
        if job_id == "runtime-grant":
            raise AmbiguousResponse("receipt stream is ambiguous")
        return original(release_id, job_id, task_arn)

    monkeypatch.setattr(r.evidence, "job_receipt", ambiguous)
    outcome = r.controller().run()
    assert_held(r, outcome, "observation_ambiguous", "migrated")
    assert not r.events("observation", subject="runtime-grant", result="job_succeeded")
    assert r.calls("update_service") == [], "no service starts after an unproven grant"


def test_partial_migration_holds_without_repair_or_down_migration():
    r = rig()
    r.ecs.plans[r.document["jobs"][1]["task"]["task_definition"]] = JobPlan(exits={"migration": 1})
    outcome = r.controller().run()
    assert_held(r, outcome, "job_container_failed", "quiesced")
    assert [e["subject"] for e in r.events("observation", result="job_succeeded")] == [
        "runtime-migrate"
    ]
    assert len(r.calls("run_task")) == 2
    assert outcome.rollback is not None and outcome.rollback["kind"] == "empty_hold"
    assert outcome.rollback["actions"] == [
        "keep_services_desired_zero",
        "retain_resources_and_evidence",
        "reconcile_partial_migration_before_rerun",
    ]


def test_job_deadline_requests_stop_and_never_claims_sql_cancellation():
    r = rig()
    r.ecs.plans[r.document["jobs"][0]["task"]["task_definition"]] = JobPlan(hang=True)
    outcome = r.controller().run()
    assert_held(r, outcome, "job_deadline_exceeded", "quiesced")
    stops = r.calls("stop_task")
    assert len(stops) == 1 and stops[0]["task"] == r.job_tasks("runtime-migrate")[0].arn
    stopped = r.events("observation", result="stop_confirmed")
    assert stopped and stopped[0]["sql_outcome"] == "unknown"
    deadline = r.events("intent", action="run_task")[0]["deadline_at"]
    assert iso(START + timedelta(seconds=900)) <= deadline
    assert r.clock.now() >= START + timedelta(seconds=900)


# Crash, ambiguity and recovery ----------------------------------------------


def test_new_session_cannot_resume_or_take_the_lock_without_recovery():
    r = rig()
    r.ecs.crash[("run_task", "after")] = 1
    with pytest.raises(SimulatedCrash):
        r.controller().run()
    mutations = len(r.ecs.mutations)
    with pytest.raises(ReleaseHalted) as error:
        r.controller("session-b").run()
    assert error.value.code == "session_conflict"
    assert len(r.ecs.mutations) == mutations
    for wrong in (
        {"lock_etag": '"stale"'},
        {"prior_session_id": "session-z"},
        {"fence_evidence_sha256": "not-a-hash"},
    ):
        values = {
            "prior_session_id": "session-a",
            "lock_etag": r.lock_etag(),
            "fence_evidence_sha256": sha("fenced"),
            "authorized_by": "fixture-operator",
            **wrong,
        }
        with pytest.raises(ReleaseHalted) as error:
            r.controller("session-b").recover(RecoveryAuthorization(**values))
        assert error.value.code == "recovery_refused"
    assert json.loads(r.store.objects[LOCK][0])["session_id"] == "session-a"


@pytest.mark.parametrize("when", ["before", "after"])
def test_launch_crash_reconciles_to_exactly_one_task(when):
    r = rig()
    r.ecs.visibility_delay = 20 if when == "after" else 0
    r.ecs.crash[("run_task", when)] = 1
    with pytest.raises(SimulatedCrash):
        r.controller().run()
    outcome = r.recover().run()
    assert outcome.state == "held_paused"
    assert len(r.job_tasks("runtime-migrate")) == 1
    intents = r.events("intent", action="run_task", subject="runtime-migrate")
    assert len({(e["token"], e["request_sha256"]) for e in intents}) == 1
    assert r.events("session", action="recovered")[0]["fence_evidence_sha256"] == sha(
        "prior session process confirmed terminated"
    )
    assert_intent_precedes_every_mutation(r)


def test_crash_before_journal_intent_launches_nothing_twice():
    r = rig()

    def crash_on_first_intent(key, body):
        event = json.loads(body)["events"][-1]
        if event["kind"] == "intent" and event["subject"] == "product-migrate":
            r.store.before_replace = None
            raise SimulatedCrash("before intent")

    r.store.before_replace = crash_on_first_intent
    with pytest.raises(SimulatedCrash):
        r.controller().run()
    assert len(r.job_tasks("product-migrate")) == 0
    assert r.recover().run().state == "held_paused"
    assert len(r.job_tasks("product-migrate")) == 1


@pytest.mark.parametrize(
    "elapsed",
    [
        900 + 1,  # job deadline passed; the token alone would still be reusable
        900 + 3600 + 1,  # token lifetime passed as well
    ],
)
def test_unknown_launch_outside_its_safe_window_holds_instead_of_minting_a_token(elapsed):
    # The schema caps job deadlines below the token lifetime, so the job deadline
    # always closes the identical-retry window first; token expiry is defense in depth.
    r = rig()
    r.ecs.visibility_delay = 10**7
    r.ecs.crash[("run_task", "after")] = 1
    with pytest.raises(SimulatedCrash):
        r.controller().run()
    r.clock.advance(seconds=elapsed)
    launches = len(r.calls("run_task"))
    outcome = r.recover().run()
    assert_held(r, outcome, "launch_outcome_unknown", "quiesced")
    assert len(r.calls("run_task")) == launches


@pytest.mark.parametrize("where", ["run_task_before", "run_task_after"])
def test_ambiguous_transport_retries_only_the_identical_request(where):
    r = rig()
    r.ecs.ambiguous[where] = 1
    outcome = r.controller().run()
    assert outcome.state == "held_paused"
    assert len(r.job_tasks("runtime-migrate")) == 1
    first, *rest = [c for c in r.calls("run_task") if c["tags"][1]["value"] == "runtime-migrate"]
    assert all(call == first for call in rest)


@pytest.mark.parametrize("when", ["before", "after"])
def test_service_update_crash_reconciles_without_a_second_deployment(when):
    r = rig()
    r.ecs.crash[("update_service", when)] = 1
    with pytest.raises(SimulatedCrash):
        r.controller().run()
    outcome = r.recover().run()
    assert outcome.state == "held_paused"
    runtime_updates = [c for c in r.calls("update_service") if c["service"].endswith("/runtime")]
    assert len(runtime_updates) == 1, "a crash before sending never reaches ECS"
    intents = r.events("intent", action="update_service", subject="runtime")
    assert len(intents) == (2 if when == "before" else 1)
    assert len({e["request_sha256"] for e in intents}) == 1
    service = r.ecs.services[r.document["environment"]["services"]["runtime"]]
    assert len([d for d in service.deployments if d["status"] == "PRIMARY"]) == 1


def test_concurrent_journal_writer_halts_before_any_mutation():
    r = rig()

    def interfere(key, body):
        event = json.loads(body)["events"][-1]
        if event["kind"] == "intent":
            stored, _ = r.store.objects[key]
            r.store.objects[key] = (stored, '"someone-else"')

    r.store.before_replace = interfere
    with pytest.raises(ReleaseHalted) as error:
        r.controller().run()
    assert error.value.code == "journal_conflict"
    assert r.ecs.mutations == []


def test_existing_environment_lock_is_never_stolen_by_age():
    r = rig()
    other = {"release_id": "other", "session_id": "old", "acquired_at": "2020-01-01T00:00:00Z"}
    r.store.create(LOCK, json.dumps(other).encode())
    outcome = r.controller().run()
    assert outcome.state == "hold" and outcome.reason == "environment_locked"
    assert outcome.last_proven == "prepared"
    assert json.loads(r.store.objects[LOCK][0]) == other
    assert r.ecs.mutations == []


def test_tampered_journal_is_not_trusted():
    r = rig()
    r.ecs.plans[r.document["jobs"][0]["task"]["task_definition"]] = JobPlan(exits={"init": 1})
    r.controller().run()
    document = r.journal()
    assert document["events"][3]["kind"] == "intent"
    document["events"][3]["request_sha256"] = "0" * 64
    r.store.objects[JOURNAL] = (json.dumps(document).encode(), r.store.objects[JOURNAL][1])
    with pytest.raises(ReleaseHalted) as error:
        r.controller().run()
    assert error.value.code == "journal_integrity"


def test_different_manifest_cannot_reuse_a_release_journal():
    r = rig()
    r.ecs.plans[r.document["jobs"][0]["task"]["task_definition"]] = JobPlan(exits={"init": 1})
    r.controller().run()
    r.document["window"]["poll_seconds"] = 6
    loaded = load_manifest(encode(r.document))
    r.approval_raw = encode(approval_document(loaded.sha256))
    with pytest.raises(ReleaseHalted) as error:
        r.controller().run()
    assert error.value.code == "journal_manifest_mismatch"


# Approval and window ---------------------------------------------------------


def test_approval_expiry_holds_before_the_next_mutation():
    r = rig(not_after=iso(START + timedelta(seconds=50)))
    outcome = r.controller().run()
    assert_held(r, outcome, "approval_expired", "quiesced")
    assert all(
        call["tags"][1]["value"] in {"runtime-migrate", "product-migrate"}
        for call in r.calls("run_task")
    )


def test_invalid_approval_never_creates_a_journal_or_lock():
    r = rig(manifest_sha256="0" * 64)
    with pytest.raises(ReleaseHalted) as error:
        r.controller().run()
    assert error.value.code == "approval_manifest_mismatch"
    assert r.store.objects == {} and r.ecs.mutations == []


# Services and operational evidence -----------------------------------------


def test_extra_task_for_the_candidate_deployment_never_counts_as_ready():
    r = rig()
    r.ecs.services[r.document["environment"]["services"]["api"]].extra_tasks = 1
    outcome = r.controller().run()
    assert_held(r, outcome, "task_count_drift", "grants_verified")


def test_failed_deployment_holds_without_automatic_rollback():
    r = rig()
    r.ecs.services[r.document["environment"]["services"]["worker"]].fail_rollout = True
    outcome = r.controller().run()
    assert_held(r, outcome, "deployment_failed", "grants_verified")
    assert all(c["deploymentConfiguration"]["deploymentCircuitBreaker"]["rollback"] is False
               for c in r.calls("update_service"))  # fmt: skip


@pytest.mark.parametrize(
    "configure, reason",
    [
        (lambda r: r.evidence.missing_checks.add("runtime-protected-readiness"),
         "operational_evidence_missing"),
        (lambda r: r.evidence.check_changes.update({"api-operational": {"status": "failed"}}),
         "operational_receipt_mismatch"),
        (lambda r: r.evidence.check_changes.update({"runtime-protected-readiness": {
            "tasks": {"worker": "arn:aws:ecs:us-east-1:111122223333:task/x"}}}),
         "operational_receipt_mismatch"),
    ],
)  # fmt: skip
def test_operational_evidence_must_pass_and_bind_the_recorded_tasks(configure, reason):
    r = rig()
    configure(r)
    outcome = r.controller().run()
    assert_held(r, outcome, reason, "services_started")


def test_replacement_during_observation_requires_a_fresh_window(monkeypatch):
    r = rig()
    original = r.evidence.operational_receipt

    def replace_worker(release_id, check_id):
        receipt = original(release_id, check_id)
        if check_id == "api-operational":
            r.ecs.services[r.document["environment"]["services"]["worker"]].replace_after = 0
        return receipt

    monkeypatch.setattr(r.evidence, "operational_receipt", replace_worker)
    outcome = r.controller().run()
    assert_held(r, outcome, "task_replaced", "services_started")


# Worker readiness gate --------------------------------------------------------

GATE = "worker-readiness"
STAMP = "%Y-%m-%dT%H:%M:%S.%fZ"


def gate_events(r: Rig, result: str) -> list[dict]:
    return r.events("observation", subject=GATE, result=result)


def moment(value: str) -> datetime:
    return datetime.fromisoformat(value)


def recorded(r: Rig, key: str = "worker"):
    return r.ecs.tasks[r.events("observation", subject=key, result="service_ready")[0]["task_arn"]]


def service_of(r: Rig, key: str):
    return r.ecs.services[r.document["environment"]["services"][key]]


def shifted(receipt: dict, seconds: float) -> dict:
    observed = datetime.strptime(receipt["observed_at"], STAMP).replace(tzinfo=timezone.utc)
    return {**receipt, "observed_at": (observed + timedelta(seconds=seconds)).strftime(STAMP)}


def only(sequence: int, change):
    return lambda current, receipt: change(receipt) if current == sequence else [receipt]


def reorder(first: int):
    held = {}

    def edit(sequence, receipt):
        if sequence == first:
            held["receipt"] = receipt
            return []
        return [receipt, held["receipt"]] if sequence == first + 1 else [receipt]

    return edit


def reboot(at: int):
    def edit(sequence, receipt):
        if sequence < at:
            return [receipt]
        uptime = receipt["uptime_seconds"] - 10 * (at - 1)
        return [{**receipt, "boot_id": "b" * 32, "sequence": sequence - at + 1,
                 "uptime_seconds": uptime}]  # fmt: skip

    return edit


def test_worker_readiness_needs_sixty_seconds_of_receipts_observed_after_the_epoch():
    r = rig()
    outcome = r.controller().run()
    assert outcome.state == "held_paused", outcome
    [started] = gate_events(r, "readiness_observing")
    [passed] = gate_events(r, "operational_passed")
    task = recorded(r)
    epoch = moment(started["epoch_at"])
    assert started["task_arn"] == passed["task_arn"] == task.arn
    assert moment(started["deadline_at"]) == epoch + timedelta(seconds=600)
    assert {key: passed[key] for key in
            ("boot_id", "first_sequence", "last_sequence", "stable_seconds", "last_reset")} == {
        "boot_id": FakeLogs.boot_id(task), "first_sequence": 2, "last_sequence": 8,
        "stable_seconds": 60.0, "last_reset": None,
    }  # fmt: skip
    assert moment(passed["at"]) == epoch + timedelta(seconds=70)
    # The pre-gate receipt was read but could not seed the window.
    assert FakeLogs.observed(task, 1) < epoch <= FakeLogs.observed(task, 2)
    assert any('"sequence":1,' in message for message in r.logs.delivered)
    # Reads name only the recorded task's fixed app stream, bounded by endTime.
    # The approved manifest's release and the ECS task fix the stream.
    stream = f"worker/{r.document['release_id']}/app/" + task.arn.rsplit("/", 1)[1]
    assert {(c["log_group"], c["log_stream"]) for c in r.logs.calls} == {
        ("/staging/worker", stream)
    }
    start = int((epoch - timedelta(seconds=5)).timestamp() * 1000)
    assert all(c["limit"] == 100 and c["start_time_ms"] == start
               and c["end_time_ms"] == int(c["at"].timestamp() * 1000)
               for c in r.logs.calls)  # fmt: skip


@pytest.mark.parametrize(
    "configure, last_reason",
    [
        (lambda logs: setattr(logs, "denied", True), "readiness_logs_unavailable"),
        (lambda logs: setattr(logs, "missing", True), "readiness_logs_unavailable"),
        (lambda logs: setattr(logs, "endless", True), "readiness_logs_incomplete"),
        (lambda logs: setattr(logs, "edit", lambda s, receipt: []), "receipt_missing"),
        (lambda logs: setattr(logs, "delay", 45.0), "receipt_stale"),
        (lambda logs: setattr(logs, "edit", lambda s, receipt: [{**receipt, "ready": False}]),
         "receipt_not_ready"),
        (lambda logs: setattr(logs, "edit", lambda s, receipt: [
            {**receipt, "draining": True, "phase": "stopped"}]), "receipt_not_ready"),
        (lambda logs: setattr(logs, "edit", lambda s, receipt: [
            {**receipt, "error_code": "runtime_unavailable"}]), "receipt_not_ready"),
        (lambda logs: setattr(logs, "edit", lambda s, receipt: [
            {**receipt, "phase_elapsed_seconds": 62.0}]), "receipt_not_ready"),
        (lambda logs: setattr(logs, "edit", lambda s, receipt: [
            {**receipt, "release_id": PRIOR_RELEASE_ID}]), "receipt_release_mismatch"),
        (lambda logs: setattr(logs, "edit", lambda s, receipt: [receipt] if s % 2 else []),
         "receipt_gap"),
        (lambda logs: setattr(logs, "edit", lambda s, receipt: [shifted(receipt, 60)]),
         "receipt_from_future"),
        (lambda logs: setattr(logs, "edit", lambda s, receipt: [
            {**receipt, "kind": "sentry.worker-readiness.v0"}]), "receipt_invalid"),
        (lambda logs: setattr(logs, "edit", lambda s, receipt: [
            {**receipt, "uptime_seconds": 5.0}]), "receipt_clock_anomaly"),
    ],
)  # fmt: skip
def test_unproven_worker_readiness_holds_at_the_fixed_gate_deadline(configure, last_reason):
    r = rig()
    configure(r.logs)
    outcome = r.controller().run()
    assert_held(r, outcome, "worker_readiness_not_proven", "services_started")
    [started] = gate_events(r, "readiness_observing")
    [unproven] = gate_events(r, "readiness_not_proven")
    assert unproven["last_reason"] == last_reason
    deadline = moment(started["epoch_at"]) + timedelta(seconds=600)
    assert moment(unproven["at"]) == moment(started["deadline_at"]) == deadline
    assert not gate_events(r, "operational_passed")
    assert r.transitions()[-2:] == ["services_started", "hold"]


@pytest.mark.parametrize(
    "configure, first, last, last_reset",
    [
        (lambda logs: setattr(logs, "edit", lambda s, receipt: [receipt, receipt]), 2, 8, None),
        (lambda logs: setattr(logs, "edit", only(4, lambda receipt: [{**receipt, "ready": False}])),
         5, 11, "receipt_not_ready"),
        (lambda logs: setattr(logs, "edit", only(4, lambda receipt: [])), 5, 11, "receipt_gap"),
        (lambda logs: setattr(logs, "stall", (4, 20.0)), 5, 11, "receipt_interval_exceeded"),
        (lambda logs: setattr(logs, "edit", reorder(4)), 6, 12, "receipt_reordered"),
        (lambda logs: setattr(logs, "edit", only(5, lambda receipt: [
            receipt, {**receipt, "ready": False}])), 6, 12, "receipt_conflict"),
        (lambda logs: setattr(logs, "edit", reboot(4)), 1, 7, "worker_rebooted"),
        # A wrongly typed marked line resets like any invalid receipt; 5 then gaps.
        (lambda logs: setattr(logs, "edit", only(4, lambda receipt: [
            {**receipt, "phase": []}])), 5, 11, "receipt_gap"),
        (lambda logs: setattr(logs, "page_size", 1) or setattr(logs, "empty_pages", 3),
         2, 8, None),
    ],
)  # fmt: skip
def test_an_anomaly_restarts_the_window_and_only_a_full_new_window_passes(
    configure, first, last, last_reset
):
    r = rig()
    configure(r.logs)
    outcome = r.controller().run()
    assert outcome.state == "held_paused", outcome
    [started] = gate_events(r, "readiness_observing")
    [passed] = gate_events(r, "operational_passed")
    assert (passed["first_sequence"], passed["last_sequence"]) == (first, last)
    assert passed["last_reset"] == last_reset and passed["stable_seconds"] >= 60
    # Each anomaly happened after the epoch, so it belongs to this attempt.
    assert FakeLogs.observed(recorded(r), 4) > moment(started["epoch_at"])


def test_ecs_health_loss_clears_stability_even_with_consecutive_receipts(monkeypatch):
    r = rig()
    describe = r.ecs._describe

    def flaky_health(task):
        result = describe(task)
        since = r.clock.now() - task.created
        if task.group == "service:worker" and timedelta(seconds=35) <= since < timedelta(
            seconds=45
        ):
            result["healthStatus"] = "UNHEALTHY"
        return result

    monkeypatch.setattr(r.ecs, "_describe", flaky_health)
    outcome = r.controller().run()
    assert outcome.state == "held_paused", outcome
    [passed] = gate_events(r, "operational_passed")
    # Receipts 4-6 are consecutive. 4 predates recovery and 5 is within the 5 s a
    # worker clock may run ahead of the last unhealthy poll, so the window starts at 6.
    assert passed["first_sequence"] == 6 and passed["last_reset"] == "task_unhealthy"


def test_incomplete_pagination_clears_stability_until_a_complete_read():
    r = rig()
    r.logs.page_size = 1

    def deny_then_backlog():
        r.logs.denied = len(r.logs.calls) <= 24

    r.logs.before_read = deny_then_backlog
    outcome = r.controller().run()
    assert outcome.state == "held_paused", outcome
    [started] = gate_events(r, "readiness_observing")
    [passed] = gate_events(r, "operational_passed")
    epoch = moment(started["epoch_at"])
    assert passed["last_reset"] == "readiness_logs_incomplete"
    # The backlog exceeded 20 one-event pages at +120 s; the window starts after it.
    assert FakeLogs.observed(recorded(r), passed["first_sequence"]) > epoch + timedelta(seconds=120)


def slow_read(r: Rig, *, failure: str, seconds: float) -> dict:
    """The fifth log request takes ``seconds``, then is denied or never completes."""
    returned: dict = {}

    def stall():
        calls = len(r.logs.calls)
        if calls == 5:
            r.clock.advance(seconds=seconds)
            returned["at"] = r.clock.now()  # later pages take no fake time
            if failure == "denied":
                raise PermissionError("AccessDeniedException")
            r.logs.endless = True  # pages 5-24 hit the 20-page bound
        elif calls == 25:
            r.logs.endless = False

    r.logs.before_read = stall
    return returned


# 60 s reproduces the acceptance probe; 25 s stays inside the 30 s freshness
# bound, so only the read-completion clear can exclude the unavailable time.
@pytest.mark.parametrize(
    ("failure", "seconds"),
    [("denied", 60), ("denied", 25), ("incomplete", 60), ("incomplete", 25)],
)
def test_time_spent_in_a_failed_read_never_counts_toward_stability(failure, seconds):
    r = rig()
    returned = slow_read(r, failure=failure, seconds=seconds)
    outcome = r.controller().run()
    assert outcome.state == "held_paused", outcome
    [started] = gate_events(r, "readiness_observing")
    [passed] = gate_events(r, "operational_passed")
    epoch, completion = moment(started["epoch_at"]), returned["at"]
    # Visibility was lost until the read returned: the window starts with a
    # receipt observed after completion plus the allowed skew, and lasts 60 s.
    first = FakeLogs.observed(recorded(r), passed["first_sequence"])
    assert first > completion + timedelta(seconds=5)
    assert moment(passed["at"]) >= first + timedelta(seconds=60)
    assert (
        passed["last_reset"]
        == {
            "denied": "readiness_logs_unavailable",
            "incomplete": "readiness_logs_incomplete",
        }[failure]
    )
    # The fixed deadline is unchanged by the slow read.
    assert moment(started["deadline_at"]) == epoch + timedelta(seconds=600)


@pytest.mark.parametrize(
    "change, reason",
    [
        (lambda r: setattr(service_of(r, "worker"), "replace_after", 0), "task_replaced"),
        (lambda r: setattr(service_of(r, "worker"), "desired", 0), "task_count_drift"),
        (lambda r: setattr(service_of(r, "worker"), "extra_tasks", 1), "task_count_drift"),
        (lambda r: r.ecs._deployment(service_of(r, "worker"),
                                     service_of(r, "worker").task_definition, 1),
         "deployment_superseded"),
        (lambda r: recorded(r).containers[1].update(imageDigest=digest("other")),
         "task_image_mismatch"),
        # Success re-enumerates every recorded service first.
        (lambda r: setattr(service_of(r, "api"), "replace_after", 0), "task_replaced"),
    ],
)  # fmt: skip
def test_platform_identity_changes_during_the_gate_hold_without_waiting(change, reason):
    r = rig()

    def change_once():
        if len(r.logs.calls) == 3:
            change(r)

    r.logs.before_read = change_once
    outcome = r.controller().run()
    assert_held(r, outcome, reason, "services_started")
    assert not gate_events(r, "operational_passed")
    assert not gate_events(r, "readiness_not_proven")
    [started] = gate_events(r, "readiness_observing")
    held = moment(r.events("transition", to="hold")[0]["at"])
    assert held - moment(started["epoch_at"]) <= timedelta(seconds=70)


def slow_final_enumeration(r: Rig, monkeypatch, seconds: float) -> None:
    """The first re-enumeration inside the gate takes ``seconds`` of clock time."""
    original = ReleaseController._require_recorded_tasks
    calls = []

    def enumerate_slowly(self, recorded_tasks):
        calls.append(1)
        if len(calls) == 2:  # the first call precedes the gate
            r.clock.advance(seconds=seconds)
        return original(self, recorded_tasks)

    monkeypatch.setattr(ReleaseController, "_require_recorded_tasks", enumerate_slowly)


def test_success_needs_the_deadline_after_the_final_enumeration(monkeypatch):
    r = rig()
    # Ready only from receipt 54, so the window completes 10 s before the deadline;
    # a 10 s enumeration then crosses it while the receipts are still fresh.
    r.logs.edit = lambda sequence, receipt: [{**receipt, "ready": sequence >= 54}]
    slow_final_enumeration(r, monkeypatch, 10)
    outcome = r.controller().run()
    assert_held(r, outcome, "worker_readiness_not_proven", "services_started")
    assert not gate_events(r, "operational_passed")
    [started] = gate_events(r, "readiness_observing")
    assert FakeLogs.observed(recorded(r), 60) == moment(started["deadline_at"]) - timedelta(
        seconds=14
    )


def test_success_needs_fresh_receipts_after_the_final_enumeration(monkeypatch):
    r = rig()
    slow_final_enumeration(r, monkeypatch, 40)
    outcome = r.controller().run()
    assert outcome.state == "held_paused", outcome
    [passed] = gate_events(r, "operational_passed")
    assert passed["last_reset"] == "receipt_stale" and passed["first_sequence"] > 8


def test_controller_clock_rollback_at_final_success_holds(monkeypatch):
    r = rig()
    original = ReleaseController._require_recorded_tasks
    calls = []

    def roll_back(self, recorded_tasks):
        calls.append(1)
        if len(calls) == 2:  # the gate's final enumeration
            r.clock.moment -= timedelta(seconds=30)
        return original(self, recorded_tasks)

    monkeypatch.setattr(ReleaseController, "_require_recorded_tasks", roll_back)
    outcome = r.controller().run()
    assert_held(r, outcome, "controller_clock_rollback", "services_started")
    assert not gate_events(r, "operational_passed")


def test_a_resumed_gate_attempt_starts_a_new_epoch():
    r = rig()

    def crash_midway():
        if len(r.logs.calls) == 16:
            r.logs.before_read = None
            raise SimulatedCrash("controller lost mid-gate")

    r.logs.before_read = crash_midway
    with pytest.raises(SimulatedCrash):
        r.controller().run()
    outcome = r.controller().run()
    assert outcome.state == "held_paused", outcome
    first, second = gate_events(r, "readiness_observing")
    [passed] = gate_events(r, "operational_passed")
    epoch = moment(second["epoch_at"])
    assert epoch > moment(first["epoch_at"])
    # Receipts from the lost attempt cannot seed the new window.
    assert FakeLogs.observed(recorded(r), passed["first_sequence"]) >= epoch
    assert moment(second["deadline_at"]) == moment(first["deadline_at"])


def test_resumed_attempts_never_extend_the_whole_gate_deadline():
    r = rig()
    r.logs.denied = True

    def crash_midway():
        if len(r.logs.calls) == 40:
            r.logs.before_read = None
            raise SimulatedCrash("controller lost mid-gate")

    r.logs.before_read = crash_midway
    with pytest.raises(SimulatedCrash):
        r.controller().run()
    outcome = r.controller().run()
    assert_held(r, outcome, "worker_readiness_not_proven", "services_started")
    first, second = gate_events(r, "readiness_observing")
    [unproven] = gate_events(r, "readiness_not_proven")
    assert moment(second["epoch_at"]) - moment(first["epoch_at"]) == timedelta(seconds=195)
    assert moment(unproven["at"]) == moment(first["epoch_at"]) + timedelta(seconds=600)
    assert moment(second["deadline_at"]) == moment(first["deadline_at"])


def test_unrelated_standalone_writer_blocks_quiescence():
    r = rig()
    r.ecs.standalone(r.document["services"]["api"]["task_definition"])
    outcome = r.controller().run()
    assert_held(r, outcome, "standalone_writer_present", "locked")
    assert r.ecs.mutations == []


# First release versus compatible rollback ------------------------------------


def test_upgrade_cannot_pretend_to_be_a_first_release():
    r = rig(rollback="compatible_release", running_prior=True)
    r.document = manifest_document()  # empty_hold against running services
    r.approval_raw = encode(approval_document(load_manifest(encode(r.document)).sha256))
    outcome = r.controller().run()
    assert_held(r, outcome, "upgrade_requires_compatible_rollback", "locked")
    assert r.ecs.mutations == []


def test_compatible_rollback_must_match_what_is_actually_running():
    r = rig(rollback="compatible_release")  # fresh services run the candidate, not the prior
    outcome = r.controller().run()
    assert_held(r, outcome, "prior_release_mismatch", "locked")
    assert r.ecs.mutations == []


def test_upgrade_quiesces_running_writers_before_migrating():
    r = rig(rollback="compatible_release", running_prior=True)
    outcome = r.controller().run()
    assert outcome.state == "held_paused", outcome
    quiesce = r.calls("update_service")[:3]
    assert all(c == {"cluster": c["cluster"], "service": c["service"], "desiredCount": 0}
               for c in quiesce)  # fmt: skip
    first_job = next(i for i, e in enumerate(r.trace) if e[:2] == ("ecs", "run_task"))
    assert [e[1] for e in r.trace[:first_job] if e[0] == "ecs"] == ["update_service"] * 3
    assert_intent_precedes_every_mutation(r)


@pytest.mark.parametrize("failed_job, runtime_compatible, last, actions", [
    (3, ["goose:1,2,3"], "migrated", ["quiesce_writers", "start_compatible_pair_paused",
                                       "repeat_readiness_denial_and_reconciliation",
                                       "remain_paused"]),
    (3, ["goose:1,2"], "migrated", ["keep_writers_quiesced",
                                     "repair_forward_or_restore_isolated_copies"]),
    (1, ["goose:1,2,3"], "quiesced", ["keep_writers_quiesced", "reconcile_unknown_schema_state"]),
])  # fmt: skip
def test_upgrade_failure_plans_rollback_only_from_known_compatible_schemas(
    failed_job, runtime_compatible, last, actions
):
    r = rig(rollback="compatible_release", running_prior=True)
    r.document["rollback"]["compatible_schemas"]["runtime"] = runtime_compatible
    r.approval_raw = encode(approval_document(load_manifest(encode(r.document)).sha256))
    task = r.document["jobs"][failed_job]["task"]
    r.ecs.plans[task["task_definition"]] = JobPlan(exits={task["containers"][1]["name"]: 1})
    outcome = r.controller().run()
    assert_held(r, outcome, "job_container_failed", last)
    product = r.document["jobs"][1]["expect"]["schema"]
    assert outcome.rollback == {
        "kind": "compatible_release",
        "prior_release_id": r.document["rollback"]["release_id"],
        # A failed migration exit does not prove its SQL rolled back.
        "actual_schemas": {"runtime": "goose:1,2,3",
                           "product": "unknown" if failed_job == 1 else product},
        "automatic": False,
        "actions": actions,
    }  # fmt: skip


@pytest.mark.parametrize(
    "error, reason",
    [
        (AmbiguousResponse("read timed out"), "observation_ambiguous"),
        (RuntimeError("unexpected response shape"), "controller_error"),
    ],
)
def test_read_errors_after_launch_hold_with_the_lock_retained(monkeypatch, error, reason):
    r = rig()
    original = r.ecs.describe_tasks

    def flaky(cluster, task_arns):
        if r.job_tasks("product-migrate"):
            raise error
        return original(cluster, task_arns)

    monkeypatch.setattr(r.ecs, "describe_tasks", flaky)
    outcome = r.controller().run()
    assert_held(r, outcome, reason, "quiesced")
    assert outcome.rollback is not None
    assert "reconcile_partial_migration_before_rerun" in outcome.rollback["actions"]


def test_crash_between_lock_and_journal_transition_recovers_the_same_lock():
    r = rig()

    def crash_on_locked(key, body):
        event = json.loads(body)["events"][-1]
        if event["kind"] == "transition" and event["to"] == "locked":
            r.store.before_replace = None
            raise SimulatedCrash("after lock, before transition")

    r.store.before_replace = crash_on_locked
    with pytest.raises(SimulatedCrash):
        r.controller().run()
    assert r.transitions() == ["prepared"] and LOCK in r.store.objects
    outcome = r.recover().run()
    assert outcome.state == "held_paused"
    assert r.transitions() == FORWARD


def test_journal_is_created_with_its_first_event_in_one_write():
    r = rig()
    r.controller().run()
    created = next(entry for entry in r.trace if entry[:2] == ("store", JOURNAL))
    assert [e["to"] for e in created[2]["events"]] == ["prepared"]
    empty = {**r.journal(), "events": []}
    r.store.objects[JOURNAL] = (json.dumps(empty).encode(), r.store.objects[JOURNAL][1])
    with pytest.raises(ReleaseHalted) as error:
        r.controller().run()
    assert error.value.code == "journal_integrity"


@pytest.mark.parametrize("when", ["before", "after"])
@pytest.mark.parametrize("elapsed", [100, 1000])
def test_expired_recovery_cleans_up_owned_jobs_without_launching(when, elapsed):
    r = rig(not_after=iso(START + timedelta(seconds=50)))
    definition = r.document["jobs"][0]["task"]["task_definition"]
    r.ecs.plans[definition] = JobPlan(hang=True)
    r.ecs.crash[("run_task", when)] = 1
    with pytest.raises(SimulatedCrash):
        r.controller().run()
    launches = len(r.calls("run_task"))
    r.clock.advance(seconds=elapsed)
    outcome = r.recover().run()
    assert_held(r, outcome, "approval_expired", "quiesced")
    assert len(r.calls("run_task")) == launches
    assert r.calls("update_service") == []
    assert len(r.calls("stop_task")) == (1 if when == "after" else 0)
    if when == "after":
        assert r.ecs._status(r.job_tasks("runtime-migrate")[0]) == "STOPPED"
        assert r.events("observation", result="stop_confirmed")[-1]["sql_outcome"] == "unknown"


def test_expiry_during_a_running_job_stops_it_before_hold():
    r = rig(not_after=iso(START + timedelta(seconds=50)))
    r.ecs.plans[r.document["jobs"][0]["task"]["task_definition"]] = JobPlan(hang=True)
    outcome = r.controller().run()
    assert_held(r, outcome, "approval_expired", "quiesced")
    assert len(r.calls("stop_task")) == 1
    assert r.clock.now() < START + timedelta(seconds=900)


def test_expired_recovery_does_not_stop_an_unrelated_task(monkeypatch):
    r = rig(not_after=iso(START + timedelta(seconds=50)))
    r.ecs.crash[("run_task", "before")] = 1
    with pytest.raises(SimulatedCrash):
        r.controller().run()
    foreign = r.ecs.standalone(r.document["jobs"][0]["task"]["task_definition"])
    monkeypatch.setattr(r.ecs, "list_tasks", lambda *args, **kwargs: [foreign.arn])
    r.clock.advance(seconds=1000)
    outcome = r.recover().run()
    assert outcome.state == "hold"
    assert not r.calls("run_task") and not r.calls("stop_task")
    assert r.ecs._status(foreign) == "RUNNING"


@pytest.mark.parametrize("duration", [899, 900, 901])
def test_recovery_cannot_promote_a_job_without_timely_observation(monkeypatch, duration):
    r = rig()
    definition = r.document["jobs"][0]["task"]["task_definition"]
    r.ecs.plans[definition] = JobPlan(seconds=duration)
    original = r.ecs.describe_tasks

    def crash_first_read(*args):
        raise SimulatedCrash("after launch record")

    monkeypatch.setattr(r.ecs, "describe_tasks", crash_first_read)
    with pytest.raises(SimulatedCrash):
        r.controller().run()
    monkeypatch.setattr(r.ecs, "describe_tasks", original)
    r.clock.advance(seconds=905)
    outcome = r.recover().run()
    assert_held(r, outcome, "job_deadline_exceeded", "quiesced")
    assert len(r.calls("run_task")) == 1
    assert not r.events("observation", result="job_succeeded")
    assert not r.calls("stop_task"), "the observed stopped task needs no StopTask"


def test_receipt_read_crossing_deadline_cannot_promote(monkeypatch):
    r = rig()
    original = r.evidence.job_receipt

    def slow_receipt(*args):
        receipt = original(*args)
        r.clock.advance(seconds=901)
        return receipt

    monkeypatch.setattr(r.evidence, "job_receipt", slow_receipt)
    outcome = r.controller().run()
    assert_held(r, outcome, "job_deadline_exceeded", "quiesced")
    assert not r.events("observation", result="job_succeeded")


@pytest.mark.parametrize("when", ["before", "after"])
@pytest.mark.parametrize("new_session", [False, True])
def test_finalization_crash_resumes_exact_lock_cleanup(monkeypatch, when, new_session):
    r = rig()
    original = r.store.delete

    def crash_delete(key, *, if_match):
        if when == "after":
            original(key, if_match=if_match)
        raise SimulatedCrash("lock release")

    monkeypatch.setattr(r.store, "delete", crash_delete)
    with pytest.raises(SimulatedCrash):
        r.controller().run()
    monkeypatch.setattr(r.store, "delete", original)
    mutations = len(r.ecs.mutations)
    # Cleanup remains legal after approval expiry; no service/job can restart.
    r.clock.advance(seconds=20_000)
    controller = r.controller()
    if new_session:
        controller = r.controller("session-b")
        controller.recover(
            RecoveryAuthorization(
                prior_session_id="session-a",
                lock_etag=r.lock_etag() if when == "before" else "",
                fence_evidence_sha256=sha("fenced"),
                authorized_by="fixture-operator",
            )
        )
    assert controller.run().state == "held_paused"
    assert LOCK not in r.store.objects
    assert len(r.ecs.mutations) == mutations
    assert r.events("observation", subject="environment", result="lock_released")


def test_pending_finalization_does_not_delete_a_replacement_lock(monkeypatch):
    r = rig()

    def crash_delete(*args, **kwargs):
        raise SimulatedCrash("before delete")

    monkeypatch.setattr(r.store, "delete", crash_delete)
    with pytest.raises(SimulatedCrash):
        r.controller().run()
    foreign = (encode({"release_id": "other", "session_id": "other"}), '"new-lock"')
    r.store.objects[LOCK] = foreign
    with pytest.raises(ReleaseHalted):
        r.controller().run()
    assert r.store.objects[LOCK] == foreign


def test_pending_finalization_needs_explicit_session_recovery(monkeypatch):
    r = rig()

    def crash_delete(*args, **kwargs):
        raise SimulatedCrash("before delete")

    monkeypatch.setattr(r.store, "delete", crash_delete)
    with pytest.raises(SimulatedCrash):
        r.controller().run()
    with pytest.raises(ReleaseHalted) as error:
        r.controller("session-b").run()
    assert error.value.code == "session_conflict"


def test_expiry_cleanup_records_unknown_when_lock_read_fails(monkeypatch):
    r = rig(not_after=iso(START + timedelta(seconds=50)))
    r.ecs.plans[r.document["jobs"][0]["task"]["task_definition"]] = JobPlan(hang=True)
    r.ecs.crash[("run_task", "after")] = 1
    with pytest.raises(SimulatedCrash):
        r.controller().run()
    r.clock.advance(seconds=1000)
    controller = r.recover()
    original = r.store.read
    lock_reads = 0

    def flaky_read(key):
        nonlocal lock_reads
        if key == LOCK:
            lock_reads += 1
            if lock_reads == 2:  # Open succeeded; cleanup cannot prove ownership.
                raise RuntimeError("temporary read failure")
        return original(key)

    monkeypatch.setattr(r.store, "read", flaky_read)
    outcome = controller.run()
    assert_held(r, outcome, "approval_expired", "quiesced")
    assert not r.calls("stop_task")
    assert r.events("observation", result="cleanup_unconfirmed")[-1]["sql_outcome"] == "unknown"
