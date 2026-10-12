"""Offline release-controller fault tests against deterministic fake ECS/S3 ports."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import sys

import pytest

from release.controller import (
    VISIBILITY_POLLS,
    FailedReleaseHandoff,
    RecoveryAuthorization,
    ReleaseController,
    ReleaseHalted,
)
from release.manifest import canonical_sha256, load_approval, load_manifest
from release.ports import AmbiguousResponse, ClockUntrusted
from release.journal import Journal, journal_key
from tests.release_fakes import (
    FAILED_RELEASE_ID,
    OPERATOR_ROLE,
    PRIOR_RELEASE_ID,
    ROLLBACK_RELEASE_ID,
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
    forward_document,
    iso,
    manifest_document,
    rollback_run_document,
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
        # After the services start: one observer task for each of the Runtime and API.
        "sentry-staging-runtime-observe:7",
        "sentry-staging-api-observe:7",
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
    }
    # Terraform alone writes deployment settings; the controller sends none of them.
    assert all(
        set(call) <= {"cluster", "service", "taskDefinition", "desiredCount", "forceNewDeployment"}
        for call in r.calls("update_service")
    )


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


def test_a_forward_recovery_never_accepts_another_releases_lock(monkeypatch):
    # Only a rollback leaves a foreign lock in place, and only its failed release's.
    r = rig()
    original = r.store.create

    def crash(key, body):
        if key == LOCK:
            raise SimulatedCrash("lock create")
        return original(key, body)

    monkeypatch.setattr(r.store, "create", crash)
    with pytest.raises(SimulatedCrash):
        r.controller().run()
    monkeypatch.setattr(r.store, "create", original)
    r.store.create(LOCK, encode({"release_id": FAILED_RELEASE_ID, "session_id": "other"}))
    before = dict(r.store.objects)
    values = {"prior_session_id": "session-a", "lock_etag": r.lock_etag(),
              "fence_evidence_sha256": sha("fenced"), "authorized_by": "fixture-operator"}  # fmt: skip
    with pytest.raises(ReleaseHalted) as error:
        r.controller("session-b").recover(RecoveryAuthorization(**values))
    assert error.value.code == "recovery_refused"
    assert r.store.objects == before


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


def test_reconciliation_finds_a_launch_that_already_stopped_without_resending():
    # Listing by launch token must include stopped tasks: a short job that ran and
    # exited before reconciliation is still the one launch, not a reason to retry.
    r = rig()
    migrate = r.document["jobs"][0]["task"]["task_definition"]
    r.ecs.plans[migrate] = JobPlan(seconds=2)
    r.ecs.crash[("run_task", "after")] = 1
    with pytest.raises(SimulatedCrash):
        r.controller().run()
    r.clock.advance(seconds=5)
    outcome = r.recover().run()
    assert outcome.state == "held_paused"
    launches = [c for c in r.calls("run_task") if c["taskDefinition"] == migrate]
    assert len(launches) == 1
    assert r.events("observation", subject="runtime-migrate", result="launched")[0]["reconciled"]


def test_a_reconciled_launch_must_be_the_approved_unmodified_task():
    r = rig()
    migrate = r.document["jobs"][0]["task"]["task_definition"]
    r.ecs.quirks[migrate] = {
        "overrides": {"containerOverrides": [{"name": "migration", "command": ["sh"]}]}
    }
    r.ecs.crash[("run_task", "after")] = 1
    with pytest.raises(SimulatedCrash):
        r.controller().run()
    outcome = r.recover().run()
    assert_held(r, outcome, "task_overrides_present", "quiesced")
    [refused] = r.events("observation", subject="runtime-migrate", result="launched_unexpected")
    assert refused["reason"] == "task_overrides_present"
    assert not r.events("observation", subject="runtime-migrate", result="launched")


def test_a_reconciled_task_briefly_invisible_to_describe_is_polled_not_held(monkeypatch):
    r = rig()
    r.ecs.crash[("run_task", "after")] = 1
    with pytest.raises(SimulatedCrash):
        r.controller().run()
    original = FakeEcs.describe_tasks
    misses = {"left": 2}

    def lagging(self, cluster, task_arns):
        if misses["left"]:
            misses["left"] -= 1
            return {
                "tasks": [],
                "failures": [{"arn": arn, "reason": "MISSING"} for arn in task_arns],
            }
        return original(self, cluster, task_arns)

    monkeypatch.setattr(FakeEcs, "describe_tasks", lagging)
    assert r.recover().run().state == "held_paused"
    assert r.events("observation", subject="runtime-migrate", result="launched")[0]["reconciled"]


def test_a_refused_launch_is_never_launched_again_when_its_hold_was_lost():
    r = rig()
    migrate = r.document["jobs"][0]["task"]["task_definition"]
    r.ecs.quirks[migrate] = {"enableExecuteCommand": True}

    def lose_the_hold(key, body):
        if key == JOURNAL and json.loads(body)["events"][-1].get("to") == "hold":
            r.store.before_replace = None
            raise SimulatedCrash("hold never journaled")

    r.store.before_replace = lose_the_hold
    with pytest.raises(SimulatedCrash):
        r.controller().run()
    outcome = r.recover().run()
    assert_held(r, outcome, "task_exec_enabled", "quiesced")
    assert len([c for c in r.calls("run_task") if c["taskDefinition"] == migrate]) == 1


def test_a_service_ready_only_after_its_deadline_holds(monkeypatch):
    r = rig()
    original = ReleaseController._service_snapshot

    def slow(self, key, deployment):
        if key == "api":
            r.clock.advance(seconds=700)  # beyond the 600 s service start budget
        return original(self, key, deployment)

    monkeypatch.setattr(ReleaseController, "_service_snapshot", slow)
    outcome = r.controller().run()
    assert_held(r, outcome, "service_start_deadline_exceeded", "grants_verified")
    assert not r.events("observation", subject="api", result="service_ready")


def test_a_failed_hold_write_never_chains_to_the_error_that_caused_it(monkeypatch):
    # A port error may quote provider or log content. The hold that follows it is
    # journaled outside the handler, so even a halt cannot carry that content.
    r = rig()

    def leaky(release_id, job_id, task_arn):
        raise ValueError("Traceback ... password=fixture-secret-7Q2 report-fixture-55aa")

    monkeypatch.setattr(r.evidence, "job_receipt", leaky)

    def competitor(key, body):
        if key == JOURNAL and json.loads(body)["events"][-1].get("to") == "hold":
            r.store.before_replace = None
            current, _ = r.store.objects[key]
            r.store.objects[key] = (current, '"etag-competitor"')

    r.store.before_replace = competitor
    with pytest.raises(ReleaseHalted) as error:
        r.controller().run()
    assert error.value.code == "journal_conflict"
    chained: list[BaseException | None] = [error.value]
    seen: list[BaseException] = []
    while chained:
        item = chained.pop()
        if item is None or item in seen:
            continue
        seen.append(item)
        chained += [item.__cause__, item.__context__]
    assert not any("fixture-secret" in repr(item.args) for item in seen), seen


def test_quiesce_waits_for_a_writer_whose_stop_is_in_progress():
    r = rig()
    writer = r.ecs.standalone(r.document["services"]["worker"]["task_definition"])
    writer.stopped_at = r.clock.now() + timedelta(seconds=110)
    writer.stop_code = "UserInitiated"
    outcome = r.controller().run()
    assert outcome.state == "held_paused", outcome
    first_launch = next(e for e in r.journal()["events"] if e.get("action") == "run_task")
    assert datetime.fromisoformat(first_launch["at"]) >= writer.stopped_at


CLEAN_QUIRKS = [
    {"overrides": {"containerOverrides": [{"name": "migration", "command": ["sh", "-c", "x"]}]}},
    {"overrides": {"containerOverrides": [{"name": "migration", "environment": [{"name": "A", "value": "1"}]}]}},
    {"overrides": {"containerOverrides": [{"name": "init", "environmentFiles": [{"type": "s3", "value": "arn"}]}]}},
    {"overrides": {"containerOverrides": [{"name": "migration", "memory": 4096}]}},
    {"overrides": {"containerOverrides": [], "taskRoleArn": "arn:aws:iam::111122223333:role/other"}},
    {"overrides": {"containerOverrides": [], "executionRoleArn": "arn:aws:iam::111122223333:role/other"}},
    {"overrides": {"containerOverrides": [], "cpu": "4096"}},
    {"overrides": {"containerOverrides": [], "ephemeralStorage": {"sizeInGiB": 100}}},
    {"overrides": {"containerOverrides": [], "inferenceAcceleratorOverrides": [{"deviceName": "x"}]}},
    {"overrides": None},
    {"enableExecuteCommand": True},
    {"enableExecuteCommand": None},
]  # fmt: skip


@pytest.mark.parametrize("quirk", CLEAN_QUIRKS)
def test_observed_override_or_exec_on_a_launched_job_holds(quirk):
    r = rig()
    migrate = r.document["jobs"][0]["task"]["task_definition"]
    r.ecs.quirks[migrate] = quirk
    outcome = r.controller().run()
    reason = "task_exec_enabled" if "enableExecuteCommand" in quirk else "task_overrides_present"
    assert_held(r, outcome, reason, "quiesced")
    assert r.events("observation", subject="runtime-migrate", result="launched_unexpected")
    assert not r.events("observation", subject="runtime-migrate", result="job_succeeded")
    # Launched under this release's token but not as approved: it is stopped.
    [task] = r.job_tasks("runtime-migrate")
    assert [c["task"] for c in r.calls("stop_task")] == [task.arn]
    assert r.events("observation", subject="runtime-migrate", result="stop_confirmed")


@pytest.mark.parametrize("quirk", [CLEAN_QUIRKS[0], CLEAN_QUIRKS[4], CLEAN_QUIRKS[-2]])
def test_observed_override_or_exec_on_a_service_task_holds(quirk):
    r = rig()
    worker = r.document["services"]["worker"]["task_definition"]
    quirk = json.loads(json.dumps(quirk).replace('"migration"', '"app"'))
    r.ecs.quirks[worker] = quirk
    outcome = r.controller().run()
    reason = "task_exec_enabled" if "enableExecuteCommand" in quirk else "task_overrides_present"
    assert_held(r, outcome, reason, "grants_verified")


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
    # Rollback stays disabled because the controller never rewrites Terraform's breaker.
    worker = r.ecs.services[r.document["environment"]["services"]["worker"]]
    assert worker.settings["deploymentConfiguration"]["deploymentCircuitBreaker"] == {
        "enable": True,
        "rollback": False,
    }
    assert all("deploymentConfiguration" not in c for c in r.calls("update_service"))


def _drift(path: tuple[str, ...], value):
    def apply(settings: dict) -> None:
        target = settings
        for key in path[:-1]:
            target = target[key]
        if value is _ABSENT:
            del target[path[-1]]
        else:
            target[path[-1]] = value

    return apply


_ABSENT = object()


@pytest.mark.parametrize(
    "change",
    [
        _drift(("deploymentConfiguration", "minimumHealthyPercent"), 100),
        _drift(("deploymentConfiguration", "maximumPercent"), 200),
        _drift(("deploymentConfiguration", "maximumPercent"), _ABSENT),
        _drift(("deploymentConfiguration", "deploymentCircuitBreaker"), {"enable": True, "rollback": True}),
        _drift(("deploymentConfiguration", "deploymentCircuitBreaker"), {"enable": False, "rollback": False}),
        _drift(("deploymentConfiguration", "alarms"), {"alarmNames": ["a"], "enable": True, "rollback": True}),
        _drift(("deploymentConfiguration", "strategy"), "BLUE_GREEN"),
        _drift(("deploymentController",), {"type": "CODE_DEPLOY"}),
        _drift(("enableExecuteCommand",), True),
        _drift(("enableExecuteCommand",), _ABSENT),
    ],
    ids=[
        "minimum", "maximum", "maximum-missing", "breaker-rollback", "breaker-off", "alarm-rollback",
        "blue-green", "controller", "exec-on", "exec-missing",
    ],
)  # fmt: skip
def test_terraform_owned_setting_drift_holds_before_the_service_is_deployed(change):
    r = rig()
    api = r.document["environment"]["services"]["api"]
    change(r.ecs.services[api].settings)
    outcome = r.controller().run()
    assert_held(r, outcome, "service_settings_drift", "grants_verified")
    # Drift on any described service holds before the first forward deploy.
    assert [c for c in r.calls("update_service") if c["desiredCount"] == 1] == []
    assert r.ecs.services[api].desired == 0


def test_reported_alarm_or_rolling_settings_that_cannot_roll_back_are_accepted():
    r = rig()
    for service in r.ecs.services.values():
        service.settings["deploymentConfiguration"].update(
            alarms={"alarmNames": [], "enable": False, "rollback": False}, strategy="ROLLING"
        )
    outcome = r.controller().run()
    assert outcome.state == "held_paused"


def test_setting_drift_while_observing_a_started_service_holds():
    r = rig()
    runtime = r.ecs.services[r.document["environment"]["services"]["runtime"]]
    original = r.ecs.update_service

    def update(request: dict) -> dict:
        response = original(request)
        if request["service"] == r.document["environment"]["services"]["worker"]:
            runtime.settings["deploymentConfiguration"]["maximumPercent"] = 200
        return response

    setattr(r.ecs, "update_service", update)
    outcome = r.controller().run()
    assert_held(r, outcome, "service_settings_drift", "services_started")


# Deployment-setting drift during update reconciliation ---------------------

DRIFT_VARIANTS = [
    _drift(("deploymentConfiguration", "deploymentCircuitBreaker"), {"enable": True, "rollback": True}),
    _drift(("deploymentConfiguration", "deploymentCircuitBreaker"), {"enable": False, "rollback": False}),
    _drift(("deploymentConfiguration", "minimumHealthyPercent"), 100),
    _drift(("deploymentConfiguration", "maximumPercent"), 200),
    _drift(("deploymentConfiguration", "alarms"), {"alarmNames": ["a"], "enable": True, "rollback": True}),
    _drift(("deploymentConfiguration", "strategy"), "BLUE_GREEN"),
    _drift(("deploymentController",), {"type": "CODE_DEPLOY"}),
    _drift(("enableExecuteCommand",), True),
]  # fmt: skip
DRIFT_IDS = ["rollback", "breaker-off", "minimum", "maximum", "alarm-rollback", "blue-green",
             "controller", "exec-on"]  # fmt: skip


class Interrupted:
    """Wrap the runtime's first forward UpdateService: drift its settings, then lose it.

    ``applied`` decides whether ECS applied the request before the response was
    lost (ambiguity) or the controller process died (crash).
    """

    def __init__(self, r: Rig, *, interruption: str, applied: bool, change=None) -> None:
        self.r, self.interruption, self.applied, self.change = r, interruption, applied, change
        self.arn = r.document["environment"]["services"]["runtime"]
        self.service = r.ecs.services[self.arn]
        self.original = r.ecs.update_service
        self.forward: list[dict] = []
        self.sent_at: list[datetime] = []
        setattr(r.ecs, "update_service", self)

    def __call__(self, request: dict) -> dict:
        if request["service"] != self.arn or request["desiredCount"] != 1:
            return self.original(request)
        self.forward.append(copy.deepcopy(request))
        self.sent_at.append(self.r.clock.now())
        if len(self.forward) > 1:
            return self.original(request)
        response = self.original(request) if self.applied else None
        if self.change is not None:
            self.change(self.service.settings)
        if self.interruption == "crash":
            raise SimulatedCrash("controller lost after the forward intent")
        raise AmbiguousResponse("forward UpdateService response lost")

    def run(self, r: Rig):
        if self.interruption == "crash":
            with pytest.raises(SimulatedCrash):
                r.controller().run()
            return r.recover().run()
        return r.controller().run()


def assert_never_deployed_under_drift(r: Rig, outcome, wrapper: Interrupted, sends: int) -> None:
    assert_held(r, outcome, "service_settings_drift", "grants_verified")
    assert len(wrapper.forward) == sends, "no forward resend once drift is observed"
    assert not r.events("observation", subject="runtime", result="service_deployed")
    assert outcome.rollback is not None
    assert "set_started_services_desired_zero" in outcome.rollback["actions"]


@pytest.mark.parametrize("interruption", ["ambiguous", "crash"])
@pytest.mark.parametrize("change", DRIFT_VARIANTS, ids=DRIFT_IDS)
def test_forward_reconciliation_holds_on_drift_before_any_resend(interruption, change):
    r = rig()
    wrapper = Interrupted(r, interruption=interruption, applied=False, change=change)
    outcome = wrapper.run(r)
    assert_never_deployed_under_drift(r, outcome, wrapper, sends=1)
    assert wrapper.service.desired == 0, "the lost request was never applied or resent"


@pytest.mark.parametrize("interruption", ["ambiguous", "crash"])
@pytest.mark.parametrize(
    "change", DRIFT_VARIANTS[:1] + DRIFT_VARIANTS[-1:], ids=["rollback", "exec-on"]
)
def test_an_applied_deploy_observed_with_drift_is_never_recognized(interruption, change):
    # The lost request did reach ECS: its deployment is visible, but so is drift.
    r = rig()
    wrapper = Interrupted(r, interruption=interruption, applied=True, change=change)
    outcome = wrapper.run(r)
    assert_never_deployed_under_drift(r, outcome, wrapper, sends=1)


def test_a_deploy_response_showing_drift_is_never_recognized():
    r = rig()
    runtime_arn = r.document["environment"]["services"]["runtime"]
    runtime = r.ecs.services[runtime_arn]
    original = r.ecs.update_service

    def drift_then_apply(request: dict) -> dict:
        if request["service"] == runtime_arn and request["desiredCount"] == 1:
            runtime.settings["deploymentConfiguration"]["deploymentCircuitBreaker"][
                "rollback"
            ] = True
        return original(request)

    setattr(r.ecs, "update_service", drift_then_apply)
    outcome = r.controller().run()
    assert_held(r, outcome, "service_settings_drift", "grants_verified")
    assert not r.events("observation", subject="runtime", result="service_deployed")
    assert len([c for c in r.calls("update_service") if c["service"] == runtime_arn]) == 1


def test_drift_during_the_last_visibility_poll_blocks_the_resend():
    # The resend is decided on a fresh observation, not one a poll interval old.
    r = rig()
    wrapper = Interrupted(r, interruption="ambiguous", applied=False)
    sleeps: list[float] = []
    original_sleep = r.clock.sleep

    def sleep(seconds: float) -> None:
        if wrapper.forward:
            sleeps.append(seconds)
            if len(sleeps) == 3:  # the last visibility poll before a resend
                wrapper.service.settings["enableExecuteCommand"] = True
        original_sleep(seconds)

    setattr(r.clock, "sleep", sleep)
    outcome = r.controller().run()
    assert_never_deployed_under_drift(r, outcome, wrapper, sends=1)


def forward_sends(r: Rig) -> list[str]:
    services = {arn: key for key, arn in r.document["environment"]["services"].items()}
    return [services[c["service"]] for c in r.calls("update_service") if c["desiredCount"] == 1]


def test_drift_on_another_service_holds_before_the_next_forward_deploy():
    # Runtime is ready; its Exec is turned on while the API deploys. The worker
    # deploy must not be sent under that observed drift.
    r = rig()
    services = r.document["environment"]["services"]
    original = r.ecs.update_service

    def drift_runtime_during_api(request: dict) -> dict:
        response = original(request)
        if request["service"] == services["api"] and request["desiredCount"] == 1:
            r.ecs.services[services["runtime"]].settings["enableExecuteCommand"] = True
        return response

    setattr(r.ecs, "update_service", drift_runtime_during_api)
    outcome = r.controller().run()
    assert_held(r, outcome, "service_settings_drift", "grants_verified")
    assert forward_sends(r) == ["runtime", "api"]


def test_drift_on_another_service_holds_api_reconciliation_before_any_resend():
    r = rig()
    services = r.document["environment"]["services"]
    original = r.ecs.update_service
    lost: list[dict] = []

    def lose_api_deploy(request: dict) -> dict:
        if request["service"] == services["api"] and request["desiredCount"] == 1 and not lost:
            lost.append(request)
            r.ecs.mutations.append(("update_service", copy.deepcopy(request)))
            r.ecs.services[services["runtime"]].settings["deploymentConfiguration"][
                "deploymentCircuitBreaker"
            ]["rollback"] = True
            raise AmbiguousResponse("API deploy response lost before it was applied")
        return original(request)

    setattr(r.ecs, "update_service", lose_api_deploy)
    outcome = r.controller().run()
    assert_held(r, outcome, "service_settings_drift", "grants_verified")
    assert forward_sends(r) == ["runtime", "api"], "no API resend under runtime drift"


def test_a_lost_deploy_that_never_appears_exhausts_identical_retries():
    r = rig()
    wrapper = Interrupted(r, interruption="ambiguous", applied=False)

    def always_lost(request: dict) -> dict:
        if request["service"] == wrapper.arn and request["desiredCount"] == 1:
            wrapper.forward.append(copy.deepcopy(request))
            raise AmbiguousResponse("every forward response lost before it was applied")
        return wrapper.original(request)

    setattr(r.ecs, "update_service", always_lost)
    outcome = r.controller().run()
    assert_held(r, outcome, "service_update_unconfirmed", "grants_verified")
    assert len(wrapper.forward) == 4 and all(c == wrapper.forward[0] for c in wrapper.forward)
    intents = r.events("intent", action="update_service", subject="runtime")
    assert len(intents) == 4
    assert len({(e["request_sha256"], e["deadline_at"]) for e in intents}) == 1


def test_a_lost_deploy_past_its_deadline_is_not_resent():
    r = rig()
    wrapper = Interrupted(r, interruption="ambiguous", applied=False)
    original_call = wrapper.__call__

    def late(request: dict) -> dict:
        if request["service"] == wrapper.arn and request["desiredCount"] == 1:
            r.clock.advance(seconds=601)  # past the 600 s service start deadline
        return original_call(request)

    setattr(r.ecs, "update_service", late)
    outcome = r.controller().run()
    assert_held(r, outcome, "service_update_unconfirmed", "grants_verified")
    assert len(wrapper.forward) == 1


def test_drift_after_a_successful_resend_is_never_recognized():
    r = rig()
    wrapper = Interrupted(r, interruption="ambiguous", applied=False)
    first = wrapper.__call__

    def drift_after_resend(request: dict) -> dict:
        response = first(request)
        if len(wrapper.forward) == 2:
            wrapper.service.settings["enableExecuteCommand"] = True
        return response

    setattr(r.ecs, "update_service", drift_after_resend)
    outcome = r.controller().run()
    assert_never_deployed_under_drift(r, outcome, wrapper, sends=2)


def test_a_drifted_deploy_response_holds_without_further_observation():
    r = rig()
    services = r.document["environment"]["services"]
    original = r.ecs.update_service
    describes: list[int] = []
    original_describe = r.ecs.describe_services

    def drifted_without_deployment(request: dict) -> dict:
        if request["service"] == services["runtime"] and request["desiredCount"] == 1:
            r.ecs.mutations.append(("update_service", copy.deepcopy(request)))
            runtime = r.ecs.services[services["runtime"]]
            runtime.settings["enableExecuteCommand"] = True
            describes.clear()
            return {"service": r.ecs._service(services["runtime"])}  # not applied
        return original(request)

    def count(cluster, arns):
        describes.append(1)
        return original_describe(cluster, arns)

    setattr(r.ecs, "update_service", drifted_without_deployment)
    setattr(r.ecs, "describe_services", count)
    outcome = r.controller().run()
    assert_held(r, outcome, "service_settings_drift", "grants_verified")
    assert describes == [], "the response's own drift holds before any reconciliation poll"


@pytest.mark.parametrize("interruption", ["ambiguous", "crash"])
def test_forward_reconciliation_without_drift_resends_the_identical_request_and_deadline(
    interruption,
):
    r = rig()
    wrapper = Interrupted(r, interruption=interruption, applied=False)
    outcome = wrapper.run(r)
    assert outcome.state == "held_paused", outcome
    assert len(wrapper.forward) == 2 and wrapper.forward[0] == wrapper.forward[1]
    first, retry = r.events("intent", action="update_service", subject="runtime")
    assert retry["request_sha256"] == first["request_sha256"]
    assert retry["deadline_at"] == first["deadline_at"]
    assert retry["retry_of"] == first["sequence"]


def test_scale_to_zero_reconciliation_is_not_blocked_by_drift():
    # Scaling a writer to zero is the safe direction: drift never blocks quiescing.
    r = rig(rollback="compatible_release", running_prior=True)
    runtime_arn = r.document["environment"]["services"]["runtime"]
    runtime = r.ecs.services[runtime_arn]
    runtime.settings["deploymentConfiguration"]["deploymentCircuitBreaker"]["rollback"] = True
    original = r.ecs.update_service
    lost: list[dict] = []

    def lose_first_scale_down(request: dict) -> dict:
        if request["service"] == runtime_arn and request["desiredCount"] == 0 and not lost:
            lost.append(request)
            raise AmbiguousResponse("scale-to-zero response lost before it was applied")
        return original(request)

    setattr(r.ecs, "update_service", lose_first_scale_down)
    outcome = r.controller().run()
    assert r.events("observation", subject="runtime", result="scaled_to_zero")[0]["reconciled"]
    assert runtime.desired == 0
    # The forward deploy of that service is what holds, before it is sent.
    assert_held(r, outcome, "service_settings_drift", "grants_verified")
    assert not [c for c in r.calls("update_service")
                if c["service"] == runtime_arn and c["desiredCount"] == 1]  # fmt: skip


# Identical resends: their responses and the original deadline ---------------


class DriftedRetryResponse(Interrupted):
    """Lose the first forward deploy, apply the identical resend, and report
    drift only in the resend's response: every later read is clean."""

    def __init__(self, r: Rig, *, interruption: str, reported, applied: bool = True) -> None:
        super().__init__(r, interruption=interruption, applied=False)
        self.reported, self.resend_applied = reported, applied

    def __call__(self, request: dict) -> dict:
        forward = request["service"] == self.arn and request["desiredCount"] == 1
        if forward and self.forward and not self.resend_applied:
            # The resend reaches ECS but is not applied: no new deployment.
            self.forward.append(copy.deepcopy(request))
            self.sent_at.append(self.r.clock.now())
            self.r.ecs.mutations.append(("update_service", copy.deepcopy(request)))
            self.r.trace.append(("ecs", "update_service", request["service"]))
            response = {"service": self.r.ecs._service(self.arn)}
        else:
            response = super().__call__(request)  # the first forward send raises
        if forward:
            response = copy.deepcopy(response)
            self.reported(response["service"])
        return response


def original_deadline(r: Rig, key: str = "runtime") -> datetime:
    first = r.events("intent", action="update_service", subject=key, desired_count=1)[0]
    return datetime.fromisoformat(first["deadline_at"].replace("Z", "+00:00"))


def slow_pre_resend_read(r: Rig, wrapper: Interrupted, *, returns_at: timedelta) -> None:
    """The read deciding the first resend returns ``returns_at`` from the deadline."""
    original = r.ecs.describe_services
    reads: list[int] = []

    def describe(cluster, arns):
        described = original(cluster, arns)
        if len(wrapper.forward) == 1:
            reads.append(1)
            if len(reads) == VISIBILITY_POLLS + 1:  # after three visibility polls
                r.clock.moment = original_deadline(r) + returns_at
        return described

    setattr(r.ecs, "describe_services", describe)


@pytest.mark.parametrize("interruption", ["ambiguous", "crash"])
@pytest.mark.parametrize("reported", DRIFT_VARIANTS, ids=DRIFT_IDS)
def test_a_resend_response_reporting_drift_holds_although_later_reads_are_clean(
    interruption, reported
):
    r = rig()
    wrapper = DriftedRetryResponse(r, interruption=interruption, reported=reported)
    terraform = copy.deepcopy(wrapper.service.settings)
    outcome = wrapper.run(r)
    assert wrapper.service.settings == terraform, "only the resend's response reported drift"
    assert_never_deployed_under_drift(r, outcome, wrapper, sends=2)
    assert forward_sends(r) == ["runtime"], "no forward progress after the drifted response"


@pytest.mark.parametrize("interruption", ["ambiguous", "crash"])
def test_a_drifted_resend_response_without_a_new_deployment_holds(interruption):
    r = rig()
    wrapper = DriftedRetryResponse(
        r, interruption=interruption, reported=DRIFT_VARIANTS[-1], applied=False
    )
    outcome = wrapper.run(r)
    assert_never_deployed_under_drift(r, outcome, wrapper, sends=2)
    assert wrapper.service.desired == 0 and not wrapper.service.settings["enableExecuteCommand"]


def test_a_clean_resend_response_is_still_confirmed_from_service_reads():
    r = rig()
    wrapper = DriftedRetryResponse(r, interruption="ambiguous", reported=lambda service: None)
    outcome = wrapper.run(r)
    assert outcome.state == "held_paused", outcome
    assert len(wrapper.forward) == 2
    assert r.events("observation", subject="runtime", result="service_deployed")[0]["reconciled"]


@pytest.mark.parametrize("interruption", ["ambiguous", "crash"])
def test_a_pre_resend_read_crossing_the_original_deadline_holds_before_the_resend(interruption):
    r = rig()
    wrapper = Interrupted(r, interruption=interruption, applied=False)
    slow_pre_resend_read(r, wrapper, returns_at=timedelta(seconds=1))
    outcome = wrapper.run(r)
    assert_held(r, outcome, "service_update_unconfirmed", "grants_verified")
    assert len(wrapper.forward) == 1, "no resend after the original service deadline"
    assert len(r.events("intent", action="update_service", subject="runtime")) == 1
    assert wrapper.service.desired == 0


def test_a_journal_write_crossing_the_original_deadline_holds_before_the_resend():
    # Journal-before-mutation stays: the resend intent is written, then the
    # deadline is checked once more before the request is sent.
    r = rig()
    wrapper = Interrupted(r, interruption="ambiguous", applied=False)
    original = r.store.replace

    def slow_append(key: str, body: bytes, *, if_match: str) -> str:
        etag = original(key, body, if_match=if_match)
        last = json.loads(body)["events"][-1]
        if last.get("action") == "update_service" and "retry_of" in last:
            r.clock.moment = original_deadline(r)
        return etag

    setattr(r.store, "replace", slow_append)
    outcome = r.controller().run()
    assert_held(r, outcome, "service_update_unconfirmed", "grants_verified")
    assert len(wrapper.forward) == 1
    first, retry = r.events("intent", action="update_service", subject="runtime")
    assert retry["retry_of"] == first["sequence"] and retry["deadline_at"] == first["deadline_at"]


def test_a_slow_first_deploy_journal_write_never_sends_at_the_deadline():
    # A journal write slow enough to reach the recorded deadline: nothing is sent.
    r = rig()
    runtime_arn = r.document["environment"]["services"]["runtime"]
    original = r.store.replace

    def slow_append(key: str, body: bytes, *, if_match: str) -> str:
        etag = original(key, body, if_match=if_match)
        last = json.loads(body)["events"][-1]
        if last.get("action") == "update_service" and last.get("desired_count") == 1:
            r.clock.moment = datetime.fromisoformat(last["deadline_at"].replace("Z", "+00:00"))
        return etag

    setattr(r.store, "replace", slow_append)
    outcome = r.controller().run()
    assert_held(r, outcome, "service_update_unconfirmed", "grants_verified")
    assert not [c for c in r.calls("update_service") if c["desiredCount"] == 1]
    assert r.ecs.services[runtime_arn].desired == 0


@pytest.mark.parametrize("interruption", ["ambiguous", "crash"])
def test_a_slow_pre_resend_read_inside_the_deadline_still_resends_identically(interruption):
    r = rig()
    wrapper = Interrupted(r, interruption=interruption, applied=False)
    slow_pre_resend_read(r, wrapper, returns_at=timedelta(seconds=-2))
    outcome = wrapper.run(r)
    deadline = original_deadline(r)
    assert len(wrapper.forward) == 2 and wrapper.forward[0] == wrapper.forward[1]
    assert wrapper.sent_at[1] == deadline - timedelta(seconds=2)
    first, retry = r.events("intent", action="update_service", subject="runtime")
    assert (retry["request_sha256"], retry["deadline_at"], retry["retry_of"]) == (
        first["request_sha256"], first["deadline_at"], first["sequence"]
    )  # fmt: skip
    assert r.events("observation", subject="runtime", result="service_deployed")
    # Two seconds is too little to become ready: readiness, not the resend, holds.
    assert_held(r, outcome, "service_start_deadline_exceeded", "grants_verified")


def lose_first_scale_down(r: Rig, key: str = "runtime") -> list[dict]:
    arn = r.document["environment"]["services"][key]
    original = r.ecs.update_service
    sent: list[dict] = []

    def update(request: dict) -> dict:
        if request["service"] != arn or request["desiredCount"] != 0:
            return original(request)
        sent.append(copy.deepcopy(request))
        if len(sent) == 1:
            raise AmbiguousResponse("scale-to-zero response lost before it was applied")
        return original(request)

    setattr(r.ecs, "update_service", update)
    return sent


def test_a_scale_to_zero_resend_response_reporting_drift_does_not_block_quiescing():
    r = rig(rollback="compatible_release", running_prior=True)
    sent = lose_first_scale_down(r)
    resend = r.ecs.update_service

    def drifted_response(request: dict) -> dict:
        response = resend(request)
        if request["desiredCount"] == 0 and len(sent) == 2:
            response = copy.deepcopy(response)
            DRIFT_VARIANTS[0](response["service"])
        return response

    setattr(r.ecs, "update_service", drifted_response)
    outcome = r.controller().run()
    assert len(sent) == 2 and sent[0] == sent[1]
    assert r.events("observation", subject="runtime", result="scaled_to_zero")[0]["reconciled"]
    assert outcome.state == "held_paused", outcome


def test_a_scale_to_zero_resend_keeps_the_release_window_guard():
    # Scale-to-zero uses the release window as its deadline; the approval and
    # window guard on its resend intent is unchanged.
    r = rig(rollback="compatible_release", running_prior=True)
    sent = lose_first_scale_down(r)
    original = r.ecs.describe_services
    reads: list[int] = []

    def describe(cluster, arns):
        described = original(cluster, arns)
        if len(sent) == 1:
            reads.append(1)
            if len(reads) == VISIBILITY_POLLS + 1:
                first = r.events("intent", action="update_service", subject="runtime")[0]
                r.clock.moment = datetime.fromisoformat(first["deadline_at"].replace("Z", "+00:00"))
        return described

    setattr(r.ecs, "describe_services", describe)
    outcome = r.controller().run()
    assert_held(r, outcome, "release_window_exceeded", "locked")
    assert len(sent) == 1


# Runtime and API observers -------------------------------------------------------

RUNTIME_CHECK, API_CHECK = "runtime-observe", "api-observe"
OTHER_TASK = "arn:aws:ecs:us-east-1:111122223333:task/sentry-staging/" + "d" * 32
MISMATCH = "operational_receipt_mismatch"


def check_document(r: Rig, check_id: str) -> dict:
    return next(c for c in r.document["operational_checks"] if c["id"] == check_id)


def service_address(r: Rig, key: str) -> str:
    arn = r.events("observation", subject=key, result="service_ready")[-1]["task_arn"]
    details = r.ecs.attachments[arn][0]["details"]
    return next(d["value"] for d in details if d["name"] == "privateIPv4Address")


def test_each_observer_is_its_own_task_bound_to_the_recorded_service_address():
    r = rig()
    outcome = r.controller().run()
    assert outcome.state == "held_paused", outcome
    passes = [e["subject"] for e in r.events("observation", result="operational_passed")]
    assert passes == [RUNTIME_CHECK, API_CHECK, "worker-readiness"]
    for check_id, key in ((RUNTIME_CHECK, "runtime"), (API_CHECK, "api")):
        [launched] = r.events("observation", subject=check_id, result="launched")
        [passed] = r.events("observation", subject=check_id, result="operational_passed")
        service_task = r.events("observation", subject=key, result="service_ready")[-1]["task_arn"]
        assert passed["task_arn"] == launched["task_arn"] != service_task
        assert passed["service_task_arn"] == service_task
        assert passed["peer"] == service_address(r, key)
        receipt = r.evidence.operational_receipt(r.document["release_id"], check_id,
                                                 passed["task_arn"])  # fmt: skip
        assert passed["receipt_sha256"] == canonical_sha256(receipt)
        [request] = [c for c in r.calls("run_task") if c["tags"][1]["value"] == check_id]
        check = check_document(r, check_id)
        assert request["taskDefinition"] == check["task"]["task_definition"]
        assert request["networkConfiguration"]["awsvpcConfiguration"]["securityGroups"] == (
            check["task"]["security_groups"]
        )
        assert "overrides" not in request and request["enableExecuteCommand"] is False
        assert len(r.job_tasks(check_id)) == 1
    assert_intent_precedes_every_mutation(r)


@pytest.mark.parametrize(
    "configure, failing, reason",
    [
        # Never visible before the observer's deadline: nothing was proven.
        (lambda r: r.evidence.missing_checks.add(RUNTIME_CHECK), RUNTIME_CHECK,
         "operational_deadline_exceeded"),
        (lambda r: r.evidence.check_changes.update({API_CHECK: {"status": "failed"}}),
         API_CHECK, MISMATCH),
        # Another task's, release's, check's or kind's receipt is not this observer's.
        (lambda r: r.evidence.check_changes.update({RUNTIME_CHECK: {"task_arn": OTHER_TASK}}),
         RUNTIME_CHECK, MISMATCH),
        (lambda r: r.evidence.check_changes.update({RUNTIME_CHECK: {
            "release_id": PRIOR_RELEASE_ID}}), RUNTIME_CHECK, MISMATCH),
        (lambda r: r.evidence.check_changes.update({API_CHECK: {"check_id": RUNTIME_CHECK}}),
         API_CHECK, MISMATCH),
        (lambda r: r.evidence.check_changes.update({API_CHECK: {
            "schema": "sentry.release-tools.job.v1"}}), API_CHECK, MISMATCH),
        (lambda r: r.evidence.check_changes.update({API_CHECK: {"tasks": {}}}), API_CHECK,
         MISMATCH),
        # The result names exactly the approved target, its checks and its denials.
        (lambda r: r.evidence.result_changes.update({RUNTIME_CHECK: {
            "host": "runtime.other.internal"}}), RUNTIME_CHECK, MISMATCH),
        (lambda r: r.evidence.result_changes.update({RUNTIME_CHECK: {"port": "443"}}),
         RUNTIME_CHECK, MISMATCH),
        (lambda r: r.evidence.result_changes.update({RUNTIME_CHECK: {"target": "api"}}),
         RUNTIME_CHECK, MISMATCH),
        (lambda r: r.evidence.result_changes.update({RUNTIME_CHECK: {"tls": "none"}}),
         RUNTIME_CHECK, MISMATCH),
        (lambda r: r.evidence.result_changes.update({RUNTIME_CHECK: {"denials": "no_token"}}),
         RUNTIME_CHECK, MISMATCH),
        (lambda r: r.evidence.result_changes.update({RUNTIME_CHECK: {"checks": "healthz"}}),
         RUNTIME_CHECK, MISMATCH),
        (lambda r: r.evidence.result_changes.update({API_CHECK: {
            "denials": "unauthenticated:200"}}), API_CHECK, MISMATCH),
        (lambda r: r.evidence.result_changes.update({API_CHECK: {"denials": None}}), API_CHECK,
         MISMATCH),
        (lambda r: r.evidence.result_changes.update({API_CHECK: {"peer": None}}), API_CHECK,
         MISMATCH),
        (lambda r: r.evidence.result_changes.update({API_CHECK: {"extra": "x"}}), API_CHECK,
         MISMATCH),
        # DNS answered from an address other than the recorded task's interface.
        (lambda r: r.evidence.dns_peers.update({"runtime": "10.0.9.9"}), RUNTIME_CHECK,
         "operational_peer_mismatch"),
        (lambda r: r.evidence.dns_peers.update({"api": "10.0.9.9"}), API_CHECK,
         "operational_peer_mismatch"),
    ],
)  # fmt: skip
def test_only_the_observers_own_passing_receipt_about_the_recorded_task_passes(
    configure, failing, reason
):
    r = rig()
    configure(r)
    outcome = r.controller().run()
    assert_held(r, outcome, reason, "services_started")
    [failed] = r.events("observation", result="operational_failed")
    assert failed["subject"] == failing and failed["reason"] == reason
    assert failed["task_arn"] == r.job_tasks(failing)[0].arn
    assert not r.events("observation", subject=failing, result="operational_passed")
    # Nothing is launched after a failed observer.
    assert launched_job_ids(r)[-1] == failing


@pytest.mark.parametrize(
    "exits, reason",
    [({"observer": 12}, "job_container_failed"), ({"observer": None}, "job_exit_missing"),
     ({"init": 1}, "job_container_failed")],
)  # fmt: skip
def test_a_failed_observer_task_holds_whatever_its_stream_says(exits, reason):
    r = rig()
    definition = check_document(r, RUNTIME_CHECK)["task"]["task_definition"]
    r.ecs.plans[definition] = JobPlan(seconds=10, exits=exits)
    outcome = r.controller().run()
    assert_held(r, outcome, reason, "services_started")
    [failed] = r.events("observation", subject=RUNTIME_CHECK, result="operational_failed")
    assert failed["reason"] == reason and API_CHECK not in launched_job_ids(r)


def test_an_observer_still_running_at_its_deadline_is_stopped_then_holds():
    r = rig()
    check = check_document(r, API_CHECK)
    r.ecs.plans[check["task"]["task_definition"]] = JobPlan(seconds=10_000)
    outcome = r.controller().run()
    assert_held(r, outcome, "operational_deadline_exceeded", "services_started")
    [task] = r.job_tasks(API_CHECK)
    [stop] = r.calls("stop_task")
    assert stop["task"] == task.arn
    [confirmed] = r.events("observation", subject=API_CHECK, result="stop_confirmed")
    # An observer runs no SQL: its stop carries no SQL outcome.
    assert "sql_outcome" not in confirmed
    [intent] = r.events("intent", action="run_task", subject=API_CHECK)
    assert intent["deadline_at"] <= iso(r.clock.now())


ADDRESS = {"name": "privateIPv4Address", "value": "10.0.0.7"}
INTERFACE = {"name": "networkInterfaceId", "value": "eni-0123456789abcdef0"}
SUBNET = {"name": "subnetId", "value": "subnet-0a1b2c3d4e5f60718"}
ENI = {"type": "ElasticNetworkInterface", "status": "ATTACHED",
       "details": [SUBNET, INTERFACE, ADDRESS]}  # fmt: skip


@pytest.mark.parametrize(
    "attachments",
    [
        [],
        [ENI, ENI],
        [{**ENI, "status": "DELETED"}],
        [{**ENI, "details": []}],
        [{**ENI, "details": ENI["details"] * 2}],
        [{**ENI, "details": [SUBNET, INTERFACE, {**ADDRESS, "value": "10.0.0"}]}],
        [{**ENI, "details": [SUBNET, INTERFACE, {**ADDRESS, "value": "runtime.internal"}]}],
        # The complete attachment: an interface id and an approved subnet too.
        [{**ENI, "details": [SUBNET, ADDRESS]}],
        [{**ENI, "details": [INTERFACE, ADDRESS]}],
        [{**ENI, "details": [{**SUBNET, "value": "subnet-0ffffffffffffffff"}, INTERFACE, ADDRESS]}],
        [{**ENI, "details": [SUBNET, {**INTERFACE, "value": "interface"}, ADDRESS]}],
    ],
)
def test_a_recorded_service_without_one_known_address_holds_before_its_observer(attachments):
    r = rig()
    r.ecs.quirks[r.document["services"]["runtime"]["task_definition"]] = {
        "attachments": attachments
    }
    outcome = r.controller().run()
    assert_held(r, outcome, "service_network_identity_unknown", "services_started")
    assert RUNTIME_CHECK not in launched_job_ids(r)


def test_an_observer_receipt_read_crossing_its_deadline_cannot_pass(monkeypatch):
    r = rig()
    original = r.evidence.operational_receipt

    def slow_receipt(release_id, check_id, task_arn):
        receipt = original(release_id, check_id, task_arn)
        if check_id == RUNTIME_CHECK:
            r.clock.advance(seconds=check_document(r, check_id)["deadline_seconds"])
        return receipt

    monkeypatch.setattr(r.evidence, "operational_receipt", slow_receipt)
    outcome = r.controller().run()
    assert_held(r, outcome, "operational_deadline_exceeded", "services_started")
    assert not r.events("observation", subject=RUNTIME_CHECK, result="operational_passed")


def test_a_recorded_task_whose_address_changes_during_observation_holds(monkeypatch):
    r = rig()
    original = r.evidence.operational_receipt

    def readdress(release_id, check_id, task_arn):
        receipt = original(release_id, check_id, task_arn)
        if check_id == RUNTIME_CHECK:
            arn = r.events("observation", subject="runtime", result="service_ready")[-1]["task_arn"]
            details = r.ecs.attachments[arn][0]["details"]
            for detail in details:
                if detail["name"] == "privateIPv4Address":
                    detail["value"] = "10.0.9.9"
        return receipt

    monkeypatch.setattr(r.evidence, "operational_receipt", readdress)
    outcome = r.controller().run()
    assert_held(r, outcome, "task_replaced", "services_started")
    assert not r.events("observation", subject=RUNTIME_CHECK, result="operational_passed")


@pytest.mark.parametrize("replaced", ["worker", "runtime"])
def test_replacement_during_observation_requires_a_fresh_window(monkeypatch, replaced):
    r = rig()
    original = r.evidence.operational_receipt

    def replace_service(release_id, check_id, task_arn):
        receipt = original(release_id, check_id, task_arn)
        if check_id == RUNTIME_CHECK and receipt is not None:
            service_of(r, replaced).replace_after = 0
        return receipt

    monkeypatch.setattr(r.evidence, "operational_receipt", replace_service)
    outcome = r.controller().run()
    assert_held(r, outcome, "task_replaced", "services_started")
    assert not r.events("observation", subject=RUNTIME_CHECK, result="operational_passed")


def test_an_observer_launch_crash_recovers_to_exactly_one_observer_task():
    r = rig()
    original = r.ecs.run_task

    def crash_after_observer(request):
        response = original(request)
        if request["tags"][1]["value"] == RUNTIME_CHECK:
            raise SimulatedCrash("observer run_task after")
        return response

    setattr(r.ecs, "run_task", crash_after_observer)
    with pytest.raises(SimulatedCrash):
        r.controller().run()
    setattr(r.ecs, "run_task", original)
    outcome = r.recover().run()
    assert outcome.state == "held_paused", outcome
    assert len(r.job_tasks(RUNTIME_CHECK)) == 1
    intents = r.events("intent", action="run_task", subject=RUNTIME_CHECK)
    assert len({(e["token"], e["request_sha256"]) for e in intents}) == 1
    assert_intent_precedes_every_mutation(r)


# Worker readiness gate --------------------------------------------------------

GATE = "worker-readiness"
STAMP = "%Y-%m-%dT%H:%M:%S.%fZ"


def gate_rig() -> Rig:
    """Observers finish at once, so the gate's epoch is where these receipt sequences assume.

    The observers run before the gate; their duration is not what these tests are about.
    """
    r = rig()
    for check in r.document["operational_checks"]:
        if "task" in check:
            r.ecs.plans[check["task"]["task_definition"]] = JobPlan(seconds=0)
    return r


def during_gate(monkeypatch) -> list[bool]:
    """A flag that is set only while the worker gate runs (after the observers)."""
    running = [False]
    original = ReleaseController._await_worker_readiness

    def gate(self, check_id, recorded_tasks):
        running[0] = True
        try:
            return original(self, check_id, recorded_tasks)
        finally:
            running[0] = False

    monkeypatch.setattr(ReleaseController, "_await_worker_readiness", gate)
    return running


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
    r = gate_rig()
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
    r = gate_rig()
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
    in_gate = during_gate(monkeypatch)
    calls = []

    def enumerate_slowly(self, recorded_tasks):
        if in_gate[0]:
            calls.append(1)
            if len(calls) == 1:
                r.clock.advance(seconds=seconds)
        return original(self, recorded_tasks)

    monkeypatch.setattr(ReleaseController, "_require_recorded_tasks", enumerate_slowly)


def test_success_needs_the_deadline_after_the_final_enumeration(monkeypatch):
    r = gate_rig()
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
    r = gate_rig()
    slow_final_enumeration(r, monkeypatch, 40)
    outcome = r.controller().run()
    assert outcome.state == "held_paused", outcome
    [passed] = gate_events(r, "operational_passed")
    assert passed["last_reset"] == "receipt_stale" and passed["first_sequence"] > 8


def test_controller_clock_rollback_at_final_success_holds(monkeypatch):
    r = gate_rig()
    original = ReleaseController._require_recorded_tasks
    in_gate = during_gate(monkeypatch)
    calls = []

    def roll_back(self, recorded_tasks):
        if in_gate[0]:
            calls.append(1)
            if len(calls) == 1:  # the gate's final enumeration
                r.clock.moment -= timedelta(seconds=30)
        return original(self, recorded_tasks)

    monkeypatch.setattr(ReleaseController, "_require_recorded_tasks", roll_back)
    outcome = r.controller().run()
    assert_held(r, outcome, "controller_clock_rollback", "services_started")
    assert not gate_events(r, "operational_passed")


def test_controller_clock_rollback_before_the_gate_holds(monkeypatch):
    r = rig()
    original = ReleaseController._await_worker_readiness

    def roll_back_first(self, check_id, recorded_tasks):
        r.clock.moment -= timedelta(seconds=120)
        return original(self, check_id, recorded_tasks)

    monkeypatch.setattr(ReleaseController, "_await_worker_readiness", roll_back_first)
    outcome = r.controller().run()
    assert_held(r, outcome, "controller_clock_rollback", "services_started")
    assert not gate_events(r, "readiness_observing")


class SteppedClock:
    """The controller's clock only; ECS and logs keep the real (fake) time."""

    def __init__(self, base: FakeClock) -> None:
        self.base, self.offset = base, timedelta(0)

    def now(self):
        return self.base.now() + self.offset

    def sleep(self, seconds: float) -> None:
        self.base.sleep(seconds)


def test_controller_clock_rollback_at_an_earlier_step_holds_the_gate(monkeypatch):
    r = rig()
    clock = SteppedClock(r.clock)
    original = ReleaseController._transition

    def step_back_at_services_started(self, target, **data):
        if target.value == "services_started":
            clock.offset = -timedelta(seconds=120)
        return original(self, target, **data)

    monkeypatch.setattr(ReleaseController, "_transition", step_back_at_services_started)
    controller = r.controller()
    controller.clock = clock
    outcome = controller.run()
    assert_held(r, outcome, "controller_clock_rollback", "services_started")
    assert not gate_events(r, "operational_passed")


def test_ecs_loss_after_a_slow_read_clears_from_when_ecs_was_observed(monkeypatch):
    r = rig()
    describe = r.ecs._describe
    state = {}

    def slow_then_check():
        if len(r.logs.calls) == 5:
            r.clock.advance(seconds=25)  # a slow read that still completes
            state["observed"] = r.clock.now()
        elif "observed" in state and r.clock.now() > state["observed"]:
            state["healthy"] = True

    def unhealthy_once(task):
        result = describe(task)
        if task.group == "service:worker" and "observed" in state and "healthy" not in state:
            result["healthStatus"] = "UNHEALTHY"
        return result

    r.logs.before_read = slow_then_check
    monkeypatch.setattr(r.ecs, "_describe", unhealthy_once)
    outcome = r.controller().run()
    assert outcome.state == "held_paused", outcome
    [passed] = gate_events(r, "operational_passed")
    first = FakeLogs.observed(recorded(r), passed["first_sequence"])
    assert passed["last_reset"] == "task_unhealthy"
    assert first > state["observed"] + timedelta(seconds=5)


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


# Mutation-send authorization -------------------------------------------------
#
# Approval and the release window are checked again after each intent is
# journaled, immediately before its send; a launch also rechecks its original
# job deadline and token lifetime there. A journal write slow enough to reach a
# limit (equality included) sends nothing, and the journaled intent stays
# outstanding: the hold treats it as possibly sent. Safety stops stay authorized.

# Each limit binds before every other deadline at the site under test: approval
# ends before any job (900 s) or service-start (600 s) deadline it could reach,
# and a short window caps those deadlines at its own end.
APPROVAL_END = START + timedelta(minutes=10)
SHORT_WINDOW_SECONDS = 600


def window_end(r: Rig) -> datetime:
    return START + timedelta(seconds=r.document["window"]["total_seconds"])


def at_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@dataclass
class SlowWrite:
    """The first matching intent journaled by a slow write, and sends made before it."""

    intent: dict | None = None
    sends_before: int = 0


def slow_intent_write(r: Rig, matches, returns_at, *, sends=lambda _r: []) -> SlowWrite:
    """The first matching intent's journal write lands, then returns at ``returns_at``.

    ``returns_at(r, intent)`` gives the moment the write returns. Only the clock
    moves: the intent is persisted exactly as the controller wrote it.
    """
    original = r.store.replace
    slow = SlowWrite()

    def replace(key: str, body: bytes, *, if_match: str) -> str:
        etag = original(key, body, if_match=if_match)
        event = json.loads(body)["events"][-1] if key == JOURNAL else {"kind": None}
        if event["kind"] == "intent" and slow.intent is None and matches(event):
            slow.intent, slow.sends_before = event, len(sends(r))
            r.clock.moment = max(r.clock.moment, returns_at(r, event))
        return etag

    setattr(r.store, "replace", replace)
    return slow


def job_launches(r: Rig, job_id: str) -> list[dict]:
    return [c for c in r.calls("run_task") if c["tags"][1]["value"] == job_id]


def service_updates(r: Rig, key: str, desired: int) -> list[dict]:
    arn = r.document["environment"]["services"][key]
    return [
        c for c in r.calls("update_service") if c["service"] == arn and c["desiredCount"] == desired
    ]


@dataclass(frozen=True)
class DispatchSite:
    """One send the controller makes after journaling its intent."""

    name: str
    action: str
    subject: str
    retry: bool
    last_proven: str
    upgrade: bool = False
    desired: int | None = None

    def matches(self, event: dict) -> bool:
        return (
            event["action"] == self.action
            and event["subject"] == self.subject
            and ("retry_of" in event) == self.retry
            and (self.desired is None or event.get("desired_count") == self.desired)
        )

    def rig(self, *, window_seconds: int | None = None, **approval) -> Rig:
        if self.upgrade:
            r = rig(rollback="compatible_release", running_prior=True, **approval)
        else:
            r = rig(**approval)
        if window_seconds is not None:
            r.document["window"]["total_seconds"] = window_seconds
            loaded = load_manifest(encode(r.document))
            r.approval_raw = encode({**approval_document(loaded.sha256), **approval})
        return r

    def prepare(self, r: Rig) -> None:
        """Lose the first send, before ECS applies it, so the site under test is a resend.

        Every send at the site is counted, including the lost first one.
        """
        if not self.retry:
            return
        if self.action == "run_task":
            r.ecs.ambiguous["run_task_before"] = 1  # recorded by the fake, then lost
        elif self.desired == 1:
            setattr(
                r, "site_sends", Interrupted(r, interruption="ambiguous", applied=False).forward
            )
        else:
            setattr(r, "site_sends", lose_first_scale_down(r, self.subject))

    def sends(self, r: Rig) -> list[dict]:
        counted = getattr(r, "site_sends", None)
        if counted is not None:
            return counted
        if self.action == "run_task":
            return job_launches(r, self.subject)
        return service_updates(r, self.subject, int(self.desired or 0))


DISPATCH_SITES = [
    DispatchSite("first-launch", "run_task", "product-migrate", False, "quiesced"),
    DispatchSite("launch-resend", "run_task", "runtime-migrate", True, "quiesced"),
    DispatchSite("first-deploy", "update_service", "runtime", False, "grants_verified", desired=1),
    DispatchSite("deploy-resend", "update_service", "runtime", True, "grants_verified", desired=1),
    DispatchSite("scale-to-zero", "update_service", "runtime", False, "locked",
                 upgrade=True, desired=0),  # fmt: skip
    DispatchSite("scale-to-zero-resend", "update_service", "runtime", True, "locked",
                 upgrade=True, desired=0),  # fmt: skip
]
SITE_IDS = [site.name for site in DISPATCH_SITES]


def limit_rig(site: DispatchSite, limit: str) -> tuple[Rig, datetime, str]:
    if limit == "approval":
        return site.rig(not_after=iso(APPROVAL_END)), APPROVAL_END, "approval_expired"
    r = site.rig(window_seconds=SHORT_WINDOW_SECONDS)
    return r, window_end(r), "release_window_exceeded"


def outstanding_after(r: Rig, intent: dict) -> bool:
    """True while no later observation resolves the intent's action and subject."""
    return not [
        e
        for e in r.events("observation", subject=intent["subject"])
        if e.get("resolves") == intent["action"] and e["sequence"] > intent["sequence"]
    ]


def assert_possibly_sent(r: Rig, site: DispatchSite, outcome, intent: dict) -> None:
    assert outstanding_after(r, intent), "a withheld send is never recorded as resolved"
    actions = outcome.rollback["actions"]
    if site.action == "run_task":
        # The job is classified unknown, not unstarted: its intent may have been sent.
        assert "reconcile_partial_migration_before_rerun" in actions
        unconfirmed = r.events("observation", subject=site.subject, result="cleanup_unconfirmed")
        if outcome.reason in {"approval_expired", "release_window_exceeded"}:
            # Expiry cleanup searched for it by token: an empty listing proves nothing.
            assert unconfirmed and unconfirmed[-1]["sql_outcome"] == "unknown"
    elif site.desired == 1:
        assert "set_started_services_desired_zero" in actions


@pytest.mark.parametrize("site", DISPATCH_SITES, ids=SITE_IDS)
@pytest.mark.parametrize("limit", ["approval", "window"])
def test_a_journal_write_reaching_the_authorization_limit_sends_nothing(site, limit):
    r, end, reason = limit_rig(site, limit)
    site.prepare(r)
    slow = slow_intent_write(r, site.matches, lambda _r, _intent: end, sends=site.sends)
    outcome = r.controller().run()
    assert slow.intent is not None, "the run must reach the dispatch site under test"
    assert len(site.sends(r)) == slow.sends_before, "nothing is sent at or after the limit"
    assert r.clock.now() >= end
    assert_held(r, outcome, reason, site.last_proven)
    assert_possibly_sent(r, site, outcome, slow.intent)


@pytest.mark.parametrize("site", DISPATCH_SITES, ids=SITE_IDS)
@pytest.mark.parametrize("limit", ["approval", "window"])
def test_a_timely_send_after_a_slow_journal_write_is_the_identical_request(site, limit):
    # One second before the limit the send proceeds with exactly what was journaled.
    r, end, _reason = limit_rig(site, limit)
    site.prepare(r)
    slow = slow_intent_write(
        r, site.matches, lambda _r, _intent: end - timedelta(seconds=1), sends=site.sends
    )
    r.controller().run()
    intent = slow.intent
    assert intent is not None
    sends = site.sends(r)
    assert len(sends) >= slow.sends_before + 1
    sent = sends[slow.sends_before]
    assert canonical_sha256(sent) == intent["request_sha256"]
    if site.action == "run_task":
        assert sent["clientToken"] == sent["startedBy"] == intent["token"]
    if site.retry:
        first = next(
            e for e in r.events("intent", action=site.action, subject=site.subject)
            if e["sequence"] == intent["retry_of"]
        )  # fmt: skip
        assert (first["request_sha256"], first["deadline_at"]) == (
            intent["request_sha256"], intent["deadline_at"]
        )  # fmt: skip
        assert sends[0] == sent, "a resend is the identical request"
        if site.action == "run_task":
            assert (first["token"], first["token_expires_at"]) == (
                intent["token"], intent["token_expires_at"]
            )  # fmt: skip


@pytest.mark.parametrize("retry", [False, True], ids=["first-launch", "launch-resend"])
@pytest.mark.parametrize("offset", [0, -1], ids=["at-deadline", "control"])
def test_a_launch_is_never_sent_at_or_after_its_original_job_deadline(retry, offset):
    r = rig()
    job_id = "runtime-migrate"
    if retry:
        r.ecs.ambiguous["run_task_before"] = 1
    slow = slow_intent_write(
        r,
        lambda event: event["action"] == "run_task"
        and event["subject"] == job_id
        and ("retry_of" in event) == retry,
        lambda _r, intent: at_time(intent["deadline_at"]) + timedelta(seconds=offset),
        sends=lambda rr: job_launches(rr, job_id),
    )
    outcome = r.controller().run()
    assert slow.intent is not None
    if offset == 0:
        assert_held(r, outcome, "launch_outcome_unknown", "quiesced")
        assert len(job_launches(r, job_id)) == slow.sends_before
        assert outstanding_after(r, slow.intent)
        assert not r.calls("stop_task")
    else:
        # Sent one second before its deadline; the job cannot finish in time.
        assert len(job_launches(r, job_id)) == slow.sends_before + 1
        assert_held(r, outcome, "job_deadline_exceeded", "quiesced")


def rechained(document: dict) -> dict:
    prior = document["manifest_sha256"]
    for event in document["events"]:
        event["prior_sha256"] = prior
        prior = canonical_sha256(event)
    return document


@pytest.mark.parametrize("offset", [0, -1], ids=["at-token-expiry", "control"])
def test_a_launch_resend_is_never_sent_at_or_after_its_recorded_token_lifetime(offset):
    # The schema keeps every job deadline below its token lifetime, so only a
    # journal recording a shorter lifetime can reach this check. It still binds.
    r = rig()
    r.ecs.crash[("run_task", "before")] = 1
    with pytest.raises(SimulatedCrash):
        r.controller().run()
    document = r.journal()
    intent = document["events"][-1]
    assert intent["action"] == "run_task"
    token_end = START + timedelta(seconds=100)
    intent["token_expires_at"] = iso(token_end)
    r.store.objects[JOURNAL] = (encode(rechained(document)), r.store.objects[JOURNAL][1])
    slow = slow_intent_write(
        r,
        lambda event: event["action"] == "run_task" and "retry_of" in event,
        lambda _r, _intent: token_end + timedelta(seconds=offset),
    )
    outcome = r.recover().run()
    assert slow.intent is not None and slow.intent["token_expires_at"] == iso(token_end)
    launches = job_launches(r, "runtime-migrate")
    if offset == 0:
        assert_held(r, outcome, "launch_outcome_unknown", "quiesced")
        assert launches == []
    else:
        assert len(launches) == 1 and launches[0]["clientToken"] == intent["token"]


def test_expiry_cleanup_still_stops_the_runs_own_running_job():
    # Approval expires while the job runs: expiry cleanup, not a forward action,
    # stops the release's own task.
    r = rig(not_after=iso(APPROVAL_END))
    definition = r.document["jobs"][0]["task"]["task_definition"]
    r.ecs.plans[definition] = JobPlan(hang=True)
    outcome = r.controller().run()
    assert_held(r, outcome, "approval_expired", "quiesced")
    assert [c["reason"] for c in r.calls("stop_task")] == ["release authorization window expired"]
    assert r.ecs._status(r.job_tasks("runtime-migrate")[0]) == "STOPPED"
    assert r.events("observation", result="stop_confirmed")[-1]["sql_outcome"] == "unknown"


def test_a_deadline_stop_whose_intent_write_crosses_approval_expiry_is_still_sent():
    # The job reaches its own deadline while approval is still valid; the stop
    # intent's journal write then returns after approval has ended. Stopping the
    # run's own job is a safety action, not a forward launch: StopTask is sent.
    approval_end = START + timedelta(minutes=20)  # after the 900 s job deadline
    r = rig(not_after=iso(approval_end))
    definition = r.document["jobs"][0]["task"]["task_definition"]
    r.ecs.plans[definition] = JobPlan(hang=True)
    slow = slow_intent_write(
        r, lambda event: event["action"] == "stop_task", lambda _r, _intent: approval_end
    )
    original = r.ecs.stop_task
    sent_at: list[datetime] = []

    def stop(cluster: str, task_arn: str, reason: str) -> dict:
        sent_at.append(r.clock.now())
        return original(cluster, task_arn, reason)

    setattr(r.ecs, "stop_task", stop)
    outcome = r.controller().run()
    assert slow.intent is not None
    assert at_time(slow.intent["at"]) < approval_end <= sent_at[0], "the write crossed expiry"
    assert [c["reason"] for c in r.calls("stop_task")] == ["release job deadline exceeded"]
    assert r.ecs._status(r.job_tasks("runtime-migrate")[0]) == "STOPPED"
    confirmed = r.events("observation", result="stop_confirmed")
    assert confirmed and confirmed[-1]["sql_outcome"] == "unknown"
    assert_held(r, outcome, "job_deadline_exceeded", "quiesced")


@pytest.mark.parametrize("resend", [False, True], ids=["first", "resend"])
def test_scale_to_zero_acquires_no_service_start_deadline_at_send(resend):
    # A scale-to-zero intent write slower than service_start_seconds, inside
    # approval and the window, still sends the identical request: quiescing is
    # bound only by approval and the window.
    r = rig(rollback="compatible_release", running_prior=True)
    sent = lose_first_scale_down(r) if resend else None
    late = timedelta(seconds=r.document["window"]["service_start_seconds"] + 1)
    slow = slow_intent_write(
        r,
        lambda event: event["action"] == "update_service"
        and event["subject"] == "runtime"
        and event.get("desired_count") == 0
        and ("retry_of" in event) == resend,
        lambda rr, _intent: rr.clock.now() + late,
    )
    outcome = r.controller().run()
    assert slow.intent is not None
    scale_downs = service_updates(r, "runtime", 0) if sent is None else sent
    assert len(scale_downs) == (2 if resend else 1)
    assert canonical_sha256(scale_downs[-1]) == slow.intent["request_sha256"]
    assert r.events("observation", subject="runtime", result="scaled_to_zero")
    assert outcome.state == "held_paused", outcome


def test_expiry_cleanup_after_a_withheld_launch_stops_only_matching_tasks():
    # The withheld product launch has no task; the earlier job's is already done.
    r = rig(not_after=iso(APPROVAL_END))
    foreign = []

    def returns_at(rr: Rig, _intent: dict) -> datetime:
        # Another writer's task with the same revision appears while the write is slow.
        foreign.append(rr.ecs.standalone(rr.document["jobs"][1]["task"]["task_definition"]))
        return APPROVAL_END

    slow_intent_write(r, DISPATCH_SITES[0].matches, returns_at)
    outcome = r.controller().run()
    assert_held(r, outcome, "approval_expired", "quiesced")
    assert not r.calls("stop_task")
    assert r.ecs._status(foreign[0]) == "RUNNING"


# Schema 2 purpose, bootstrap, clock trust and operator abort ---------------------


def document_rig(document: dict, *, running_prior: bool = False, **approval) -> Rig:
    r = rig(rollback=document["rollback"]["kind"], running_prior=running_prior, **approval)
    r.document = document
    r.ecs.configure(document, running_prior=running_prior)
    r.evidence = FakeEvidence(r.ecs, document)
    r.logs = FakeLogs(r.ecs, document)
    loaded = load_manifest(encode(document))
    r.approval_raw = encode({**approval_document(loaded.sha256), **approval})
    return r


def launched_job_ids(r: Rig) -> list[str]:
    return [call["tags"][1]["value"] for call in r.calls("run_task")]


def test_a_first_deployment_bootstraps_both_databases_before_any_migration():
    r = document_rig(forward_document())
    outcome = r.controller().run()
    assert outcome.state == "held_paused", outcome
    assert launched_job_ids(r) == [
        "runtime-bootstrap", "product-bootstrap", "runtime-migrate", "product-migrate",
        "runtime-grant", "product-grant", "runtime-proof", "product-proof",
        "runtime-observe", "api-observe",
    ]  # fmt: skip
    assert r.transitions() == FORWARD
    assert_intent_precedes_every_mutation(r)


def test_a_failed_bootstrap_holds_before_migrations_and_plans_its_reconciliation():
    document = forward_document()
    r = document_rig(document)
    r.ecs.plans[document["jobs"][1]["task"]["task_definition"]] = JobPlan(exits={"bootstrap": 3})
    outcome = r.controller().run()
    assert_held(r, outcome, "job_container_failed", "quiesced")
    assert launched_job_ids(r) == ["runtime-bootstrap", "product-bootstrap"]
    assert outcome.rollback is not None
    assert "reconcile_bootstrap_before_rerun" in outcome.rollback["actions"]


def test_a_forward_upgrade_with_a_compatible_fallback_still_migrates_under_schema_two():
    document = manifest_document(rollback="compatible_release")
    document["schema_version"], document["purpose"] = 2, {"kind": "forward"}
    document["operator_role"] = OPERATOR_ROLE
    r = document_rig(document, running_prior=True)
    outcome = r.controller().run()
    assert outcome.state == "held_paused", outcome
    assert launched_job_ids(r)[:2] == ["runtime-migrate", "product-migrate"]


# Rollback runs ----------------------------------------------------------------------

ROLLBACK_SEQUENCE = [
    "prepared", "locked", "quiesced", "reconciled", "proven", "services_started",
    "operational_verified", "held_paused",
]  # fmt: skip
FAILED_SESSION = "session-failed"
ROLLBACK_JOURNAL = journal_key(ROLLBACK_RELEASE_ID)
RELEASE_ID_FIXTURE = "0b9f7c1e-4d2a-4f6b-9a3e-2c1d0e9f8a7b"


def failed_release(r: Rig, *, lock: bool = True, finished: bool = False,
                   tokens: tuple[str, ...] = (), environment: str = "staging",
                   learned: dict[str, list[dict]] | None = None) -> None:  # fmt: skip
    """The failed forward release's own journal (and lock) in the same environment.

    Each token is one job's launch intent. ``learned`` maps a token to the
    observations the failed release journaled about that launch afterwards; a
    token without any is a launch whose outcome it never learned.
    """
    journal = Journal(r.store, journal_key(FAILED_RELEASE_ID))
    stamp = iso(START - timedelta(minutes=20))
    journal.create(
        {"schema_version": 1, "release_id": FAILED_RELEASE_ID, "environment": environment,
         "manifest_sha256": sha("failed manifest"), "session_id": FAILED_SESSION},
        {"at": stamp, "kind": "transition", "to": "prepared"},
    )  # fmt: skip
    for number, token in enumerate(tokens):
        subject = "runtime-migrate" if len(tokens) == 1 else f"failed-job-{number}"
        journal.append({"at": stamp, "kind": "intent", "action": "run_task",
                        "subject": subject, "request_sha256": sha(token),
                        "token": token})  # fmt: skip
        for observation in (learned or {}).get(token, []):
            journal.append({"at": stamp, "kind": "observation", "subject": subject,
                            **observation})  # fmt: skip
    if finished:
        journal.append({"at": stamp, "kind": "transition", "to": "held_paused"})
        journal.append({"at": stamp, "kind": "observation", "subject": "environment",
                        "result": "lock_released", "resolves": "release_lock"})  # fmt: skip
    else:
        journal.append({"at": stamp, "kind": "transition", "to": "hold", "reason": "job_failed"})
    if lock:
        r.store.create(LOCK, encode({"release_id": FAILED_RELEASE_ID, "session_id": FAILED_SESSION,
                                     "manifest_sha256": sha("failed manifest")}))  # fmt: skip


def rollback_rig(**changes) -> Rig:
    document = rollback_run_document()
    document["purpose"]["failed_release_id"] = FAILED_RELEASE_ID
    return document_rig(document, running_prior=True, release_id=ROLLBACK_RELEASE_ID, **changes)


def handoff(r: Rig, **changes) -> FailedReleaseHandoff:
    values = {"failed_session_id": FAILED_SESSION, "lock_etag": r.lock_etag(),
              "fence_evidence_sha256": sha("failed session fenced"),
              "authorized_by": "fixture-operator", **changes}  # fmt: skip
    return FailedReleaseHandoff(**values)


def rollback_controller(r: Rig, grant: FailedReleaseHandoff | None,
                        session: str = "session-b") -> ReleaseController:  # fmt: skip
    return ReleaseController(
        load_manifest(encode(r.document)), load_approval(r.approval_raw), store=r.store,
        ecs=r.ecs, evidence=r.evidence, logs=r.logs, clock=r.clock, tokens=r.tokens,
        session_id=session, handoff=grant,
    )  # fmt: skip


def rollback_events(r: Rig, kind: str, **match) -> list[dict]:
    events = json.loads(r.store.objects[ROLLBACK_JOURNAL][0])["events"]
    return [e for e in events if e["kind"] == kind and all(e.get(k) == v for k, v in match.items())]


def test_a_rollback_restores_the_prior_pair_and_finishes_held_paused():
    r = rollback_rig()
    failed_release(r)
    before = r.store.objects[journal_key(FAILED_RELEASE_ID)]
    outcome = rollback_controller(r, handoff(r)).run()
    assert outcome.state == "held_paused", outcome
    assert [e["to"] for e in rollback_events(r, "transition")] == ROLLBACK_SEQUENCE
    # Never a migration, grant or bootstrap: the stated schemas are reconciled and proven.
    assert launched_job_ids(r) == [
        "runtime-reconcile", "product-reconcile", "runtime-proof", "product-proof",
        "runtime-observe", "api-observe",
    ]  # fmt: skip
    deploys = [c for c in r.calls("update_service") if c.get("taskDefinition")]
    prior = r.document["rollback"]["services"]
    assert [c["taskDefinition"] for c in deploys] == [
        prior[name]["task_definition"] for name in ("runtime", "api", "worker")
    ]
    [moved] = rollback_events(r, "observation", result="lock_handed_off")
    assert moved["from_release_id"] == FAILED_RELEASE_ID
    [intent] = rollback_events(r, "intent", action="lock_handoff")
    assert intent["from_session_id"] == FAILED_SESSION and intent["lock_etag"]
    assert intent["fence_evidence_sha256"] == sha("failed session fenced")
    [reconciled] = rollback_events(r, "observation", result="failed_release_reconciled")
    assert reconciled["failed_journal_sha256"] == canonical_sha256(json.loads(before[0]))
    # Every receipt named the retained prior release whose revisions ran.
    for event in rollback_events(r, "observation", result="job_succeeded"):
        task = r.ecs.tasks[event["task_arn"]]
        receipt = r.evidence.job_receipt(PRIOR_RELEASE_ID, event["subject"], task.arn)
        assert receipt is not None and receipt["release_id"] == PRIOR_RELEASE_ID
        assert task.tags["sentry:release-id"] == ROLLBACK_RELEASE_ID
    assert {c["log_stream"].split("/")[1] for c in r.logs.calls} == {PRIOR_RELEASE_ID}
    assert LOCK not in r.store.objects
    assert r.store.objects[journal_key(FAILED_RELEASE_ID)] == before


@pytest.mark.parametrize(
    "changes",
    [
        None,
        {"failed_session_id": "session-other"},
        {"lock_etag": '"stale"'},
        {"fence_evidence_sha256": "not-a-hash"},
        {"authorized_by": " "},
    ],
)
def test_the_failed_lock_moves_only_under_an_exact_fenced_handoff(changes):
    r = rollback_rig()
    failed_release(r)
    lock = r.store.objects[LOCK]
    grant = None if changes is None else handoff(r, **changes)
    outcome = rollback_controller(r, grant).run()
    assert outcome.state == "hold" and outcome.reason == "handoff_refused", outcome
    assert r.store.objects[LOCK] == lock and r.ecs.mutations == []


def test_a_lock_held_by_another_release_is_never_taken():
    r = rollback_rig()
    failed_release(r, lock=False)
    r.store.create(LOCK, encode({"release_id": PRIOR_RELEASE_ID, "session_id": "session-z"}))
    lock = r.store.objects[LOCK]
    outcome = rollback_controller(r, handoff(r, failed_session_id=FAILED_SESSION)).run()
    assert (outcome.state, outcome.reason) == ("hold", "environment_locked")
    assert r.store.objects[LOCK] == lock and r.ecs.mutations == []


@pytest.mark.parametrize("case", ["missing", "other-environment"])
def test_an_unknown_failed_release_holds_before_anything_moves(case):
    r = rollback_rig()
    if case == "other-environment":
        failed_release(r, environment="production")
    else:
        r.store.create(
            LOCK, encode({"release_id": FAILED_RELEASE_ID, "session_id": FAILED_SESSION})
        )
    outcome = rollback_controller(r, handoff(r)).run()
    assert (outcome.state, outcome.reason) == ("hold", "failed_release_unknown")
    assert json.loads(r.store.objects[LOCK][0])["release_id"] == FAILED_RELEASE_ID
    assert r.ecs.mutations == []


def test_a_missing_lock_is_acceptable_only_after_the_failed_release_finished():
    r = rollback_rig()
    failed_release(r, lock=False)
    outcome = rollback_controller(r, None).run()
    assert (outcome.state, outcome.reason) == ("hold", "failed_release_lock_missing")
    assert LOCK not in r.store.objects and r.ecs.mutations == []
    r = rollback_rig()
    failed_release(r, lock=False, finished=True)
    outcome = rollback_controller(r, None).run()
    assert outcome.state == "held_paused", outcome
    assert not rollback_events(r, "intent", action="lock_handoff")


def test_a_lock_moved_by_someone_else_first_is_a_conflict(monkeypatch):
    r = rollback_rig()
    failed_release(r)
    grant = handoff(r)
    original = r.store.replace

    def raced(key, body, *, if_match):
        if key == LOCK:
            original(LOCK, encode({"release_id": PRIOR_RELEASE_ID, "session_id": "racer"}),
                     if_match=if_match)  # fmt: skip
        return original(key, body, if_match=if_match)

    monkeypatch.setattr(r.store, "replace", raced)
    outcome = rollback_controller(r, grant).run()
    assert (outcome.state, outcome.reason) == ("hold", "handoff_conflict")
    assert json.loads(r.store.objects[LOCK][0])["session_id"] == "racer"
    assert rollback_events(r, "observation", result="handoff_conflict")
    assert r.ecs.mutations == []


@pytest.mark.parametrize("when", ["before", "after"])
def test_a_crash_during_the_handoff_resumes_from_the_lock_it_finds(monkeypatch, when):
    r = rollback_rig()
    failed_release(r)
    grant = handoff(r)
    original = r.store.replace

    def crash(key, body, *, if_match):
        if key == LOCK:
            if when == "after":
                original(key, body, if_match=if_match)
            raise SimulatedCrash("lock handoff")
        return original(key, body, if_match=if_match)

    monkeypatch.setattr(r.store, "replace", crash)
    with pytest.raises(SimulatedCrash):
        rollback_controller(r, grant).run()
    monkeypatch.setattr(r.store, "replace", original)
    outcome = rollback_controller(r, grant).run()
    if when == "after":
        assert outcome.state == "held_paused", outcome
        [moved] = rollback_events(r, "observation", result="lock_handed_off")
        assert moved["reconciled"] is True
    else:
        # The replace never landed: the failed lock was exactly as authorized, so the
        # same conditional handoff is sent again and the rollback proceeds.
        assert outcome.state == "held_paused", outcome
        results = [e["result"] for e in rollback_events(r, "observation", subject="environment")]
        assert results.index("handoff_not_applied") < results.index("lock_handed_off")
        assert len(rollback_events(r, "intent", action="lock_handoff")) == 2


def test_every_failed_launch_token_is_swept_before_anything_else():
    r = rollback_rig()
    tokens = ("t" * 20 + "running01", "t" * 20 + "stopped02", "t" * 20 + "refused03")
    # The first two outcomes were never learned, and their tasks are listed. The
    # third launch was refused by the provider, on record: no task ever existed.
    failed_release(r, tokens=tokens, learned={tokens[2]: [LAUNCH_REFUSED]})
    running = r.ecs._task("arn:failed-migrate:3", tokens[0], "family:failed", [("migration", "x")],
                          plan=JobPlan(seconds=10_000),
                          tags={"sentry:job-id": "runtime-migrate"})  # fmt: skip
    done = r.ecs._task("arn:failed-migrate:3", tokens[1], "family:failed", [("migration", "x")],
                       plan=JobPlan(seconds=1), tags={"sentry:job-id": "runtime-migrate"})  # fmt: skip
    r.clock.advance(seconds=5)
    outcome = rollback_controller(r, handoff(r)).run()
    assert outcome.state == "held_paused", outcome
    stops = r.calls("stop_task")
    assert [call["task"] for call in stops][:1] == [running.arn] and done.arn not in {
        call["task"] for call in stops
    }
    [swept] = rollback_events(r, "observation", result="failed_launches_swept")
    assert (swept["tokens"], swept["stopped"]) == (3, 1)
    [confirmed] = rollback_events(r, "observation", subject=f"failed:{tokens[0]}",
                                  result="stop_confirmed")  # fmt: skip
    assert confirmed["sql_outcome"] == "unknown"
    # The sweep, under the moved lock, precedes every forward action.
    kinds = [(e["kind"], e.get("action") or e.get("result") or e.get("to"))
             for e in json.loads(r.store.objects[ROLLBACK_JOURNAL][0])["events"]]  # fmt: skip
    assert kinds.index(("observation", "failed_launches_swept")) < kinds.index(
        ("transition", "locked")
    )


def test_a_failed_task_that_cannot_be_described_or_stopped_holds(monkeypatch):
    token = "u" * 20 + "running01"
    r = rollback_rig()
    failed_release(r, tokens=(token,))
    task = r.ecs._task("arn:failed-migrate:3", token, "family:failed", [("migration", "x")],
                       plan=JobPlan(seconds=10_000), tags={"sentry:job-id": "runtime-migrate"})  # fmt: skip
    original = r.ecs._describe

    def never_stops(item):
        described = original(item)
        if item.arn == task.arn:
            described = {**described, "lastStatus": "RUNNING"}
        return described

    monkeypatch.setattr(r.ecs, "_describe", never_stops)
    outcome = rollback_controller(r, handoff(r)).run()
    assert (outcome.state, outcome.reason) == ("hold", "failed_release_unreconciled")
    assert rollback_events(r, "observation", result="stop_unconfirmed")
    assert not [c for c in r.calls("update_service")] and not r.calls("run_task")


LAUNCH_REFUSED = {"result": "launch_failed", "resolves": "run_task", "reason": "launch_failed"}
SECOND_ROLLBACK_ID = "66666666-6666-4666-8666-666666666666"
GONE_TASK = "arn:aws:ecs:us-east-1:111122223333:task/sentry-staging/" + "f" * 32


def launched(arn: str) -> dict:
    return {"result": "launched", "resolves": "run_task", "task_arn": arn}


def failed_task(r: Rig, token: str, *, seconds: float = 10_000):
    return r.ecs._task("arn:failed-migrate:3", token, "family:failed", [("migration", "x")],
                       plan=JobPlan(seconds=seconds), tags={"sentry:job-id": "runtime-migrate"})  # fmt: skip


def omit_from_listings(monkeypatch, r: Rig, task) -> dict:
    """ECS lists everything except this task, as an incomplete or lagging listing does."""
    original, shown = r.ecs.list_tasks, {"visible": False}

    def listing(cluster, **filters):
        found = original(cluster, **filters)
        return found if shown["visible"] else [arn for arn in found if arn != task.arn]

    monkeypatch.setattr(r.ecs, "list_tasks", listing)
    return shown


def assert_nothing_forward(r: Rig) -> None:
    """No reconcile or proof job, no service revision and no scale: nothing activated."""
    assert not r.calls("run_task") and not r.calls("update_service")


def second_rollback(r: Rig) -> Rig:
    """A further rollback run in the same environment, naming the first one as failed."""
    document = copy.deepcopy(r.document)
    document["release_id"] = SECOND_ROLLBACK_ID
    document["purpose"]["failed_release_id"] = ROLLBACK_RELEASE_ID
    loaded = load_manifest(encode(document))
    approval = encode(approval_document(loaded.sha256, release_id=SECOND_ROLLBACK_ID))
    return Rig(document=document, clock=r.clock, trace=r.trace, store=r.store, ecs=r.ecs,
               evidence=FakeEvidence(r.ecs, document), logs=FakeLogs(r.ecs, document),
               tokens=r.tokens, approval_raw=approval)  # fmt: skip


def second_events(r: Rig, kind: str, **match) -> list[dict]:
    events = json.loads(r.store.objects[journal_key(SECOND_ROLLBACK_ID)][0])["events"]
    return [e for e in events if e["kind"] == kind and all(e.get(k) == v for k, v in match.items())]


@pytest.mark.parametrize("task", ["not_yet_listed", "never_launched"])
def test_a_launch_whose_outcome_was_never_learned_holds_until_its_task_is_found(monkeypatch, task):
    # An empty listing proves nothing: the request may have been accepted and its
    # task not listed yet, and that task can still connect and write afterwards.
    token = "u" * 20 + "pending01"
    r = rollback_rig()
    failed_release(r, tokens=(token,))
    pending = failed_task(r, token) if task == "not_yet_listed" else None
    if pending is not None:
        omit_from_listings(monkeypatch, r, pending)
    outcome = rollback_controller(r, handoff(r)).run()
    assert (outcome.state, outcome.reason) == ("hold", "failed_release_unreconciled")
    [unresolved] = rollback_events(r, "observation", result="failed_launches_unresolved")
    assert unresolved["launches"] == [
        {"release_id": FAILED_RELEASE_ID, "subject": "runtime-migrate", "token": token,
         "reason": "outcome_unknown"}
    ]  # fmt: skip
    assert not rollback_events(r, "observation", result="failed_launches_swept")
    assert not rollback_events(r, "observation", result="failed_release_reconciled")
    assert rollback_events(r, "transition")[-2]["to"] == "prepared"
    assert_nothing_forward(r)
    if pending is not None:
        assert r.ecs._status(pending) != "STOPPED" and not r.calls("stop_task")
    # The held run keeps the lock it was handed: nobody else may proceed either.
    assert json.loads(r.store.objects[LOCK][0])["release_id"] == ROLLBACK_RELEASE_ID


def test_a_recorded_task_is_stopped_by_its_identity_when_listings_omit_it(monkeypatch):
    token = "k" * 20 + "running01"
    r = rollback_rig()
    task = failed_task(r, token)
    failed_release(r, tokens=(token,), learned={token: [launched(task.arn)]})
    omit_from_listings(monkeypatch, r, task)
    outcome = rollback_controller(r, handoff(r)).run()
    assert outcome.state == "held_paused", outcome
    assert [call["task"] for call in r.calls("stop_task")][0] == task.arn
    assert r.ecs._status(task) == "STOPPED"
    [confirmed] = rollback_events(r, "observation", subject=f"failed:{token}",
                                  result="stop_confirmed")  # fmt: skip
    assert confirmed["task_arn"] == task.arn
    [swept] = rollback_events(r, "observation", result="failed_launches_swept")
    assert (swept["tokens"], swept["stopped"]) == (1, 1)


@pytest.mark.parametrize(
    "then, held",
    [
        # ECS forgets a stopped task; the failed release's own record of it is the proof.
        ([{"result": "job_succeeded", "task_arn": GONE_TASK}], False),
        ([{"result": "job_failed", "task_arn": GONE_TASK, "reason": "job_exit_code"}], False),
        ([{"result": "stop_confirmed", "resolves": "stop_task", "task_arn": GONE_TASK}], False),
        ([{"result": "cleanup_stopped", "task_arn": GONE_TASK}], False),
        # Never recorded as stopped and not describable now: its state is unknown.
        ([], True),
        ([{"result": "stop_unconfirmed", "task_arn": GONE_TASK}], True),
        ([{"result": "cleanup_unconfirmed"}], True),
        # A stop recorded for some other task says nothing about this one.
        ([{"result": "stop_confirmed", "resolves": "stop_task", "task_arn": GONE_TASK[:-1] + "e"}],
         True),
    ],
)  # fmt: skip
def test_a_recorded_task_ecs_no_longer_describes_needs_its_recorded_stop(then, held):
    token = "g" * 20 + "launched1"
    r = rollback_rig()
    failed_release(r, tokens=(token,), learned={token: [launched(GONE_TASK), *then]})
    outcome = rollback_controller(r, handoff(r)).run()
    if not held:
        assert outcome.state == "held_paused", outcome
        assert not r.calls("stop_task")
        return
    assert (outcome.state, outcome.reason) == ("hold", "failed_release_unreconciled")
    [unresolved] = rollback_events(r, "observation", result="failed_launches_unresolved")
    assert unresolved["launches"] == [
        {"release_id": FAILED_RELEASE_ID, "subject": "runtime-migrate", "token": token,
         "reason": "task_not_described", "task_arn": GONE_TASK}
    ]  # fmt: skip
    assert_nothing_forward(r)


def test_every_task_of_a_launch_recorded_with_several_is_stopped(monkeypatch):
    token = "m" * 20 + "multiple1"
    r = rollback_rig()
    first, second = failed_task(r, token), failed_task(r, token)
    record = {"result": "launched_multiple", "resolves": "run_task",
              "task_arns": [first.arn, second.arn], "reason": "launch_task_count"}  # fmt: skip
    failed_release(r, tokens=(token,), learned={token: [record]})
    omit_from_listings(monkeypatch, r, second)
    outcome = rollback_controller(r, handoff(r)).run()
    assert outcome.state == "held_paused", outcome
    assert {call["task"] for call in r.calls("stop_task")} >= {first.arn, second.arn}
    assert (r.ecs._status(first), r.ecs._status(second)) == ("STOPPED", "STOPPED")


def test_a_resent_launch_left_unresolved_by_a_crash_is_reconciled_by_its_listed_task():
    token = "c" * 20 + "crashed01"
    r = rollback_rig()
    failed_release(r, tokens=(token,))
    journal = Journal(r.store, journal_key(FAILED_RELEASE_ID))
    assert journal.load()
    first = next(e for e in journal.events if e["kind"] == "intent")
    journal.append({"at": first["at"], "kind": "intent", "action": "run_task",
                    "subject": first["subject"], "request_sha256": first["request_sha256"],
                    "token": token, "retry_of": first["sequence"]})  # fmt: skip
    grant = FailedReleaseHandoff(
        failed_session_id=FAILED_SESSION, lock_etag=r.lock_etag(),
        fence_evidence_sha256=sha("failed session fenced"), authorized_by="fixture-operator",
    )  # fmt: skip
    task = failed_task(r, token)
    outcome = rollback_controller(r, grant).run()
    assert outcome.state == "held_paused", outcome
    assert [call["task"] for call in r.calls("stop_task")][0] == task.arn
    [swept] = rollback_events(r, "observation", result="failed_launches_swept")
    assert (swept["tokens"], swept["stopped"]) == (1, 1)


def test_a_resolution_recorded_without_a_launch_intent_is_unknown_state():
    r = rollback_rig()
    failed_release(r)
    journal = Journal(r.store, journal_key(FAILED_RELEASE_ID))
    assert journal.load()
    journal.append({"at": journal.events[0]["at"], "kind": "observation",
                    "subject": "runtime-migrate", **launched(GONE_TASK)})  # fmt: skip
    outcome = rollback_controller(r, handoff(r)).run()
    assert (outcome.state, outcome.reason) == ("hold", "failed_release_unreconciled")
    assert_nothing_forward(r)


@pytest.mark.parametrize("listed_by_then", [False, True])
def test_a_second_rollback_cannot_skip_what_the_first_left_unreconciled(
    monkeypatch, listed_by_then
):
    # The held first run owns the lock, so a retry names it as the failed release.
    # Its journal launched nothing, but the original failure is still unreconciled.
    token = "u" * 20 + "pending01"
    r = rollback_rig()
    failed_release(r, tokens=(token,))
    pending = failed_task(r, token)
    shown = omit_from_listings(monkeypatch, r, pending)
    first = rollback_controller(r, handoff(r)).run()
    assert (first.state, first.reason) == ("hold", "failed_release_unreconciled")
    shown["visible"] = listed_by_then
    again = second_rollback(r)
    grant = handoff(again, failed_session_id="session-b")
    outcome = rollback_controller(again, grant, session="session-c").run()
    if not listed_by_then:
        assert (outcome.state, outcome.reason) == ("hold", "failed_release_unreconciled")
        [unresolved] = second_events(again, "observation", result="failed_launches_unresolved")
        assert unresolved["launches"][0]["release_id"] == FAILED_RELEASE_ID
        assert r.ecs._status(pending) != "STOPPED"
        assert_nothing_forward(again)
        return
    assert outcome.state == "held_paused", outcome
    assert [call["task"] for call in r.calls("stop_task")][0] == pending.arn
    assert r.ecs._status(pending) == "STOPPED"
    [reconciled] = second_events(again, "observation", result="failed_release_reconciled")
    assert reconciled["failed_release_id"] == ROLLBACK_RELEASE_ID
    assert [item["release_id"] for item in reconciled["predecessors"]] == [FAILED_RELEASE_ID]
    stop = second_events(again, "intent", action="stop_task", subject=f"failed:{token}")
    proof = second_events(again, "intent", action="run_task")
    assert stop and proof and stop[-1]["sequence"] < proof[0]["sequence"]


def test_a_predecessor_journal_that_cannot_be_read_holds():
    r = rollback_rig()
    failed_release(r, tokens=("u" * 20 + "pending01",))
    first = rollback_controller(r, handoff(r)).run()
    assert (first.state, first.reason) == ("hold", "failed_release_unreconciled")
    body, etag = r.store.objects[journal_key(FAILED_RELEASE_ID)]
    r.store.delete(journal_key(FAILED_RELEASE_ID), if_match=etag)
    again = second_rollback(r)
    grant = handoff(again, failed_session_id="session-b")
    outcome = rollback_controller(again, grant, session="session-c").run()
    assert (outcome.state, outcome.reason) == ("hold", "failed_release_unknown")
    assert_nothing_forward(again)


def test_a_run_that_finished_reconciling_its_predecessor_is_not_reconciled_again():
    token = "d" * 20 + "running01"
    r = rollback_rig()
    failed_release(r, tokens=(token,))
    task = failed_task(r, token)
    r.evidence.job_changes["runtime-proof"] = {"release_id": ROLLBACK_RELEASE_ID}
    first = rollback_controller(r, handoff(r)).run()
    assert (first.state, first.reason) == ("hold", "job_receipt_mismatch")
    assert r.ecs._status(task) == "STOPPED"
    del r.evidence.job_changes["runtime-proof"]
    again = second_rollback(r)
    grant = handoff(again, failed_session_id="session-b")
    outcome = rollback_controller(again, grant, session="session-c").run()
    assert outcome.state == "held_paused", outcome
    [reconciled] = second_events(again, "observation", result="failed_release_reconciled")
    assert "predecessors" not in reconciled


@pytest.mark.parametrize(
    "change, reason",
    [
        # A schema other than the stated one is unknown state: nothing starts.
        ({"result": {"database": "runtime_db", "principal": "runtime_owner", "schema": "goose:1",
                     "release_sessions": "0", "owner_sessions": "0"}}, "job_receipt_mismatch"),
        # A remaining session of the failed release or owner holds too.
        ({"result": {"database": "runtime_db", "principal": "runtime_owner", "schema": None,
                     "release_sessions": "0", "owner_sessions": "1"}}, "job_receipt_mismatch"),
        # Receipts name the prior release whose revisions run, never the rollback run.
        ({"release_id": ROLLBACK_RELEASE_ID}, "job_receipt_mismatch"),
    ],
)  # fmt: skip
def test_unknown_or_unproven_schema_state_holds_before_any_service_starts(change, reason):
    r = rollback_rig()
    failed_release(r)
    if change.get("result", {}).get("schema", "") is None:
        change["result"]["schema"] = r.document["purpose"]["actual_schemas"]["runtime"]
    r.evidence.job_changes["runtime-reconcile"] = change
    outcome = rollback_controller(r, handoff(r)).run()
    assert (outcome.state, outcome.reason) == ("hold", reason), outcome
    assert not [c for c in r.calls("update_service") if c.get("taskDefinition")]
    assert outcome.rollback is not None and outcome.rollback["kind"] == "rollback_hold"
    assert outcome.rollback["automatic"] is False


def test_a_rollback_run_may_be_aborted_and_recovered_like_any_release():
    r = rollback_rig()
    failed_release(r)
    r.ecs.crash[("run_task", "after")] = 1
    with pytest.raises(SimulatedCrash):
        rollback_controller(r, handoff(r)).run()
    controller = rollback_controller(r, None, session="session-c")
    controller.recover(
        RecoveryAuthorization("session-b", r.lock_etag(), sha("rollback session fenced"),
                              "fixture-operator")  # fmt: skip
    )
    outcome = controller.abort()
    assert (outcome.state, outcome.reason) == ("hold", "operator_abort")
    assert json.loads(r.store.objects[LOCK][0])["session_id"] == "session-c"


def lose_rollback_session_before_handoff(r: Rig, monkeypatch, when: str) -> None:
    """Session b dies while the failed release still holds its lock."""
    original_read, original_replace = r.store.read, r.store.replace

    def read(key):
        if when == "before_intent" and key == journal_key(FAILED_RELEASE_ID):
            raise SimulatedCrash("failed journal read")
        return original_read(key)

    def replace(key, body, *, if_match):
        if when == "before_replace" and key == LOCK:
            raise SimulatedCrash("lock handoff")
        return original_replace(key, body, if_match=if_match)

    monkeypatch.setattr(r.store, "read", read)
    monkeypatch.setattr(r.store, "replace", replace)
    with pytest.raises(SimulatedCrash):
        rollback_controller(r, handoff(r)).run()
    monkeypatch.setattr(r.store, "read", original_read)
    monkeypatch.setattr(r.store, "replace", original_replace)


def recover_rollback(r: Rig, grant: FailedReleaseHandoff | None, **changes) -> ReleaseController:
    controller = rollback_controller(r, grant, session="session-c")
    values = {"prior_session_id": "session-b", "lock_etag": r.lock_etag(),
              "fence_evidence_sha256": sha("rollback session fenced"),
              "authorized_by": "fixture-operator", **changes}  # fmt: skip
    controller.recover(RecoveryAuthorization(**values))
    return controller


@pytest.mark.parametrize("when", ["before_intent", "before_replace"])
def test_a_rollback_session_lost_before_its_handoff_is_recovered_and_completes(monkeypatch, when):
    r = rollback_rig()
    failed_release(r)
    lose_rollback_session_before_handoff(r, monkeypatch, when)
    failed_lock = r.store.objects[LOCK]
    assert json.loads(failed_lock[0])["release_id"] == FAILED_RELEASE_ID
    recover_rollback(r, None)
    # Recovery moves no lock: the failed release's lock waits for the fenced handoff.
    assert r.store.objects[LOCK] == failed_lock
    [recovered] = rollback_events(r, "session", action="recovered")
    assert recovered["prior_session_id"] == "session-b"
    outcome = rollback_controller(r, handoff(r), session="session-c").run()
    assert outcome.state == "held_paused", outcome
    assert [e["to"] for e in rollback_events(r, "transition")] == ROLLBACK_SEQUENCE
    [moved] = rollback_events(r, "observation", result="lock_handed_off")
    assert moved["from_release_id"] == FAILED_RELEASE_ID
    assert LOCK not in r.store.objects
    if when == "before_replace":
        # Session b's handoff intent is settled from the untouched lock first.
        results = [e["result"] for e in rollback_events(r, "observation", subject="environment")]
        assert results.index("handoff_not_applied") < results.index("lock_handed_off")


def test_a_recovered_rollback_before_its_handoff_may_be_aborted_leaving_the_failed_lock(
    monkeypatch,
):
    r = rollback_rig()
    failed_release(r)
    lose_rollback_session_before_handoff(r, monkeypatch, "before_replace")
    failed_lock = r.store.objects[LOCK]
    outcome = recover_rollback(r, None).abort()
    assert (outcome.state, outcome.reason) == ("hold", "operator_abort")
    assert r.store.objects[LOCK] == failed_lock
    assert r.ecs.mutations == []


@pytest.mark.parametrize(
    "case",
    ["wrong_etag", "other_release", "held_rollback"],
)
def test_recovery_refuses_a_foreign_lock_unless_it_is_the_untouched_failed_lock(monkeypatch, case):
    r = rollback_rig()
    failed_release(r)
    if case == "held_rollback":
        # Session b held at prepared (a wrong handoff): that run is finished.
        outcome = rollback_controller(r, handoff(r, lock_etag="0" * 32)).run()
        assert (outcome.state, outcome.reason) == ("hold", "handoff_refused")
    else:
        lose_rollback_session_before_handoff(r, monkeypatch, "before_replace")
    if case == "other_release":
        body, etag = r.store.objects[LOCK]
        r.store.replace(LOCK, encode({**json.loads(body), "release_id": PRIOR_RELEASE_ID}),
                        if_match=etag)  # fmt: skip
    before = dict(r.store.objects)
    with pytest.raises(ReleaseHalted) as halted:
        recover_rollback(r, None, **({"lock_etag": "0" * 32} if case == "wrong_etag" else {}))
    assert halted.value.code == "recovery_refused"
    assert r.store.objects == before


class FailingClock:
    """Delegates to a fake clock until ``fail`` is set, then cannot vouch for time."""

    def __init__(self, base: FakeClock) -> None:
        self.base = base
        self.fail = False

    def now(self) -> datetime:
        if self.fail:
            raise ClockUntrusted("fixture divergence")
        return self.base.now()

    def sleep(self, seconds: float) -> None:
        if self.fail:
            raise ClockUntrusted("fixture divergence")
        self.base.sleep(seconds)


def controller_with_clock(r: Rig, clock, session: str = "session-a") -> ReleaseController:
    return ReleaseController(
        load_manifest(encode(r.document)),
        load_approval(r.approval_raw),
        store=r.store,
        ecs=r.ecs,
        evidence=r.evidence,
        logs=r.logs,
        clock=clock,
        tokens=r.tokens,
        session_id=session,
    )


def test_an_untrusted_clock_before_journaling_halts_without_writing():
    r = rig()
    clock = FailingClock(r.clock)
    clock.fail = True
    with pytest.raises(ReleaseHalted) as error:
        controller_with_clock(r, clock).run()
    assert error.value.code == "controller_clock_untrusted"
    assert r.store.objects == {} and r.ecs.mutations == []


def test_a_clock_losing_trust_mid_release_holds_and_journals_without_new_sends():
    r = rig()
    clock = FailingClock(r.clock)
    original = r.ecs.run_task

    def fail_after_first_launch(request: dict) -> dict:
        response = original(request)
        clock.fail = True
        return response

    setattr(r.ecs, "run_task", fail_after_first_launch)
    outcome = controller_with_clock(r, clock).run()
    assert_held(r, outcome, "controller_clock_untrusted", "quiesced")
    assert len(r.calls("run_task")) == 1 and not r.calls("update_service")
    hold = r.events("transition", to="hold")[-1]
    assert hold["clock_untrusted"] is True
    latest_trusted = max(e["at"] for e in r.journal()["events"] if "clock_untrusted" not in e)
    assert hold["at"] == latest_trusted


def test_a_restarted_controller_whose_clock_is_behind_its_journal_holds():
    r = rig()
    r.ecs.crash[("run_task", "after")] = 1
    with pytest.raises(SimulatedCrash):
        r.controller().run()
    sends = len(r.ecs.mutations)
    controller = r.recover()
    r.clock.moment -= timedelta(seconds=30)
    outcome = controller.run()
    assert_held(r, outcome, "controller_clock_rollback", "quiesced")
    assert len(r.ecs.mutations) == sends


def test_operator_abort_stops_only_the_releases_own_running_job_then_holds():
    r = rig()
    migrate = r.document["jobs"][0]["task"]["task_definition"]
    r.ecs.plans[migrate] = JobPlan(hang=True)
    original = r.ecs.describe_tasks
    calls = []

    def crash_while_waiting(cluster, arns):
        calls.append(arns)
        if len(calls) == 3:
            raise SimulatedCrash("operator machine lost while the job runs")
        return original(cluster, arns)

    setattr(r.ecs, "describe_tasks", crash_while_waiting)
    with pytest.raises(SimulatedCrash):
        r.controller().run()
    setattr(r.ecs, "describe_tasks", original)
    foreign = r.ecs.standalone(migrate)
    launches = len(r.calls("run_task"))
    outcome = r.recover().abort()
    assert_held(r, outcome, "operator_abort", "quiesced")
    assert len(r.calls("run_task")) == launches and not r.calls("update_service")
    assert [c["task"] for c in r.calls("stop_task")] == [r.job_tasks("runtime-migrate")[0].arn]
    assert r.ecs._status(foreign) == "RUNNING"
    assert r.events("observation", result="stop_confirmed")[-1]["sql_outcome"] == "unknown"


def test_operator_abort_needs_this_sessions_journal_and_leaves_a_finished_release():
    r = rig()
    assert r.controller().run().state == "held_paused"
    assert r.controller().abort().state == "held_paused"
    with pytest.raises(ReleaseHalted) as error:
        rig().controller().abort()
    assert error.value.code == "journal_missing"
    other = rig()
    other.ecs.crash[("run_task", "after")] = 1
    with pytest.raises(SimulatedCrash):
        other.controller().run()
    with pytest.raises(ReleaseHalted) as error:
        other.controller("session-b").abort()
    assert error.value.code == "session_conflict"
    assert not other.calls("stop_task")


class JournalTimeClock:
    """Refuses to vouch for time exactly when one matching event is being timestamped.

    The controller reads the clock for its guard and again for the journal time;
    this double fails only the second read, the gap the latch must close.
    """

    def __init__(self, base: FakeClock, matches, *, once: bool = False) -> None:
        self.base, self.matches, self.once, self.failed = base, matches, once, 0

    def now(self) -> datetime:
        caller = sys._getframe(1)
        if caller.f_code.co_name == "_now":
            caller = caller.f_back
        event = (
            caller.f_locals.get("event") if caller and caller.f_code.co_name == "_append" else None
        )
        if isinstance(event, dict) and self.matches(event) and not (self.once and self.failed):
            self.failed += 1
            raise ClockUntrusted("fixture: lost at the journal timestamp")
        return self.base.now()

    def sleep(self, seconds: float) -> None:
        self.base.sleep(seconds)


def test_no_forward_intent_is_journaled_once_the_clock_fails_at_its_timestamp():
    r = rig()
    clock = JournalTimeClock(r.clock, lambda e: e.get("action") == "run_task")
    outcome = controller_with_clock(r, clock).run()
    assert_held(r, outcome, "controller_clock_untrusted", "quiesced")
    assert not r.events("intent", action="run_task") and not r.calls("run_task")
    assert r.events("transition", to="hold")[-1]["clock_untrusted"] is True


def test_a_clock_lost_at_the_success_transition_never_finishes_held_paused():
    r = rig()
    clock = JournalTimeClock(r.clock, lambda e: e.get("to") == "held_paused")
    outcome = controller_with_clock(r, clock).run()
    assert_held(r, outcome, "controller_clock_untrusted", "operational_verified")
    assert "held_paused" not in r.transitions()


def test_a_clock_that_refused_once_never_authorizes_a_later_send():
    r = rig()
    clock = JournalTimeClock(r.clock, lambda e: e.get("action") == "run_task", once=True)
    outcome = controller_with_clock(r, clock).run()
    assert_held(r, outcome, "controller_clock_untrusted", "quiesced")
    assert not r.calls("run_task") and not r.calls("update_service")


def test_recovery_without_a_trusted_clock_moves_no_lock_and_journals_nothing():
    r = rig()
    r.ecs.crash[("run_task", "after")] = 1
    with pytest.raises(SimulatedCrash):
        r.controller().run()
    before = {key: value for key, value in r.store.objects.items()}
    clock = FailingClock(r.clock)
    clock.fail = True
    controller = controller_with_clock(r, clock, session="session-b")
    with pytest.raises(ClockUntrusted):
        controller.recover(
            RecoveryAuthorization(
                prior_session_id="session-a",
                lock_etag=r.lock_etag(),
                fence_evidence_sha256=sha("prior session process confirmed terminated"),
                authorized_by="fixture-operator",
            )
        )
    assert r.store.objects == before
    assert json.loads(r.store.objects[LOCK][0])["session_id"] == "session-a"
    # With its clock back, the same authorization still recovers the release.
    outcome = r.recover().run()
    assert outcome.state == "held_paused", outcome


def test_a_takeover_is_journaled_at_the_time_read_before_the_lock_moved():
    r = rig()
    r.ecs.crash[("run_task", "after")] = 1
    with pytest.raises(SimulatedCrash):
        r.controller().run()
    clock = JournalTimeClock(r.clock, lambda event: event.get("action") == "recovered")
    controller = controller_with_clock(r, clock, session="session-b")
    controller.recover(
        RecoveryAuthorization(
            prior_session_id="session-a",
            lock_etag=r.lock_etag(),
            fence_evidence_sha256=sha("prior session process confirmed terminated"),
            authorized_by="fixture-operator",
        )
    )
    # The journal time was read before the lock write; no second read could strand it.
    assert clock.failed == 0
    [recovered] = r.events("session", action="recovered")
    assert "clock_untrusted" not in recovered
    assert json.loads(r.store.objects[LOCK][0])["session_id"] == "session-b"
    assert r.journal()["session_id"] == "session-b"


def test_a_lost_handoff_response_is_settled_from_the_lock_it_left(monkeypatch):
    r = rollback_rig()
    failed_release(r)
    grant = handoff(r)
    original = r.store.replace
    applied: list[bool] = []

    def lost(key, body, *, if_match):
        if key == LOCK and not applied:
            applied.append(True)
            raise AmbiguousResponse("connection reset before the replace was sent")
        return original(key, body, if_match=if_match)

    monkeypatch.setattr(r.store, "replace", lost)
    outcome = rollback_controller(r, grant).run()
    # Unapplied: the failed lock is untouched and the run holds rather than resend now.
    assert (outcome.state, outcome.reason) == ("hold", "handoff_unconfirmed")
    assert json.loads(r.store.objects[LOCK][0])["session_id"] == FAILED_SESSION
    assert r.ecs.mutations == []


def test_a_failed_lock_under_another_session_than_its_journal_is_never_taken():
    """The lock and the failed journal must name the same session: otherwise unreconciled."""
    r = rollback_rig()
    failed_release(r, lock=False)
    r.store.create(LOCK, encode({"release_id": FAILED_RELEASE_ID, "session_id": "session-other"}))
    lock = r.store.objects[LOCK]
    outcome = rollback_controller(r, handoff(r)).run()
    assert (outcome.state, outcome.reason) == ("hold", "environment_locked")
    assert r.store.objects[LOCK] == lock and r.ecs.mutations == []


@pytest.mark.parametrize("case", ["invisible", "other-token"])
def test_a_listed_failed_task_that_is_not_exactly_its_token_holds(monkeypatch, case):
    token = "v" * 20 + "running01"
    r = rollback_rig()
    failed_release(r, tokens=(token,))
    task = r.ecs._task("arn:failed-migrate:3", token, "family:failed", [("migration", "x")],
                       plan=JobPlan(seconds=10_000), tags={"sentry:job-id": "runtime-migrate"})  # fmt: skip
    original = r.ecs.describe_tasks

    def describe(cluster, arns):
        described = original(cluster, arns)
        if task.arn in arns:
            if case == "invisible":
                return {"tasks": [t for t in described["tasks"] if t["taskArn"] != task.arn]}
            return {"tasks": [{**t, "startedBy": "someone-else"} if t["taskArn"] == task.arn else t
                              for t in described["tasks"]]}  # fmt: skip
        return described

    monkeypatch.setattr(r.ecs, "describe_tasks", describe)
    outcome = rollback_controller(r, handoff(r)).run()
    assert (outcome.state, outcome.reason) == ("hold", "failed_release_unreconciled")
    assert not r.calls("stop_task") and not r.calls("run_task")


@pytest.mark.parametrize("scaled_to_zero", [False, True])
def test_a_rollback_after_a_release_that_started_its_services_restores_the_prior_pair(
    scaled_to_zero,
):
    """A real failed upgrade (its services started, its observer never reported), then
    the rollback in the same environment: the failed revisions are recognised from the
    manifest, scaled to zero, and the prior pair is deployed and verified."""
    r = rig(rollback="compatible_release", running_prior=True)
    r.evidence.missing_checks.add("runtime-observe")
    failed = r.controller("session-a").run()
    assert (failed.state, failed.last_proven) == ("hold", "services_started")
    candidate = {key: spec["task_definition"] for key, spec in r.document["services"].items()}
    assert {s.task_definition for s in r.ecs.services.values()} == set(candidate.values())
    if scaled_to_zero:
        # The operator scaled the failed services to zero (revision unchanged).
        for arn in list(r.ecs.services):
            r.ecs.update_service({"cluster": r.document["environment"]["cluster_arn"],
                                  "service": arn, "desiredCount": 0})  # fmt: skip
        r.clock.advance(seconds=60)
    document = rollback_run_document()
    document["purpose"]["failed_release_id"] = RELEASE_ID_FIXTURE
    document["purpose"]["failed_services"] = candidate
    loaded = load_manifest(encode(document))
    r.document = document
    r.ecs.learn(document)
    r.evidence = FakeEvidence(r.ecs, document)
    r.logs = FakeLogs(r.ecs, document)
    r.approval_raw = encode({**approval_document(loaded.sha256), "release_id": ROLLBACK_RELEASE_ID})
    grant = FailedReleaseHandoff("session-a", r.lock_etag(), sha("failed session fenced"),
                                 "fixture-operator")  # fmt: skip
    outcome = rollback_controller(r, grant).run()
    assert outcome.state == "held_paused", outcome
    prior = document["rollback"]["services"]
    assert {key: s.task_definition for key, s in (
        (name, r.ecs.services[arn]) for name, arn in document["environment"]["services"].items()
    )} == {key: prior[key]["task_definition"] for key in prior}  # fmt: skip
    events = json.loads(r.store.objects[ROLLBACK_JOURNAL][0])["events"]
    assert [e["to"] for e in events if e["kind"] == "transition"] == ROLLBACK_SEQUENCE
    scale = [e for e in events if e["kind"] == "intent" and e["action"] == "update_service"
             and e.get("desired_count") == 0]  # fmt: skip
    assert len(scale) == (0 if scaled_to_zero else 3)
    assert LOCK not in r.store.objects


def test_a_rollback_holds_on_a_service_revision_neither_prior_nor_failed():
    r = rollback_rig()
    failed_release(r)
    service = next(iter(r.ecs.services.values()))
    service.task_definition = service.task_definition.rsplit(":", 1)[0] + ":99"
    outcome = rollback_controller(r, handoff(r)).run()
    assert (outcome.state, outcome.reason) == ("hold", "rollback_service_revision_unknown")
    assert not [c for c in r.calls("update_service") if c.get("taskDefinition")]
    assert not r.calls("run_task")


@pytest.mark.parametrize("when", ["before", "after"])
def test_a_crash_around_the_sweep_stop_still_stops_the_failed_task_on_resume(monkeypatch, when):
    token = "w" * 20 + "running01"
    r = rollback_rig()
    failed_release(r, tokens=(token,))
    task = r.ecs._task("arn:failed-migrate:3", token, "family:failed", [("migration", "x")],
                       plan=JobPlan(seconds=10_000), tags={"sentry:job-id": "runtime-migrate"})  # fmt: skip
    original = r.ecs.stop_task

    def crash(cluster, arn, reason):
        if when == "after":
            original(cluster, arn, reason)
        raise SimulatedCrash("sweep stop")

    monkeypatch.setattr(r.ecs, "stop_task", crash)
    with pytest.raises(SimulatedCrash):
        rollback_controller(r, handoff(r)).run()
    monkeypatch.setattr(r.ecs, "stop_task", original)
    outcome = rollback_controller(r, None).run()
    assert outcome.state == "held_paused", outcome
    assert r.ecs._status(task) == "STOPPED"
    stops = rollback_events(r, "intent", action="stop_task", subject=f"failed:{token}")
    assert len(stops) == 2 and stops[0]["request_sha256"] == stops[1]["request_sha256"]
    assert [c["task"] for c in r.calls("stop_task")].count(task.arn) >= 1


@pytest.mark.parametrize("lock", ["deleted", "another_release"])
def test_a_resumed_sweep_stop_needs_the_runs_own_lock(monkeypatch, lock):
    token = "w" * 20 + "running01"
    r = rollback_rig()
    failed_release(r, tokens=(token,))
    task = r.ecs._task("arn:failed-migrate:3", token, "family:failed", [("migration", "x")],
                       plan=JobPlan(seconds=10_000), tags={"sentry:job-id": "runtime-migrate"})  # fmt: skip
    original = r.ecs.stop_task

    def crash(cluster, arn, reason):
        raise SimulatedCrash("sweep stop")

    monkeypatch.setattr(r.ecs, "stop_task", crash)
    with pytest.raises(SimulatedCrash):
        rollback_controller(r, handoff(r)).run()
    monkeypatch.setattr(r.ecs, "stop_task", original)
    body, etag = r.store.objects[LOCK]
    assert json.loads(body)["release_id"] == ROLLBACK_RELEASE_ID
    if lock == "deleted":
        r.store.delete(LOCK, if_match=etag)
    else:
        r.store.replace(LOCK, encode({"release_id": PRIOR_RELEASE_ID, "session_id": "other"}),
                        if_match=etag)  # fmt: skip
    outcome = rollback_controller(r, None).run()
    # No ownership proof, no stop authority: nothing is sent and the intent stays
    # outstanding, possibly sent, for the operator's review.
    assert (outcome.state, outcome.reason) == ("hold", "lock_not_held")
    assert r.calls("stop_task") == []
    assert r.ecs._status(task) != "STOPPED"
    assert len(rollback_events(r, "intent", action="stop_task", subject=f"failed:{token}")) == 1
    assert not rollback_events(r, "observation", subject=f"failed:{token}")


@pytest.mark.parametrize("limit", ["approval", "window"])
def test_a_handoff_reaching_its_authorization_limit_at_the_intent_write_moves_no_lock(
    monkeypatch, limit
):
    if limit == "approval":
        r = rollback_rig(not_after=iso(START + timedelta(minutes=10)))
        boundary = START + timedelta(minutes=10)
    else:
        r = rollback_rig()
        boundary = None
    failed_release(r)
    lock = r.store.objects[LOCK]
    original = r.store.replace

    def slow_intent(key, body, *, if_match):
        result = original(key, body, if_match=if_match)
        events = json.loads(body).get("events", []) if key == ROLLBACK_JOURNAL else []
        if events and events[-1].get("action") == "lock_handoff":
            target = boundary
            if target is None:
                prepared = json.loads(r.store.objects[ROLLBACK_JOURNAL][0])["events"][0]
                window = r.document["window"]["total_seconds"]
                target = datetime.fromisoformat(prepared["at"].replace("Z", "+00:00")) + timedelta(
                    seconds=window
                )
                target = min(target, datetime.fromisoformat(
                    r.document["window"]["expires_at"].replace("Z", "+00:00")))  # fmt: skip
            r.clock.moment = target
        return result

    monkeypatch.setattr(r.store, "replace", slow_intent)
    outcome = rollback_controller(r, handoff(r)).run()
    assert outcome.state == "hold"
    assert outcome.reason in {"approval_expired", "release_window_exceeded"}
    assert r.store.objects[LOCK] == lock and r.ecs.mutations == []
    [intent] = rollback_events(r, "intent", action="lock_handoff")
    assert not rollback_events(r, "observation", result="lock_handed_off")
    assert intent["lock_etag"] == lock[1]
