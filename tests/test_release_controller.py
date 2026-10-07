"""Offline release-controller fault tests against deterministic fake ECS/S3 ports."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
import json

import pytest

from release.controller import RecoveryAuthorization, ReleaseController, ReleaseHalted
from release.manifest import load_approval, load_manifest
from release.ports import AmbiguousResponse
from tests.release_fakes import (
    START,
    FakeClock,
    FakeEcs,
    FakeEvidence,
    FakeStore,
    JobPlan,
    SimulatedCrash,
    Tokens,
    Trace,
    approval_document,
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
    tokens: Tokens
    approval_raw: bytes

    def controller(self, session: str = "session-a") -> ReleaseController:
        return ReleaseController(
            load_manifest(encode(self.document)),
            load_approval(self.approval_raw),
            store=self.store,
            ecs=self.ecs,
            evidence=self.evidence,
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
    assert_held(r, outcome, "job_receipt_missing", "migrated")


@pytest.mark.parametrize(
    "change",
    [
        {"status": "failed"},
        {"task_arn": "arn:aws:ecs:us-east-1:111122223333:task/sentry-staging/forged"},
        {"release_id": "11111111-2222-4333-8444-555555555555"},
        {"principal": "product_owner"},
        {"schema": "sentry.release.other.v1"},
    ],
)
def test_receipt_must_bind_release_job_task_and_expectations(change):
    r = rig()
    r.evidence.job_changes["product-proof"] = change
    outcome = r.controller().run()
    assert_held(r, outcome, "job_receipt_mismatch", "migrated")


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
        (lambda r: r.evidence.missing_checks.add("worker-readiness"), "operational_evidence_missing"),
        (lambda r: r.evidence.check_changes.update({"api-operational": {"status": "failed"}}),
         "operational_receipt_mismatch"),
        (lambda r: r.evidence.check_changes.update(
            {"worker-readiness": {"tasks": {"worker": "arn:aws:ecs:us-east-1:111122223333:task/x"}}}),
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
