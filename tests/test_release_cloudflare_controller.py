"""The release controller on the Cloudflare platform, against offline fakes.

The controller matrix of tests/test_release_controller.py rebuilt on
``CloudflarePlatform``. Every command goes through the real signed control
client into ``FakeDOControl``, which verifies the Ed25519 signature over the
canonical bytes and applies the object rules (fence, cross-release allowlist,
replay, nonce-bound stops). Then the plan's Cloudflare cases:
- an idempotent version upload;
- an ambiguous deploy response;
- an incomplete instance listing;
- a stale session refused by the object;
- a job deadline and a lost job response.

Then the three AWS traps as regression probes. Nothing here models Cloudflare
scheduling, IAM, networking or latency.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import json

import pytest

from release.controller import RecoveryAuthorization, ReleaseController, ReleaseHalted
from release.ports import AmbiguousResponse, PlatformHold
from release_cloudflare.control_client import ControlClient, Ed25519Signer
from release_cloudflare.manifest import load_approval, load_manifest
from release_cloudflare.platform import CloudflarePlatform, upload_version
from tests.cloudflare_control_vectors import private_key
from tests.cloudflare_fakes import (
    SERVICE_OBJECTS,
    FakeDOControl,
    FakeReceipts,
    FakeVersions,
    JobBehavior,
    approval_document,
    manifest_document,
)
from tests.release_fakes import (
    START,
    FakeClock,
    FakeStore,
    SimulatedCrash,
    Tokens,
    Trace,
    encode,
    iso,
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


def _public_key() -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return private_key().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


@dataclass
class Rig:
    document: dict
    clock: FakeClock
    trace: Trace
    store: FakeStore
    versions: FakeVersions
    control: FakeDOControl
    receipts: FakeReceipts
    tokens: Tokens
    approval_raw: bytes

    def platform(self) -> CloudflarePlatform:
        client = ControlClient(
            self.control,
            Ed25519Signer(private_key()),
            self.clock,
            release_id=self.document["release_id"],
        )
        reads = iter(range(1, 1 << 30))
        return CloudflarePlatform(
            load_manifest(encode(self.document)),
            control=client,
            versions=self.versions,
            receipts=self.receipts,
            clock=self.clock,
            read_ids=lambda: f"{next(reads):032x}",
        )

    def controller(self, session: str = "session-a") -> ReleaseController:
        return ReleaseController(
            load_manifest(encode(self.document)),
            load_approval(self.approval_raw),
            store=self.store,
            platform=self.platform(),
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

    def lock_etag(self) -> str:
        return self.store.objects[LOCK][1]

    def recover(self, session: str = "session-b", prior: str = "session-a") -> ReleaseController:
        controller = self.controller(session)
        controller.recover(
            RecoveryAuthorization(
                prior_session_id=prior,
                lock_etag=self.lock_etag(),
                fence_evidence_sha256=sha(f"{prior} process confirmed terminated"),
                authorized_by="fixture-operator",
            )
        )
        return controller

    def effects(self, kind: str) -> list[tuple]:
        return [entry for entry in self.trace if entry[0] == "control" and entry[1] == kind]


def rig(*, rollback: str = "empty_hold", **approval) -> Rig:
    document = manifest_document(rollback=rollback)
    loaded = load_manifest(encode(document))
    clock, trace = FakeClock(), Trace()
    store = FakeStore(trace)
    versions = FakeVersions(clock, document, trace)
    control = FakeDOControl(clock, versions, document, _public_key(), trace)
    # Models the migration images' receipt producers, which do not exist yet
    # (the real JobRunner refuses migrate; see the no-producer cases below).
    control.wire_migrations = True
    return Rig(
        document=document,
        clock=clock,
        trace=trace,
        store=store,
        versions=versions,
        control=control,
        receipts=FakeReceipts(control, document),
        tokens=Tokens(),
        approval_raw=encode({**approval_document(loaded.sha256), **approval}),
    )


def rollback(outcome) -> dict:
    assert outcome.rollback is not None
    return outcome.rollback


def assert_intent_precedes_every_mutation(r: Rig) -> None:
    last_journal = None
    actions = {"run": "run_job", "start": "start_service", "stop": "stop_service",
               "stop_job": "stop_job", "deploy": "activate_version"}  # fmt: skip
    for entry in r.trace:
        if entry[0] == "store" and entry[1] == JOURNAL:
            last_journal = entry[2]
        elif entry[0] in ("control", "versions"):
            assert last_journal is not None, entry
            event = last_journal["events"][-1]
            assert event["kind"] == "intent" and event["action"] == actions[entry[1]], (
                entry,
                event,
            )


def assert_held(r: Rig, outcome, reason: str, last_proven: str) -> None:
    assert (outcome.state, outcome.reason) == ("hold", reason), outcome
    assert outcome.last_proven == last_proven
    assert r.transitions()[-1] == "hold"
    assert LOCK in r.store.objects, "a held release keeps the environment lock"
    assert outcome.admission == "paused"
    assert_intent_precedes_every_mutation(r)


# Normal attended release ----------------------------------------------------------


def test_first_release_journals_every_step_and_finishes_held_paused():
    r = rig()
    outcome = r.controller().run()
    assert outcome.state == "held_paused", outcome
    assert r.transitions() == FORWARD
    assert LOCK not in r.store.objects
    intents = r.events("intent")
    assert {e["action"] for e in intents} == {
        "activate_version",
        "run_job",
        "start_service",
        "release_lock",
    }
    for event in intents:
        assert ("command_expires_at" in event) == (event["action"] != "release_lock")
    for name in ("task_arn", "task_arns", "deployment_id", "prior_deployments", "cluster"):
        assert not any(name in e for e in r.journal()["events"]), name
    activated = [e["subject"] for e in r.events("observation", result="activated")]
    assert activated == [
        "version/jobs",
        "version/runtime",
        "version/api",
        "version/worker",
        "version/edge",
    ]
    assert len(r.events("observation", result="job_succeeded")) == 6
    ready = {e["subject"]: e["instance"] for e in r.events("observation", result="service_ready")}
    assert set(ready) == {"runtime", "api", "worker"}
    assert_intent_precedes_every_mutation(r)


def run_bodies(r: Rig) -> list[dict]:
    return [q for q in r.control.requests if q["service"] == "jobs" and q["action"] == "run"]


def test_launch_commands_are_exact_signed_runs_under_the_launch_token():
    r = rig()
    r.controller().run()
    runs = run_bodies(r)
    assert [q["name"] for q in runs] == [
        f"job-{r.document['release_id']}-{job['id']}" for job in r.document["jobs"]
    ]
    assert all(q["result"] == 200 for q in runs)
    launched = r.events("intent", action="run_job")
    assert [e["token"] for e in launched] == [q["command_id"] for q in runs]
    reads = [q for q in r.control.requests if q["method"] == "GET"]
    assert reads and all(q["command_id"].startswith("read-") for q in reads)


@pytest.mark.parametrize(
    ("job_index", "behavior", "reason"),
    [
        (0, JobBehavior(exit_detail="Error: exit 1"), "job_container_failed"),
        (2, JobBehavior(receipt="mismatch", receipt_changes={"job_id": "other"}),
         "job_receipt_mismatch"),
        (3, JobBehavior(receipt="failed"), "job_receipt_mismatch"),
        (1, JobBehavior(receipt="exact", receipt_changes={"durable_object_id": "f" * 64}),
         "job_receipt_mismatch"),
    ],
)  # fmt: skip
def test_a_job_is_successful_only_with_complete_exact_evidence(job_index, behavior, reason):
    r = rig()
    job = r.document["jobs"][job_index]
    r.control.jobs[job["id"]] = behavior
    outcome = r.controller().run()
    assert outcome.state == "hold" and outcome.reason == reason
    assert r.events("observation", subject=job["id"], result="job_failed")


def test_an_exited_job_without_its_receipt_is_not_success_and_holds_at_the_deadline():
    r = rig()
    r.control.jobs["runtime-migrate"] = JobBehavior(receipt="missing")
    outcome = r.controller().run()
    assert_held(r, outcome, "job_deadline_exceeded", "quiesced")
    failed = r.events("observation", subject="runtime-migrate", result="job_failed")
    assert failed and failed[-1]["sql_outcome"] == "unknown"
    assert not r.events("observation", result="job_succeeded")


def test_a_job_with_another_image_is_not_success():
    r = rig()
    r.control.image_override[("jobs", "runtime")] = (
        "registry.cloudflare.com/x/other@sha256:" + "0" * 64
    )
    outcome = r.controller().run()
    assert (outcome.state, outcome.reason) == ("hold", "job_image_mismatch")


def test_a_job_deadline_stops_the_named_start_and_never_claims_sql_cancellation():
    r = rig()
    r.control.jobs["runtime-migrate"] = JobBehavior(hang=True)
    outcome = r.controller().run()
    assert_held(r, outcome, "job_deadline_exceeded", "quiesced")
    stops = r.events("intent", action="stop_job")
    assert stops
    nonce = stops[0]["instance"].split("/")[1]
    sent = [q for q in r.control.requests if q["service"] == "jobs" and q["action"] == "stop"]
    assert [q["command_id"].rsplit("-", 1)[0] for q in sent] == [f"stop-{nonce}"]
    # The object had already signalled at its own deadline; the stop changes nothing.
    assert r.control.objects[("jobs", sent[0]["name"])].starts[-1]["state"] == "destroyed"
    outcomes = {e["result"]: e.get("sql_outcome") for e in r.events("observation",
                                                                      subject="runtime-migrate")}  # fmt: skip
    assert outcomes.get("stop_confirmed") == "unknown"
    assert "job_succeeded" not in outcomes
    assert rollback(outcome)["actions"][0] == "restore_prior_platform_versions"


@pytest.mark.parametrize("when", ["crash_before", "crash_after"])
def test_a_launch_crash_reconciles_to_exactly_one_run(when):
    r = rig()
    r.control.fault("jobs", "run", when)
    with pytest.raises(SimulatedCrash):
        r.controller().run()
    r.clock.advance(seconds=5)
    outcome = r.recover().run()
    assert outcome.state == "held_paused", outcome
    first = f"job-{r.document['release_id']}-runtime-migrate"
    assert len([q for q in run_bodies(r) if q["name"] == first and q["result"] == 200]) == 1
    assert len(r.effects("run")) == 6


def test_a_lost_run_reply_is_recognized_from_the_object_without_a_second_run():
    r = rig()
    r.control.fault("jobs", "run", "lose_reply")
    outcome = r.controller().run()
    assert outcome.state == "held_paused", outcome
    reconciled = r.events("observation", subject="runtime-migrate", result="launched")
    assert reconciled[0].get("reconciled") is True
    assert len(r.effects("run")) == 6


def test_a_dropped_run_is_resent_identically_under_the_same_command_id():
    r = rig()
    r.control.fault("jobs", "run", "drop")
    outcome = r.controller().run()
    assert outcome.state == "held_paused", outcome
    intents = r.events("intent", action="run_job", subject="runtime-migrate")
    assert len(intents) == 2 and intents[1]["retry_of"] == intents[0]["sequence"]
    assert intents[0]["token"] == intents[1]["token"]
    assert intents[0]["request_sha256"] == intents[1]["request_sha256"]
    assert intents[1]["command_expires_at"] >= intents[0]["command_expires_at"]


@pytest.mark.parametrize("when", ["crash_before", "crash_after"])
def test_a_start_crash_reconciles_without_a_second_start(when):
    r = rig()
    r.control.fault("runtime", "start", when)
    with pytest.raises(SimulatedCrash):
        r.controller().run()
    outcome = r.recover().run()
    assert outcome.state == "held_paused", outcome
    starts = [e for e in r.effects("start") if e[2] == "runtime"]
    assert len(starts) == 1


def test_a_new_session_cannot_resume_or_take_the_lock_without_recovery():
    r = rig()
    r.control.fault("jobs", "run", "crash_after")
    with pytest.raises(SimulatedCrash):
        r.controller().run()
    effects = len(r.trace)
    with pytest.raises(ReleaseHalted) as error:
        r.controller("session-b").run()
    assert error.value.code == "session_conflict"
    assert len(r.trace) == effects


def test_approval_expiry_holds_before_the_next_command():
    r = rig(not_after=iso(START + timedelta(seconds=40)))
    r.control.jobs["runtime-migrate"] = JobBehavior(seconds=60)
    outcome = r.controller().run()
    assert (outcome.state, outcome.reason) == ("hold", "approval_expired")
    assert len(r.effects("run")) == 1


def test_an_invalid_approval_never_creates_a_journal_or_lock():
    r = rig(zone_id="0" * 32)
    with pytest.raises(ReleaseHalted) as error:
        r.controller().run()
    assert error.value.code == "approval_scope_mismatch"
    assert JOURNAL not in r.store.objects and LOCK not in r.store.objects
    assert r.control.requests == [] and r.versions.mutations == []


def test_an_aws_approval_never_authorizes_a_cloudflare_release():
    from release.manifest import load_approval as aws_load_approval
    from tests import release_fakes

    r = rig()
    loaded = load_manifest(encode(r.document))
    approval = aws_load_approval(encode(release_fakes.approval_document(loaded.sha256)))
    controller = ReleaseController(
        loaded,
        approval,
        store=r.store,
        platform=r.platform(),
        clock=r.clock,
        tokens=r.tokens,
        session_id="session-a",
    )
    with pytest.raises(ReleaseHalted) as error:
        controller.run()
    assert error.value.code == "approval_platform_mismatch"


# Services, quiesce and upgrade ------------------------------------------------------


def upgrade(*, legacy: bool = False) -> Rig:
    """A compatible prior release is deployed and its three services run."""
    r = rig(rollback="compatible_release")
    for worker, version in r.document["rollback"]["versions"].items():
        r.versions.set_deployment(worker, (version, 100))
    for service in SERVICE_OBJECTS:
        r.control.start_prior(service)
        r.control.object(service, SERVICE_OBJECTS[service]).legacy = legacy
    return r


def test_an_upgrade_quiesces_the_prior_release_with_nonce_bound_cross_release_stops():
    r = upgrade()
    prior = {
        s: r.control.objects[(s, n)].starts[-1]["start_nonce"] for s, n in SERVICE_OBJECTS.items()
    }
    outcome = r.controller().run()
    assert outcome.state == "held_paused", outcome
    stops = r.events("intent", action="stop_service")
    assert {e["subject"]: e["start_nonce"] for e in stops} == prior
    sent = [q for q in r.control.requests if q["action"] == "stop" and q["service"] != "jobs"]
    assert {q["command_id"].rsplit("-", 1)[0] for q in sent} == {
        f"stop-{n}" for n in prior.values()
    }
    assert len(r.events("observation", result="scaled_to_zero")) == 3
    assert_intent_precedes_every_mutation(r)


def test_an_upgrade_over_code_without_the_authority_protocol_holds_before_any_command():
    r = upgrade(legacy=True)
    outcome = r.controller().run()
    assert_held(r, outcome, "prior_protocol_unsupported", "locked")
    assert not r.events("intent")


def test_an_upgrade_cannot_pretend_to_be_a_first_release():
    r = rig()
    for worker in ("runtime", "api", "worker"):
        r.control.start_foreign(worker)
    outcome = r.controller().run()
    assert_held(r, outcome, "upgrade_requires_compatible_rollback", "locked")


def test_a_compatible_rollback_must_match_what_is_deployed():
    r = upgrade()
    r.versions.set_deployment("api", (r.document["versions"]["api"], 100))
    outcome = r.controller().run()
    assert_held(r, outcome, "prior_release_mismatch", "locked")


@pytest.mark.parametrize("worker", ["jobs", "api"])
def test_an_unaccounted_instance_blocks_quiescence(worker):
    r = rig()
    r.versions.standalone[worker] = [{"durable_object_id": "e" * 64, "state": "running"}]
    outcome = r.controller().run()
    assert_held(r, outcome, "standalone_writer_present", "locked")


@pytest.mark.parametrize("mode", ["endless", "failing"])
def test_an_incomplete_instance_listing_holds(mode):
    r = rig()
    getattr(r.versions, f"{mode}_listing").add("worker")
    outcome = r.controller().run()
    assert_held(r, outcome, "instance_listing_incomplete", "locked")


def test_an_extra_instance_for_a_started_service_never_counts_as_ready():
    r = rig()
    r.versions.standalone["api"] = []
    original = r.control.running_instances

    def running(worker):
        found = original(worker)
        if worker == "api" and found:
            found.append({"durable_object_id": "e" * 64, "state": "running"})
        return found

    r.control.running_instances = running  # ty: ignore[invalid-assignment]
    outcome = r.controller().run()
    assert_held(r, outcome, "instance_count_drift", "grants_verified")


def test_a_service_that_exits_after_starting_holds_without_rollback():
    r = rig()
    original = r.control._service_status

    def status(item, command, body):
        if item.service == "api" and item.running and r.clock.now() > item.starts[-1]["started_at"]:
            r.control.exit_service("api", "Error: exit 3")
        return original(item, command, body)

    r.control._service_status = status  # ty: ignore[invalid-assignment]
    outcome = r.controller().run()
    assert_held(r, outcome, "instance_stopped", "grants_verified")
    assert rollback(outcome)["actions"][0] == "restore_prior_platform_versions"
    assert "set_started_services_desired_zero" in rollback(outcome)["actions"]


def test_an_unhealthy_service_holds_at_its_start_deadline():
    r = rig()
    r.control.health["runtime"] = "unhealthy"
    outcome = r.controller().run()
    assert_held(r, outcome, "instance_unhealthy", "grants_verified")


# Operational evidence and the worker gate ---------------------------------------------


@pytest.mark.parametrize(
    ("configure", "reason"),
    [
        (lambda r: r.receipts.missing_checks.add("api-operational"),
         "operational_evidence_missing"),
        (lambda r: r.receipts.check_changes.update({"api-operational": {"instances": {}}}),
         "operational_receipt_mismatch"),
        (lambda r: r.receipts.check_changes.update(
            {"runtime-protected-readiness": {"status": "failed"}}),
         "operational_receipt_mismatch"),
    ],
)  # fmt: skip
def test_operational_evidence_must_pass_and_bind_the_recorded_instances(configure, reason):
    r = rig()
    configure(r)
    outcome = r.controller().run()
    assert_held(r, outcome, reason, "services_started")


def test_worker_readiness_needs_sixty_seconds_of_receipts_from_the_object():
    r = rig()
    outcome = r.controller().run()
    assert outcome.state == "held_paused"
    [passed] = r.events("observation", subject="worker-readiness", result="operational_passed")
    assert passed["stable_seconds"] >= 60
    assert (
        passed["instance"]
        == r.events("observation", subject="worker", result="service_ready")[0]["instance"]
    )
    pages = [q for q in r.control.requests if q["action"] == "receipts"]
    assert pages and all(q["method"] == "POST" for q in pages)


def test_unready_receipts_hold_at_the_fixed_gate_deadline():
    r = rig()
    r.control.ready_after = 10_000
    outcome = r.controller().run()
    assert_held(r, outcome, "worker_readiness_not_proven", "services_started")
    [unproven] = r.events("observation", subject="worker-readiness", result="readiness_not_proven")
    assert unproven["last_reason"] == "receipt_not_ready"


def test_a_gap_restarts_the_window_and_only_a_full_new_window_passes():
    r = rig()
    r.control.receipt_edit = lambda sequence, receipt: [] if sequence == 3 else [receipt]
    outcome = r.controller().run()
    assert outcome.state == "held_paused", outcome
    [passed] = r.events("observation", subject="worker-readiness", result="operational_passed")
    assert passed["last_reset"] == "receipt_gap" and passed["first_sequence"] > 3


def test_an_incomplete_receipt_store_never_proves_readiness():
    r = rig()
    r.control.receipt_flags["evicted"] = True
    outcome = r.controller().run()
    assert_held(r, outcome, "worker_readiness_not_proven", "services_started")
    [unproven] = r.events("observation", subject="worker-readiness", result="readiness_not_proven")
    assert unproven["last_reason"] == "readiness_logs_incomplete"


def test_a_replaced_worker_during_the_gate_holds_at_once():
    r = rig()
    original = r.control._service_receipts
    calls = {"n": 0}

    def receipts(item, command, body):
        calls["n"] += 1
        if calls["n"] == 3:
            r.control.start_foreign("worker")
        return original(item, command, body)

    r.control._service_receipts = receipts  # ty: ignore[invalid-assignment]
    outcome = r.controller().run()
    assert outcome.state == "hold"
    assert outcome.reason in {"deployment_superseded", "task_replaced"}


# The plan's Cloudflare cases -------------------------------------------------------------


def test_a_version_upload_is_idempotent_and_reconciled_by_its_tag_and_bundle():
    r = rig()
    script = r.document["environment"]["workers"]["api"]
    later = START + timedelta(minutes=2)

    def upload(tag: str, bundle: str) -> str:
        return upload_version(r.versions, script, tag=tag, message=f"bundle {bundle}",
                              bundle_sha256=bundle, not_after=later)  # fmt: skip

    first = upload("t1", "a" * 64)
    assert upload("t1", "a" * 64) == first and len(r.versions.uploaded[script]) == 1
    # The same tag for another bundle is never reused (CF05-R21).
    other = upload("t1", "b" * 64)
    assert other != first and len(r.versions.uploaded[script]) == 2
    r.versions.fault("upload", "lose_reply")
    lost = upload("t2", "c" * 64)
    assert [v.id for v in r.versions.uploaded[script] if v.tag == "t2"] == [lost]
    r.versions.fault("upload", "drop")
    with pytest.raises(PlatformHold) as error:
        upload("t3", "d" * 64)
    assert error.value.code == "version_upload_unconfirmed"
    for _ in range(2):
        r.versions.upload(script, tag="t4", message="bundle " + "e" * 64, bundle_sha256="e" * 64,
                          not_after=later)  # fmt: skip
    with pytest.raises(PlatformHold) as error:
        upload("t4", "e" * 64)
    assert error.value.code == "version_upload_ambiguous"
    with pytest.raises(ValueError):
        upload_version(r.versions, script, tag="t5", message="no digest", bundle_sha256="f" * 64,
                       not_after=later)  # fmt: skip


@pytest.mark.parametrize("fault", ["lose_reply", "drop"])
def test_an_ambiguous_deploy_response_is_reconciled_from_the_deployment(fault):
    r = rig()
    r.versions.fault("deploy", fault)
    outcome = r.controller().run()
    assert outcome.state == "held_paused", outcome
    jobs = r.document["environment"]["workers"]["jobs"]
    deploys = [m for m in r.versions.mutations if m[0] == "deploy" and m[1] == jobs]
    assert len(deploys) == 1
    reconciled = r.events("observation", subject="version/jobs", result="activated")
    assert reconciled and reconciled[0].get("reconciled") is True
    intents = r.events("intent", action="activate_version", subject="version/jobs")
    assert len(intents) == (2 if fault == "drop" else 1)


def test_a_deploy_reply_reporting_drift_holds():
    r = rig()
    r.versions.fault("deploy", "drift_reply")
    outcome = r.controller().run()
    assert_held(r, outcome, "deployment_drift", "quiesced")
    assert not r.effects("run")


def test_someone_elses_deployment_holds_activation_as_drift():
    r = rig()
    r.versions.set_deployment("jobs", ("1" * 8 + "-1111-4111-8111-" + "1" * 12, 100))
    outcome = r.controller().run()
    assert_held(r, outcome, "deployment_drift", "quiesced")
    assert not r.versions.mutations


def test_application_drift_holds_activation_and_launch():
    r = rig()
    import dataclasses

    r.versions.apps["jobs"] = dataclasses.replace(r.versions.apps["jobs"], ssh_enabled=True)
    outcome = r.controller().run()
    assert_held(r, outcome, "application_drift", "quiesced")
    assert not r.effects("run") and not r.versions.mutations


def test_a_stale_sessions_command_is_rejected_by_the_object():
    from release.ports import SessionAuthority, SessionSuperseded

    r = rig()
    r.control.fault("jobs", "run", "crash_after")
    with pytest.raises(SimulatedCrash):
        r.controller().run()
    assert r.recover().run().state == "held_paused"
    stale = r.platform()
    stale.bind(SessionAuthority(r.document["release_id"], "session-a", 1, None))
    job = load_manifest(encode(r.document)).manifest.jobs[0]
    intent = {
        "token": "tok-stale-0000000001",
        "command_expires_at": iso(r.clock.now() + timedelta(seconds=60)),
    }
    with pytest.raises(SessionSuperseded):
        stale.launch(job, stale.launch_request(job, intent["token"]), intent)
    refused = [q for q in r.control.requests if q["command_id"] == intent["token"]]
    assert [q["result"] for q in refused] == [409]


def test_a_delayed_earlier_command_cannot_act_after_the_handover():
    r = rig()
    r.control.fault("jobs", "run", "delay")
    r.control.fault("jobs", "run", "crash_before")
    with pytest.raises(SimulatedCrash):
        r.controller().run()
    assert len(r.control.delayed) == 1
    successor = r.recover()
    delivered = {}

    def first_contact(service, action):
        if service == "jobs" and r.control.delayed and "status" in action:
            delivered["reply"] = r.control.deliver_delayed()

    r.control.before_read = first_contact
    outcome = successor.run()
    assert outcome.state == "held_paused", outcome
    status, body = delivered["reply"]
    assert (status, body["code"]) == (401, "expired")
    first = f"job-{r.document['release_id']}-runtime-migrate"
    assert len([q for q in run_bodies(r) if q["name"] == first and q["result"] == 200]) == 1


def test_a_lost_job_response_and_a_deadline_hold_with_sql_outcome_unknown():
    r = rig()
    r.control.fault("jobs", "run", "lose_reply")
    r.control.jobs["runtime-migrate"] = JobBehavior(hang=True)
    outcome = r.controller().run()
    assert_held(r, outcome, "job_deadline_exceeded", "quiesced")
    observations = r.events("observation", subject="runtime-migrate")
    assert observations[0]["result"] == "launched" and observations[0].get("reconciled")
    assert any(e.get("sql_outcome") == "unknown" for e in observations)
    assert not r.events("observation", result="job_succeeded")
    # The migration may have run: the plan reconciles before any rerun.
    assert "reconcile_partial_migration_before_rerun" in rollback(outcome)["actions"]


def test_without_migration_receipt_producers_a_cloudflare_release_holds_not_started():
    r = rig()
    r.control.wire_migrations = False
    outcome = r.controller().run()
    assert_held(r, outcome, "launch_failed", "quiesced")
    assert r.events("observation", subject="runtime-migrate", result="launch_failed")
    assert rollback(outcome)["kind"] == "empty_hold"
    assert "reconcile_partial_migration_before_rerun" not in rollback(outcome)["actions"]


def test_without_operational_observers_a_cloudflare_release_holds():
    r = rig()
    r.receipts.missing_checks.update({"runtime-protected-readiness", "api-operational"})
    outcome = r.controller().run()
    assert_held(r, outcome, "operational_evidence_missing", "services_started")


# The three AWS traps ------------------------------------------------------------------


@pytest.mark.parametrize("fault", ["lose_reply", "drop"])
def test_trap_1_drift_holds_before_recognizing_or_retrying_a_start(fault):
    """The runtime start is lost (applied, or not); drift appears with it."""
    import dataclasses

    r = rig()
    r.control.fault("runtime", "start", fault)
    sends = []
    original = r.control.send

    def send(request, *, timeout):
        if request.path.endswith("/runtime/runtime-0/start"):
            sends.append(request)
            r.versions.apps["runtime"] = dataclasses.replace(
                r.versions.apps["runtime"], logs_enabled=True
            )
        return original(request, timeout=timeout)

    r.control.send = send  # ty: ignore[invalid-assignment]
    outcome = r.controller().run()
    assert (outcome.state, outcome.reason) == ("hold", "application_drift")
    assert not r.events("observation", subject="runtime", result="service_deployed")
    assert len(sends) == 1, "no resend after drift"
    applied = [e for e in r.effects("start") if e[2] == "runtime"]
    assert len(applied) == (1 if fault == "lose_reply" else 0)


def test_trap_2_a_resend_reply_reporting_another_start_holds():
    r = rig()
    r.control.fault("runtime", "start", "drop", "steal")
    outcome = r.controller().run()
    assert outcome.state == "hold" and outcome.reason == "start_conflict"
    starts = [q for q in r.control.requests if q["action"] == "start" and q["service"] == "runtime"]
    assert len(starts) == 1, "only the resend reached the object; its reply was not discarded"


def test_trap_3_no_resend_after_its_deadline_following_a_slow_fresh_read():
    r = rig()
    r.control.fault("runtime", "start", "drop")
    slow = {"armed": False}
    original = r.versions.deployment

    def deployment(script):
        if slow["armed"]:
            r.clock.advance(seconds=700)
            slow["armed"] = False
        return original(script)

    r.versions.deployment = deployment  # ty: ignore[invalid-assignment]
    original_start = r.control.send

    def send(request, *, timeout):
        if request.path.endswith("/runtime/runtime-0/start"):
            slow["armed"] = True
        return original_start(request, timeout=timeout)

    r.control.send = send  # ty: ignore[invalid-assignment]
    outcome = r.controller().run()
    assert (outcome.state, outcome.reason) == ("hold", "service_update_unconfirmed")
    [intent] = r.events("intent", action="start_service")
    sent = [q for q in r.control.requests if q["action"] == "start"]
    assert all(q["at"] < datetime.fromisoformat(intent["deadline_at"]) for q in sent)


# Expiry and recovery ------------------------------------------------------------------------


def test_an_expired_recovery_waits_out_the_earlier_session_then_stops_its_job_without_launching():
    r = rig(not_after=iso(START + timedelta(seconds=50)))
    r.control.jobs["runtime-migrate"] = JobBehavior(hang=True)
    r.control.fault("jobs", "run", "crash_after")
    with pytest.raises(SimulatedCrash):
        r.controller().run()
    r.clock.advance(seconds=100)
    runs_before = len(r.effects("run"))
    successor = r.recover()
    outcome = successor.run()
    assert (outcome.state, outcome.reason) == ("hold", "approval_expired")
    assert len(r.effects("run")) == runs_before == 1
    expiry = max(
        datetime.fromisoformat(e["command_expires_at"])
        for e in r.events("intent")
        if "command_expires_at" in e and e["action"] == "run_job"
    )
    stops = [q for q in r.control.requests if q["action"] == "stop"]
    assert stops and all(q["at"] >= expiry + timedelta(seconds=30) for q in stops)
    assert r.events("observation", subject="runtime-migrate", sql_outcome="unknown")


def test_read_errors_after_launch_hold_with_the_lock_retained():
    r = rig()
    original = r.control._job_status
    calls = {"n": 0}

    def status(item, command, body):
        calls["n"] += 1
        if calls["n"] > 1:
            return 500, {"error": "internal"}
        return original(item, command, body)

    r.control._job_status = status  # ty: ignore[invalid-assignment]
    outcome = r.controller().run()
    assert_held(r, outcome, "observation_ambiguous", "quiesced")


# Slice review P3s ---------------------------------------------------------------------


def test_an_abandoned_run_is_definitively_not_started():
    """CF05-R18: the object dropped the claim before starting anything."""
    r = rig()
    r.control.abandon.add(("jobs", "run"))
    outcome = r.controller().run()
    assert_held(r, outcome, "launch_failed", "quiesced")
    assert not r.events("observation", subject="runtime-migrate", result="launched")
    assert r.events("observation", subject="runtime-migrate", result="launch_failed")
    assert "reconcile_partial_migration_before_rerun" not in rollback(outcome)["actions"]
    assert not r.effects("run")


def test_an_abandoned_start_is_resent_and_started_once():
    r = rig()
    r.control.abandon.add(("runtime", "start"))
    outcome = r.controller().run()
    assert outcome.state == "held_paused", outcome
    starts = [e for e in r.effects("start") if e[2] == "runtime"]
    assert len(starts) == 1
    intents = r.events("intent", action="start_service", subject="runtime")
    assert len(intents) == 2 and intents[1]["retry_of"] == intents[0]["sequence"]


def test_a_quiesce_stop_that_did_nothing_is_reconciled_not_recorded_done():
    """CF05-R19: the prior start is still starting when its stop arrives."""
    r = upgrade()
    for service in SERVICE_OBJECTS:
        r.control.object(service, SERVICE_OBJECTS[service]).starts[-1]["state"] = "starting"
    r.control.starting_seconds = 20
    outcome = r.controller().run()
    assert outcome.state == "held_paused", outcome
    scaled = r.events("observation", result="scaled_to_zero")
    # The first stop found its start still starting: reconciliation, not the
    # reply, resolved it. By then the other starts ran and stopped at once.
    assert len(scaled) == 3 and scaled[0].get("reconciled") is True
    assert len(r.effects("stop")) == 3
    first = scaled[0]["subject"]
    sent = [q for q in r.control.requests if q["action"] == "stop" and q["service"] == first]
    assert [q["result"] for q in sent][:1] == [200] and len(sent) >= 2


def test_a_receipt_page_without_its_completeness_fields_never_proves_readiness():
    """CF05-R20."""
    r = rig()
    r.control.receipt_flags["evicted"] = True
    original = r.control._service_receipts

    def receipts(item, command, body):
        status, page = original(item, command, body)
        for field in ("evictedAfterCursor", "duplicatesConflicting", "refusedBoots"):
            page.pop(field, None)
        return status, page

    r.control._service_receipts = receipts  # ty: ignore[invalid-assignment]
    outcome = r.controller().run()
    assert_held(r, outcome, "worker_readiness_not_proven", "services_started")
