"""Provider-neutral regression cases for the release controller's platform strategy.

The AWS suites run unchanged against ``EcsPlatform``. These cases pin what the
extraction added, on a non-ECS platform (``tests/neutral_platform_fakes.py``):
the constructor's forms, the core's import boundary, the session authority and
quiet period, activation, the three AWS traps (drift held before recognizing
and before retrying, a drift-reporting retry reply never discarded, the
deadline re-checked after a slow read), drift before activation and launch,
platform holds and refusals, a superseded session, identical retries carrying
request fields, and the rollback plan after activation. Many are adopted from
the CF-05 checkpoint review's probes.
"""

from __future__ import annotations

import ast
import copy
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from release.controller import EcsPlatform, ReleaseController, ReleaseHalted
from release.machine import plan_rollback
from release.manifest import load_approval, load_manifest
from release.ports import AmbiguousResponse, PlatformHold, SessionSuperseded
from release.readiness import GatePolicy, ReadinessGate
from tests.neutral_platform_fakes import Knobs, ProbePlatform, authorization, probe_controller
from tests.release_fakes import START, JobPlan, SimulatedCrash, encode, iso
from tests.test_release_controller import JOURNAL, LOCK, rig

RELEASE = Path(__file__).resolve().parents[1] / "release"
FORBIDDEN_IMPORTS = (
    "release_cloudflare",
    "boto3",
    "botocore",
    "httpx",
    "requests",
    "urllib",
    "http",
    "socket",
    "ssl",
    "cryptography",
    "subprocess",
)


def rollback(outcome) -> dict:
    assert outcome.rollback is not None
    return outcome.rollback


def events(r, kind=None, **match):
    return [
        e
        for e in r.journal()["events"]
        if (kind is None or e["kind"] == kind) and all(e.get(k) == v for k, v in match.items())
    ]


def moment(value: str) -> datetime:
    return datetime.fromisoformat(value)


def hang_first_migration(r):
    r.ecs.plans[r.document["jobs"][0]["task"]["task_definition"]] = JobPlan(hang=True)


# Construction and boundary ------------------------------------------------------


def test_the_constructor_takes_the_aws_ports_or_one_platform_for_this_manifest():
    r = rig()
    loaded, approval = load_manifest(encode(r.document)), load_approval(r.approval_raw)
    common: dict[str, Any] = dict(store=r.store, clock=r.clock, tokens=r.tokens,
                                  session_id="session-a")  # fmt: skip
    aws: dict[str, Any] = dict(ecs=r.ecs, evidence=r.evidence, logs=r.logs)
    assert isinstance(ReleaseController(loaded, approval, **common, **aws).platform, EcsPlatform)
    platform = ProbePlatform(loaded, r.ecs, r.evidence, r.logs, clock=r.clock)
    assert ReleaseController(loaded, approval, **common, platform=platform).platform is platform
    for ports in ({}, {"ecs": r.ecs}, {"ecs": r.ecs, "evidence": r.evidence}):
        with pytest.raises(TypeError):
            ReleaseController(loaded, approval, **common, **ports)
    with pytest.raises(TypeError):
        ReleaseController(loaded, approval, **common, **aws, platform=platform)
    with pytest.raises(TypeError):
        ReleaseController(loaded, approval, **common, logs=r.logs, platform=platform)
    # As before the extraction, an explicit None port is accepted at construction.
    unset: dict[str, Any] = {"ecs": None, "evidence": r.evidence, "logs": r.logs}
    ReleaseController(loaded, approval, **common, **unset)


def test_a_platform_built_from_another_manifest_is_refused():
    r = rig()
    other = copy.deepcopy(r.document)
    for spec in other["services"].values():
        spec["task_definition"] = spec["task_definition"].rsplit(":", 1)[0] + ":8"
    platform = ProbePlatform(load_manifest(encode(other)), r.ecs, r.evidence, r.logs, clock=r.clock)
    with pytest.raises(ValueError):
        ReleaseController(
            load_manifest(encode(r.document)),
            load_approval(r.approval_raw),
            store=r.store,
            clock=r.clock,
            tokens=r.tokens,
            session_id="session-a",
            platform=platform,
        )
    assert r.ecs.mutations == [] and JOURNAL not in r.store.objects


def test_the_release_core_imports_no_cloud_sdk_network_or_cloudflare_module():
    found = []
    for path in sorted(RELEASE.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(), filename=str(path))):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            for name in names:
                if name.split(".")[0] in FORBIDDEN_IMPORTS:
                    found.append((path.name, name))
    assert found == []


def test_the_readiness_gate_takes_exactly_one_identity():
    with pytest.raises(TypeError):
        ReadinessGate(GatePolicy(), release_id="r", epoch_start=START)
    with pytest.raises(TypeError):
        ReadinessGate(GatePolicy(), release_id="r", epoch_start=START, task_arn="a", run="b")
    assert ReadinessGate(GatePolicy(), release_id="r", epoch_start=START, run="b").run == "b"


def test_a_rollback_plan_depends_on_the_rollback_kind_and_names_activated_code():
    r = rig(rollback="compatible_release")
    manifest = load_manifest(encode(r.document)).manifest
    outcomes = {job.id: "succeeded" for job in manifest.jobs}
    expected = plan_rollback(manifest, outcomes, services_touched=True)
    duck: Any = SimpleNamespace(
        jobs=manifest.jobs, rollback=SimpleNamespace(**dict(manifest.rollback))
    )
    assert plan_rollback(duck, outcomes, services_touched=True) == expected
    empty: Any = SimpleNamespace(jobs=manifest.jobs, rollback=SimpleNamespace(kind="empty_hold"))
    assert plan_rollback(empty, outcomes, services_touched=True)["kind"] == "empty_hold"
    moved = plan_rollback(manifest, outcomes, services_touched=True, activated=("version/jobs",))
    assert moved["actions"] == ["restore_prior_platform_versions", *expected["actions"]]
    assert moved["activated"] == ["version/jobs"]
    assert "activated" not in expected


# A full release on non-ECS names -------------------------------------------------


def test_a_full_release_on_its_own_names_puts_command_expiry_on_every_command_intent():
    r = rig()
    controller, platform = probe_controller(r)
    outcome = controller.run()
    assert outcome.state == "held_paused", outcome
    intents = events(r, "intent")
    assert {e["action"] for e in intents} == {"run_job", "start_service", "release_lock"}
    for event in intents:
        assert ("command_expires_at" in event) == (event["action"] != "release_lock")
    for name in ("task_arn", "task_arns", "deployment_id", "prior_deployments", "cluster"):
        assert not any(name in e for e in r.journal()["events"]), name
    assert platform.command_field_calls == len(intents) - 1
    assert [(a.fence, a.quiet_until) for a in platform.bound] == [(1, None)]


def test_a_deadline_stop_intent_carries_its_command_expiry():
    r = rig()
    hang_first_migration(r)
    controller, _ = probe_controller(r)
    controller.run()
    stops = events(r, "intent", action="stop_job")
    assert stops and all("command_expires_at" in e for e in stops)


# Session authority and the quiet period --------------------------------------------


def crash_after_start_send(r, session="session-a"):
    r.ecs.crash[("update_service", "after")] = 1
    controller, platform = probe_controller(r, session)
    with pytest.raises(SimulatedCrash):
        controller.run()
    return platform


def test_a_recovered_session_sends_nothing_before_quiet_until():
    r = rig()
    crash_after_start_send(r)
    successor, platform = probe_controller(r, "session-b")
    successor.recover(authorization(r, "session-a"))
    outcome = successor.run()
    authority = platform.bound[-1]
    boundary = events(r, "session", action="recovered")[-1]["sequence"]
    before = [
        moment(e["command_expires_at"])
        for e in events(r, "intent")
        if e.get("command_expires_at") and e["sequence"] < boundary
    ]
    assert authority.fence == 2
    assert authority.quiet_until == max(before) + timedelta(seconds=30)
    assert platform.timeline and all(s.at >= authority.quiet_until for s in platform.timeline)
    assert outcome.state == "held_paused", outcome


def test_each_recovery_counts_once_and_the_quiet_period_covers_every_earlier_session():
    r = rig()
    crash_after_start_send(r)
    b, bp = probe_controller(r, "session-b")
    b.recover(authorization(r, "session-a"))
    b.recover(authorization(r, "session-a"))
    assert len(events(r, "session", action="recovered")) == 1
    r.ecs.crash[("update_service", "after")] = 1
    with pytest.raises(SimulatedCrash):
        b.run()
    assert bp.bound[-1].fence == 2
    c, cp = probe_controller(r, "session-c")
    c.recover(authorization(r, "session-b"))
    c.run()
    assert cp.bound[-1].fence == 3
    b_expiries = [moment(s.intent["command_expires_at"]) for s in bp.timeline]
    assert b_expiries and cp.bound[-1].quiet_until >= max(b_expiries) + timedelta(seconds=30)
    assert all(s.at >= cp.bound[-1].quiet_until for s in cp.timeline)


def test_a_restarted_session_gets_no_quiet_period_for_its_own_commands():
    """Recorded assumption: its own commands share its session and fence, and the
    deterministic command ids keep an identical duplicate harmless."""
    r = rig()
    crash_after_start_send(r)
    again, platform = probe_controller(r, "session-a")
    again.run()
    assert [(a.fence, a.quiet_until) for a in platform.bound] == [(1, None)]


def launched_then_lost(r):
    hang_first_migration(r)
    r.ecs.crash[("run_task", "after")] = 1
    controller, _ = probe_controller(r, "session-a")
    with pytest.raises(SimulatedCrash):
        controller.run()


@pytest.mark.parametrize("approval_seconds, advance", [(50, 100), (110, 100)])
def test_expiry_cleanup_waits_for_the_quiet_period(approval_seconds, advance):
    """Expired before the recovered run, or during its quiet wait."""
    r = rig(not_after=iso(START + timedelta(seconds=approval_seconds)))
    launched_then_lost(r)
    r.clock.advance(seconds=advance)
    successor, platform = probe_controller(r, "session-b")
    successor.recover(authorization(r, "session-a"))
    outcome = successor.run()
    quiet = platform.bound[-1].quiet_until
    assert (outcome.state, outcome.reason) == ("hold", "approval_expired")
    assert [s for s in platform.timeline if s.at < quiet] == []
    hold = events(r, "transition", to="hold")[-1]
    assert moment(hold["at"]) >= quiet - timedelta(seconds=1)


def test_a_bind_failure_halts_without_journaling():
    r = rig()
    controller, _ = probe_controller(r, knobs=Knobs(bind_raises=RuntimeError("no key")))
    with pytest.raises(ReleaseHalted) as error:
        controller.run()
    assert error.value.code == "authority_unavailable"
    assert [e.get("to") for e in events(r, "transition")] == ["prepared"]


@pytest.mark.parametrize("value", ["not-a-time", iso(START + timedelta(days=1))])
def test_an_unusable_earlier_command_expiry_halts_the_recovered_session(value):
    r = rig()
    r.ecs.crash[("run_task", "after")] = 1
    controller, _ = probe_controller(r, knobs=Knobs(command_expires_override=value))
    with pytest.raises(SimulatedCrash):
        controller.run()
    successor, platform = probe_controller(r, "session-b")
    successor.recover(authorization(r, "session-a"))
    with pytest.raises(ReleaseHalted) as error:
        successor.run()
    assert error.value.code == "journal_integrity"
    assert platform.timeline == []


# The three AWS traps ------------------------------------------------------------------


@pytest.mark.parametrize("lost", ["after", "before"])
def test_trap_1_drift_holds_before_recognizing_or_retrying_a_start(lost):
    r = rig()
    controller, platform = probe_controller(
        r, knobs=Knobs(drift_code="deployment_drift", lose_first_deploy=lost)
    )
    outcome = controller.run()
    assert (outcome.state, outcome.reason) == ("hold", "deployment_drift")
    assert not events(r, "observation", subject="runtime", result="service_deployed")
    assert len([s for s in platform.timeline if s.action == "start_service"]) == 1


def test_trap_2_a_resend_reply_reporting_drift_holds():
    r = rig()
    controller, platform = probe_controller(
        r, knobs=Knobs(lose_first_deploy="before", response_drift_code="service_settings_drift")
    )
    outcome = controller.run()
    assert (outcome.state, outcome.reason) == ("hold", "service_settings_drift")
    resends = [
        s for s in platform.timeline if s.op == "send_update" and s.action == "start_service"
    ]
    assert len(resends) == 1


def test_trap_3_no_start_resend_after_its_deadline_following_a_slow_fresh_read():
    r = rig()
    controller, platform = probe_controller(
        r, knobs=Knobs(lose_first_deploy="before", drift_slow_seconds=700)
    )
    outcome = controller.run()
    assert (outcome.state, outcome.reason) == ("hold", "service_update_unconfirmed")
    late = [
        s
        for s in platform.timeline
        if s.action == "start_service" and s.at >= moment(s.intent["deadline_at"])
    ]
    assert late == []


def test_trap_3_no_activation_resend_after_its_deadline_following_a_slow_fresh_read():
    r = rig()
    knobs = Knobs(
        activations={"jobs": ("version/jobs",)},
        # 0: initial; 1-3: visibility polls; 4: the fresh read before a resend (slow)
        activation_states=["prior"] * 6,
        activation_slow_seconds={4: 700},
        activate_replies=[AmbiguousResponse("deploy reply lost"), "active"],
    )
    controller, platform = probe_controller(r, knobs=knobs)
    outcome = controller.run()
    assert (outcome.state, outcome.reason) == ("hold", "activation_unconfirmed")
    activations = [s for s in platform.timeline if s.op == "activate"]
    assert len(activations) == 1
    assert all(s.at < moment(s.intent["deadline_at"]) for s in activations)


# Drift before activation and launch -------------------------------------------------


def test_activation_drift_holds_before_recognition_and_before_any_job():
    r = rig()
    knobs = Knobs(
        activations={"jobs": ("version/jobs",)},
        activation_states=["active"],
        activation_drift_code="application_drift",
    )
    controller, platform = probe_controller(r, knobs=knobs)
    outcome = controller.run()
    assert (outcome.state, outcome.reason, outcome.last_proven) == (
        "hold",
        "application_drift",
        "quiesced",
    )
    assert not events(r, "observation", result="activated")
    assert not [s for s in platform.timeline if s.op == "launch"]


def test_activation_drift_holds_before_the_first_activation_send_and_every_resend():
    r = rig()
    knobs = Knobs(
        activations={"jobs": ("version/jobs",)},
        activation_states=["prior"],
        activation_drift_code="application_drift",
    )
    controller, platform = probe_controller(r, knobs=knobs)
    outcome = controller.run()
    assert (outcome.state, outcome.reason) == ("hold", "application_drift")
    assert not [s for s in platform.timeline if s.op == "activate"]


def test_launch_drift_holds_before_the_first_launch_and_before_an_identical_retry():
    r = rig()
    controller, platform = probe_controller(r, knobs=Knobs(launch_drift_code="application_drift"))
    outcome = controller.run()
    assert (outcome.state, outcome.reason, outcome.last_proven) == (
        "hold",
        "application_drift",
        "quiesced",
    )
    assert not [s for s in platform.timeline if s.op == "launch"]
    assert not events(r, "intent", action="run_job")
    # A retry after a lost launch reply consults it again.
    r = rig()
    r.ecs.crash[("run_task", "before")] = 1
    controller, _ = probe_controller(r)
    with pytest.raises(SimulatedCrash):
        controller.run()
    successor, platform = probe_controller(
        r, "session-b", knobs=Knobs(launch_drift_code="application_drift")
    )
    successor.recover(authorization(r, "session-a"))
    outcome = successor.run()
    assert outcome.state == "hold"
    assert [s for s in platform.timeline if s.op == "launch"] == []


# Activation stages, replies and recovery ---------------------------------------------


def test_job_code_is_activated_before_the_first_job_and_service_code_before_the_first_start():
    r = rig()
    knobs = Knobs(
        activations={"jobs": ("version/jobs",), "services": ("version/api", "version/edge")},
        activation_states=["prior", "active"] * 3,
        activate_replies=["active"],
    )
    controller, platform = probe_controller(r, knobs=knobs)
    outcome = controller.run()
    assert outcome.state == "held_paused", outcome
    order = [(s.op, s.subject) for s in platform.timeline]
    first_launch = next(i for i, (op, _) in enumerate(order) if op == "launch")
    first_start = next(i for i, (op, _) in enumerate(order) if op == "deploy")
    assert order.index(("activate", "version/jobs")) < first_launch
    assert first_launch < order.index(("activate", "version/api")) < first_start
    assert len(events(r, "observation", result="activated")) == 3


@pytest.mark.parametrize("reply", [None, "", 7])
def test_an_unusable_activation_reply_holds_with_a_named_reason(reply):
    r = rig()
    controller, _ = probe_controller(
        r,
        knobs=Knobs(
            activations={"jobs": ("version/jobs",)},
            activation_states=["prior"],
            activate_replies=[reply],
        ),
    )
    outcome = controller.run()
    assert (outcome.state, outcome.reason) == ("hold", "activation_reply_invalid")


def test_an_outstanding_activation_is_reconciled_after_recovery_on_its_own_name():
    r = rig()
    knobs = Knobs(
        activations={"jobs": ("version/jobs",)},
        activation_states=["prior"],
        activate_replies=[SimulatedCrash("lost after sending the deploy")],
    )
    controller, _ = probe_controller(r, knobs=knobs)
    with pytest.raises(SimulatedCrash):
        controller.run()
    assert events(r, "intent", action="activate_version")
    successor, platform = probe_controller(
        r,
        "session-b",
        knobs=Knobs(activations={"jobs": ("version/jobs",)}, activation_states=["active"]),
    )
    successor.recover(authorization(r, "session-a"))
    outcome = successor.run()
    assert outcome.state == "held_paused", outcome
    reconciled = events(r, "observation", result="activated", resolves="activate_version")
    assert reconciled and reconciled[0].get("reconciled") is True
    assert not [s for s in platform.timeline if s.op == "activate"]


def test_the_guard_is_checked_before_an_activation_send_after_a_slow_read():
    r = rig(not_after=iso(START + timedelta(seconds=50)))
    knobs = Knobs(
        activations={"jobs": ("version/jobs",)},
        activation_states=["prior"],
        activation_slow_seconds={0: 100},
    )
    controller, platform = probe_controller(r, knobs=knobs)
    outcome = controller.run()
    assert (outcome.state, outcome.reason) == ("hold", "approval_expired")
    assert not [s for s in platform.timeline if s.op == "activate"]


def test_a_hold_after_activation_plans_to_restore_the_prior_platform_versions():
    r = rig()
    r.ecs.plans[r.document["jobs"][0]["task"]["task_definition"]] = JobPlan(exits={"migration": 3})
    knobs = Knobs(activations={"jobs": ("version/jobs",)}, activation_states=["prior", "active"])
    controller, _ = probe_controller(r, knobs=knobs)
    outcome = controller.run()
    assert (outcome.state, outcome.reason) == ("hold", "job_container_failed")
    assert rollback(outcome)["actions"][0] == "restore_prior_platform_versions"
    assert rollback(outcome)["activated"] == ["version/jobs"]


# Refusals, holds and a superseded session ---------------------------------------------


def test_a_refused_deadline_stop_still_records_sql_outcome_unknown():
    r = rig()
    hang_first_migration(r)
    controller, _ = probe_controller(r, knobs=Knobs(stop_raises=PlatformHold("command_refused")))
    outcome = controller.run()
    assert (outcome.state, outcome.reason) == ("hold", "job_deadline_exceeded")
    refused = events(r, "observation", subject="runtime-migrate", result="stop_refused")
    assert refused and refused[0]["sql_outcome"] == "unknown"
    assert refused[0]["reason"] == "command_refused"
    assert events(r, "observation", subject="runtime-migrate", result="stop_unconfirmed")


def test_expiry_cleanup_records_a_platform_hold_as_unconfirmed():
    r = rig(not_after=iso(START + timedelta(seconds=50)))
    hang_first_migration(r)
    controller, _ = probe_controller(r, knobs=Knobs(stop_raises=PlatformHold("command_refused")))
    outcome = controller.run()
    assert (outcome.state, outcome.reason) == ("hold", "approval_expired")
    assert events(r, "observation", subject="runtime-migrate", sql_outcome="unknown")


@pytest.mark.parametrize("where", ["services", "cleanup", "deadline_stop", "receipts"])
def test_a_superseded_session_halts_without_writing_again(where):
    r = rig(not_after=iso(START + timedelta(seconds=50))) if where == "cleanup" else rig()
    knobs = Knobs()
    if where in ("cleanup", "deadline_stop"):
        hang_first_migration(r)
        knobs.stop_raises = SessionSuperseded()

    class Platform(ProbePlatform):
        def services(self):
            if where == "services":
                raise SessionSuperseded()
            return super().services()

        def worker_reader(self, run, generation):
            if where != "receipts":
                return super().worker_reader(run, generation)

            class Reader:
                def read(self, **_):
                    raise SessionSuperseded()

            return Reader()

    loaded = load_manifest(encode(r.document))
    platform = Platform(loaded, r.ecs, r.evidence, r.logs, clock=r.clock, knobs=knobs)
    controller, _ = probe_controller(r, platform=platform)
    with pytest.raises(ReleaseHalted) as error:
        controller.run()
    assert error.value.code == "session_superseded"
    assert not events(r, "transition", to="hold")
    assert LOCK in r.store.objects


def test_a_platform_hold_holds_with_its_code_and_keeps_the_lock():
    class Platform(ProbePlatform):
        def writers_present(self):
            raise PlatformHold("instance_listing_incomplete")

    r = rig()
    loaded = load_manifest(encode(r.document))
    controller, _ = probe_controller(
        r, platform=Platform(loaded, r.ecs, r.evidence, r.logs, clock=r.clock)
    )
    outcome = controller.run()
    assert (outcome.state, outcome.reason) == ("hold", "instance_listing_incomplete")
    assert LOCK in r.store.objects


# Identical retries and outstanding dispatch -----------------------------------------------


class NonceBound(ProbePlatform):
    """Quiesce stops bound to the observed generation, as on Cloudflare."""

    request_fields = ("start_nonce",)

    def __init__(self, *args, lose_first_scale=True, crash_on_retry=False, **kwargs):
        super().__init__(*args, **kwargs)
        self.lose_first_scale = lose_first_scale
        self.crash_on_retry = crash_on_retry

    def scale_fields(self, key, view):
        return {"start_nonce": self.prior_generations(key, view)[-1]}

    def scale_request(self, key, fields):
        return {**super().scale_request(key, fields), "boundNonce": fields["start_nonce"]}

    def send_update(self, request, intent):
        self._record("send_update", intent)
        stop = intent.get("action") == "stop_service"
        if stop and "retry_of" in intent and self.crash_on_retry:
            self.crash_on_retry = False
            raise SimulatedCrash("lost after journaling the identical retry")
        if stop and self.lose_first_scale:
            self.lose_first_scale = False
            raise AmbiguousResponse("stop lost before applying")
        return self.ecs.update_service({k: v for k, v in request.items() if k != "boundNonce"})


def nonce_platform(r, cls=NonceBound, **kwargs):
    return cls(load_manifest(encode(r.document)), r.ecs, r.evidence, r.logs, clock=r.clock,
               **kwargs)  # fmt: skip


def test_an_identical_retry_carries_its_request_fields_and_recovers():
    r = rig(rollback="compatible_release", running_prior=True)
    controller, _ = probe_controller(r, platform=nonce_platform(r, crash_on_retry=True))
    with pytest.raises(SimulatedCrash):
        controller.run()
    retries = [e for e in events(r, "intent", action="stop_service") if "retry_of" in e]
    assert retries and all("start_nonce" in e for e in retries)
    successor, _ = probe_controller(
        r, "session-b", platform=nonce_platform(r, lose_first_scale=False)
    )
    successor.recover(authorization(r, "session-a"))
    assert successor.run().state == "held_paused"


def test_a_request_that_cannot_be_rebuilt_from_its_intent_halts_as_journal_integrity():
    class Misdeclared(NonceBound):
        request_fields = ()

    r = rig(rollback="compatible_release", running_prior=True)
    controller, _ = probe_controller(
        r, platform=nonce_platform(r, Misdeclared, crash_on_retry=True)
    )
    with pytest.raises(SimulatedCrash):
        controller.run()
    successor, _ = probe_controller(
        r, "session-b", platform=nonce_platform(r, Misdeclared, lose_first_scale=False)
    )
    successor.recover(authorization(r, "session-a"))
    with pytest.raises(ReleaseHalted) as error:
        successor.run()
    assert error.value.code == "journal_integrity"


def test_an_outstanding_stop_is_dispatched_on_its_own_name_after_the_quiet_period():
    r = rig()
    hang_first_migration(r)
    controller, _ = probe_controller(
        r, knobs=Knobs(stop_raises=SimulatedCrash("lost after journaling the deadline stop"))
    )
    with pytest.raises(SimulatedCrash):
        controller.run()
    successor, platform = probe_controller(r, "session-b")
    successor.recover(authorization(r, "session-a"))
    outcome = successor.run()
    assert (outcome.state, outcome.reason) == ("hold", "job_deadline_exceeded")
    stops = [s for s in platform.timeline if s.op == "send_stop"]
    assert stops and stops[0].intent["instance"]
    assert all(s.at >= platform.bound[-1].quiet_until for s in platform.timeline)


def test_trap_3_no_launch_retry_after_its_deadline_following_a_slow_drift_read():
    """CF05-R14: the fresh launch-drift read before an identical retry is slow."""
    r = rig()
    knobs = Knobs(lose_first_launch=True, launch_drift_slow_after=1, launch_drift_slow_seconds=1000)
    controller, platform = probe_controller(r, knobs=knobs)
    outcome = controller.run()
    assert (outcome.state, outcome.reason) == ("hold", "launch_outcome_unknown")
    launches = [s for s in platform.timeline if s.op == "launch"]
    assert len(launches) == 1
    assert all(s.at < moment(s.intent["deadline_at"]) for s in launches)
    assert len(events(r, "intent", action="run_job")) == 1


@pytest.mark.parametrize("when", ["before", "after"])
def test_a_successor_finishes_a_held_paused_release_only_after_the_quiet_period(when):
    """CF05-R15: finalization by a recovered session is a decision like any other."""
    r = rig()
    original = r.store.delete

    def crash_delete(key, *, if_match):
        if when == "after":
            original(key, if_match=if_match)
        raise SimulatedCrash("lock release")

    r.store.delete = crash_delete  # ty: ignore[invalid-assignment]
    controller, _ = probe_controller(r)
    with pytest.raises(SimulatedCrash):
        controller.run()
    r.store.delete = original  # ty: ignore[invalid-assignment]
    successor, platform = probe_controller(r, "session-b")
    successor.recover(authorization(r, "session-a"))
    assert successor.run().state == "held_paused"
    quiet = platform.bound[-1].quiet_until
    assert quiet is not None
    [released] = events(r, "observation", subject="environment", result="lock_released")
    assert moment(released["at"]) >= quiet - timedelta(seconds=1)
    assert LOCK not in r.store.objects
