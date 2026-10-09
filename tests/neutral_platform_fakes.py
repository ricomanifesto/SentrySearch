"""A non-ECS platform over the ECS fakes, for provider-neutral controller tests.

``ProbePlatform`` keeps the deterministic ECS/S3 fakes as its source of
services, runs and receipts, but writes its own journal names and controls
every hook a non-ECS platform has: ``command_fields``, ``bind``, drift on
services, activation and launch, reply drift, activation, and send-time
behaviour. Every send is recorded on a timeline with the fake clock and the
intent it carries. Adapted from the CF-05 checkpoint review's probe support.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from release.controller import EcsPlatform, RecoveryAuthorization, ReleaseController
from release.manifest import load_approval, load_manifest
from release.ports import AmbiguousResponse, JournalNames
from tests.release_fakes import encode, iso, sha
from tests.test_release_controller import Rig

NAMES = JournalNames(
    launch="run_job",
    scale="stop_service",
    deploy="start_service",
    stop="stop_job",
    activate="activate_version",
    run="instance",
    runs="instances",
    generation="start_nonce",
    prior="prior_starts",
)
COMMAND_LIFETIME = timedelta(seconds=120)


@dataclass
class Send:
    at: Any
    op: str
    action: str | None
    subject: str | None
    intent: dict


@dataclass
class Knobs:
    # Service drift: the code is returned once armed; a fresh read can be slow.
    drift_code: str | None = None
    drift_armed: bool = False
    drift_slow_seconds: float = 0.0
    drift_calls: list = field(default_factory=list)
    # The first forward start is lost before or after it applied.
    lose_first_deploy: str | None = None
    response_drift_code: str | None = None
    # Activation: subjects per stage, scripted states, slow reads and replies.
    activations: dict = field(default_factory=dict)
    activation_states: list = field(default_factory=lambda: ["active"])
    activation_slow_seconds: dict = field(default_factory=dict)
    activate_replies: list = field(default_factory=lambda: ["active"])
    activation_drift_code: str | None = None
    launch_drift_code: str | None = None
    launch_drift_slow_after: int | None = None  # calls before reads turn slow
    launch_drift_slow_seconds: float = 0.0
    lose_first_launch: bool = False
    drift_hook_calls: list = field(default_factory=list)
    # Stops, binding, command expiry.
    stop_raises: BaseException | None = None
    bind_raises: BaseException | None = None
    command_expires_override: str | None = None


class ProbePlatform(EcsPlatform):
    names = NAMES
    count_drift = "instance_count_drift"
    request_fields: tuple[str, ...] = ()

    def __init__(self, loaded, ecs, evidence, logs, *, clock, knobs: Knobs | None = None):
        super().__init__(loaded, ecs, evidence, logs)
        self.clock = clock
        self.knobs = knobs or Knobs()
        self.timeline: list[Send] = []
        self.bound: list = []
        self.command_field_calls = 0
        self._activation_calls = 0

    # Authority ---------------------------------------------------------------

    def bind(self, authority):
        self.bound.append(authority)
        if self.knobs.bind_raises is not None:
            raise self.knobs.bind_raises

    def command_fields(self):
        self.command_field_calls += 1
        if self.knobs.command_expires_override is not None:
            return {"command_expires_at": self.knobs.command_expires_override}
        return {"command_expires_at": iso(self.clock.now() + COMMAND_LIFETIME)}

    def _record(self, op, intent):
        self.timeline.append(
            Send(self.clock.now(), op, intent.get("action"), intent.get("subject"), dict(intent))
        )

    # Sends -------------------------------------------------------------------

    def send_update(self, request, intent):
        self._record("send_update", intent)
        return super().send_update(request, intent)

    def deploy(self, key, request, intent, prior):
        self._record("deploy", intent)
        mode = self.knobs.lose_first_deploy
        if mode is not None:
            self.knobs.lose_first_deploy = None
            if mode == "after":
                self.ecs.update_service(request)
            self.knobs.drift_armed = True
            raise AmbiguousResponse(f"first forward send lost {mode} applying")
        self.knobs.drift_armed = True
        return super().deploy(key, request, intent, prior)

    def launch(self, job, request, intent):
        self._record("launch", intent)
        if self.knobs.lose_first_launch:
            self.knobs.lose_first_launch = False
            raise AmbiguousResponse("launch request lost before applying")
        return super().launch(job, request, intent)

    def send_stop(self, request, intent):
        self._record("send_stop", intent)
        if self.knobs.stop_raises is not None:
            raise self.knobs.stop_raises
        return super().send_stop(request, intent)

    # Drift hooks ---------------------------------------------------------------

    def drift(self, views):
        self.knobs.drift_calls.append((self.clock.now(), views is None))
        if views is None and self.knobs.drift_slow_seconds:
            self.clock.advance(seconds=self.knobs.drift_slow_seconds)
        return self.knobs.drift_code if self.knobs.drift_armed else None

    def response_drift(self, key, response):
        return self.knobs.response_drift_code

    def activation_drift(self, subject):
        self.knobs.drift_hook_calls.append(("activation", subject, self.clock.now()))
        return self.knobs.activation_drift_code

    def launch_drift(self, job):
        calls = [c for c in self.knobs.drift_hook_calls if c[0] == "launch"]
        slow_after = self.knobs.launch_drift_slow_after
        if slow_after is not None and len(calls) >= slow_after:
            self.clock.advance(seconds=self.knobs.launch_drift_slow_seconds)
        self.knobs.drift_hook_calls.append(("launch", job.id, self.clock.now()))
        return self.knobs.launch_drift_code

    # Activation ------------------------------------------------------------------

    def activations(self, stage):
        return tuple(self.knobs.activations.get(stage, ()))

    def activation_request(self, subject):
        return {"subject": subject, "version": "v-next", "percentage": 100}

    def activation_state(self, subject):
        index = self._activation_calls
        self._activation_calls += 1
        slow = self.knobs.activation_slow_seconds.get(index)
        if slow:
            self.clock.advance(seconds=slow)
        states = self.knobs.activation_states
        return states.pop(0) if len(states) > 1 else states[0]

    def activate(self, subject, request, intent):
        self._record("activate", intent)
        replies = self.knobs.activate_replies
        reply = replies.pop(0) if len(replies) > 1 else replies[0]
        if isinstance(reply, BaseException):
            raise reply
        return reply


def probe_controller(
    r: Rig,
    session: str = "session-a",
    *,
    knobs: Knobs | None = None,
    platform: ProbePlatform | None = None,
) -> tuple[ReleaseController, ProbePlatform]:
    loaded = load_manifest(encode(r.document))
    platform = platform or ProbePlatform(
        loaded, r.ecs, r.evidence, r.logs, clock=r.clock, knobs=knobs
    )
    controller = ReleaseController(
        loaded,
        load_approval(r.approval_raw),
        store=r.store,
        clock=r.clock,
        tokens=r.tokens,
        session_id=session,
        platform=platform,
    )
    return controller, platform


def authorization(r: Rig, prior: str) -> RecoveryAuthorization:
    lock = r.store.objects.get("locks/staging.json")
    return RecoveryAuthorization(
        prior_session_id=prior,
        lock_etag=lock[1] if lock else "",
        fence_evidence_sha256=sha(f"{prior} process confirmed terminated"),
        authorized_by="fixture-operator",
    )
