"""Attended release controller: journal intent, act, then prove the outcome.

The controller runs one approved manifest to ``held_paused`` or stops in
``hold`` with a bounded reason. It never enables admission, retries blindly,
steals a lock or treats a partial observation as success. Every platform
operation goes through a ``ReleasePlatform``; ``EcsPlatform`` below is the ECS
strategy over the AWS ports. This module contains no SDK, credential or
network code.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import re
from typing import Any

from release.journal import Journal, ObjectStore, PreconditionFailed, encode, journal_key, lock_key
from release.machine import (
    TERMINAL_STATES,
    State,
    check_transition,
    evaluate_job,
    evaluate_service,
    plan_rollback,
    token_expires_at,
)
from release.manifest import (
    Job,
    LoadedApproval,
    LoadedManifest,
    Manifest,
    ReleaseRejected,
    canonical_sha256,
    verify_approval,
)
from release.ports import (
    AmbiguousResponse,
    Clock,
    Deploy,
    EcsPort,
    EvidencePort,
    JournalNames,
    Launch,
    LogPort,
    PlatformHold,
    ReleasePlatform,
    ServiceView,
    SessionAuthority,
    SessionSuperseded,
)
from release.readiness import (
    WORKER_READINESS_CHECK,
    GatePolicy,
    LogRead,
    ReadinessGate,
    read_stream,
    worker_stream,
)

SERVICE_KEYS = ("runtime", "api", "worker")
TOKEN = re.compile(r"[A-Za-z0-9_-]{16,64}")
SHA256 = re.compile(r"[0-9a-f]{64}")
IDENTICAL_RETRIES = 3
VISIBILITY_POLLS = 3
STOP_CONFIRMATION_MARGIN = timedelta(seconds=30)
READINESS_POLICY = GatePolicy()
# A recovered session sends nothing until every command an earlier session
# journaled has expired at every platform clock within this allowance.
MAX_CLOCK_SKEW = timedelta(seconds=30)
ACTIVE = "active"
PRIOR = "prior"


def _iso(moment: datetime) -> str:
    # Whole seconds, rounded down: recorded deadlines never extend a budget.
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value)


class ReleaseHalted(Exception):
    """The controller cannot act safely, or cannot even journal; nothing further ran."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class _Hold(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class RecoveryAuthorization:
    """Recorded break-glass decision that the prior session is fenced and cannot resume."""

    prior_session_id: str
    lock_etag: str
    fence_evidence_sha256: str
    authorized_by: str


@dataclass(frozen=True)
class Outcome:
    state: str
    reason: str | None
    last_proven: str
    admission: str = "paused"
    rollback: dict[str, Any] | None = None


class ReleaseController:
    def __init__(
        self,
        loaded: LoadedManifest,
        approval: LoadedApproval,
        *,
        store: ObjectStore,
        clock: Clock,
        tokens: Callable[[], str],
        session_id: str,
        ecs: EcsPort | None = None,
        evidence: EvidencePort | None = None,
        logs: LogPort | None = None,
        platform: ReleasePlatform | None = None,
    ) -> None:
        aws = (ecs, evidence, logs)
        if platform is None:
            if any(port is None for port in aws):
                raise TypeError("pass ecs, evidence and logs, or a platform")
            platform = EcsPlatform(loaded.manifest, ecs, evidence, logs)  # type: ignore[arg-type]
        elif any(port is not None for port in aws):
            raise TypeError("pass ecs, evidence and logs, or a platform, not both")
        self.loaded = loaded
        self.manifest = loaded.manifest
        self.approval = approval
        self.store = store
        self.ecs = ecs
        self.evidence = evidence
        self.logs = logs
        self.platform = platform
        self.names = platform.names
        self.clock = clock
        self.tokens = tokens
        self.session_id = session_id
        self.release_id = self.manifest.release_id
        self.poll = self.manifest.window.poll_seconds
        self.journal = Journal(store, journal_key(self.release_id))
        self.lock = lock_key(self.manifest.environment.name)
        self.jobs = {job.id: job for job in self.manifest.jobs}
        self._quiet_until: datetime | None = None

    # Entry points ----------------------------------------------------------

    def run(self) -> Outcome:
        try:
            return self._run()
        except SessionSuperseded:
            # Another session holds this release's authority: write nothing more.
            raise ReleaseHalted("session_superseded") from None

    def _run(self) -> Outcome:
        approval_error = self._approval_error()
        if approval_error not in (None, "approval_expired"):
            raise ReleaseHalted(str(approval_error))
        if not self._open(may_create=approval_error is None):
            return self._outcome()
        self._bind()
        steps = {
            State.PREPARED: self._lock_environment,
            State.LOCKED: self._quiesce,
            State.QUIESCED: self._migrate,
            State.MIGRATED: lambda: self._run_jobs({"grant", "proof"}, State.GRANTS_VERIFIED),
            State.GRANTS_VERIFIED: self._start_services,
            State.SERVICES_STARTED: self._verify_operational,
            State.OPERATIONAL_VERIFIED: self._finish,
        }
        try:
            if approval_error is not None:
                raise _Hold(approval_error)
            self._await_quiet()
            self._reconcile_outstanding()
            while self.state not in TERMINAL_STATES:
                steps[self.state]()
        except _Hold as hold:
            if hold.code in {"approval_expired", "release_window_exceeded"}:
                # Expiry forbids forward progress, not cleanup of this release's
                # already-launched work. Never retry a launch during cleanup.
                self._cleanup_expired_jobs()
            self._hold(hold.code)
        except PlatformHold as hold:
            self._hold(hold.code)
        except (ReleaseHalted, SessionSuperseded):
            raise
        except AmbiguousResponse:
            # An uncertain read proves nothing either way.
            self._hold("observation_ambiguous")
        except Exception:
            # Any other port or evaluation error is uncertainty, never success.
            if self.state == State.HELD_PAUSED:
                raise ReleaseHalted("finalization_unconfirmed") from None
            self._hold("controller_error")
        return self._outcome()

    def recover(self, authorization: RecoveryAuthorization) -> None:
        """Transfer a lost session's journal and exact lock to this session.

        Nothing is executed here. The next ``run`` reconciles outstanding intents
        against real observations before taking any new action.
        """
        auth = authorization
        refused = ReleaseHalted("recovery_refused")
        if (
            not SHA256.fullmatch(auth.fence_evidence_sha256)
            or not auth.authorized_by.strip()
            or auth.prior_session_id == self.session_id
        ):
            raise refused
        if not self._load() or self.journal.document.get("session_id") not in (
            auth.prior_session_id,
            self.session_id,
        ):
            raise refused
        record = self._lock_record()
        if record is not None:
            body, etag = record
            if body.get("release_id") != self.release_id:
                raise refused
            if body.get("session_id") == auth.prior_session_id:
                if etag != auth.lock_etag:
                    raise refused
                moved = {
                    **body,
                    "session_id": self.session_id,
                    "transferred_from": auth.prior_session_id,
                }
                try:
                    self.store.replace(self.lock, encode(moved), if_match=etag)
                except PreconditionFailed:
                    raise refused from None
            elif body.get("session_id") != self.session_id:
                raise refused
        elif auth.lock_etag:
            raise refused
        if self.journal.document.get("session_id") != self.session_id:
            self._append(
                {
                    "kind": "session",
                    "action": "recovered",
                    "prior_session_id": auth.prior_session_id,
                    "fence_evidence_sha256": auth.fence_evidence_sha256,
                    "authorized_by": auth.authorized_by,
                },
                session_id=self.session_id,
            )

    # Journal ---------------------------------------------------------------

    def _approval_error(self) -> str | None:
        try:
            self.platform.verify_approval(self.loaded, self.approval, self.clock.now())
        except ReleaseRejected as error:
            return error.code
        return None

    def _load(self) -> bool:
        try:
            found = self.journal.load()
        except ReleaseRejected as error:
            raise ReleaseHalted(error.code) from None
        if found and (
            self.journal.document.get("manifest_sha256") != self.loaded.sha256
            or self.journal.document.get("release_id") != self.release_id
        ):
            raise ReleaseHalted("journal_manifest_mismatch")
        return found

    def _open(self, *, may_create: bool) -> bool:
        """Create or load the journal; return whether this session may act."""
        if not self._load():
            if not may_create:
                raise ReleaseHalted("approval_expired")
            header = {
                "schema_version": 1,
                "release_id": self.release_id,
                "environment": self.manifest.environment.name,
                "manifest_sha256": self.loaded.sha256,
                "session_id": self.session_id,
            }
            prepared = {
                "at": _iso(self.clock.now()),
                "kind": "transition",
                "to": State.PREPARED.value,
                "approval_sha256": self.approval.sha256,
                "plan_sha256": self.manifest.plan_sha256,
            }
            try:
                self.journal.create(header, prepared)
            except PreconditionFailed:
                raise ReleaseHalted("journal_conflict") from None
            return True
        if self.state == State.HOLD:
            return False
        if self.state == State.HELD_PAUSED:
            if self._last("environment", "lock_released") is not None:
                return False
            if self.journal.document.get("session_id") != self.session_id:
                raise ReleaseHalted("session_conflict")
            self._release_environment_lock()
            return False
        if self.journal.document.get("session_id") != self.session_id:
            raise ReleaseHalted("session_conflict")
        if self.state != State.PREPARED and not self._lock_is_ours():
            raise ReleaseHalted("lock_not_held")
        presented = {e.get("approval_sha256") for e in self.journal.events}
        if self.approval.sha256 not in presented:
            self._append(
                {
                    "kind": "session",
                    "action": "approval_presented",
                    "approval_sha256": self.approval.sha256,
                }
            )
        return True

    def _bind(self) -> None:
        """Hand the platform this session's authority, derived from the journal.

        The fence is the session's takeover ordinal: each recovery appends one
        ``recovered`` event by journal CAS, so ordinals are unique and increase.
        Commands journaled before the last recovery bound what an earlier session
        could still have in flight; none of them can act after ``quiet_until``.
        """
        recovered = [
            event
            for event in self.journal.events
            if event["kind"] == "session" and event.get("action") == "recovered"
        ]
        quiet = None
        if recovered:
            boundary = recovered[-1]["sequence"]
            expiries = [
                _time(event["command_expires_at"])
                for event in self.journal.events
                if event["sequence"] < boundary
                and event["kind"] == "intent"
                and "command_expires_at" in event
            ]
            if expiries:
                quiet = max(expiries) + MAX_CLOCK_SKEW
        self._quiet_until = quiet
        self.platform.bind(
            SessionAuthority(self.release_id, self.session_id, 1 + len(recovered), quiet)
        )

    def _await_quiet(self) -> None:
        if self._quiet_until is None:
            return
        while self.clock.now() < self._quiet_until:
            self._guard()
            self.clock.sleep(self.poll)

    def _append(self, event: dict[str, Any], **header: Any) -> dict[str, Any]:
        try:
            return self.journal.append({"at": _iso(self.clock.now()), **event}, **header)
        except PreconditionFailed:
            raise ReleaseHalted("journal_conflict") from None

    def _transitions(self) -> list[dict[str, Any]]:
        return [event for event in self.journal.events if event["kind"] == "transition"]

    @property
    def state(self) -> State:
        return State(self._transitions()[-1]["to"])

    @property
    def last_proven(self) -> str:
        return [e["to"] for e in self._transitions() if e["to"] != State.HOLD.value][-1]

    def _transition(self, target: State, **data: Any) -> None:
        check_transition(self.state, target)
        if target != State.HOLD:
            self._guard()
        self._append({"kind": "transition", "to": target.value, **data})

    def _intent(self, action: str, subject: str, request: dict[str, Any], *, guard: bool = True,
                command: bool = True, **data: Any) -> dict[str, Any]:  # fmt: skip
        if guard:
            self._guard()
        fields = self.platform.command_fields() if command else {}
        return self._append(
            {
                "kind": "intent",
                "action": action,
                "subject": subject,
                "request_sha256": canonical_sha256(request),
                **data,
                **fields,
            }
        )

    def _observe(
        self, subject: str, result: str, *, resolves: str | None = None, **data: Any
    ) -> None:
        event = {"kind": "observation", "subject": subject, "result": result, **data}
        if resolves is not None:
            event["resolves"] = resolves
        self._append(event)

    def _results(self, subject: str) -> list[dict[str, Any]]:
        return [
            event
            for event in self.journal.events
            if event["kind"] == "observation" and event["subject"] == subject
        ]

    def _last(self, subject: str, *results: str) -> dict[str, Any] | None:
        matches = [event for event in self._results(subject) if event["result"] in results]
        return matches[-1] if matches else None

    def _last_intent(self, action: str, subject: str) -> dict[str, Any]:
        return [
            event
            for event in self.journal.events
            if event["kind"] == "intent"
            and event["action"] == action
            and event["subject"] == subject
        ][-1]

    def _outstanding(self) -> list[dict[str, Any]]:
        latest: dict[tuple[str, str], dict[str, Any]] = {}
        for event in self.journal.events:
            if event["kind"] == "intent":
                latest[(event["action"], event["subject"])] = event
            elif event["kind"] == "observation" and event.get("resolves"):
                latest.pop((event["resolves"], event["subject"]), None)
        return sorted(latest.values(), key=lambda event: event["sequence"])

    # Guards and lock ---------------------------------------------------------

    def _window_deadline(self) -> datetime:
        started = _time(self._transitions()[0]["at"])
        window = self.manifest.window
        return min(started + timedelta(seconds=window.total_seconds), window.expires_at)

    def _guard(self) -> None:
        """No mutation or promotion without a current approval inside the window."""
        now = self.clock.now()
        if now >= self.approval.approval.not_after:
            raise _Hold("approval_expired")
        if now >= self._window_deadline():
            raise _Hold("release_window_exceeded")

    def _lock_record(self) -> tuple[dict[str, Any], str] | None:
        found = self.store.read(self.lock)
        if found is None:
            return None
        try:
            body = json.loads(found[0])
        except ValueError:
            body = {}
        return (body if isinstance(body, dict) else {}), found[1]

    def _lock_is_ours(self) -> bool:
        record = self._lock_record()
        return record is not None and (
            record[0].get("release_id"),
            record[0].get("session_id"),
        ) == (self.release_id, self.session_id)

    def _lock_environment(self) -> None:
        body = {
            "release_id": self.release_id,
            "session_id": self.session_id,
            "manifest_sha256": self.loaded.sha256,
            "acquired_at": _iso(self.clock.now()),
        }
        try:
            self.store.create(self.lock, encode(body))
        except PreconditionFailed:
            # No TTL or age-based stealing: only this exact session may continue.
            if not self._lock_is_ours():
                raise _Hold("environment_locked") from None
        self._transition(State.LOCKED)

    # Reconciliation ------------------------------------------------------------

    def _reconcile_outstanding(self) -> None:
        names = self.names
        for intent in self._outstanding():
            action = intent["action"]
            if action == names.launch:
                self._reconcile_launch(self.jobs[intent["subject"]], intent)
            elif action in (names.scale, names.deploy):
                self._reconcile_update(intent)
            elif action == names.activate:
                self._reconcile_activation(intent)
            else:
                self._stop_after_deadline(self.jobs[intent["subject"]], intent[names.run])

    def _reconcile_launch(self, job: Job, intent: dict[str, Any]) -> None:
        """Find the run launched under this token, or retry the identical request."""
        names = self.names
        request = self.platform.launch_request(job, intent["token"])
        if canonical_sha256(request) != intent["request_sha256"]:
            raise ReleaseHalted("journal_integrity")
        for attempt in range(IDENTICAL_RETRIES + 1):
            runs = self.platform.runs_for(job, intent["token"])
            if len(runs) == 1:
                self._observe(
                    job.id, "launched", resolves=names.launch, **{names.run: runs[0]},
                    reconciled=True,
                )  # fmt: skip
                return
            if len(runs) > 1:
                self._observe(job.id, "launched_multiple", resolves=names.launch,
                              **{names.runs: list(runs)})  # fmt: skip
                raise _Hold("launch_task_count")
            # An eventually consistent empty listing is not proof that nothing launched.
            now = self.clock.now()
            if (
                now >= _time(intent["token_expires_at"])
                or now >= _time(intent["deadline_at"])
                or attempt == IDENTICAL_RETRIES
            ):
                raise _Hold("launch_outcome_unknown")
            retry = self._intent(
                names.launch,
                job.id,
                request,
                token=intent["token"],
                issued_at=intent["issued_at"],
                deadline_at=intent["deadline_at"],
                token_expires_at=intent["token_expires_at"],
                retry_of=intent["sequence"],
            )
            try:
                launch = self.platform.launch(job, request, retry)
            except AmbiguousResponse:
                self.clock.sleep(self.poll)
                continue
            self._accept_launch(job, launch)
            return

    def _reconcile_update(self, intent: dict[str, Any]) -> None:
        """Confirm a service update from observations, or reissue the identical update.

        A forward (desired 1) recognition and every forward resend first check
        drift; a forward resend's reply is never discarded.
        """
        names = self.names
        key, desired = intent["subject"], intent["desired_count"]
        if desired == 0:
            request = self.platform.scale_request(key, intent)
        else:
            request = self.platform.deploy_request(key, intent)
        if canonical_sha256(request) != intent["request_sha256"]:
            raise ReleaseHalted("journal_integrity")
        prior = intent.get(names.prior, [])
        carried = {name: intent[name] for name in self.platform.request_fields if name in intent}
        for attempt in range(IDENTICAL_RETRIES + 1):
            for _ in range(VISIBILITY_POLLS):
                views = self.platform.services()
                view = views[key]
                if desired == 0 and self.platform.scaled_down(key, view, intent):
                    self._observe(key, "scaled_to_zero", resolves=intent["action"], reconciled=True)
                    return
                generation = (
                    self.platform.new_generation(key, view, prior, intent) if desired == 1 else None
                )
                if generation is not None:
                    self._hold_on_drift(views)
                    self._observe(key, "service_deployed", resolves=intent["action"],
                                  **{names.generation: generation}, reconciled=True)  # fmt: skip
                    return
                self.clock.sleep(self.poll)
            if self.clock.now() >= _time(intent["deadline_at"]) or attempt == IDENTICAL_RETRIES:
                raise _Hold("service_update_unconfirmed")
            if desired == 1:
                self._hold_on_drift(None)
            retry = self._intent(
                intent["action"],
                key,
                request,
                desired_count=desired,
                **{names.prior: prior},
                deadline_at=intent["deadline_at"],
                retry_of=intent["sequence"],
                **carried,
            )
            try:
                response = self.platform.send_update(request, retry)
            except AmbiguousResponse:
                continue
            if desired == 1:
                drift = self.platform.response_drift(key, response)
                if drift is not None:
                    raise _Hold(drift)

    def _hold_on_drift(self, views: Mapping[str, ServiceView] | None) -> None:
        """Hold on drift; ``None`` asks the platform for a fresh observation."""
        drift = self.platform.drift(views)
        if drift is not None:
            raise _Hold(drift)

    # Quiesce -------------------------------------------------------------------

    def _quiesce(self) -> None:
        names = self.names
        views = self.platform.services()
        if self.manifest.rollback.kind == "compatible_release":
            for key, view in views.items():
                if not self.platform.prior_matches(key, view):
                    raise _Hold("prior_release_mismatch")
        elif any(view.active for view in views.values()):
            # A running environment has a prior binary; never invent an empty one.
            raise _Hold("upgrade_requires_compatible_rollback")
        deadline = _iso(self._window_deadline())
        for key, view in views.items():
            if view.wants_running:
                fields = self.platform.scale_fields(key, view)
                request = self.platform.scale_request(key, fields)
                intent = self._intent(
                    names.scale, key, request, desired_count=0, deadline_at=deadline, **fields
                )
                try:
                    self.platform.send_update(request, intent)
                except AmbiguousResponse:
                    self._reconcile_update(intent)
                    continue
                self._observe(key, "scaled_to_zero", resolves=names.scale)
        while not self.platform.idle(self.platform.services()):
            self._guard()
            self.clock.sleep(self.poll)
        # Any remaining run in the environment is an unaccounted writer.
        if self.platform.writers_present():
            raise _Hold("standalone_writer_present")
        self._transition(State.QUIESCED)

    # Activation ------------------------------------------------------------------

    def _migrate(self) -> None:
        self._activate()
        self._run_jobs({"migrate"}, State.MIGRATED)

    def _activate(self) -> None:
        """Make the platform's release code current before the first job (none on ECS).

        Only an exact prior state may be moved forward; any other state is drift
        and holds. A reply is screened for drift, never discarded; recognition
        always comes from a fresh observation.
        """
        names = self.names
        for subject in self.platform.activations():
            if self._last(subject, "activated") is not None:
                continue
            state = self.platform.activation_state(subject)
            if state == ACTIVE:
                self._observe(subject, "activated")
                continue
            if state != PRIOR:
                raise _Hold(state)
            request = self.platform.activation_request(subject)
            now = self.clock.now()
            deadline = min(now + timedelta(seconds=self.manifest.window.service_start_seconds),
                           self._window_deadline())  # fmt: skip
            intent = self._intent(names.activate, subject, request, deadline_at=_iso(deadline))
            try:
                reply = self.platform.activate(subject, request, intent)
            except AmbiguousResponse:
                reply = ACTIVE  # unknown: the observations below decide
            if reply != ACTIVE:
                raise _Hold(reply)
            self._reconcile_activation(intent)

    def _reconcile_activation(self, intent: dict[str, Any]) -> None:
        names = self.names
        subject = intent["subject"]
        request = self.platform.activation_request(subject)
        if canonical_sha256(request) != intent["request_sha256"]:
            raise ReleaseHalted("journal_integrity")
        for attempt in range(IDENTICAL_RETRIES + 1):
            for _ in range(VISIBILITY_POLLS):
                state = self.platform.activation_state(subject)
                if state == ACTIVE:
                    self._observe(subject, "activated", resolves=names.activate, reconciled=True)
                    return
                if state != PRIOR:
                    raise _Hold(state)
                self.clock.sleep(self.poll)
            if self.clock.now() >= _time(intent["deadline_at"]) or attempt == IDENTICAL_RETRIES:
                raise _Hold("activation_unconfirmed")
            # A fresh observation decides the resend, after the polls' sleep.
            state = self.platform.activation_state(subject)
            if state == ACTIVE:
                self._observe(subject, "activated", resolves=names.activate, reconciled=True)
                return
            if state != PRIOR:
                raise _Hold(state)
            retry = self._intent(names.activate, subject, request,
                                 deadline_at=intent["deadline_at"], retry_of=intent["sequence"])  # fmt: skip
            try:
                reply = self.platform.activate(subject, request, retry)
            except AmbiguousResponse:
                continue
            if reply != ACTIVE:
                raise _Hold(reply)

    # Jobs ----------------------------------------------------------------------

    def _run_jobs(self, phases: set[str], target: State) -> None:
        for job in self.manifest.jobs:
            if job.phase not in phases or self._last(job.id, "job_succeeded") is not None:
                continue
            if self._last(job.id, "launched") is None:
                self._launch(job)
            self._await_job(job)
        self._transition(target)

    def _launch(self, job: Job) -> None:
        token = self.tokens()
        if not TOKEN.fullmatch(token):
            raise ReleaseHalted("invalid_launch_token")
        request = self.platform.launch_request(job, token)
        now = self.clock.now()
        deadline = min(now + timedelta(seconds=job.deadline_seconds), self._window_deadline())
        intent = self._intent(
            self.names.launch,
            job.id,
            request,
            token=token,
            issued_at=_iso(now),
            deadline_at=_iso(deadline),
            token_expires_at=_iso(token_expires_at(now, job.deadline_seconds)),
        )
        try:
            launch = self.platform.launch(job, request, intent)
        except AmbiguousResponse:
            self._reconcile_launch(job, intent)
            return
        self._accept_launch(job, launch)

    def _accept_launch(self, job: Job, launch: Launch) -> None:
        names = self.names
        if launch.failed and not launch.runs:
            self._observe(job.id, "launch_failed", resolves=names.launch,
                          failure_count=launch.failed)  # fmt: skip
            raise _Hold("launch_failed")
        if launch.failed or not launch.runs:
            raise _Hold("launch_response_incomplete")
        runs = list(launch.runs)
        if len(runs) != 1:
            self._observe(job.id, "launched_multiple", resolves=names.launch, **{names.runs: runs})
            raise _Hold("launch_task_count")
        if launch.unexpected:
            self._observe(job.id, "launched_unexpected", resolves=names.launch,
                          **{names.runs: runs})  # fmt: skip
            raise _Hold("job_identity_mismatch")
        self._observe(job.id, "launched", resolves=names.launch, **{names.run: runs[0]})

    def _await_job(self, job: Job) -> None:
        names = self.names
        intent = self._last_intent(names.launch, job.id)
        launched = self._last(job.id, "launched")
        assert launched is not None
        run = launched[names.run]
        deadline = _time(intent["deadline_at"])
        while True:
            self._guard()
            # A missing run is eventual consistency, not proof that it never ran.
            view = self.platform.describe_run(job, run)
            now = self.clock.now()
            if now >= deadline:
                if view is None or not self.platform.run_stopped(view):
                    self._stop_after_deadline(job, run)
                self._observe(job.id, "job_failed", **{names.run: run},
                              reason="job_deadline_exceeded", sql_outcome="unknown")  # fmt: skip
                raise _Hold("job_deadline_exceeded")
            self._guard()
            if view is not None and self.platform.run_stopped(view):
                receipt = self.platform.job_receipt(job, run)
                # There is no trusted completion timestamp in this port contract.
                # Even a timely run needs its complete receipt before the deadline.
                if self.clock.now() >= deadline:
                    self._observe(job.id, "job_failed", **{names.run: run},
                                  reason="job_deadline_exceeded", sql_outcome="unknown")  # fmt: skip
                    raise _Hold("job_deadline_exceeded")
                self._guard()
                failure = self.platform.evaluate_job(job, intent["token"], view, receipt)
                if failure is None:
                    self._observe(job.id, "job_succeeded", **{names.run: run},
                                  receipt_sha256=canonical_sha256(receipt))  # fmt: skip
                    return
                if failure != "job_receipt_missing":
                    self._observe(job.id, "job_failed", **{names.run: run}, reason=failure)
                    raise _Hold(failure)
            self.clock.sleep(self.poll)

    def _stop_after_deadline(self, job: Job, run: str) -> None:
        """Request a stop and confirm it. A stopped client never proves SQL stopped."""
        self._stop_job(job, run, "release job deadline exceeded")
        raise _Hold("job_deadline_exceeded")

    def _cleanup_expired_jobs(self) -> None:
        """Best-effort safety cleanup only; no launch retry or success promotion.

        An empty listing or failed observation leaves SQL outcome unknown and
        needs operator reconciliation. It never proves that nothing ran.
        """
        names = self.names
        try:
            owns_lock = self._lock_is_ours()
        except Exception:
            # No ownership proof means no stop authority. Persist the uncertainty
            # if journal CAS is still available; its failure remains a hard halt.
            self._observe("environment", "cleanup_unconfirmed", sql_outcome="unknown")
            return
        if not owns_lock:
            return
        for job in self.manifest.jobs:
            intents = [e for e in self.journal.events
                       if e["kind"] == "intent" and e["action"] == names.launch
                       and e["subject"] == job.id]  # fmt: skip
            if not intents or self._last(job.id, "job_succeeded", "launch_failed") is not None:
                continue
            intent = intents[-1]
            try:
                launched = self._last(job.id, "launched")
                runs = ([launched[names.run]] if launched else
                        self.platform.runs_for(job, intent["token"]))  # fmt: skip
                if not runs:
                    self._observe(job.id, "cleanup_unconfirmed", sql_outcome="unknown")
                for run in runs:
                    view = self.platform.describe_run(job, run)
                    if view is None or not self.platform.run_matches(job, intent["token"], view):
                        self._observe(job.id, "cleanup_unconfirmed", sql_outcome="unknown")
                        continue
                    if not self.platform.run_stopped(view):
                        self._stop_job(job, run, "release authorization window expired")
                    else:
                        self._observe(job.id, "cleanup_stopped", **{names.run: run},
                                      sql_outcome="unknown")  # fmt: skip
            except (ReleaseHalted, SessionSuperseded):
                raise
            except Exception:
                self._observe(job.id, "cleanup_unconfirmed", sql_outcome="unknown")

    def _stop_job(self, job: Job, run: str, reason: str) -> None:
        names = self.names
        request = self.platform.stop_request(job, run, reason)
        # Stopping the release's own job is a covered safety action, even after expiry.
        intent = self._intent(names.stop, job.id, request, guard=False, **{names.run: run})
        try:
            self.platform.send_stop(request, intent)
        except AmbiguousResponse:
            pass
        give_up = (
            self.clock.now() + timedelta(seconds=job.stop_grace_seconds) + STOP_CONFIRMATION_MARGIN
        )
        while True:
            view = self.platform.describe_run(job, run)
            if view is not None and self.platform.run_stopped(view):
                self._observe(job.id, "stop_confirmed", resolves=names.stop, **{names.run: run},
                              sql_outcome="unknown")  # fmt: skip
                break
            if self.clock.now() >= give_up:
                self._observe(job.id, "stop_unconfirmed", **{names.run: run},
                              sql_outcome="unknown")  # fmt: skip
                break
            self.clock.sleep(self.poll)

    # Services ------------------------------------------------------------------

    def _deployment_id(self, key: str) -> str | None:
        event = self._last(key, "service_deployed")
        return None if event is None else event[self.names.generation]

    def _start_services(self) -> None:
        for key in SERVICE_KEYS:  # Runtime first, API paused, worker last.
            if self._last(key, "service_ready") is not None:
                continue
            deployment = self._deployment_id(key) or self._deploy(key)
            self._await_service(key, deployment)
        self._transition(State.SERVICES_STARTED)

    def _deploy(self, key: str) -> str:
        names = self.names
        views = self.platform.services()
        view = views[key]
        prior = list(view.generations)
        self._hold_on_drift(views)
        fields = self.platform.deploy_fields(key, view)
        request = self.platform.deploy_request(key, fields)
        now = self.clock.now()
        deadline = min(now + timedelta(seconds=self.manifest.window.service_start_seconds),
                       self._window_deadline())  # fmt: skip
        intent = self._intent(names.deploy, key, request, desired_count=1,
                              **{names.prior: prior}, deadline_at=_iso(deadline), **fields)  # fmt: skip
        try:
            deployed = self.platform.deploy(key, request, intent, prior)
        except AmbiguousResponse:
            deployed = Deploy(None)
        if deployed.drift is not None:
            raise _Hold(deployed.drift)
        if deployed.generation is None:
            self._reconcile_update(intent)
            return str(self._deployment_id(key))
        self._observe(key, "service_deployed", resolves=names.deploy,
                      **{names.generation: deployed.generation})  # fmt: skip
        return deployed.generation

    def _await_service(self, key: str, deployment: str) -> None:
        deadline = _time(self._last_intent(self.names.deploy, key)["deadline_at"])
        while True:
            status, detail, _ = self.platform.service_snapshot(key, deployment)
            if status == "ready":
                self._observe(key, "service_ready", **{self.names.generation: deployment},
                              **{self.names.run: detail})  # fmt: skip
                return
            if status == "failed" or self.clock.now() >= deadline:
                raise _Hold(detail)
            self.clock.sleep(self.poll)

    def _verify_operational(self) -> None:
        recorded = {}
        for key in SERVICE_KEYS:
            ready = self._last(key, "service_ready")
            assert ready is not None
            recorded[key] = ready[self.names.run]
        self._require_recorded_tasks(recorded)
        for check in self.manifest.operational_checks:
            if check.id == WORKER_READINESS_CHECK:
                self._await_worker_readiness(check.id, recorded)
                continue
            receipt = self.platform.operational_receipt(check.id)
            if receipt is None:
                raise _Hold("operational_evidence_missing")
            if dict(receipt) != self.platform.expected_operational(check, recorded):
                raise _Hold("operational_receipt_mismatch")
            self._observe(check.id, "operational_passed", receipt_sha256=canonical_sha256(receipt))
        # Re-enumerate immediately before success: a replacement needs a fresh window.
        self._require_recorded_tasks(recorded)
        self._transition(State.OPERATIONAL_VERIFIED)

    def _await_worker_readiness(self, check_id: str, recorded: dict[str, str]) -> None:
        """Observe the recorded worker run's own receipts for one bounded gate attempt.

        Identity comes from the platform: the recorded generation and run, whose
        identity and image digests ``service_snapshot`` checks on every poll, and
        the receipt source derived from that run. Each attempt is a new epoch;
        resumed attempts keep the first attempt's deadline. Missing receipts,
        denied or incomplete reads and visibility loss only clear stability, so
        they end as not proven at the deadline. Platform identity changes hold at
        once.
        """
        names = self.names
        policy = READINESS_POLICY
        run = recorded["worker"]
        deployment = self._deployment_id("worker")
        assert deployment is not None
        reader = self.platform.worker_reader(run, deployment)
        epoch = self.clock.now()
        # Journal times are controller time, rounded down: an epoch before any of
        # them means the clock moved backwards at some earlier step.
        if epoch < max(_time(event["at"]) for event in self.journal.events):
            raise _Hold("controller_clock_rollback")
        earlier = [
            _time(event["deadline_at"])
            for event in self._results(check_id)
            if event["result"] == "readiness_observing"
        ]
        # A resumed attempt never gets a later deadline. Enforce exactly the
        # recorded whole-second (rounded-down) value.
        limit = min(
            [epoch + timedelta(seconds=policy.gate_seconds), self._window_deadline(), *earlier]
        )
        deadline = _time(_iso(limit))
        self._observe(check_id, "readiness_observing", **{names.run: run},
                      epoch_at=_iso(epoch), deadline_at=_iso(deadline))  # fmt: skip
        gate = ReadinessGate(policy, release_id=self.release_id, epoch_start=epoch, run=run)
        start = epoch - timedelta(seconds=policy.max_future_skew_seconds)
        token: str | None = None
        latest = epoch

        def observed_now() -> datetime:
            # Deadlines and freshness assume the clock never moves backwards.
            nonlocal latest
            current = self.clock.now()
            if current < latest:
                raise _Hold("controller_clock_rollback")
            latest = current
            return current

        while True:
            self._guard()
            now = observed_now()
            if now >= deadline:
                reason = gate.reason or (
                    "window_incomplete" if gate.received else "receipt_missing"
                )
                self._observe(check_id, "readiness_not_proven", **{names.run: run},
                              last_reason=reason, receipts=gate.received)  # fmt: skip
                raise _Hold("worker_readiness_not_proven")
            try:
                read = reader.read(token=token, start=start, end=now, policy=policy)
            except Exception:
                # Denied, missing or malformed reads prove nothing for this poll.
                # Visibility was lost until the read returned, however long it took.
                gate.clear("readiness_logs_unavailable", observed_now())
            else:
                token = read.token
                gate.ingest(read.messages, now)
                if not read.complete:
                    gate.clear("readiness_logs_incomplete", observed_now())
            status, detail, runs = self.platform.service_snapshot("worker", deployment)
            if status == "failed" or detail == self.platform.count_drift:
                raise _Hold(detail)
            if run not in runs or (status == "ready" and detail != run):
                raise _Hold("task_replaced")
            if status != "ready":
                gate.clear(detail, observed_now())  # when the platform was observed
            elif gate.stable(observed_now()):
                # Re-enumerate every recorded service immediately before success;
                # success still needs the deadline and fresh receipts after it.
                self._require_recorded_tasks(recorded)
                checked = observed_now()
                if checked < deadline and gate.stable(checked):
                    self._guard()
                    self._observe(check_id, "operational_passed", **{names.run: run},
                                  last_reset=gate.reason, **gate.summary())  # fmt: skip
                    return
            self.clock.sleep(self.poll)

    def _require_recorded_tasks(self, recorded: dict[str, str]) -> None:
        for key in SERVICE_KEYS:
            deployment = self._deployment_id(key)
            assert deployment is not None
            status, detail, runs = self.platform.service_snapshot(key, deployment)
            if status == "ready" and detail == recorded[key]:
                continue
            if recorded[key] not in runs or status == "ready":
                raise _Hold("task_replaced")
            raise _Hold(detail)

    def _finish(self) -> None:
        if self._outstanding():
            raise _Hold("outstanding_actions")
        self._transition(State.HELD_PAUSED, admission="paused")
        self._release_environment_lock()

    def _release_environment_lock(self) -> None:
        """Resume terminal finalization using only the exact owned lock.

        Persist deletion intent before deleting. A missing lock after that intent
        is safe to confirm; a replacement lock is never removed. A recovered
        session records a fresh intent for its explicitly transferred lock.
        """
        try:
            intents = [e for e in self.journal.events
                       if e["kind"] == "intent" and e["action"] == "release_lock"]  # fmt: skip
            prior = intents[-1] if intents else None
            record = self._lock_record()
            if record is None:
                if prior is None:
                    raise ReleaseHalted("lock_not_held")
            else:
                body, etag = record
                if (body.get("release_id"), body.get("session_id")) != (
                    self.release_id,
                    self.session_id,
                ):
                    raise ReleaseHalted("lock_release_conflict")
                if prior is not None and prior["session_id"] == self.session_id:
                    if prior["lock_etag"] != etag:
                        raise ReleaseHalted("lock_release_conflict")
                else:
                    self._intent("release_lock", "environment", {"key": self.lock, "etag": etag},
                                 guard=False, command=False, lock_etag=etag,
                                 session_id=self.session_id)  # fmt: skip
                self.store.delete(self.lock, if_match=etag)
            self._observe("environment", "lock_released", resolves="release_lock")
        except PreconditionFailed:
            raise ReleaseHalted("lock_release_conflict") from None
        except ReleaseHalted:
            raise
        except Exception:
            raise ReleaseHalted("finalization_unconfirmed") from None

    # Hold ----------------------------------------------------------------------

    def _job_outcomes(self) -> dict[str, str]:
        outcomes = {}
        for job_id in self.jobs:
            if self._last(job_id, "job_succeeded") is not None:
                outcomes[job_id] = "succeeded"
            elif (
                not any(
                    event["kind"] == "intent" and event["subject"] == job_id
                    for event in self.journal.events
                )
                or self._last(job_id, "launch_failed") is not None
            ):
                outcomes[job_id] = "not_started"
            else:
                outcomes[job_id] = "unknown"
        return outcomes

    def _hold(self, code: str) -> None:
        touched = any(
            event["kind"] == "intent"
            and event["action"] == self.names.deploy
            and event.get("desired_count") == 1
            for event in self.journal.events
        )
        plan = plan_rollback(self.manifest, self._job_outcomes(), services_touched=touched)
        self._transition(State.HOLD, reason=code, last_proven=self.last_proven, rollback=plan)

    def _outcome(self) -> Outcome:
        last = self._transitions()[-1]
        return Outcome(
            state=last["to"],
            reason=last.get("reason"),
            last_proven=self.last_proven,
            rollback=last.get("rollback"),
        )


class _LogStreamReader:
    """The observed ECS task's configured worker stream, read with ``read_stream``."""

    def __init__(self, logs: LogPort, group: str, stream: str) -> None:
        self.logs = logs
        self.group = group
        self.stream = stream

    def read(
        self, *, token: str | None, start: datetime, end: datetime, policy: GatePolicy
    ) -> LogRead:
        return read_stream(self.logs, self.group, self.stream, token=token, start=start, end=end,
                           policy=policy)  # fmt: skip


class EcsPlatform:
    """The ECS strategy: exactly the calls the controller made before the extraction.

    Journal names are the historical ones, so AWS journals are unchanged. Nothing
    here adds an ECS call the controller did not make before.
    """

    names = JournalNames(
        launch="run_task",
        scale="update_service",
        deploy="update_service",
        stop="stop_task",
        activate="activate_platform",
        run="task_arn",
        runs="task_arns",
        generation="deployment_id",
        prior="prior_deployments",
    )
    count_drift = "task_count_drift"
    request_fields: tuple[str, ...] = ()

    def __init__(
        self, manifest: Manifest, ecs: EcsPort, evidence: EvidencePort, logs: LogPort
    ) -> None:
        self.manifest = manifest
        self.ecs = ecs
        self.evidence = evidence
        self.logs = logs
        self.release_id = manifest.release_id
        self.cluster = manifest.environment.cluster_arn
        images = manifest.images
        self.digests = {
            "runtime": images.runtime.arm64_digest,
            "search": images.search.arm64_digest,
            "release_tools": images.release_tools.arm64_digest,
        }

    def verify_approval(self, loaded: LoadedManifest, approval: LoadedApproval,
                        now: datetime) -> None:  # fmt: skip
        verify_approval(loaded, approval, now)

    def bind(self, authority: SessionAuthority) -> None:
        """ECS calls carry no session authority; the lock and journal CAS fence them."""

    def command_fields(self) -> dict[str, Any]:
        return {}

    # Services ------------------------------------------------------------------

    def _service_arn(self, key: str) -> str:
        return getattr(self.manifest.environment.services, key)

    def services(self) -> dict[str, ServiceView]:
        arns = [self._service_arn(key) for key in SERVICE_KEYS]
        found = {
            item.get("serviceArn"): item for item in self.ecs.describe_services(self.cluster, arns)
        }
        if set(found) != set(arns):
            raise _Hold("service_missing")
        views = {}
        for key in SERVICE_KEYS:
            service = found[self._service_arn(key)]
            views[key] = ServiceView(
                wants_running=bool(service.get("desiredCount")),
                active=bool(
                    service.get("desiredCount")
                    or service.get("runningCount")
                    or service.get("pendingCount")
                ),
                generations=tuple(str(item.get("id")) for item in service.get("deployments") or []),
                raw=service,
            )
        return views

    def prior_matches(self, key: str, view: ServiceView) -> bool:
        rollback = self.manifest.rollback
        return view.raw.get("taskDefinition") == getattr(rollback.services, key).task_definition

    def scale_fields(self, key: str, view: ServiceView) -> dict[str, Any]:
        return {}

    def scale_request(self, key: str, fields: Mapping[str, Any]) -> dict[str, Any]:
        return {"cluster": self.cluster, "service": self._service_arn(key), "desiredCount": 0}

    def scaled_down(self, key: str, view: ServiceView, intent: Mapping[str, Any]) -> bool:
        return view.raw.get("desiredCount") == 0

    def send_update(self, request: dict[str, Any], intent: Mapping[str, Any]) -> dict[str, Any]:
        return self.ecs.update_service(request)

    def idle(self, views: Mapping[str, ServiceView]) -> bool:
        return all(not view.active for view in views.values())

    def writers_present(self) -> bool:
        return bool(self.ecs.list_tasks(self.cluster))

    def deploy_fields(self, key: str, view: ServiceView) -> dict[str, Any]:
        return {}

    def deploy_request(self, key: str, fields: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "cluster": self.cluster,
            "service": self._service_arn(key),
            "taskDefinition": getattr(self.manifest.services, key).task_definition,
            "desiredCount": 1,
            # A fresh deployment ID: tasks of an older deployment never count.
            "forceNewDeployment": True,
            "enableExecuteCommand": False,
            # The prior binary may be schema-incompatible, so ECS never rolls back.
            "deploymentConfiguration": {
                "deploymentCircuitBreaker": {"enable": True, "rollback": False}
            },
        }

    def deploy(self, key: str, request: dict[str, Any], intent: Mapping[str, Any],
               prior: list[str]) -> Deploy:  # fmt: skip
        response = self.ecs.update_service(request)
        return Deploy(self._new_deployment(key, response.get("service") or {}, prior))

    def _new_deployment(self, key: str, service: Mapping[str, Any], prior: list[str]) -> str | None:
        definition = getattr(self.manifest.services, key).task_definition
        for deployment in service.get("deployments") or []:
            if (
                deployment.get("status") == "PRIMARY"
                and deployment.get("taskDefinition") == definition
                and deployment.get("id") not in prior
            ):
                return str(deployment["id"])
        return None

    def new_generation(self, key: str, view: ServiceView, prior: list[str],
                       intent: Mapping[str, Any]) -> str | None:  # fmt: skip
        return self._new_deployment(key, view.raw, prior)

    def drift(self, views: Mapping[str, ServiceView] | None) -> str | None:
        return None

    def response_drift(self, key: str, response: Any) -> str | None:
        return None

    def service_snapshot(self, key: str, generation: str) -> tuple[str, str, list[str]]:
        service = self.services()[key].raw
        arns = self.ecs.list_tasks(
            self.cluster, service_name=self._service_arn(key).rsplit("/", 1)[1]
        )
        described = self.ecs.describe_tasks(self.cluster, arns) if arns else {"tasks": []}
        if described.get("failures"):
            return "waiting", "task_enumeration_incomplete", arns
        spec = getattr(self.manifest.services, key)
        status, detail = evaluate_service(
            spec, self.digests, service, described["tasks"], generation
        )
        return status, detail, arns

    # Activation: none on ECS (task definitions are registered by Terraform).

    def activations(self) -> tuple[str, ...]:
        return ()

    def activation_request(self, subject: str) -> dict[str, Any]:
        raise AssertionError("ECS has no activation step")

    def activation_state(self, subject: str) -> str:
        raise AssertionError("ECS has no activation step")

    def activate(self, subject: str, request: dict[str, Any], intent: Mapping[str, Any]) -> str:
        raise AssertionError("ECS has no activation step")

    # Jobs ----------------------------------------------------------------------

    def launch_request(self, job: Job, token: str) -> dict[str, Any]:
        network = self.manifest.network
        return {
            "cluster": self.cluster,
            "taskDefinition": job.task.task_definition,
            "count": 1,
            "launchType": "FARGATE",
            "platformVersion": network.platform_version,
            "networkConfiguration": {
                "awsvpcConfiguration": {
                    "subnets": list(network.subnets),
                    "securityGroups": list(job.task.security_groups),
                    "assignPublicIp": "DISABLED",
                }
            },
            "enableExecuteCommand": False,
            "startedBy": token,
            "clientToken": token,
            "tags": [
                {"key": "sentry:release-id", "value": self.release_id},
                {"key": "sentry:job-id", "value": job.id},
            ],
        }

    def launch(self, job: Job, request: dict[str, Any], intent: Mapping[str, Any]) -> Launch:
        response = self.ecs.run_task(request)
        tasks = response.get("tasks") or []
        failures = response.get("failures") or []
        if failures:
            # Classified before any task is read, as before the extraction: with
            # tasks present the response is incomplete and no task is recorded.
            return Launch(runs=("unread",) * len(tasks), failed=len(failures))
        arns = tuple(str(task.get("taskArn")) for task in tasks)
        unexpected = len(tasks) == 1 and (
            tasks[0].get("taskDefinitionArn") != job.task.task_definition
            or tasks[0].get("startedBy") != intent["token"]
        )
        return Launch(runs=arns, failed=len(failures), unexpected=unexpected)

    def runs_for(self, job: Job, token: str) -> list[str]:
        return self.ecs.list_tasks(self.cluster, started_by=token)

    def describe_run(self, job: Job, run: str) -> dict[str, Any] | None:
        tasks = self.ecs.describe_tasks(self.cluster, [run]).get("tasks") or []
        return next((task for task in tasks if task.get("taskArn") == run), None)

    def run_stopped(self, view: Mapping[str, Any]) -> bool:
        return view.get("lastStatus") == "STOPPED"

    def run_matches(self, job: Job, token: str, view: Mapping[str, Any]) -> bool:
        return (
            view.get("taskDefinitionArn") == job.task.task_definition
            and view.get("startedBy") == token
        )

    def evaluate_job(self, job: Job, token: str, view: Mapping[str, Any],
                     receipt: Mapping[str, Any] | None) -> str | None:  # fmt: skip
        return evaluate_job(job, self.digests, release_id=self.release_id, token=token,
                            task=view, receipt=receipt)  # fmt: skip

    def job_receipt(self, job: Job, run: str) -> dict[str, Any] | None:
        return self.evidence.job_receipt(self.release_id, job.id, run)

    def stop_request(self, job: Job, run: str, reason: str) -> dict[str, Any]:
        return {"cluster": self.cluster, "task": run, "reason": reason}

    def send_stop(self, request: dict[str, Any], intent: Mapping[str, Any]) -> None:
        self.ecs.stop_task(request["cluster"], request["task"], request["reason"])

    # Operational evidence ---------------------------------------------------------

    def operational_receipt(self, check_id: str) -> dict[str, Any] | None:
        return self.evidence.operational_receipt(self.release_id, check_id)

    def expected_operational(self, check: Any, recorded: Mapping[str, str]) -> dict[str, Any]:
        return {
            "schema": check.receipt_schema,
            "release_id": self.release_id,
            "check_id": check.id,
            "status": "passed",
            "tasks": dict(recorded),
        }

    def worker_reader(self, run: str, generation: str) -> _LogStreamReader:
        group, stream = worker_stream(self.manifest.environment.name, self.release_id, run)
        return _LogStreamReader(self.logs, group, stream)
