"""Attended release controller: journal intent, act, then prove the outcome.

The controller runs one approved manifest to ``held_paused`` or stops in
``hold`` with a bounded reason. It never enables admission, retries blindly,
steals a lock or treats a partial observation as success. All AWS access goes
through ports; this module contains no SDK, credential or network code.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import json
import re
from typing import Any

from release.journal import Journal, ObjectStore, PreconditionFailed, encode, journal_key, lock_key
from release.machine import (
    FORWARD_STATES,
    ROLLBACK_STATES,
    TERMINAL_STATES,
    State,
    check_transition,
    evaluate_job,
    evaluate_observation,
    evaluate_service,
    evaluate_task,
    plan_rollback,
    service_settings_drift,
    task_network_address,
    task_runtime_issue,
    token_expires_at,
)
from release.manifest import (
    CompatibleRelease,
    Job,
    LoadedApproval,
    LoadedManifest,
    ObserverCheck,
    ReleaseRejected,
    RollbackRun,
    canonical_sha256,
    executable,
    verify_approval,
)
from release.ports import AmbiguousResponse, Clock, ClockUntrusted, EcsPort, EvidencePort, LogPort
from release.readiness import (
    WORKER_READINESS_CHECK,
    GatePolicy,
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
# A failed release's leftover task gets its job's longest stop grace (120 s).
FAILED_TASK_STOP_GRACE = timedelta(seconds=120)
# Observations that resolve a launch intent without a usable task.
REFUSED_LAUNCHES = ("launch_failed", "launched_multiple", "launched_unexpected")
# Observations a release journals for a task it launched only after seeing that
# task stopped. ECS forgets a stopped task; this record of it does not expire.
RECORDED_STOPS = frozenset(
    {"job_succeeded", "job_failed", "operational_passed", "operational_failed",
     "stop_confirmed", "cleanup_stopped"}
)  # fmt: skip
# A rollback of a held rollback inherits what that run left unreconciled. Longer
# chains than this are not followed: the run holds for the operator instead.
MAX_UNRECONCILED_PREDECESSORS = 4
READINESS_POLICY = GatePolicy()


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


def _hold_on_drift(services: dict[str, dict[str, Any]]) -> None:
    """No forward deployment action while any service reports drifted settings."""
    if any(service_settings_drift(service) for service in services.values()):
        raise _Hold("service_settings_drift")


@dataclass(frozen=True)
class RecoveryAuthorization:
    """Recorded break-glass decision that the prior session is fenced and cannot resume."""

    prior_session_id: str
    lock_etag: str
    fence_evidence_sha256: str
    authorized_by: str


@dataclass(frozen=True)
class FailedReleaseHandoff:
    """Recorded decision that the failed release's session is fenced and cannot resume.

    A rollback takes the environment lock from the failed release only with this:
    the failed session named in its journal, the lock's exact ETag, evidence that
    the old operator session was fenced, and who decided it.
    """

    failed_session_id: str
    lock_etag: str
    fence_evidence_sha256: str
    authorized_by: str


@dataclass
class _FailedLaunch:
    """What a failed release's journal records about one launch token of its own."""

    subject: str
    token: str
    # The release learned the outcome: the tasks below, or a refusal with none.
    resolved: bool = False
    task_arns: set[str] = field(default_factory=set)
    # Tasks the release itself recorded as stopped.
    stopped: set[str] = field(default_factory=set)


def _failed_launches(events: list[dict[str, Any]]) -> list[_FailedLaunch] | None:
    """Every launch a release journaled and what it learned; ``None`` if the record is unclear.

    A retry reuses its launch's token, so all intents of one token are one launch.
    """
    launches: dict[str, _FailedLaunch] = {}
    latest: dict[str, _FailedLaunch] = {}
    for event in events:
        subject = event.get("subject")
        if event["kind"] == "intent" and event.get("action") == "run_task":
            token = event.get("token")
            if not isinstance(subject, str) or not isinstance(token, str) or not token:
                return None
            launch = launches.setdefault(token, _FailedLaunch(subject, token))
            if launch.subject != subject:
                return None
            latest[subject] = launch
        elif event["kind"] == "observation" and isinstance(subject, str):
            launch = latest.get(subject)
            result = event.get("result")
            if event.get("resolves") == "run_task":
                if result == "launched":
                    arns = [event.get("task_arn")]
                elif result in ("launched_multiple", "launched_unexpected"):
                    arns = event.get("task_arns")
                elif result == "launch_failed":
                    arns = []
                else:
                    return None
                if launch is None or not isinstance(arns, list):
                    return None
                recorded = [arn for arn in arns if isinstance(arn, str) and arn]
                if len(recorded) != len(arns):
                    return None
                launch.resolved = True
                launch.task_arns.update(recorded)
            elif launch is not None and result in RECORDED_STOPS:
                arn = event.get("task_arn")
                if isinstance(arn, str):
                    launch.stopped.add(arn)
    return list(launches.values())


def _unreconciled_predecessor(events: list[dict[str, Any]]) -> Any:
    """The release a rollback run was taking over from, unless it finished reconciling it."""
    named = None
    for event in events:
        if event["kind"] == "observation" and event.get("subject") == "environment":
            if event.get("result") == "failed_release_reconciled":
                return None
            if event.get("result") == "failed_release_named":
                named = event.get("failed_release_id")
        elif event["kind"] == "intent" and event.get("action") == "lock_handoff":
            named = event.get("from_release_id") if named is None else named
    return named


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
        ecs: EcsPort,
        evidence: EvidencePort,
        logs: LogPort,
        clock: Clock,
        tokens: Callable[[], str],
        session_id: str,
        handoff: FailedReleaseHandoff | None = None,
    ) -> None:
        self.loaded = loaded
        try:
            self.manifest = executable(loaded)
        except ReleaseRejected as error:
            # A schema-1 manifest is read and matched to its approval, never run.
            raise ReleaseHalted(error.code) from None
        self.approval = approval
        self.store = store
        self.ecs = ecs
        self.evidence = evidence
        self.logs = logs
        self.clock = clock
        self.tokens = tokens
        self.session_id = session_id
        self.handoff = handoff
        self.release_id = self.manifest.release_id
        # Every receipt names the release whose revisions run: for a rollback, the
        # retained prior release. Journal, lock, approval and launch tags use ours.
        self.evidence_id = self.manifest.evidence_release_id
        self.rollback_run = self.manifest.execution == "rollback"
        self.sequence = ROLLBACK_STATES if self.rollback_run else FORWARD_STATES
        self.cluster = self.manifest.environment.cluster_arn
        self.poll = self.manifest.window.poll_seconds
        self.journal = Journal(store, journal_key(self.release_id))
        self.lock = lock_key(self.manifest.environment.name)
        images = self.manifest.images
        self.digests = {
            "runtime": images.runtime.arm64_digest,
            "search": images.search.arm64_digest,
            "release_tools": images.release_tools.arm64_digest,
        }
        self.jobs = {job.id: job for job in self.manifest.jobs}
        # Once the Clock fails to vouch for time, this controller never trusts it again.
        self._clock_untrusted = False
        self.observers = [
            check for check in self.manifest.operational_checks if isinstance(check, ObserverCheck)
        ]
        # Everything this release launches with RunTask: database jobs and observers.
        self.launchables: dict[str, Job | ObserverCheck] = {
            **self.jobs,
            **{check.id: check for check in self.observers},
        }

    # Entry points ----------------------------------------------------------

    def run(self) -> Outcome:
        try:
            approval_error = self._approval_error()
            if approval_error not in (None, "approval_expired"):
                raise ReleaseHalted(str(approval_error))
            if not self._open(may_create=approval_error is None):
                return self._outcome()
        except ClockUntrusted:
            # Nothing recorded yet can anchor a hold; nothing was sent.
            raise ReleaseHalted("controller_clock_untrusted") from None
        steps = {
            State.PREPARED: self._lock_environment,
            State.LOCKED: self._quiesce,
            # Bootstrap jobs, when present, come first in the manifest's job order.
            State.QUIESCED: lambda: self._run_jobs({"bootstrap", "migrate"}, State.MIGRATED),
            State.MIGRATED: lambda: self._run_jobs({"grant", "proof"}, State.GRANTS_VERIFIED),
            State.GRANTS_VERIFIED: self._start_services,
            State.SERVICES_STARTED: self._verify_operational,
            State.OPERATIONAL_VERIFIED: self._finish,
        }
        if self.rollback_run:
            # The retained prior pair over the stated schemas: reconcile, prove,
            # then start and verify; never a migration, grant or bootstrap.
            steps = {
                State.PREPARED: self._lock_environment,
                State.LOCKED: self._quiesce,
                State.QUIESCED: lambda: self._run_jobs({"reconcile"}, State.RECONCILED),
                State.RECONCILED: lambda: self._run_jobs({"proof"}, State.PROVEN),
                State.PROVEN: self._start_services,
                State.SERVICES_STARTED: self._verify_operational,
                State.OPERATIONAL_VERIFIED: self._finish,
            }
        code: str | None = None
        try:
            self._require_clock_after_journal()
            if approval_error is not None:
                raise _Hold(approval_error)
            self._reconcile_outstanding()
            while self.state not in TERMINAL_STATES:
                steps[self.state]()
        except _Hold as hold:
            code = hold.code
        except ReleaseHalted:
            raise
        except ClockUntrusted:
            code = "controller_clock_untrusted"
        except AmbiguousResponse:
            # An uncertain read proves nothing either way.
            code = "observation_ambiguous"
        except Exception:
            # Any other port or evaluation error is uncertainty, never success.
            code = "controller_error"
        # Act outside the except blocks, so nothing journaled or raised from here
        # chains to the original error, which may quote provider or log content.
        if code is not None:
            if code == "controller_error" and self.state == State.HELD_PAUSED:
                raise ReleaseHalted("finalization_unconfirmed")
            if code in {"approval_expired", "release_window_exceeded"}:
                # Expiry forbids forward progress, not cleanup of this release's
                # already-launched work. Never retry a launch during cleanup.
                self._cleanup_expired_jobs()
            self._hold(code)
        return self._outcome()

    def abort(self) -> Outcome:
        """Operator abort: stop this release's own unfinished jobs, then hold.

        Nothing forward runs: no launch, deploy, scale-to-zero or promotion.
        Stopping the release's own job tasks is the same safety action as expiry
        cleanup, so it needs no current approval, only this session's exact lock
        (``recover`` first after a lost session). A finished release is unchanged.
        """
        if not self._load():
            raise ReleaseHalted("journal_missing")
        if self.journal.document.get("session_id") != self.session_id:
            raise ReleaseHalted("session_conflict")
        if self.state == State.HELD_PAUSED:
            return self._outcome()
        self._cleanup_expired_jobs()
        if self.state != State.HOLD:
            self._hold("operator_abort")
        return self._outcome()

    def recover(self, authorization: RecoveryAuthorization) -> None:
        """Transfer a lost session's journal and exact lock to this session.

        Nothing is executed here. The next ``run`` reconciles outstanding intents
        against real observations before taking any new action. A rollback session
        lost before its handoff never held a lock: the failed release's lock, at
        the exact ETag the operator saw, stays where it is, and the next ``run``
        hands it off under its own fenced handoff.
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
        # The takeover is journaled at a time read before the lock moves, so a
        # clock that cannot vouch for time refuses here with nothing written.
        taken_at = self._now()
        record = self._lock_record()
        if record is not None:
            body, etag = record
            if body.get("release_id") != self.release_id:
                if not self._failed_lock_untouched(body, etag, auth.lock_etag):
                    raise refused
            elif body.get("session_id") == auth.prior_session_id:
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
                at=taken_at,
                session_id=self.session_id,
            )

    def _failed_lock_untouched(self, body: dict[str, Any], etag: str, seen: str) -> bool:
        purpose = self.manifest.purpose
        return (
            isinstance(purpose, RollbackRun)
            and self.state == State.PREPARED
            and body.get("release_id") == purpose.failed_release_id
            and etag == seen
        )

    # Clock -----------------------------------------------------------------

    def _now(self) -> datetime:
        """Controller time; after one ``ClockUntrusted`` every later reading refuses too."""
        if self._clock_untrusted:
            raise ClockUntrusted("controller clock untrusted")
        try:
            return self.clock.now()
        except ClockUntrusted:
            self._clock_untrusted = True
            raise

    def _sleep(self, seconds: float) -> None:
        if self._clock_untrusted:
            raise ClockUntrusted("controller clock untrusted")
        try:
            self.clock.sleep(seconds)
        except ClockUntrusted:
            self._clock_untrusted = True
            raise

    # Journal ---------------------------------------------------------------

    def _approval_error(self) -> str | None:
        try:
            verify_approval(self.loaded, self.approval, self._now())
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
                "at": _iso(self._now()),
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

    def _append(
        self,
        event: dict[str, Any],
        *,
        safety: bool = False,
        at: datetime | None = None,
        **header: Any,
    ) -> dict[str, Any]:
        """Append one event. Without a trusted clock only safety events are written.

        Safety events are a hold transition, an observation, or a ``guard=False``
        intent (stopping the release's own job, releasing its lock). They are
        journaled at the latest time already recorded, marked ``clock_untrusted``,
        because that is only a lower bound. Anything else raises ``ClockUntrusted``
        and the run holds. ``at`` is a trusted reading the caller already took.
        """
        stamp: dict[str, Any]
        try:
            stamp = {"at": _iso(at if at is not None else self._now())}
        except ClockUntrusted:
            if not safety:
                raise
            latest = max(_time(item["at"]) for item in self.journal.events)
            stamp = {"at": _iso(latest), "clock_untrusted": True}
        try:
            return self.journal.append({**stamp, **event}, **header)
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
        check_transition(self.state, target, self.sequence)
        if target != State.HOLD:
            self._guard()
        self._append({"kind": "transition", "to": target.value, **data},
                     safety=target == State.HOLD)  # fmt: skip

    def _intent(self, action: str, subject: str, request: dict[str, Any], *, guard: bool = True,
                **data: Any) -> dict[str, Any]:  # fmt: skip
        if guard:
            self._guard()
        return self._append(
            {
                "kind": "intent",
                "action": action,
                "subject": subject,
                "request_sha256": canonical_sha256(request),
                **data,
            },
            safety=not guard,
        )

    def _observe(
        self, subject: str, result: str, *, resolves: str | None = None, **data: Any
    ) -> None:
        event = {"kind": "observation", "subject": subject, "result": result, **data}
        if resolves is not None:
            event["resolves"] = resolves
        self._append(event, safety=True)

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

    def _require_clock_after_journal(self) -> None:
        """A restarted or recovered controller's clock is never behind its journal.

        Deadlines are absolute journal times; a clock that reads earlier than an
        already recorded event would extend them.
        """
        latest = max(_time(event["at"]) for event in self.journal.events)
        if self._now() < latest:
            raise _Hold("controller_clock_rollback")

    def _window_deadline(self) -> datetime:
        started = _time(self._transitions()[0]["at"])
        window = self.manifest.window
        return min(started + timedelta(seconds=window.total_seconds), window.expires_at)

    def _guard(self, now: datetime | None = None) -> None:
        """Before each forward mutation intent or promotion: approval inside the window.

        Safety intents (stopping the release's own job, releasing the lock) are
        journaled with ``guard=False`` and never come here.
        """
        now = self._now() if now is None else now
        if now >= self.approval.approval.not_after:
            raise _Hold("approval_expired")
        if now >= self._window_deadline():
            raise _Hold("release_window_exceeded")

    def _authorize_send(self, intent: dict[str, Any]) -> None:
        """Immediately before sending a journaled launch or service update.

        The intent append, and any read that decided it, take time. Approval and
        the release window are checked again here, then a launch's original job
        deadline and token lifetime, or a forward deploy's original service-start
        deadline. Equality holds. A hold here leaves the journaled intent
        outstanding, so it counts as possibly sent. Scale-to-zero needs only the
        approval and window; safety stops and lock release never come here.
        """
        now = self._now()
        self._guard(now)
        if intent["action"] == "run_task":
            if now >= _time(intent["deadline_at"]) or now >= _time(intent["token_expires_at"]):
                raise _Hold("launch_outcome_unknown")
        elif intent["desired_count"] and now >= _time(intent["deadline_at"]):
            raise _Hold("service_update_unconfirmed")

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

    def _lock_body(self, **extra: Any) -> dict[str, Any]:
        return {
            "release_id": self.release_id,
            "session_id": self.session_id,
            "manifest_sha256": self.loaded.sha256,
            "acquired_at": _iso(self._now()),
            **extra,
        }

    def _acquire_free_lock(self) -> None:
        try:
            self.store.create(self.lock, encode(self._lock_body()))
        except PreconditionFailed:
            # No TTL or age-based stealing: only this exact session may continue.
            if not self._lock_is_ours():
                raise _Hold("environment_locked") from None

    def _lock_environment(self) -> None:
        if self.rollback_run:
            self._take_over_from_failed_release()
        else:
            self._acquire_free_lock()
        self._transition(State.LOCKED)

    # Rollback: failed-release handoff ---------------------------------------------

    def _failed_journal(self, release_id: Any = None) -> Journal:
        """A failed release's own journal, which must name it and this environment.

        Without an ID, the release this rollback run's manifest names as failed.
        """
        if release_id is None:
            purpose = self.manifest.purpose
            assert isinstance(purpose, RollbackRun)
            release_id = purpose.failed_release_id
        if not isinstance(release_id, str) or not release_id:
            raise _Hold("failed_release_unknown")
        failed = Journal(self.store, journal_key(release_id))
        if not failed.load():
            raise _Hold("failed_release_unknown")
        document = failed.document
        if (
            document.get("release_id") != release_id
            or document.get("environment") != self.manifest.environment.name
            or not isinstance(document.get("session_id"), str)
        ):
            raise _Hold("failed_release_unknown")
        return failed

    def _unreconciled_chain(self, failed: Journal) -> list[Journal]:
        """The failed release, then each earlier one whose reconciliation it left unfinished.

        A rollback run that stopped before recording ``failed_release_reconciled``
        never accounted for its own failed release. It still holds the lock, so a
        retry names it as the failed release and inherits that open reconciliation.
        """
        chain = [failed]
        seen = {failed.document["release_id"]}
        while (earlier := _unreconciled_predecessor(chain[-1].events)) is not None:
            if earlier in seen or len(chain) > MAX_UNRECONCILED_PREDECESSORS:
                raise _Hold("failed_release_unknown")
            chain.append(self._failed_journal(earlier))
            seen.add(earlier)
        return chain

    def _take_over_from_failed_release(self) -> None:
        """Take the environment from the failed release, never by stealing its lock.

        The failed release's journal is read first. If its lock is still held, it
        moves only by an exact conditional replace of the ETag the operator saw,
        under a handoff that names the failed journal's session and the evidence
        that it was fenced. A lock held by anyone else, or a missing lock while
        the failed release had not finished, holds. Every launch token the failed
        release journaled is then reconciled, with any task still running stopped,
        before anything else happens.
        """
        failed = self._failed_journal()
        failed_id = failed.document["release_id"]
        failed_session = failed.document["session_id"]
        if self._last("environment", "failed_release_named") is None:
            # Recorded before the lock moves: whoever takes over from this run
            # learns from its journal which release it had still to reconcile.
            self._observe("environment", "failed_release_named", failed_release_id=failed_id,
                          failed_session_id=failed_session)  # fmt: skip
        record = self._lock_record()
        if record is None:
            # Only a release that finished and released its lock leaves none behind.
            finished = [e for e in failed.events if e["kind"] == "observation"
                        and e["subject"] == "environment" and e["result"] == "lock_released"]  # fmt: skip
            if not finished:
                raise _Hold("failed_release_lock_missing")
            self._acquire_free_lock()
        else:
            body, etag = record
            owner = (body.get("release_id"), body.get("session_id"))
            if owner == (self.release_id, self.session_id):
                pass  # Already handed off to this session (a resumed run).
            elif owner == (failed_id, failed_session):
                self._hand_off_lock(failed_id, failed_session, etag)
            else:
                raise _Hold("environment_locked")
        chain = self._unreconciled_chain(failed)
        launches = stopped = 0
        unresolved: list[dict[str, Any]] = []
        for journal in chain:
            counted = self._sweep_failed_launches(journal, unresolved)
            launches, stopped = launches + counted[0], stopped + counted[1]
        if unresolved:
            # Whatever could be found was stopped. The rest is unknown, and unknown
            # holds: no schema is reconciled or proven and no service starts.
            self._observe("environment", "failed_launches_unresolved", launches=unresolved)
            raise _Hold("failed_release_unreconciled")
        self._observe("environment", "failed_launches_swept", tokens=launches, stopped=stopped)
        earlier = [{"release_id": journal.document["release_id"],
                    "journal_sha256": canonical_sha256(journal.document)}
                   for journal in chain[1:]]  # fmt: skip
        self._observe("environment", "failed_release_reconciled", failed_release_id=failed_id,
                      failed_session_id=failed_session,
                      failed_journal_sha256=canonical_sha256(failed.document),
                      **({"predecessors": earlier} if earlier else {}))  # fmt: skip

    def _hand_off_lock(self, failed_id: str, failed_session: str, etag: str) -> None:
        handoff = self.handoff
        if (
            handoff is None
            or handoff.failed_session_id != failed_session
            or handoff.lock_etag != etag
            or not SHA256.fullmatch(handoff.fence_evidence_sha256)
            or not handoff.authorized_by.strip()
        ):
            raise _Hold("handoff_refused")
        request = {"key": self.lock, "if_match": etag, "from_release_id": failed_id,
                   "from_session_id": failed_session}  # fmt: skip
        self._intent("lock_handoff", "environment", request, lock_etag=etag,
                     from_release_id=failed_id, from_session_id=failed_session,
                     fence_evidence_sha256=handoff.fence_evidence_sha256,
                     authorized_by=handoff.authorized_by)  # fmt: skip
        moved = self._lock_body(
            transferred_from={"release_id": failed_id, "session_id": failed_session}
        )
        # Approval and the window again after the intent write, as for every
        # forward send: a lapse leaves the intent outstanding and the lock unmoved.
        self._guard()
        try:
            self.store.replace(self.lock, encode(moved), if_match=etag)
        except PreconditionFailed:
            # Someone else moved it first: nothing of ours was written.
            self._observe("environment", "handoff_conflict", resolves="lock_handoff")
            raise _Hold("handoff_conflict") from None
        except AmbiguousResponse:
            self._confirm_handoff(failed_id, failed_session, etag)
            if not self._lock_is_ours():
                # A lost response for a replace that never landed: hold rather
                # than resend within this step.
                raise _Hold("handoff_unconfirmed") from None
            return
        self._observe("environment", "lock_handed_off", resolves="lock_handoff",
                      from_release_id=failed_id)  # fmt: skip

    def _confirm_handoff(self, failed_id: str, failed_session: str, etag: str) -> None:
        """After a crash or lost response: the lock is ours, untouched, or held."""
        record = self._lock_record()
        if record is not None and (record[0].get("release_id"), record[0].get("session_id")) == (
            self.release_id,
            self.session_id,
        ):
            self._observe("environment", "lock_handed_off", resolves="lock_handoff",
                          from_release_id=failed_id, reconciled=True)  # fmt: skip
            return
        if (
            record is not None
            and record[1] == etag
            and (
                record[0].get("release_id"),
                record[0].get("session_id"),
            )
            == (failed_id, failed_session)
        ):
            # The replace never landed: the failed lock is exactly as authorized,
            # so the same conditional handoff may be sent again.
            self._observe("environment", "handoff_not_applied", resolves="lock_handoff")
            return
        self._observe("environment", "handoff_conflict", resolves="lock_handoff")
        raise _Hold("handoff_conflict")

    def _sweep_failed_launches(
        self, failed: Journal, unresolved: list[dict[str, Any]]
    ) -> tuple[int, int]:
        """Account for every launch one failed release journaled, by positive evidence only.

        Each launch is settled by a task: one the release recorded, or one ECS
        lists under the launch token. A task ECS describes must carry that token
        and is stopped unless already stopped. A recorded task ECS no longer
        describes counts only if the release itself recorded seeing it stopped.
        A launch the provider refused, on record, has no task.

        Everything else is appended to ``unresolved``, above all a launch whose
        outcome was never learned and for which no task is found. That request
        may have been accepted with its task not listed yet, and such a task can
        still connect and write later. An empty listing, however often repeated,
        is not evidence that it does not exist. Returns the launches and stops.
        """
        release_id = failed.document["release_id"]
        launches = _failed_launches(failed.events)
        if launches is None:
            raise _Hold("failed_release_unreconciled")
        stopped = 0
        for launch in sorted(launches, key=lambda item: item.token):
            open_item = {"release_id": release_id, "subject": launch.subject,
                         "token": launch.token}  # fmt: skip
            listed = self.ecs.list_tasks(self.cluster, started_by=launch.token)
            arns = sorted(launch.task_arns.union(listed))
            if not arns and not launch.resolved:
                unresolved.append({**open_item, "reason": "outcome_unknown"})
            for arn in arns:
                task = self._describe_task(arn)
                if task is None:
                    if arn not in launch.stopped:
                        unresolved.append({**open_item, "reason": "task_not_described",
                                           "task_arn": arn})  # fmt: skip
                elif task.get("startedBy") != launch.token:
                    unresolved.append({**open_item, "reason": "task_identity_mismatch",
                                       "task_arn": arn})  # fmt: skip
                elif task.get("lastStatus") != "STOPPED":
                    self._stop_failed_task(arn, launch.token)
                    stopped += 1
        return len(launches), stopped

    def _stop_failed_task(self, arn: str, token: str) -> None:
        """A journaled safety stop of the failed release's own task, then confirmation."""
        subject = f"failed:{token}"
        request = {"cluster": self.cluster, "task": arn, "reason": "rollback of failed release"}
        self._intent("stop_task", subject, request, guard=False, task_arn=arn)
        try:
            self.ecs.stop_task(self.cluster, arn, request["reason"])
        except AmbiguousResponse:
            pass
        self._confirm_failed_stop(subject, arn)

    def _confirm_failed_stop(self, subject: str, arn: str) -> None:
        give_up = self._now() + FAILED_TASK_STOP_GRACE + STOP_CONFIRMATION_MARGIN
        while True:
            task = self._describe_task(arn)
            if task is not None and task.get("lastStatus") == "STOPPED":
                self._observe(subject, "stop_confirmed", resolves="stop_task", task_arn=arn,
                              sql_outcome="unknown")  # fmt: skip
                return
            if self._now() >= give_up:
                self._observe(subject, "stop_unconfirmed", resolves="stop_task", task_arn=arn,
                              sql_outcome="unknown")  # fmt: skip
                raise _Hold("failed_release_unreconciled")
            self._sleep(self.poll)

    # Reconciliation ------------------------------------------------------------

    def _reconcile_outstanding(self) -> None:
        for intent in self._outstanding():
            if intent["action"] == "run_task":
                self._reconcile_launch(self.launchables[intent["subject"]], intent)
            elif intent["action"] == "update_service":
                self._reconcile_update(intent)
            elif intent["action"] == "lock_handoff":
                self._confirm_handoff(intent["from_release_id"], intent["from_session_id"],
                                      intent["lock_etag"])  # fmt: skip
            elif intent["subject"].startswith("failed:"):
                # The stop may never have been sent: journal and send it again,
                # identically, then confirm. Like every safety stop it needs this
                # run's own lock, under which the sweep ran; without it nothing is
                # sent and the intent stays outstanding.
                if not self._lock_is_ours():
                    raise _Hold("lock_not_held")
                self._stop_failed_task(intent["task_arn"], intent["subject"].split(":", 1)[1])
            else:
                item = self.launchables[intent["subject"]]
                self._stop_after_deadline(item, intent["task_arn"], self._deadline_code(item))

    def _reconcile_launch(self, job: Job | ObserverCheck, intent: dict[str, Any]) -> None:
        """Find the task launched under this token, or retry the identical request."""
        request = self._launch_request(job, intent["token"])
        if canonical_sha256(request) != intent["request_sha256"]:
            raise ReleaseHalted("journal_integrity")
        for attempt in range(IDENTICAL_RETRIES + 1):
            arns = self.ecs.list_tasks(self.cluster, started_by=intent["token"])
            if len(arns) == 1:
                # A listing proves only the token; the task must be the approved one.
                task = self._describe_task(arns[0])
                for _ in range(VISIBILITY_POLLS - 1):
                    if task is not None:
                        break
                    # Briefly invisible right after launch is eventual consistency.
                    self._sleep(self.poll)
                    task = self._describe_task(arns[0])
                if task is None:
                    raise _Hold("launch_outcome_unknown")
                self._verify_launched(job, intent["token"], task, arns, reconciled=True)
                return
            if len(arns) > 1:
                self._observe(job.id, "launched_multiple", resolves="run_task", task_arns=arns,
                              reason="launch_task_count")  # fmt: skip
                raise _Hold("launch_task_count")
            # An eventually consistent empty listing is not proof that nothing launched.
            now = self._now()
            if (
                now >= _time(intent["token_expires_at"])
                or now >= _time(intent["deadline_at"])
                or attempt == IDENTICAL_RETRIES
            ):
                raise _Hold("launch_outcome_unknown")
            retry = self._intent(
                "run_task",
                job.id,
                request,
                token=intent["token"],
                issued_at=intent["issued_at"],
                deadline_at=intent["deadline_at"],
                token_expires_at=intent["token_expires_at"],
                retry_of=intent["sequence"],
            )
            self._authorize_send(retry)
            try:
                response = self.ecs.run_task(request)
            except AmbiguousResponse:
                self._sleep(self.poll)
                continue
            self._accept_launch(job, retry, response)
            return

    def _reconcile_update(self, intent: dict[str, Any]) -> None:
        """Confirm a service update from observations, or reissue the identical update."""
        key, desired = intent["subject"], intent["desired_count"]
        request = self._scale_request(key) if desired == 0 else self._deploy_request(key)
        if canonical_sha256(request) != intent["request_sha256"]:
            raise ReleaseHalted("journal_integrity")
        prior = intent.get("prior_deployments", [])
        deadline = _time(intent["deadline_at"])
        for attempt in range(IDENTICAL_RETRIES + 1):
            for _ in range(VISIBILITY_POLLS):
                if self._update_observed(key, desired, prior):
                    return
                self._sleep(self.poll)
            if self._now() >= deadline or attempt == IDENTICAL_RETRIES:
                raise _Hold("service_update_unconfirmed")
            # Decide the identical resend on a fresh observation, not one a poll old.
            if self._update_observed(key, desired, prior):
                return
            # That read and the journal write each take time: a forward resend is
            # never sent at or after the original service-start deadline, and no
            # resend after approval or the window ends. The limit of identical
            # resends applies per reconciliation.
            self._before_forward_deadline(desired, deadline)
            retry = self._intent(
                "update_service",
                key,
                request,
                desired_count=desired,
                prior_deployments=prior,
                deadline_at=intent["deadline_at"],
                retry_of=intent["sequence"],
            )
            self._authorize_send(retry)
            try:
                response = self.ecs.update_service(request)
            except AmbiguousResponse:
                continue
            # A resend response reporting drift holds, whatever later reads say.
            service = response.get("service") or {}
            if desired and service and service_settings_drift(service):
                raise _Hold("service_settings_drift")

    def _before_forward_deadline(self, desired: int, deadline: datetime) -> None:
        # Scaling to zero keeps only the approval and release-window guard.
        if desired and self._now() >= deadline:
            raise _Hold("service_update_unconfirmed")

    def _update_observed(self, key: str, desired: int, prior: list[str]) -> bool:
        """One observation of a pending service update; True once it is recorded.

        A forward deployment is never recognized or resent while ECS reports, for
        any service, Terraform-owned settings other than the approved ones: the
        hold comes before any further forward action, whether or not the lost
        request was applied. Scaling to zero is the safe direction and drift
        never blocks it.
        """
        services = self._describe_services()
        service = services[key]
        if desired == 0:
            if service.get("desiredCount") != 0:
                return False
            self._observe(key, "scaled_to_zero", resolves="update_service", reconciled=True)
            return True
        _hold_on_drift(services)
        deployment = self._new_deployment(key, service, prior)
        if deployment is None:
            return False
        self._observe(key, "service_deployed", resolves="update_service",
                      deployment_id=deployment, reconciled=True)  # fmt: skip
        return True

    # Quiesce -------------------------------------------------------------------

    def _service_arn(self, key: str) -> str:
        return getattr(self.manifest.environment.services, key)

    def _describe_services(self) -> dict[str, dict[str, Any]]:
        arns = [self._service_arn(key) for key in SERVICE_KEYS]
        found = {
            item.get("serviceArn"): item for item in self.ecs.describe_services(self.cluster, arns)
        }
        if set(found) != set(arns):
            raise _Hold("service_missing")
        return {key: found[self._service_arn(key)] for key in SERVICE_KEYS}

    def _scale_request(self, key: str) -> dict[str, Any]:
        return {"cluster": self.cluster, "service": self._service_arn(key), "desiredCount": 0}

    def _quiesce(self) -> None:
        services = self._describe_services()
        rollback = self.manifest.rollback
        purpose = self.manifest.purpose
        if isinstance(purpose, RollbackRun) and isinstance(rollback, CompatibleRelease):
            # A rollback finds each service on the prior revision or on the failed
            # release's own, as the approved manifest names it; anything else is
            # not this environment's known state.
            for key, service in services.items():
                known = {
                    getattr(rollback.services, key).task_definition,
                    getattr(purpose.failed_services, key),
                }
                if service.get("taskDefinition") not in known:
                    raise _Hold("rollback_service_revision_unknown")
        elif isinstance(rollback, CompatibleRelease):
            for key, service in services.items():
                if service.get("taskDefinition") != getattr(rollback.services, key).task_definition:
                    raise _Hold("prior_release_mismatch")
        elif any(
            service.get("desiredCount")
            or service.get("runningCount")
            or service.get("pendingCount")
            for service in services.values()
        ):
            # A running environment has a prior binary; never invent an empty one.
            raise _Hold("upgrade_requires_compatible_rollback")
        deadline = _iso(self._window_deadline())
        for key, service in services.items():
            if service.get("desiredCount"):
                request = self._scale_request(key)
                intent = self._intent(
                    "update_service", key, request, desired_count=0, deadline_at=deadline
                )
                # Quiescing is authorized work: only approval and the window bind it.
                self._authorize_send(intent)
                try:
                    self.ecs.update_service(request)
                except AmbiguousResponse:
                    self._reconcile_update(intent)
                    continue
                self._observe(key, "scaled_to_zero", resolves="update_service")
        while not all(
            not service.get("desiredCount") and not service.get("runningCount") and not service.get("pendingCount")
            for service in self._describe_services().values()
        ):  # fmt: skip
            self._guard()
            self._sleep(self.poll)
        # Every task not yet stopped is a possible writer. One that ECS still
        # intends to run is unaccounted for; one already stopping must finish.
        while arns := self.ecs.list_tasks(self.cluster):
            tasks = self.ecs.describe_tasks(self.cluster, arns).get("tasks") or []
            if any(task.get("desiredStatus") != "STOPPED" for task in tasks):
                raise _Hold("standalone_writer_present")
            self._guard()
            self._sleep(self.poll)
        self._transition(State.QUIESCED)

    # Jobs ----------------------------------------------------------------------

    def _launch_request(self, job: Job | ObserverCheck, token: str) -> dict[str, Any]:
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

    def _run_jobs(self, phases: set[str], target: State) -> None:
        for job in self.manifest.jobs:
            if job.phase not in phases or self._last(job.id, "job_succeeded") is not None:
                continue
            if self._last(job.id, "launched") is None:
                refused = self._last(job.id, *REFUSED_LAUNCHES)
                if refused is not None:
                    # Its hold may never have been journaled: never launch again.
                    raise _Hold(refused.get("reason", "launch_not_accepted"))
                self._launch(job)
            self._await_job(job)
        self._transition(target)

    def _launch(self, job: Job | ObserverCheck) -> None:
        token = self.tokens()
        if not TOKEN.fullmatch(token):
            raise ReleaseHalted("invalid_launch_token")
        request = self._launch_request(job, token)
        now = self._now()
        deadline = min(now + timedelta(seconds=job.deadline_seconds), self._window_deadline())
        intent = self._intent(
            "run_task",
            job.id,
            request,
            token=token,
            issued_at=_iso(now),
            deadline_at=_iso(deadline),
            token_expires_at=_iso(token_expires_at(now, job.deadline_seconds)),
        )
        self._authorize_send(intent)
        try:
            response = self.ecs.run_task(request)
        except AmbiguousResponse:
            self._reconcile_launch(job, intent)
            return
        self._accept_launch(job, intent, response)

    def _accept_launch(
        self, job: Job | ObserverCheck, intent: dict[str, Any], response: dict[str, Any]
    ) -> None:
        tasks = response.get("tasks") or []
        failures = response.get("failures") or []
        if failures and not tasks:
            self._observe(job.id, "launch_failed", resolves="run_task",
                          failure_count=len(failures), reason="launch_failed")  # fmt: skip
            raise _Hold("launch_failed")
        if failures or not tasks:
            raise _Hold("launch_response_incomplete")
        arns = [str(task.get("taskArn")) for task in tasks]
        if len(tasks) != 1:
            self._observe(job.id, "launched_multiple", resolves="run_task", task_arns=arns,
                          reason="launch_task_count")  # fmt: skip
            raise _Hold("launch_task_count")
        self._verify_launched(job, intent["token"], tasks[0], arns)

    def _verify_launched(
        self, job: Job | ObserverCheck, token: str, task: dict[str, Any], arns: list[str],
        **data: Any,
    ) -> None:  # fmt: skip
        """Record the launch only for the approved revision under this token, unmodified."""
        if (
            task.get("taskDefinitionArn") != job.task.task_definition
            or task.get("startedBy") != token
        ):
            reason: str | None = "job_identity_mismatch"
        else:
            # The request carried no overrides; a task reporting any did not run
            # the reviewed revision as approved.
            reason = task_runtime_issue(task)
        if reason is not None:
            self._observe(job.id, "launched_unexpected", resolves="run_task", task_arns=arns,
                          reason=reason)  # fmt: skip
            arn = task.get("taskArn")
            if task.get("startedBy") == token and arn and task.get("lastStatus") != "STOPPED":
                # Launched under this release's token but not as approved: stop it
                # rather than leave it running under the job's role.
                self._stop_job(job, str(arn), "release job launched outside its approved shape")
            raise _Hold(reason)
        self._observe(job.id, "launched", resolves="run_task", task_arn=arns[0], **data)

    def _describe_task(self, arn: str) -> dict[str, Any] | None:
        tasks = self.ecs.describe_tasks(self.cluster, [arn]).get("tasks") or []
        return next((task for task in tasks if task.get("taskArn") == arn), None)

    @staticmethod
    def _deadline_code(item: Job | ObserverCheck) -> str:
        return "job_deadline_exceeded" if isinstance(item, Job) else "operational_deadline_exceeded"

    def _await_launched(
        self,
        item: Job | ObserverCheck,
        settle: Callable[[dict[str, Any], str, str, datetime], tuple[str | None, dict[str, Any]]],
        *,
        missing: str,
        succeeded: str,
        failed: str,
        **outcome: Any,
    ) -> None:
        """Poll the launched task to STOPPED and settle it inside its recorded deadline.

        ``settle`` reads and evaluates the task's own receipt; ``missing`` keeps
        waiting. At the deadline a live or unseen task receives a journaled stop.
        """
        intent = self._last_intent("run_task", item.id)
        launched = self._last(item.id, "launched")
        assert launched is not None
        arn = launched["task_arn"]
        deadline = _time(intent["deadline_at"])
        code = self._deadline_code(item)
        while True:
            self._guard()
            # A missing task is eventual consistency, not proof that it never ran.
            task = self._describe_task(arn)
            now = self._now()
            if now >= deadline:
                if task is None or task.get("lastStatus") != "STOPPED":
                    self._stop_after_deadline(item, arn, code)
                self._observe(item.id, failed, task_arn=arn, reason=code, **outcome)
                raise _Hold(code)
            self._guard()
            if task is not None and task.get("lastStatus") == "STOPPED":
                failure, data = settle(task, arn, intent["token"], deadline)
                if failure is None:
                    self._observe(item.id, succeeded, task_arn=arn, **data)
                    return
                if failure != missing:
                    self._observe(item.id, failed, task_arn=arn, reason=failure)
                    raise _Hold(failure)
            self._sleep(self.poll)

    def _await_job(self, job: Job) -> None:
        def settle(task: dict[str, Any], arn: str, token: str,
                   deadline: datetime) -> tuple[str | None, dict[str, Any]]:  # fmt: skip
            receipt = self.evidence.job_receipt(self.evidence_id, job.id, arn)
            # There is no trusted completion timestamp in this port contract.
            # Even a timely task needs its complete receipt before the deadline.
            if self._now() >= deadline:
                self._observe(job.id, "job_failed", task_arn=arn,
                              reason="job_deadline_exceeded", sql_outcome="unknown")  # fmt: skip
                raise _Hold("job_deadline_exceeded")
            self._guard()
            failure = evaluate_job(
                job, self.digests, release_id=self.evidence_id, token=token, task=task,
                receipt=receipt,
            )  # fmt: skip
            if failure is not None:
                return failure, {}
            return None, {"receipt_sha256": canonical_sha256(receipt)}

        self._await_launched(job, settle, missing="job_receipt_missing", succeeded="job_succeeded",
                             failed="job_failed", sql_outcome="unknown")  # fmt: skip

    @staticmethod
    def _sql_unknown(item: Job | ObserverCheck) -> dict[str, str]:
        """A stopped or unseen database job may have run SQL; an observer runs none."""
        return {"sql_outcome": "unknown"} if isinstance(item, Job) else {}

    def _stop_after_deadline(self, item: Job | ObserverCheck, arn: str, code: str) -> None:
        """Request a stop and confirm it. A stopped client never proves SQL stopped."""
        self._stop_job(item, arn, "release job deadline exceeded")
        raise _Hold(code)

    def _cleanup_expired_jobs(self) -> None:
        """Best-effort safety cleanup only; no launch retry or success promotion.

        An empty listing or failed observation leaves SQL outcome unknown and
        needs operator reconciliation. It never proves that nothing ran.
        """
        try:
            owns_lock = self._lock_is_ours()
        except Exception:
            # No ownership proof means no stop authority. Persist the uncertainty
            # if journal CAS is still available; its failure remains a hard halt.
            self._observe("environment", "cleanup_unconfirmed", sql_outcome="unknown")
            return
        if not owns_lock:
            return
        for job in self.launchables.values():
            intents = [e for e in self.journal.events
                       if e["kind"] == "intent" and e["action"] == "run_task"
                       and e["subject"] == job.id]  # fmt: skip
            if (
                not intents
                or self._last(job.id, "job_succeeded", "operational_passed", "launch_failed")
                is not None
            ):
                continue
            intent = intents[-1]
            try:
                launched = self._last(job.id, "launched")
                arns = ([launched["task_arn"]] if launched else
                        self.ecs.list_tasks(self.cluster, started_by=intent["token"]))  # fmt: skip
                if not arns:
                    self._observe(job.id, "cleanup_unconfirmed", **self._sql_unknown(job))
                for arn in arns:
                    task = self._describe_task(arn)
                    if task is None or (
                        task.get("taskDefinitionArn") != job.task.task_definition
                        or task.get("startedBy") != intent["token"]
                    ):
                        self._observe(job.id, "cleanup_unconfirmed", **self._sql_unknown(job))
                        continue
                    if task.get("lastStatus") != "STOPPED":
                        self._stop_job(job, arn, "release authorization window expired")
                    else:
                        self._observe(job.id, "cleanup_stopped", task_arn=arn,
                                      **self._sql_unknown(job))  # fmt: skip
            except ReleaseHalted:
                raise
            except Exception:
                self._observe(job.id, "cleanup_unconfirmed", **self._sql_unknown(job))

    def _stop_job(self, job: Job | ObserverCheck, arn: str, reason: str) -> None:
        request = {"cluster": self.cluster, "task": arn, "reason": reason}
        # Stopping the release's own job is a covered safety action, even after expiry.
        self._intent("stop_task", job.id, request, guard=False, task_arn=arn)
        try:
            self.ecs.stop_task(self.cluster, arn, reason)
        except AmbiguousResponse:
            pass
        give_up = self._now() + timedelta(seconds=job.stop_grace_seconds) + STOP_CONFIRMATION_MARGIN
        while True:
            task = self._describe_task(arn)
            if task is not None and task.get("lastStatus") == "STOPPED":
                self._observe(job.id, "stop_confirmed", resolves="stop_task", task_arn=arn,
                              **self._sql_unknown(job))  # fmt: skip
                break
            if self._now() >= give_up:
                self._observe(job.id, "stop_unconfirmed", task_arn=arn, **self._sql_unknown(job))
                break
            self._sleep(self.poll)

    # Services ------------------------------------------------------------------

    def _deploy_request(self, key: str) -> dict[str, Any]:
        # Only the controller-owned fields. Terraform alone writes deployment
        # settings and Exec; resending any part of them could reset the rest.
        return {
            "cluster": self.cluster,
            "service": self._service_arn(key),
            "taskDefinition": getattr(self.manifest.services, key).task_definition,
            "desiredCount": 1,
            # A fresh deployment ID: tasks of an older deployment never count.
            "forceNewDeployment": True,
        }

    def _new_deployment(self, key: str, service: dict[str, Any], prior: list[str]) -> str | None:
        definition = getattr(self.manifest.services, key).task_definition
        for deployment in service.get("deployments") or []:
            if (
                deployment.get("status") == "PRIMARY"
                and deployment.get("taskDefinition") == definition
                and deployment.get("id") not in prior
            ):
                return str(deployment["id"])
        return None

    def _deployment_id(self, key: str) -> str | None:
        event = self._last(key, "service_deployed")
        return None if event is None else event["deployment_id"]

    def _start_services(self) -> None:
        for key in SERVICE_KEYS:  # Runtime first, API paused, worker last.
            if self._last(key, "service_ready") is not None:
                continue
            deployment = self._deployment_id(key) or self._deploy(key)
            self._await_service(key, deployment)
        self._transition(State.SERVICES_STARTED)

    def _deploy(self, key: str) -> str:
        services = self._describe_services()
        # Verify, never write, the Terraform-owned settings the release relies on.
        _hold_on_drift(services)
        service = services[key]
        prior = [str(item.get("id")) for item in service.get("deployments") or []]
        request = self._deploy_request(key)
        now = self._now()
        deadline = min(now + timedelta(seconds=self.manifest.window.service_start_seconds),
                       self._window_deadline())  # fmt: skip
        intent = self._intent("update_service", key, request, desired_count=1,
                              prior_deployments=prior, deadline_at=_iso(deadline))  # fmt: skip
        # A slow journal write must not carry the send past approval, the window
        # or the deadline it just recorded.
        self._authorize_send(intent)
        service: dict[str, Any] = {}
        try:
            response = self.ecs.update_service(request)
            service = response.get("service") or {}
            deployment = self._new_deployment(key, service, prior)
        except AmbiguousResponse:
            deployment = None
        # A response reporting drifted settings is never recognized or reconciled.
        if service and service_settings_drift(service):
            raise _Hold("service_settings_drift")
        if deployment is None:
            self._reconcile_update(intent)
            return str(self._deployment_id(key))
        self._observe(key, "service_deployed", resolves="update_service", deployment_id=deployment)
        return deployment

    def _service_snapshot(self, key: str, deployment: str) -> tuple[str, str, list[str]]:
        service = self._describe_services()[key]
        arns = self.ecs.list_tasks(
            self.cluster, service_name=self._service_arn(key).rsplit("/", 1)[1]
        )
        described = self.ecs.describe_tasks(self.cluster, arns) if arns else {"tasks": []}
        if described.get("failures"):
            return "waiting", "task_enumeration_incomplete", arns
        spec = getattr(self.manifest.services, key)
        status, detail = evaluate_service(
            spec, self.digests, service, described["tasks"], deployment
        )
        return status, detail, arns

    def _await_service(self, key: str, deployment: str) -> None:
        deadline = _time(self._last_intent("update_service", key)["deadline_at"])
        while True:
            status, detail, _ = self._service_snapshot(key, deployment)
            # One snapshot is several calls: readiness must still be inside the deadline.
            late = self._now() >= deadline
            if status == "ready" and not late:
                self._observe(key, "service_ready", deployment_id=deployment, task_arn=detail)
                return
            if status == "failed":
                raise _Hold(detail)
            if late:
                raise _Hold("service_start_deadline_exceeded" if status == "ready" else detail)
            self._sleep(self.poll)

    def _verify_operational(self) -> None:
        recorded = {}
        for key in SERVICE_KEYS:
            ready = self._last(key, "service_ready")
            assert ready is not None
            recorded[key] = ready["task_arn"]
        self._require_recorded_tasks(recorded)
        # One observer per target, then the worker gate (every attempt a new epoch);
        # each starts from the recorded tasks.
        for check in self.observers:
            self._run_observer(check, recorded)
        self._await_worker_readiness(WORKER_READINESS_CHECK, recorded)
        # Re-enumerate immediately before success: a replacement needs a fresh window.
        self._require_recorded_tasks(recorded)
        self._transition(State.OPERATIONAL_VERIFIED)

    def _service_address(self, task_arn: str) -> str:
        """The recorded service task's one ENI address; anything else is not known."""
        address = task_network_address(self._describe_task(task_arn), self.manifest.network.subnets)
        if address is None:
            raise _Hold("service_network_identity_unknown")
        return address

    def _run_observer(self, check: ObserverCheck, recorded: dict[str, str]) -> None:
        """Launch the check's observer task and bind its receipt to the recorded task.

        The receipt must come from this observer task, about the target's private
        name and port, naming the one address it actually connected to; that
        address must be the recorded service task's network interface, observed
        before the launch and again after the observer stopped, with every
        recorded service still in place. DNS answering from another healthy task
        holds; so does a recorded task without exactly one known address.
        """
        if self._last(check.id, "operational_passed") is not None:
            return
        target = recorded[check.target]
        peer = self._service_address(target)
        if self._last(check.id, "launched") is None:
            refused = self._last(check.id, *REFUSED_LAUNCHES)
            if refused is not None:
                raise _Hold(refused.get("reason", "launch_not_accepted"))
            self._launch(check)

        def settle(task: dict[str, Any], arn: str, token: str,
                   deadline: datetime) -> tuple[str | None, dict[str, Any]]:  # fmt: skip
            issue = evaluate_task(check.task, self.digests, token=token, task=task)
            if issue is not None:
                return issue, {}
            receipt = self.evidence.operational_receipt(self.evidence_id, check.id, arn)
            self._require_recorded_tasks(recorded)
            if self._service_address(target) != peer:
                raise _Hold("task_replaced")
            if self._now() >= deadline:
                self._observe(check.id, "operational_failed", task_arn=arn,
                              reason="operational_deadline_exceeded")  # fmt: skip
                raise _Hold("operational_deadline_exceeded")
            self._guard()
            failure = evaluate_observation(check, release_id=self.evidence_id, task_arn=arn,
                                           peer=peer, receipt=receipt)  # fmt: skip
            if failure is not None:
                return failure, {}
            assert receipt is not None
            return None, {"receipt_sha256": canonical_sha256(receipt), "peer": peer,
                          "service_task_arn": target}  # fmt: skip

        self._await_launched(check, settle, missing="operational_evidence_missing",
                             succeeded="operational_passed", failed="operational_failed")  # fmt: skip

    def _await_worker_readiness(self, check_id: str, recorded: dict[str, str]) -> None:
        """Observe the recorded worker task's own receipts for one bounded gate attempt.

        Identity comes from ECS: the recorded deployment and task, whose revision
        and image digests ``evaluate_service`` checks on every poll, and the fixed
        app-container stream derived from that task. Each attempt is a new epoch;
        resumed attempts keep the first attempt's deadline. Missing logs, denied or
        incomplete reads and ECS visibility loss only clear stability, so they end
        as not proven at the deadline. Platform identity changes hold at once.
        """
        policy = READINESS_POLICY
        task_arn = recorded["worker"]
        deployment = self._deployment_id("worker")
        assert deployment is not None
        group, stream = worker_stream(self.manifest.environment.name, self.evidence_id, task_arn)
        epoch = self._now()
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
        self._observe(check_id, "readiness_observing", task_arn=task_arn,
                      epoch_at=_iso(epoch), deadline_at=_iso(deadline))  # fmt: skip
        gate = ReadinessGate(policy, release_id=self.evidence_id, epoch_start=epoch,
                             task_arn=task_arn)  # fmt: skip
        start = epoch - timedelta(seconds=policy.max_future_skew_seconds)
        token: str | None = None
        latest = epoch

        def observed_now() -> datetime:
            # Deadlines and freshness assume the clock never moves backwards.
            nonlocal latest
            current = self._now()
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
                self._observe(check_id, "readiness_not_proven", task_arn=task_arn,
                              last_reason=reason, receipts=gate.received)  # fmt: skip
                raise _Hold("worker_readiness_not_proven")
            try:
                read = read_stream(self.logs, group, stream, token=token, start=start, end=now,
                                   policy=policy)  # fmt: skip
            except Exception:
                # Denied, missing or malformed reads prove nothing for this poll.
                # Visibility was lost until the read returned, however long it took.
                gate.clear("readiness_logs_unavailable", observed_now())
            else:
                token = read.token
                gate.ingest(read.messages, now)
                if not read.complete:
                    gate.clear("readiness_logs_incomplete", observed_now())
            status, detail, arns = self._service_snapshot("worker", deployment)
            if status == "failed" or detail == "task_count_drift":
                raise _Hold(detail)
            if task_arn not in arns or (status == "ready" and detail != task_arn):
                raise _Hold("task_replaced")
            if status != "ready":
                gate.clear(detail, observed_now())  # when ECS was observed
            elif gate.stable(observed_now()):
                # Re-enumerate every recorded service immediately before success;
                # success still needs the deadline and fresh receipts after it.
                self._require_recorded_tasks(recorded)
                checked = observed_now()
                if checked < deadline and gate.stable(checked):
                    self._guard()
                    self._observe(check_id, "operational_passed", task_arn=task_arn,
                                  last_reset=gate.reason, **gate.summary())  # fmt: skip
                    return
            self._sleep(self.poll)

    def _require_recorded_tasks(self, recorded: dict[str, str]) -> None:
        for key in SERVICE_KEYS:
            deployment = self._deployment_id(key)
            assert deployment is not None
            status, detail, arns = self._service_snapshot(key, deployment)
            if status == "ready" and detail == recorded[key]:
                continue
            if recorded[key] not in arns or status == "ready":
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
                                 guard=False, lock_etag=etag, session_id=self.session_id)  # fmt: skip
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
            and event["action"] == "update_service"
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
