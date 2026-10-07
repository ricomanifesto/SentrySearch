"""Attended release controller: journal intent, act, then prove the outcome.

The controller runs one approved manifest to ``held_paused`` or stops in
``hold`` with a bounded reason. It never enables admission, retries blindly,
steals a lock or treats a partial observation as success. All AWS access goes
through ports; this module contains no SDK, credential or network code.
"""

from __future__ import annotations

from collections.abc import Callable
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
    CompatibleRelease,
    Job,
    LoadedApproval,
    LoadedManifest,
    ReleaseRejected,
    canonical_sha256,
    verify_approval,
)
from release.ports import AmbiguousResponse, Clock, EcsPort, EvidencePort, LogPort
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
        ecs: EcsPort,
        evidence: EvidencePort,
        logs: LogPort,
        clock: Clock,
        tokens: Callable[[], str],
        session_id: str,
    ) -> None:
        self.loaded = loaded
        self.manifest = loaded.manifest
        self.approval = approval
        self.store = store
        self.ecs = ecs
        self.evidence = evidence
        self.logs = logs
        self.clock = clock
        self.tokens = tokens
        self.session_id = session_id
        self.release_id = self.manifest.release_id
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

    # Entry points ----------------------------------------------------------

    def run(self) -> Outcome:
        approval_error = self._approval_error()
        if approval_error not in (None, "approval_expired"):
            raise ReleaseHalted(str(approval_error))
        if not self._open(may_create=approval_error is None):
            return self._outcome()
        steps = {
            State.PREPARED: self._lock_environment,
            State.LOCKED: self._quiesce,
            State.QUIESCED: lambda: self._run_jobs({"migrate"}, State.MIGRATED),
            State.MIGRATED: lambda: self._run_jobs({"grant", "proof"}, State.GRANTS_VERIFIED),
            State.GRANTS_VERIFIED: self._start_services,
            State.SERVICES_STARTED: self._verify_operational,
            State.OPERATIONAL_VERIFIED: self._finish,
        }
        try:
            if approval_error is not None:
                raise _Hold(approval_error)
            self._reconcile_outstanding()
            while self.state not in TERMINAL_STATES:
                steps[self.state]()
        except _Hold as hold:
            if hold.code in {"approval_expired", "release_window_exceeded"}:
                # Expiry forbids forward progress, not cleanup of this release's
                # already-launched work. Never retry a launch during cleanup.
                self._cleanup_expired_jobs()
            self._hold(hold.code)
        except ReleaseHalted:
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
            verify_approval(self.loaded, self.approval, self.clock.now())
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
        for intent in self._outstanding():
            if intent["action"] == "run_task":
                self._reconcile_launch(self.jobs[intent["subject"]], intent)
            elif intent["action"] == "update_service":
                self._reconcile_update(intent)
            else:
                self._stop_after_deadline(self.jobs[intent["subject"]], intent["task_arn"])

    def _reconcile_launch(self, job: Job, intent: dict[str, Any]) -> None:
        """Find the task launched under this token, or retry the identical request."""
        request = self._launch_request(job, intent["token"])
        if canonical_sha256(request) != intent["request_sha256"]:
            raise ReleaseHalted("journal_integrity")
        for attempt in range(IDENTICAL_RETRIES + 1):
            arns = self.ecs.list_tasks(self.cluster, started_by=intent["token"])
            if len(arns) == 1:
                self._observe(
                    job.id, "launched", resolves="run_task", task_arn=arns[0], reconciled=True
                )
                return
            if len(arns) > 1:
                self._observe(job.id, "launched_multiple", resolves="run_task", task_arns=arns)
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
                "run_task",
                job.id,
                request,
                token=intent["token"],
                issued_at=intent["issued_at"],
                deadline_at=intent["deadline_at"],
                token_expires_at=intent["token_expires_at"],
                retry_of=intent["sequence"],
            )
            try:
                response = self.ecs.run_task(request)
            except AmbiguousResponse:
                self.clock.sleep(self.poll)
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
        for attempt in range(IDENTICAL_RETRIES + 1):
            for _ in range(VISIBILITY_POLLS):
                service = self._describe_services()[key]
                if desired == 0 and service.get("desiredCount") == 0:
                    self._observe(key, "scaled_to_zero", resolves="update_service", reconciled=True)
                    return
                deployment = self._new_deployment(key, service, prior) if desired == 1 else None
                if deployment is not None:
                    self._observe(key, "service_deployed", resolves="update_service",
                                  deployment_id=deployment, reconciled=True)  # fmt: skip
                    return
                self.clock.sleep(self.poll)
            if self.clock.now() >= _time(intent["deadline_at"]) or attempt == IDENTICAL_RETRIES:
                raise _Hold("service_update_unconfirmed")
            self._intent(
                "update_service",
                key,
                request,
                desired_count=desired,
                prior_deployments=prior,
                deadline_at=intent["deadline_at"],
                retry_of=intent["sequence"],
            )
            try:
                self.ecs.update_service(request)
            except AmbiguousResponse:
                continue

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
        if isinstance(rollback, CompatibleRelease):
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
            self.clock.sleep(self.poll)
        # Any remaining task in the cluster is an unaccounted writer.
        if self.ecs.list_tasks(self.cluster):
            raise _Hold("standalone_writer_present")
        self._transition(State.QUIESCED)

    # Jobs ----------------------------------------------------------------------

    def _launch_request(self, job: Job, token: str) -> dict[str, Any]:
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
                self._launch(job)
            self._await_job(job)
        self._transition(target)

    def _launch(self, job: Job) -> None:
        token = self.tokens()
        if not TOKEN.fullmatch(token):
            raise ReleaseHalted("invalid_launch_token")
        request = self._launch_request(job, token)
        now = self.clock.now()
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
        try:
            response = self.ecs.run_task(request)
        except AmbiguousResponse:
            self._reconcile_launch(job, intent)
            return
        self._accept_launch(job, intent, response)

    def _accept_launch(self, job: Job, intent: dict[str, Any], response: dict[str, Any]) -> None:
        tasks = response.get("tasks") or []
        failures = response.get("failures") or []
        if failures and not tasks:
            self._observe(job.id, "launch_failed", resolves="run_task", failure_count=len(failures))
            raise _Hold("launch_failed")
        if failures or not tasks:
            raise _Hold("launch_response_incomplete")
        arns = [str(task.get("taskArn")) for task in tasks]
        if len(tasks) != 1:
            self._observe(job.id, "launched_multiple", resolves="run_task", task_arns=arns)
            raise _Hold("launch_task_count")
        task = tasks[0]
        if (
            task.get("taskDefinitionArn") != job.task.task_definition
            or task.get("startedBy") != intent["token"]
        ):
            self._observe(job.id, "launched_unexpected", resolves="run_task", task_arns=arns)
            raise _Hold("job_identity_mismatch")
        self._observe(job.id, "launched", resolves="run_task", task_arn=arns[0])

    def _describe_task(self, arn: str) -> dict[str, Any] | None:
        tasks = self.ecs.describe_tasks(self.cluster, [arn]).get("tasks") or []
        return next((task for task in tasks if task.get("taskArn") == arn), None)

    def _await_job(self, job: Job) -> None:
        intent = self._last_intent("run_task", job.id)
        launched = self._last(job.id, "launched")
        assert launched is not None
        arn = launched["task_arn"]
        deadline = _time(intent["deadline_at"])
        while True:
            self._guard()
            # A missing task is eventual consistency, not proof that it never ran.
            task = self._describe_task(arn)
            now = self.clock.now()
            if now >= deadline:
                if task is None or task.get("lastStatus") != "STOPPED":
                    self._stop_after_deadline(job, arn)
                self._observe(job.id, "job_failed", task_arn=arn,
                              reason="job_deadline_exceeded", sql_outcome="unknown")  # fmt: skip
                raise _Hold("job_deadline_exceeded")
            self._guard()
            if task is not None and task.get("lastStatus") == "STOPPED":
                receipt = self.evidence.job_receipt(self.release_id, job.id, arn)
                # There is no trusted completion timestamp in this port contract.
                # Even a timely task needs its complete receipt before the deadline.
                if self.clock.now() >= deadline:
                    self._observe(job.id, "job_failed", task_arn=arn,
                                  reason="job_deadline_exceeded", sql_outcome="unknown")  # fmt: skip
                    raise _Hold("job_deadline_exceeded")
                self._guard()
                failure = evaluate_job(
                    job, self.digests, release_id=self.release_id, token=intent["token"],
                    task=task, receipt=receipt,
                )  # fmt: skip
                if failure is None:
                    self._observe(job.id, "job_succeeded", task_arn=arn,
                                  receipt_sha256=canonical_sha256(receipt))  # fmt: skip
                    return
                if failure != "job_receipt_missing":
                    self._observe(job.id, "job_failed", task_arn=arn, reason=failure)
                    raise _Hold(failure)
            self.clock.sleep(self.poll)

    def _stop_after_deadline(self, job: Job, arn: str) -> None:
        """Request a stop and confirm it. A stopped client never proves SQL stopped."""
        self._stop_job(job, arn, "release job deadline exceeded")
        raise _Hold("job_deadline_exceeded")

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
        for job in self.manifest.jobs:
            intents = [e for e in self.journal.events
                       if e["kind"] == "intent" and e["action"] == "run_task"
                       and e["subject"] == job.id]  # fmt: skip
            if not intents or self._last(job.id, "job_succeeded", "launch_failed") is not None:
                continue
            intent = intents[-1]
            try:
                launched = self._last(job.id, "launched")
                arns = ([launched["task_arn"]] if launched else
                        self.ecs.list_tasks(self.cluster, started_by=intent["token"]))  # fmt: skip
                if not arns:
                    self._observe(job.id, "cleanup_unconfirmed", sql_outcome="unknown")
                for arn in arns:
                    task = self._describe_task(arn)
                    if task is None or (
                        task.get("taskDefinitionArn") != job.task.task_definition
                        or task.get("startedBy") != intent["token"]
                    ):
                        self._observe(job.id, "cleanup_unconfirmed", sql_outcome="unknown")
                        continue
                    if task.get("lastStatus") != "STOPPED":
                        self._stop_job(job, arn, "release authorization window expired")
                    else:
                        self._observe(job.id, "cleanup_stopped", task_arn=arn,
                                      sql_outcome="unknown")  # fmt: skip
            except ReleaseHalted:
                raise
            except Exception:
                self._observe(job.id, "cleanup_unconfirmed", sql_outcome="unknown")

    def _stop_job(self, job: Job, arn: str, reason: str) -> None:
        request = {"cluster": self.cluster, "task": arn, "reason": reason}
        # Stopping the release's own job is a covered safety action, even after expiry.
        self._intent("stop_task", job.id, request, guard=False, task_arn=arn)
        try:
            self.ecs.stop_task(self.cluster, arn, reason)
        except AmbiguousResponse:
            pass
        give_up = (
            self.clock.now() + timedelta(seconds=job.stop_grace_seconds) + STOP_CONFIRMATION_MARGIN
        )
        while True:
            task = self._describe_task(arn)
            if task is not None and task.get("lastStatus") == "STOPPED":
                self._observe(job.id, "stop_confirmed", resolves="stop_task", task_arn=arn,
                              sql_outcome="unknown")  # fmt: skip
                break
            if self.clock.now() >= give_up:
                self._observe(job.id, "stop_unconfirmed", task_arn=arn, sql_outcome="unknown")
                break
            self.clock.sleep(self.poll)

    # Services ------------------------------------------------------------------

    def _deploy_request(self, key: str) -> dict[str, Any]:
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
        prior = [
            str(item.get("id")) for item in self._describe_services()[key].get("deployments") or []
        ]
        request = self._deploy_request(key)
        now = self.clock.now()
        deadline = min(now + timedelta(seconds=self.manifest.window.service_start_seconds),
                       self._window_deadline())  # fmt: skip
        intent = self._intent("update_service", key, request, desired_count=1,
                              prior_deployments=prior, deadline_at=_iso(deadline))  # fmt: skip
        try:
            response = self.ecs.update_service(request)
            deployment = self._new_deployment(key, response.get("service") or {}, prior)
        except AmbiguousResponse:
            deployment = None
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
            if status == "ready":
                self._observe(key, "service_ready", deployment_id=deployment, task_arn=detail)
                return
            if status == "failed" or self.clock.now() >= deadline:
                raise _Hold(detail)
            self.clock.sleep(self.poll)

    def _verify_operational(self) -> None:
        recorded = {}
        for key in SERVICE_KEYS:
            ready = self._last(key, "service_ready")
            assert ready is not None
            recorded[key] = ready["task_arn"]
        self._require_recorded_tasks(recorded)
        for check in self.manifest.operational_checks:
            if check.id == WORKER_READINESS_CHECK:
                self._await_worker_readiness(check.id, recorded)
                continue
            receipt = self.evidence.operational_receipt(self.release_id, check.id)
            if receipt is None:
                raise _Hold("operational_evidence_missing")
            wanted = {
                "schema": check.receipt_schema,
                "release_id": self.release_id,
                "check_id": check.id,
                "status": "passed",
                "tasks": recorded,
            }
            if dict(receipt) != wanted:
                raise _Hold("operational_receipt_mismatch")
            self._observe(check.id, "operational_passed", receipt_sha256=canonical_sha256(receipt))
        # Re-enumerate immediately before success: a replacement needs a fresh window.
        self._require_recorded_tasks(recorded)
        self._transition(State.OPERATIONAL_VERIFIED)

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
        group, stream = worker_stream(self.manifest.environment.name, self.release_id, task_arn)
        epoch = self.clock.now()
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
        gate = ReadinessGate(policy, release_id=self.release_id, epoch_start=epoch,
                             task_arn=task_arn)  # fmt: skip
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
            self.clock.sleep(self.poll)

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
