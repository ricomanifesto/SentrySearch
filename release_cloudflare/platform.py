"""The Cloudflare release platform: the controller's operations on Workers and Durable Objects.

The controller (``release/controller.py``) owns the journal, lock, guards,
deadlines, retries, reconciliation and holds; this module only builds requests
that can be rebuilt from their intents, sends them and classifies what it
observes (CF-D015, CF-D016, design checkpoint DESIGN.md §2 and §13):

- **Services** are the named objects ``runtime-0``, ``api-0`` and ``worker-0``.
  A quiesce is a stop bound to the live start's nonce; a start is
  ``start-<key>-<release>``, at most once per service per release. Identity comes
  from the object (object id, start nonce, release, Worker version, image) and
  the container application's instance listing, never from the container.
- **Jobs** run in ``job-<release>-<job>`` objects under the launch token as their
  command id; success needs the object's natural ``exit 0``, no signal, the
  exact identity and image and the job's own Cloudflare receipt.
- **Activation** deploys a Worker's manifest version at 100% only from exactly
  its prior version (``version/<worker>`` subjects; jobs before the first job,
  services and the edge before the first service start).
- **Authority:** commands carry the session and its fence; the signed expiry is
  exactly the intent's ``command_expires_at`` and nothing is transmitted after
  ``min(command_expires_at, deadline_at)``. Refusals are classified by code.

Hypotheses H-V1/H-V2 (image map and the account APIs) are proven only against
fakes here. No Cloudflare SDK, credential or network code: the ports are
injected.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime, timedelta, timezone
import json
import re
from typing import Any
import uuid

from release.ports import (
    AmbiguousResponse,
    Deploy,
    JournalNames,
    Launch,
    PlatformHold,
    ServiceView,
    SessionAuthority,
    SessionSuperseded,
)
from release.readiness import WORKER_RECEIPT_MARKER, GatePolicy, LogRead
from release_cloudflare.control_client import CommandNotSent, ControlReply, TransportAmbiguous
from release_cloudflare.manifest import (
    AUTHORITY_PROTOCOL,
    CONTAINER_WORKERS,
    OBJECT_NAMES,
    WORKERS,
    CompatibleRelease,
    Job,
    LoadedManifest,
    Manifest,
    expected_job_receipt,
    verify_approval,
)
from release_cloudflare.ports import ControlPort, ReceiptPort, VersionsPort

COMMAND_LIFETIME = timedelta(seconds=120)
READ_LIFETIME = timedelta(seconds=60)
MAX_INSTANCE_PAGES = 20
ACTIVE = "active"
PRIOR = "prior"
LIVE = ("starting", "running", "draining")
WANTED = ("starting", "running")
ACTIVATION_STAGES = {
    "jobs": ("version/jobs",),
    "services": ("version/runtime", "version/api", "version/worker", "version/edge"),
}
OBJECT_ID = re.compile(r"[0-9a-f]{64}")
NONCE = re.compile(r"[0-9a-f]{32}")
# Refusal codes that only say the command was already applied or ran.
APPLIED_EARLIER = frozenset({"replayed", "already_run"})


class _Refused(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value)


def run_id(object_id: str, start_nonce: str) -> str:
    return f"{object_id}/{start_nonce}"


def _split(run: str) -> tuple[str, str]:
    object_id, _, nonce = run.partition("/")
    return object_id, nonce


class CloudflarePlatform:
    names = JournalNames(
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
    count_drift = "instance_count_drift"
    request_fields: tuple[str, ...] = ("start_nonce",)

    def __init__(
        self,
        loaded: LoadedManifest,
        *,
        control: ControlPort,
        versions: VersionsPort,
        receipts: ReceiptPort,
        clock: Any,
        read_ids: Callable[[], str] = lambda: uuid.uuid4().hex,
    ) -> None:
        manifest = loaded.manifest
        if not isinstance(manifest, Manifest):
            raise TypeError("a Cloudflare manifest is required")
        self.manifest: Manifest = manifest
        self.manifest_sha256 = loaded.sha256
        self.control = control
        self.versions = versions
        self.receipts = receipts
        self.clock = clock
        self.read_ids = read_ids
        self.release_id = manifest.release_id
        self.scripts = {w: getattr(manifest.environment.workers, w) for w in WORKERS}
        self.version = {w: getattr(manifest.versions, w) for w in WORKERS}
        rollback = manifest.rollback
        prior = rollback.versions if isinstance(rollback, CompatibleRelease) else None
        source = prior or manifest.environment.bootstrap_versions
        self.prior_version = {w: getattr(source, w) for w in WORKERS}
        self.authority: SessionAuthority | None = None

    # Approval and authority ---------------------------------------------------------

    def verify_approval(self, loaded: Any, approval: Any, now: datetime) -> None:
        verify_approval(loaded, approval, now)

    def bind(self, authority: SessionAuthority) -> None:
        self.control.bind(authority.session_id, authority.fence)
        self.authority = authority

    def command_fields(self) -> dict[str, Any]:
        return {"command_expires_at": _iso(self.clock.now() + COMMAND_LIFETIME)}

    # Sending and reading --------------------------------------------------------------

    def _limits(self, intent: Mapping[str, Any]) -> tuple[datetime, datetime | None]:
        try:
            expires = _time(intent["command_expires_at"])
            deadline = _time(intent["deadline_at"]) if "deadline_at" in intent else None
        except (KeyError, TypeError, ValueError):
            raise PlatformHold("command_window_invalid") from None
        return expires, deadline

    def _command(self, request: Mapping[str, Any], intent: Mapping[str, Any]) -> dict[str, Any]:
        """Send one journaled command; refusals raise ``_Refused`` with their code."""
        expires, deadline = self._limits(intent)
        try:
            reply = self.control.send(
                method="POST",
                service=request["service"],
                name=request["object"],
                action=request["action"],
                body=request["body"],
                command_id=self._command_id(request, intent),
                expires_at=expires,
                send_before=deadline,
            )
        except CommandNotSent as error:
            raise _Refused("not_sent") from error
        except TransportAmbiguous:
            raise AmbiguousResponse("control reply lost") from None
        return self._classify(reply)

    @staticmethod
    def _command_id(request: Mapping[str, Any], intent: Mapping[str, Any]) -> str:
        """The command id: the request's own for starts and runs (deduplicated by
        the object), a per-send id for stops.

        A stop names its start nonce and is idempotent by itself; a fresh id per
        journaled send lets a stop that found the start still starting be sent
        again instead of being refused as a replay (CF05-R19).
        """
        if "command_id" in request:
            return str(request["command_id"])
        return f"stop-{request['body']['start_nonce']}-{intent['sequence']}"

    def _classify(self, reply: ControlReply) -> dict[str, Any]:
        body = reply.body
        if 200 <= reply.status < 300 and body is not None:
            return body
        code = reply.code
        if reply.status == 409 and code == "superseded":
            raise SessionSuperseded()
        if reply.status in (400, 401, 403, 404, 409, 413) and isinstance(code, str):
            raise _Refused(code)
        # A 5xx, an unparseable reply or an uncoded refusal proves nothing.
        raise AmbiguousResponse(f"control reply {reply.status}")

    def _read(
        self, service: str, name: str, action: str, body: Mapping[str, Any] | None = None
    ) -> dict[str, Any]:
        """A signed read; anything but a clean answer proves nothing."""
        try:
            reply = self.control.send(
                method="GET" if body is None else "POST",
                service=service,
                name=name,
                action=action,
                body=body,
                command_id=f"read-{self.read_ids()}",
                expires_at=self.clock.now().replace(microsecond=0) + READ_LIFETIME,
            )
        except (CommandNotSent, TransportAmbiguous):
            raise AmbiguousResponse("control read failed") from None
        try:
            return self._classify(reply)
        except _Refused as refused:
            if refused.code == "another_release":
                # Code that predates the authority protocol refuses a next release's reads.
                raise PlatformHold("prior_protocol_unsupported") from None
            raise AmbiguousResponse(f"control read refused: {refused.code}") from None

    def _status(self, service: str, name: str) -> dict[str, Any]:
        status = self._read(service, name, "status")
        if status.get("control_protocol") != AUTHORITY_PROTOCOL:
            raise PlatformHold("prior_protocol_unsupported")
        if not isinstance(status.get("object_id"), str) or not OBJECT_ID.fullmatch(
            status["object_id"]
        ):
            raise PlatformHold("instance_identity_invalid")
        return status

    # Services ----------------------------------------------------------------------------

    def services(self) -> dict[str, ServiceView]:
        views = {}
        for key, name in OBJECT_NAMES.items():
            status = self._status(key, name)
            if status.get("service") != key:
                raise PlatformHold("instance_identity_invalid")
            start = status.get("start") or None
            state = None if start is None else start.get("state")
            views[key] = ServiceView(
                wants_running=state in WANTED,
                active=bool(status.get("running")) or state in LIVE,
                raw={"status": status},
            )
        return views

    @staticmethod
    def _start(view: ServiceView) -> dict[str, Any] | None:
        return view.raw["status"].get("start") or None

    def prior_matches(self, key: str, view: ServiceView) -> bool:
        rollback = self.manifest.rollback
        assert isinstance(rollback, CompatibleRelease)
        deployment = self.versions.deployment(self.scripts[key])
        start = self._start(view)
        live = start is not None and start.get("state") in LIVE
        return deployment.exactly(getattr(rollback.versions, key)) and (
            not live or start.get("release_id") == rollback.release_id
        )

    def prior_generations(self, key: str, view: ServiceView) -> list[str]:
        start = self._start(view)
        return [] if start is None else [str(start.get("start_nonce"))]

    def scale_fields(self, key: str, view: ServiceView) -> dict[str, Any]:
        start = self._start(view)
        assert start is not None
        return {"start_nonce": start["start_nonce"]}

    def scale_request(self, key: str, fields: Mapping[str, Any]) -> dict[str, Any]:
        nonce = fields["start_nonce"]
        if not isinstance(nonce, str) or not NONCE.fullmatch(nonce):
            raise ValueError("start nonce")
        return {
            "service": key,
            "object": OBJECT_NAMES[key],
            "action": "stop",
            "body": {"start_nonce": nonce},
        }

    def scaled_down(self, key: str, view: ServiceView, intent: Mapping[str, Any]) -> bool:
        start = self._start(view)
        return not (
            start is not None
            and start.get("start_nonce") == intent["start_nonce"]
            and start.get("state") in WANTED
        )

    def send_update(self, request: dict[str, Any], intent: Mapping[str, Any]) -> Any:
        try:
            reply = self._command(request, intent)
        except _Refused as refused:
            if refused.code == "not_sent" or refused.code in APPLIED_EARLIER:
                raise AmbiguousResponse(refused.code) from None
            if refused.code == "version_mismatch":
                return {"refused": "version_mismatch"}
            raise PlatformHold("command_refused") from None
        if (
            request["action"] == "stop"
            and reply.get("stopping") is False
            and reply.get("state") in WANTED
        ):
            # The named start is still wanted and nothing was signalled (it may
            # still be starting): only an observation can resolve the stop.
            raise AmbiguousResponse("stop did not take effect")
        return reply

    def idle(self, views: Mapping[str, ServiceView]) -> bool:
        return all(not view.active for view in views.values())

    def _instances(self, worker: str) -> list[Mapping[str, Any]] | None:
        """The application's complete instance listing, or None if it is incomplete."""
        application = getattr(self.manifest.applications, worker).id
        found: list[Mapping[str, Any]] = []
        cursor: str | None = None
        for _ in range(MAX_INSTANCE_PAGES):
            try:
                page = self.versions.instances(application, cursor=cursor)
            except AmbiguousResponse:
                return None
            found.extend(page.instances)
            if page.next is None:
                return found
            cursor = page.next
        return None

    @staticmethod
    def _running(instances: list[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
        # Anything not explicitly stopped may be writing.
        return [item for item in instances if item.get("state") != "stopped"]

    def writers_present(self) -> bool:
        for worker in CONTAINER_WORKERS:
            listing = self._instances(worker)
            if listing is None:
                raise PlatformHold("instance_listing_incomplete")
            if self._running(listing):
                return True
        return False

    def deploy_fields(self, key: str, view: ServiceView) -> dict[str, Any]:
        return {}

    def deploy_request(self, key: str, fields: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "service": key,
            "object": OBJECT_NAMES[key],
            "action": "start",
            "body": {"release_id": self.release_id, "version_id": self.version[key]},
            "command_id": f"start-{key}-{self.release_id}",
        }

    def deploy(self, key: str, request: dict[str, Any], intent: Mapping[str, Any],
               prior: list[str]) -> Deploy:  # fmt: skip
        try:
            reply = self._command(request, intent)
        except _Refused as refused:
            if refused.code == "not_sent" or refused.code in APPLIED_EARLIER:
                raise AmbiguousResponse(refused.code) from None
            if refused.code == "version_mismatch":
                return Deploy(None, "version_drift")
            raise PlatformHold("command_refused") from None
        drift = self.response_drift(key, reply)
        if drift is not None:
            return Deploy(None, drift)
        nonce = reply.get("start_nonce")
        if (
            not reply.get("abandoned")
            and reply.get("command_id") == request["command_id"]
            and isinstance(nonce, str)
            and nonce not in prior
            and reply.get("state") in WANTED
        ):
            return Deploy(nonce)
        # Not started (abandoned, or another start holds the object): observe.
        return Deploy(None)

    def new_generation(self, key: str, view: ServiceView, prior: list[str],
                       intent: Mapping[str, Any]) -> str | None:  # fmt: skip
        start = self._start(view)
        if (
            start is not None
            and start.get("command_id") == f"start-{key}-{self.release_id}"
            and start.get("release_id") == self.release_id
            and start.get("start_nonce") not in prior
        ):
            return str(start["start_nonce"])
        return None

    def _application_drift(self, worker: str) -> bool:
        spec = getattr(self.manifest.applications, worker)
        state = self.versions.application(spec.id)
        return (
            state.id != spec.id
            or state.scheduling_policy != spec.scheduling_policy
            or state.instance_type != spec.instance_type
            or state.ssh_enabled is not False
            or state.logs_enabled is not False
            or tuple(state.images) != tuple(spec.images)
        )

    def drift(self, views: Mapping[str, ServiceView] | None) -> str | None:
        for worker in WORKERS:
            if not self.versions.deployment(self.scripts[worker]).exactly(self.version[worker]):
                return "deployment_drift"
        for worker in CONTAINER_WORKERS:
            if self._application_drift(worker):
                return "application_drift"
        views = self.services() if views is None else views
        for key, view in views.items():
            start = self._start(view)
            if start is not None and start.get("state") in LIVE:
                if (start.get("release_id"), start.get("version_id")) != (
                    self.release_id,
                    self.version[key],
                ):
                    return "version_drift"
        return None

    def response_drift(self, key: str, response: Any) -> str | None:
        if not isinstance(response, Mapping):
            return "start_reply_invalid"
        if response.get("refused") == "version_mismatch":
            return "version_drift"
        version = response.get("version_id")
        if version is not None and version != self.version[key]:
            return "version_drift"
        if (
            response.get("started") is False
            and not response.get("replayed")
            and not response.get("abandoned")
            and response.get("start_nonce") is not None
        ):
            # Another live start holds this object: not this release's start.
            return "start_conflict"
        return None

    def activation_drift(self, subject: str) -> str | None:
        worker = self._worker(subject)
        if worker in CONTAINER_WORKERS and self._application_drift(worker):
            return "application_drift"
        return None

    def launch_drift(self, job: Job) -> str | None:
        if not self.versions.deployment(self.scripts["jobs"]).exactly(self.version["jobs"]):
            return "deployment_drift"
        if self._application_drift("jobs"):
            return "application_drift"
        return None

    def service_snapshot(self, key: str, generation: str) -> tuple[str, str, list[str]]:
        status = self._status(key, OBJECT_NAMES[key])
        start = status.get("start") or None
        current = None if start is None else run_id(status["object_id"], start["start_nonce"])
        live = start is not None and start.get("state") in LIVE and bool(status.get("running"))
        runs = [current] if live and current is not None else []
        if start is None:
            return "waiting", "deployment_not_visible", runs
        if start.get("start_nonce") != generation:
            return "failed", "deployment_superseded", runs
        if (start.get("release_id"), start.get("version_id"), status.get("version_id")) != (
            self.release_id,
            self.version[key],
            self.version[key],
        ):
            return "failed", "version_mismatch", runs
        image = getattr(self.manifest.images, "runtime" if key == "runtime" else "search")
        if start.get("image") != f"{image.repository}@{image.amd64_digest}":
            return "failed", "instance_image_mismatch", runs
        if start.get("state") == "starting":
            return "waiting", "instance_not_running", runs
        if start.get("state") != "running" or not status.get("running"):
            return "failed", "instance_stopped", runs
        listing = self._instances(key)
        if listing is None:
            return "waiting", "instance_enumeration_incomplete", runs
        if [item.get("durable_object_id") for item in self._running(listing)] != [
            status["object_id"]
        ]:
            return "waiting", self.count_drift, runs
        if status.get("health") != "healthy":
            return "waiting", "instance_unhealthy", runs
        assert current is not None
        return "ready", current, runs

    # Activation --------------------------------------------------------------------------

    @staticmethod
    def _worker(subject: str) -> str:
        prefix, _, worker = subject.partition("/")
        if prefix != "version" or worker not in WORKERS:
            raise ValueError("activation subject")
        return worker

    def activations(self, stage: str) -> tuple[str, ...]:
        return ACTIVATION_STAGES.get(stage, ())

    def activation_request(self, subject: str) -> dict[str, Any]:
        worker = self._worker(subject)
        return {
            "script": self.scripts[worker],
            "version_id": self.version[worker],
            "percentage": 100,
        }

    def activation_state(self, subject: str) -> str:
        worker = self._worker(subject)
        deployment = self.versions.deployment(self.scripts[worker])
        if deployment.exactly(self.version[worker]):
            return ACTIVE
        if deployment.exactly(self.prior_version[worker]):
            return PRIOR
        return "deployment_drift"

    def activate(self, subject: str, request: dict[str, Any], intent: Mapping[str, Any]) -> str:
        expires, deadline = self._limits(intent)
        authority = self.authority
        message = f"sentry release {self.release_id}"
        if authority is not None:
            message += f" session {authority.session_id} fence {authority.fence}"
        try:
            deployment = self.versions.deploy(
                request["script"],
                request["version_id"],
                message=message,
                not_after=expires if deadline is None else min(expires, deadline),
            )
        except CommandNotSent:
            raise AmbiguousResponse("deploy not sent") from None
        return ACTIVE if deployment.exactly(request["version_id"]) else "deployment_drift"

    # Jobs --------------------------------------------------------------------------------

    def _job_object(self, job: Job) -> str:
        return f"job-{self.release_id}-{job.id}"

    def launch_request(self, job: Job, token: str) -> dict[str, Any]:
        return {
            "service": "jobs",
            "object": self._job_object(job),
            "action": "run",
            "body": {
                "job_id": job.id,
                "phase": job.phase,
                "database": job.database,
                "image": job.image,
                "deadline_seconds": job.deadline_seconds,
            },
            "command_id": token,
        }

    def launch(self, job: Job, request: dict[str, Any], intent: Mapping[str, Any]) -> Launch:
        first = "retry_of" not in intent
        try:
            reply = self._command(request, intent)
        except _Refused as refused:
            if refused.code in APPLIED_EARLIER or not first:
                # The original may have applied: only an observation can tell.
                raise AmbiguousResponse(refused.code) from None
            # Nothing was sent, or the object definitively refused the only copy.
            return Launch(runs=(), failed=1)
        if reply.get("abandoned"):
            # The object dropped its claim before starting anything; every other
            # copy of this command has expired (it was signed earlier) or will
            # meet the object's run-once rule: definitively not started.
            return Launch(runs=(), failed=1)
        object_id, nonce = reply.get("object_id"), reply.get("start_nonce")
        if not (
            isinstance(object_id, str)
            and OBJECT_ID.fullmatch(object_id)
            and isinstance(nonce, str)
            and NONCE.fullmatch(nonce)
        ):
            raise AmbiguousResponse("run reply without identity")
        return Launch(
            runs=(run_id(object_id, nonce),),
            unexpected=reply.get("command_id") != intent["token"],
        )

    def _job_status(self, job: Job) -> dict[str, Any]:
        return self._status("jobs", self._job_object(job))

    def runs_for(self, job: Job, token: str) -> list[str]:
        status = self._job_status(job)
        row = status.get("job")
        if isinstance(row, Mapping) and row.get("command_id") == token:
            return [run_id(status["object_id"], str(row.get("start_nonce")))]
        return []

    def describe_run(self, job: Job, run: str) -> dict[str, Any] | None:
        object_id, nonce = _split(run)
        status = self._job_status(job)
        row = status.get("job")
        if not isinstance(row, Mapping) or status["object_id"] != object_id:
            return None
        if row.get("start_nonce") != nonce:
            return None
        return {**row, "object_id": object_id, "running": bool(status.get("running"))}

    def run_stopped(self, view: Mapping[str, Any]) -> bool:
        return view.get("state") not in ("running", "signalled") and not view.get("running")

    def run_matches(self, job: Job, token: str, view: Mapping[str, Any]) -> bool:
        return view.get("command_id") == token and view.get("job") == job.id

    def evaluate_job(self, job: Job, token: str, view: Mapping[str, Any] | None,
                     receipt: Mapping[str, Any] | None) -> str | None:  # fmt: skip
        if view is None:
            return "job_run_missing"
        if not self.run_stopped(view):
            return "job_not_stopped"
        if not self.run_matches(job, token, view) or view.get("version_id") != self.version["jobs"]:
            return "job_identity_mismatch"
        image = getattr(self.manifest.images, job.image)
        if view.get("image") != f"{image.repository}@{image.amd64_digest}":
            return "job_image_mismatch"
        if view.get("signalled_at") is not None or view.get("state") != "exited":
            return "job_stopped_abnormally"
        if view.get("exit_detail") != "exit 0":
            return "job_container_failed"
        if receipt is None:
            return "job_receipt_missing"
        wanted = expected_job_receipt(
            job, self.release_id, str(view["object_id"]), str(view.get("start_nonce"))
        )
        if dict(receipt) != wanted:
            return "job_receipt_mismatch"
        return None

    def job_receipt(self, job: Job, run: str) -> dict[str, Any] | None:
        _, nonce = _split(run)
        reply = self._read("jobs", self._job_object(job), "receipt", {"start_nonce": nonce})
        receipt = reply.get("receipt")
        if reply.get("start_nonce") != nonce or not isinstance(receipt, dict):
            return None
        return receipt

    def stop_request(self, job: Job, run: str, reason: str) -> dict[str, Any]:
        _, nonce = _split(run)
        return {
            "service": "jobs",
            "object": self._job_object(job),
            "action": "stop",
            "body": {"start_nonce": nonce},
        }

    def send_stop(self, request: dict[str, Any], intent: Mapping[str, Any]) -> None:
        try:
            self._command(request, intent)
        except _Refused as refused:
            if refused.code == "not_sent" or refused.code in APPLIED_EARLIER:
                raise AmbiguousResponse(refused.code) from None
            raise PlatformHold("command_refused") from None

    # Operational evidence ------------------------------------------------------------------

    def operational_receipt(self, check_id: str) -> dict[str, Any] | None:
        return self.receipts.operational_receipt(self.release_id, check_id)

    def expected_operational(self, check: Any, recorded: Mapping[str, str]) -> dict[str, Any]:
        return {
            "schema": check.receipt_schema,
            "release_id": self.release_id,
            "check_id": check.id,
            "status": "passed",
            "instances": dict(recorded),
        }

    def worker_reader(self, run: str, generation: str) -> _ObjectReceiptReader:
        _, nonce = _split(run)
        if nonce != generation or not NONCE.fullmatch(nonce):
            raise ValueError("worker run and generation disagree")
        return _ObjectReceiptReader(self, generation)


class _ObjectReceiptReader:
    """The worker object's receipts for one start, paged from a cursor (CF-D015).

    Each receipt is fed to the unchanged gate as a marked line. A read is
    incomplete when it stops at the page or byte bound, when receipts after the
    cursor were evicted, or when the store reports conflicts or refused boots;
    the gate then clears stability for that poll.
    """

    def __init__(self, platform: CloudflarePlatform, start_nonce: str) -> None:
        self.platform = platform
        self.start_nonce = start_nonce

    def read(
        self, *, token: str | None, start: datetime, end: datetime, policy: GatePolicy
    ) -> LogRead:
        after = int(token or 0)
        messages: list[str] = []
        size = 0
        complete = True
        for _ in range(policy.max_pages):
            page = self.platform._read(
                "worker",
                OBJECT_NAMES["worker"],
                "receipts",
                {"start_nonce": self.start_nonce, "after": after, "limit": policy.page_limit},
            )
            if page.get("startNonce") != self.start_nonce:
                raise ValueError("receipt page for another start")
            receipts, following = page.get("receipts"), page.get("next")
            evicted, conflicts, refused = (
                page.get("evictedAfterCursor"),
                page.get("duplicatesConflicting"),
                page.get("refusedBoots"),
            )
            # Every completeness field must be present with its type: a missing
            # one never reads as clean (CF05-R20).
            if (
                not isinstance(receipts, list)
                or type(following) is not int
                or type(page.get("more")) is not bool
                or type(evicted) is not bool
                or type(conflicts) is not int
                or type(refused) is not int
            ):
                raise ValueError("malformed receipt page")
            if evicted or conflicts or refused:
                complete = False
            for receipt in receipts:
                line = f"{WORKER_RECEIPT_MARKER} " + json.dumps(receipt, separators=(",", ":"))
                size += len(line.encode())
                if size > policy.max_bytes:
                    return LogRead(messages, str(after), False)
                messages.append(line)
            after = following
            if not page.get("more"):
                return LogRead(messages, str(after), complete)
        return LogRead(messages, str(after), False)


def upload_version(
    versions: VersionsPort,
    script: str,
    *,
    tag: str,
    message: str,
    bundle_sha256: str,
    not_after: datetime,
) -> str:
    """Upload a Worker version at most once per bundle (a prepare step, before approval).

    The message must carry the bundle's SHA-256, and only a version with this tag
    and this exact message is reused, so a tag never stands for another bundle.
    After a lost upload reply the listing decides; two matching versions hold,
    because either could be the one the manifest names.
    """
    if bundle_sha256 not in message:
        raise ValueError("the version message must carry the bundle digest")

    def tagged() -> list[Any]:
        return [
            item
            for item in versions.versions(script)
            if item.tag == tag and item.message == message
        ]

    found = tagged()
    if len(found) > 1:
        raise PlatformHold("version_upload_ambiguous")
    if found:
        return str(found[0].id)
    try:
        return str(
            versions.upload(
                script, tag=tag, message=message, bundle_sha256=bundle_sha256, not_after=not_after
            ).id
        )
    except (AmbiguousResponse, CommandNotSent):
        found = tagged()
    if len(found) == 1:
        return str(found[0].id)
    raise PlatformHold("version_upload_ambiguous" if found else "version_upload_unconfirmed")
