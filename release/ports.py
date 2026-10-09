"""Narrow ports the controller depends on. No implementation here talks to a cloud.

``ReleasePlatform`` is the provider-neutral strategy the controller drives. The
ECS strategy (``release.controller.EcsPlatform``) is built from ``EcsPort``,
``EvidencePort`` and ``LogPort``, whose shapes mirror the ECS API subset the
release contract needs: a future adapter must translate exactly these calls and
add no command, environment, role, volume or resource overrides.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:  # pragma: no cover - typing only
    from release.readiness import GatePolicy, LogRead


class AmbiguousResponse(Exception):
    """The request may or may not have been applied; reconcile before retrying."""


class PlatformHold(Exception):
    """An observation or a definitive refusal that holds the release with ``code``."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class SessionSuperseded(Exception):
    """The platform refused this session's authority: a later session holds it."""


class Clock(Protocol):
    """UTC wall time that never moves backwards within a controller session.

    Deadlines, freshness and journal order rely on it, and the readiness gate
    compares it with worker clocks within a 5 s skew, so it must also stay within
    a small bounded offset of true UTC. An adapter must enforce both (anchoring to
    a monotonic clock alone would keep any initial offset). The readiness gate
    holds if it observes controller time moving backwards, including against any
    time already in the journal.
    """

    def now(self) -> datetime: ...

    def sleep(self, seconds: float) -> None: ...


class EcsPort(Protocol):
    def run_task(self, request: dict[str, Any]) -> dict[str, Any]: ...

    def describe_tasks(self, cluster: str, task_arns: list[str]) -> dict[str, Any]: ...

    def list_tasks(
        self, cluster: str, *, started_by: str | None = None, service_name: str | None = None
    ) -> list[str]: ...

    def update_service(self, request: dict[str, Any]) -> dict[str, Any]: ...

    def describe_services(self, cluster: str, services: list[str]) -> list[dict[str, Any]]: ...

    def stop_task(self, cluster: str, task_arn: str, reason: str) -> dict[str, Any]: ...


class EvidencePort(Protocol):
    """Sanitized logical receipts read from fixed log streams, never raw log bodies."""

    def job_receipt(self, release_id: str, job_id: str, task_arn: str) -> dict[str, Any] | None: ...

    def operational_receipt(self, release_id: str, check_id: str) -> dict[str, Any] | None: ...


class LogPort(Protocol):
    """GetLogEvents on one controller-derived stream, read forward from its head.

    Returns ``{"events": [{"timestamp", "message"}...], "nextForwardToken"}``.
    The adapter passes the bounds and token through unchanged; the caller owns
    pagination, so an adapter must not page internally or drop events.
    """

    def get_log_events(
        self,
        log_group: str,
        log_stream: str,
        *,
        start_time_ms: int,
        end_time_ms: int,
        next_token: str | None,
        limit: int,
    ) -> dict[str, Any]: ...


@dataclass(frozen=True)
class JournalNames:
    """Journal action and identity field names a platform's events use.

    The ECS names are the historical ones, so AWS journals stay byte-identical.
    A platform never writes its values under another platform's names.
    """

    launch: str
    scale: str
    deploy: str
    stop: str
    activate: str
    run: str
    runs: str
    generation: str
    prior: str


@dataclass(frozen=True)
class SessionAuthority:
    """This session's authority, derived from the CAS-ordered journal.

    ``fence`` is the session's takeover ordinal (1 + recoveries); ``quiet_until``
    is when every command an earlier session journaled has expired, or None.
    """

    release_id: str
    session_id: str
    fence: int
    quiet_until: datetime | None


@dataclass(frozen=True)
class ServiceView:
    """One service observation: neutral fields for the controller, raw for the platform."""

    wants_running: bool
    active: bool
    generations: tuple[str, ...]
    raw: Mapping[str, Any] = field(default_factory=dict, compare=False)


@dataclass(frozen=True)
class Launch:
    """A classified launch response.

    ``failed`` counts definitive failures (nothing ran for them); ``unexpected``
    means the single run does not carry this launch's identity.
    """

    runs: tuple[str, ...]
    failed: int = 0
    unexpected: bool = False


@dataclass(frozen=True)
class Deploy:
    """A forward send's classified reply: the new generation, or drift, or neither."""

    generation: str | None
    drift: str | None = None


class ReceiptReader(Protocol):
    """Reads one observed worker's readiness receipts forward from ``token``."""

    def read(
        self, *, token: str | None, start: datetime, end: datetime, policy: GatePolicy
    ) -> LogRead: ...


class ReleasePlatform(Protocol):
    """Every platform operation the release controller performs.

    The controller owns the journal, lock, guards, deadlines, identical-retry
    limits, reconciliation order and holds; a platform only builds requests,
    sends them and classifies observations. Requests must be rebuildable from
    the recorded intent, which stores only their canonical SHA-256.
    """

    names: JournalNames
    count_drift: str
    # Intent fields the request builders read; carried into identical retries.
    request_fields: tuple[str, ...]

    def verify_approval(self, loaded: Any, approval: Any, now: datetime) -> None: ...

    def bind(self, authority: SessionAuthority) -> None: ...

    def command_fields(self) -> dict[str, Any]: ...

    # Services: observation, quiesce and start.
    def services(self) -> dict[str, ServiceView]: ...

    def prior_matches(self, key: str, view: ServiceView) -> bool: ...

    def scale_fields(self, key: str, view: ServiceView) -> dict[str, Any]: ...

    def scale_request(self, key: str, fields: Mapping[str, Any]) -> dict[str, Any]: ...

    def scaled_down(self, key: str, view: ServiceView, intent: Mapping[str, Any]) -> bool: ...

    def send_update(self, request: dict[str, Any], intent: Mapping[str, Any]) -> Any: ...

    def idle(self, views: Mapping[str, ServiceView]) -> bool: ...

    def writers_present(self) -> bool: ...

    def deploy_fields(self, key: str, view: ServiceView) -> dict[str, Any]: ...

    def deploy_request(self, key: str, fields: Mapping[str, Any]) -> dict[str, Any]: ...

    def deploy(
        self, key: str, request: dict[str, Any], intent: Mapping[str, Any], prior: list[str]
    ) -> Deploy: ...

    def new_generation(
        self, key: str, view: ServiceView, prior: list[str], intent: Mapping[str, Any]
    ) -> str | None: ...

    def drift(self, views: Mapping[str, ServiceView] | None) -> str | None:
        """A drift code, or None. ``None`` views ask for a fresh observation."""
        ...

    def response_drift(self, key: str, response: Any) -> str | None: ...

    def service_snapshot(self, key: str, generation: str) -> tuple[str, str, list[str]]: ...

    # Activation of platform code before the first job (none on ECS).
    def activations(self) -> tuple[str, ...]: ...

    def activation_request(self, subject: str) -> dict[str, Any]: ...

    def activation_state(self, subject: str) -> str: ...

    def activate(self, subject: str, request: dict[str, Any], intent: Mapping[str, Any]) -> str: ...

    # Jobs.
    def launch_request(self, job: Any, token: str) -> dict[str, Any]: ...

    def launch(self, job: Any, request: dict[str, Any], intent: Mapping[str, Any]) -> Launch: ...

    def runs_for(self, job: Any, token: str) -> list[str]: ...

    def describe_run(self, job: Any, run: str) -> Any | None: ...

    def run_stopped(self, view: Any) -> bool: ...

    def run_matches(self, job: Any, token: str, view: Any) -> bool: ...

    def evaluate_job(
        self, job: Any, token: str, view: Any, receipt: Mapping[str, Any] | None
    ) -> str | None: ...

    def job_receipt(self, job: Any, run: str) -> dict[str, Any] | None: ...

    def stop_request(self, job: Any, run: str, reason: str) -> dict[str, Any]: ...

    def send_stop(self, request: dict[str, Any], intent: Mapping[str, Any]) -> None: ...

    # Operational evidence.
    def operational_receipt(self, check_id: str) -> dict[str, Any] | None: ...

    def expected_operational(self, check: Any, recorded: Mapping[str, str]) -> dict[str, Any]: ...

    def worker_reader(self, run: str, generation: str) -> ReceiptReader: ...
