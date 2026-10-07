"""Narrow ports the controller depends on. No implementation here talks to AWS.

The shapes mirror the ECS API subset the release contract needs. A future
adapter must translate exactly these calls and add no command, environment,
role, volume or resource overrides.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Protocol


class AmbiguousResponse(Exception):
    """The request may or may not have been applied; reconcile before retrying."""


class Clock(Protocol):
    """UTC wall time that never moves backwards within a controller session.

    Deadlines, freshness and journal order rely on it, and the readiness gate
    compares it with worker clocks within a 5 s skew, so it must also stay within
    a small bounded offset of true UTC. An adapter must enforce both (anchoring to
    a monotonic clock alone would keep any initial offset). The readiness gate
    holds if it observes controller time moving backwards, including against the
    journal's latest event.
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
