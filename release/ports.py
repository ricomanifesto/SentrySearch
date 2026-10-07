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
