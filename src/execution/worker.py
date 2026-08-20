"""Version-scoped SentrySearch report-generation worker."""

from __future__ import annotations

from collections.abc import Callable
import logging
import threading
from typing import Any, Protocol

from src.core.generation_failures import build_generation_failure
from src.domain.reports import ReportStatus
from src.execution.runtime_client import RuntimeRun

logger = logging.getLogger(__name__)


class RuntimePort(Protocol):
    def claim(self, worker_id: str, *, lease_seconds: int) -> RuntimeRun | None: ...

    def complete(
        self,
        run_id: str,
        lease_owner: str,
        lease_version: int,
        output_ref: dict[str, Any],
    ) -> RuntimeRun: ...

    def heartbeat(
        self,
        run_id: str,
        lease_owner: str,
        lease_version: int,
        *,
        lease_seconds: int,
    ) -> RuntimeRun: ...

    def fail(
        self,
        run_id: str,
        lease_owner: str,
        lease_version: int,
        *,
        error_code: str,
        error_summary: str,
    ) -> RuntimeRun: ...


class ReportPort(Protocol):
    def get_report(
        self,
        report_id: str,
        include_content: bool = False,
    ) -> dict[str, Any] | None: ...

    def mark_report_failed(
        self,
        report_id: str,
        *,
        error_code: str,
        retryable: bool,
        failure: dict[str, Any],
    ) -> bool: ...


class LeaseHeartbeat:
    """Extend one lease until the worker exits the guarded execution block."""

    def __init__(
        self,
        runtime: RuntimePort,
        run: RuntimeRun,
        *,
        lease_seconds: int,
        interval_seconds: float,
    ) -> None:
        self.runtime = runtime
        self.run = run
        self.lease_seconds = lease_seconds
        self.interval_seconds = interval_seconds
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._heartbeat_until_stopped,
            name=f"runtime-heartbeat-{run.run_id}",
            daemon=True,
        )

    def __enter__(self) -> "LeaseHeartbeat":
        self._thread.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self._stop.set()
        self._thread.join(timeout=self.interval_seconds + 1)

    def _heartbeat_until_stopped(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            try:
                self.runtime.heartbeat(
                    self.run.run_id,
                    self.run.lease_owner,
                    self.run.lease_version,
                    lease_seconds=self.lease_seconds,
                )
            except Exception as error:  # pragma: no cover - defensive logging boundary
                logger.warning("Runtime heartbeat failed for %s: %s", self.run.run_id, error)


class DurableGenerationWorker:
    """Claim and execute at most one versioned generation run."""

    def __init__(
        self,
        *,
        runtime: RuntimePort,
        reports: ReportPort,
        generate: Callable[[str, str, str], None],
        after_complete: Callable[[str, str], None] | None = None,
        worker_id: str,
        lease_seconds: int,
        heartbeat_interval_seconds: float | None = None,
    ) -> None:
        if not worker_id.strip() or lease_seconds < 3:
            raise ValueError("worker ID and lease duration are required")
        self.runtime = runtime
        self.reports = reports
        self.generate = generate
        self.after_complete = after_complete
        self.worker_id = worker_id
        self.lease_seconds = lease_seconds
        self.heartbeat_interval_seconds = heartbeat_interval_seconds or max(
            1.0,
            lease_seconds / 3,
        )
        if self.heartbeat_interval_seconds >= lease_seconds:
            raise ValueError("heartbeat interval must be shorter than the lease")

    def run_once(self) -> bool:
        """Return true when a run was claimed, including an idempotent replay."""

        run = self.runtime.claim(self.worker_id, lease_seconds=self.lease_seconds)
        if run is None:
            return False

        report_id = run.input_ref.get("report_id")
        if not isinstance(report_id, str) or not report_id:
            self._fail_invalid_input(run, "runtime input is invalid")
            return True
        report = self.reports.get_report(report_id, include_content=False)
        if report is None:
            self._fail_invalid_input(run, "report input is unavailable")
            return True

        if report.get("status") == ReportStatus.COMPLETED.value:
            self.runtime.complete(
                run.run_id,
                run.lease_owner,
                run.lease_version,
                {"report_id": report_id, "status": ReportStatus.COMPLETED.value},
            )
            if (
                self.after_complete is not None
                and report.get("evaluation_status") == "pending"
                and isinstance(report.get("user_id"), str)
            ):
                self.after_complete(report_id, report["user_id"])
            return True

        tool_name = report.get("tool_name")
        user_id = report.get("user_id")
        if not isinstance(tool_name, str) or not tool_name or not isinstance(user_id, str):
            self._fail_invalid_input(run, "report input is invalid")
            return True
        try:
            with LeaseHeartbeat(
                self.runtime,
                run,
                lease_seconds=self.lease_seconds,
                interval_seconds=self.heartbeat_interval_seconds,
            ):
                self.generate(report_id, tool_name, user_id)
            finalized = self.reports.get_report(report_id, include_content=False)
            if finalized is None or finalized.get("status") != ReportStatus.COMPLETED.value:
                raise RuntimeError("generation returned without a completed report")
        except Exception as error:
            carried_failure = getattr(error, "generation_failure", None)
            failure = (
                dict(carried_failure)
                if isinstance(carried_failure, dict)
                else build_generation_failure(error, stage=None)
            )
            runtime_result = self.runtime.fail(
                run.run_id,
                run.lease_owner,
                run.lease_version,
                error_code=runtime_error_code(error, failure),
                error_summary="report generation failed",
            )
            if runtime_result.state == "failed":
                self.reports.mark_report_failed(
                    report_id,
                    error_code=str(failure["error_code"]),
                    retryable=bool(failure["retryable"]),
                    failure=failure,
                )
            return True
        self.runtime.complete(
            run.run_id,
            run.lease_owner,
            run.lease_version,
            {"report_id": report_id, "status": ReportStatus.COMPLETED.value},
        )
        if self.after_complete is not None:
            self.after_complete(report_id, user_id)
        return True

    def _fail_invalid_input(self, run: RuntimeRun, summary: str) -> None:
        self.runtime.fail(
            run.run_id,
            run.lease_owner,
            run.lease_version,
            error_code="invalid_input",
            error_summary=summary,
        )


def runtime_error_code(error: BaseException, failure: dict[str, Any]) -> str:
    """Map product-safe failure data onto the runtime retry taxonomy."""

    if isinstance(error, TimeoutError):
        return "dependency_timeout"
    if failure.get("error_code") in {"provider_rate_limited", "provider_unavailable"}:
        return "dependency_unavailable"
    if failure.get("error_code") != "unknown" and failure.get("retryable") is False:
        return "invalid_result"
    return "worker_error"
