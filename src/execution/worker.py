"""Version-scoped SentrySearch report-generation worker."""

from __future__ import annotations

from collections.abc import Callable
import logging
import threading
from typing import Any, Protocol

from src.core.generation_failures import build_generation_failure
from src.core.evidence_admissibility import ContentPolicyExclusion
from src.core.report_content_policy import load_checked_report
from src.domain.reports import ReportStatus
from src.domain.execution import GenerationLease, GenerationLeaseLost
from src.execution.runtime_client import RuntimeAccessDenied, RuntimeLeaseFenced, RuntimeRun

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
    def begin_runtime_attempt(self, report_id: str, lease: GenerationLease) -> bool: ...

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
        generation_lease: GenerationLease | None = None,
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
        self._failure: Exception | None = None
        self._thread = threading.Thread(
            target=self._heartbeat_until_stopped,
            name=f"runtime-heartbeat-{run.run_id}",
            daemon=True,
        )

    def __enter__(self) -> "LeaseHeartbeat":
        self._thread.start()
        return self

    def __exit__(self, exception_type: object, *_args: object) -> None:
        self._stop.set()
        # RuntimeClient uses network timeouts. Do not close its transport while
        # a heartbeat is still using it; this is not a whole-job deadline.
        self._thread.join()
        if self._failure is not None and exception_type is None:
            raise self._failure

    def _heartbeat_until_stopped(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            try:
                self.runtime.heartbeat(
                    self.run.run_id,
                    self.run.lease_owner,
                    self.run.lease_version,
                    lease_seconds=self.lease_seconds,
                )
            except (RuntimeAccessDenied, RuntimeLeaseFenced) as error:
                self._failure = error
                return
            except Exception as error:  # pragma: no cover - defensive logging boundary
                logger.warning("Runtime heartbeat failed for %s: %s", self.run.run_id, error)


class DurableGenerationWorker:
    """Claim and execute at most one versioned generation run."""

    def __init__(
        self,
        *,
        runtime: RuntimePort,
        reports: ReportPort,
        generate: Callable[[str, str, str, GenerationLease], None],
        after_complete: Callable[[str, str], None] | None = None,
        on_runtime_ready: Callable[[], None] | None = None,
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
        self.on_runtime_ready = on_runtime_ready
        self.worker_id = worker_id
        self.lease_seconds = lease_seconds
        self.heartbeat_interval_seconds = (
            heartbeat_interval_seconds
            if heartbeat_interval_seconds is not None
            else max(
                1.0,
                lease_seconds / 3,
            )
        )
        if not 0 < self.heartbeat_interval_seconds < lease_seconds:
            raise ValueError("heartbeat interval must be shorter than the lease")

    def run_once(self) -> bool:
        """Return true when a run was claimed, including an idempotent replay."""
        try:
            return self._run_once()
        except (GenerationLeaseLost, RuntimeLeaseFenced):
            logger.info("Generation attempt was fenced; leaving recovery to the current owner")
            return True

    def _run_once(self) -> bool:

        run = self.runtime.claim(self.worker_id, lease_seconds=self.lease_seconds)
        if self.on_runtime_ready is not None:
            self.on_runtime_ready()
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

        def load_content(key: str) -> str:
            loader = getattr(self.reports, "download_report_content", None)
            if not callable(loader):
                raise RuntimeError("Retained report content is unavailable")
            return loader(key)

        try:
            report = load_checked_report(report, load_content)
        except ContentPolicyExclusion:
            self._fail_invalid_input(run, "report input is unavailable under content policy")
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
        lease = GenerationLease(run.run_id, run.lease_owner, run.lease_version)
        if not self.reports.begin_runtime_attempt(report_id, lease):
            return True
        try:
            with LeaseHeartbeat(
                self.runtime,
                run,
                lease_seconds=self.lease_seconds,
                interval_seconds=self.heartbeat_interval_seconds,
            ):
                self.generate(report_id, tool_name, user_id, lease)
            finalized = self.reports.get_report(report_id, include_content=False)
            if finalized is None or finalized.get("status") != ReportStatus.COMPLETED.value:
                raise RuntimeError("generation returned without a completed report")
        except (GenerationLeaseLost, RuntimeLeaseFenced, RuntimeAccessDenied):
            raise
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
                    generation_lease=lease,
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
