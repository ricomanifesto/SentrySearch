"""Transactional-outbox dispatcher for report-generation runs."""

from __future__ import annotations

from typing import Protocol

from src.execution.runtime_client import RuntimeRun, RuntimeUnavailable


class RuntimeSubmitPort(Protocol):
    def submit_report(self, report_id: str) -> RuntimeRun: ...


class DispatchStorePort(Protocol):
    def get_pending_runtime_dispatches(self, *, limit: int) -> list[str]: ...

    def mark_runtime_dispatch_submitted(
        self,
        report_id: str,
        runtime_run_id: str,
    ) -> bool: ...

    def record_runtime_dispatch_failure(self, report_id: str, error_code: str) -> bool: ...


def dispatch_pending_reports(
    runtime: RuntimeSubmitPort,
    reports: DispatchStorePort,
    *,
    limit: int = 20,
) -> int:
    """Submit pending intents, leaving failed attempts available for replay."""

    submitted = 0
    for report_id in reports.get_pending_runtime_dispatches(limit=limit):
        try:
            run = runtime.submit_report(report_id)
        except RuntimeUnavailable:
            reports.record_runtime_dispatch_failure(report_id, "runtime_unavailable")
            continue
        if reports.mark_runtime_dispatch_submitted(report_id, run.run_id):
            submitted += 1
    return submitted
