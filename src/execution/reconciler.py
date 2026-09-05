"""Recover product terminal state from the durable runtime ledger."""

from typing import Protocol

from src.execution.runtime_client import RuntimeRun, RuntimeRunMissing, RuntimeUnavailable


class RuntimeReadPort(Protocol):
    def get_run(self, run_id: str) -> RuntimeRun: ...


class ReconciliationStorePort(Protocol):
    def get_runtime_reconciliation_batch(self, *, limit: int) -> list[tuple[str, str]]: ...
    def record_runtime_check_error(self, report_id: str, code: str) -> None: ...
    def apply_runtime_observation(
        self, report_id: str, run_id: str, *, state: str, lease_version: int, error_code: str | None
    ) -> bool: ...


def reconcile_runtime_reports(
    runtime: RuntimeReadPort, reports: ReconciliationStorePort, *, limit: int = 20
) -> int:
    reconciled = 0
    for report_id, run_id in reports.get_runtime_reconciliation_batch(limit=limit):
        try:
            run = runtime.get_run(run_id)
        except RuntimeUnavailable:
            reports.record_runtime_check_error(report_id, "runtime_unavailable")
            continue
        except RuntimeRunMissing:
            reports.record_runtime_check_error(report_id, "runtime_run_missing")
            continue
        if run.run_id != run_id or run.input_ref.get("report_id") != report_id:
            reports.record_runtime_check_error(report_id, "runtime_reference_mismatch")
            continue
        if reports.apply_runtime_observation(
            report_id,
            run_id,
            state=run.state,
            lease_version=run.lease_version,
            error_code=run.error_code,
        ):
            reconciled += 1
    return reconciled
