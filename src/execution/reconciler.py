"""Recover product terminal state from the durable runtime ledger."""

from typing import Protocol

from src.domain.execution import RuntimeObservation
from src.execution.runtime_client import RuntimeRun, RuntimeRunMissing, RuntimeUnavailable


class RuntimeReadPort(Protocol):
    def get_run(self, run_id: str) -> RuntimeRun: ...


class ReconciliationStorePort(Protocol):
    def get_runtime_reconciliation_batch(self, *, limit: int) -> list[tuple[str, str]]: ...
    def record_runtime_check_error(self, report_id: str, code: str) -> None: ...

    # The product store returns a RuntimeObservation; a plain bool (an older or test
    # store) is an applied flag with no disagreement.
    def apply_runtime_observation(
        self, report_id: str, run_id: str, *, state: str, lease_version: int, error_code: str | None
    ) -> bool | RuntimeObservation: ...


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


# Check errors that are disagreements about a bound run: it names another report or
# answers as another run, or the Runtime no longer has it. runtime_unavailable is
# transient and never counts.
DISAGREEING_CHECKS = frozenset({"runtime_reference_mismatch", "runtime_run_missing"})


class ReconcileCounts:
    """A reconciliation store that also counts what one pass checked and how many of its
    observations found the product and the Runtime disagreeing about a bound run: the
    run names another report, answers as another run or is missing, or the product
    store recorded a terminal disagreement. A refused observation (stale, not terminal, repeated, of a deleted
    report or already applied by another worker) never counts. Counts are of
    observations, not reports: a store disagreement is counted once, since the report
    then leaves the batch; a reference mismatch or a missing run is counted on every
    pass until the data is repaired."""

    def __init__(self, store: ReconciliationStorePort) -> None:
        self._store = store
        self.checked = 0
        self.mismatches = 0

    def get_runtime_reconciliation_batch(self, *, limit: int) -> list[tuple[str, str]]:
        batch = self._store.get_runtime_reconciliation_batch(limit=limit)
        self.checked += len(batch)
        return batch

    def record_runtime_check_error(self, report_id: str, code: str) -> None:
        self._store.record_runtime_check_error(report_id, code)
        if code in DISAGREEING_CHECKS:
            self.mismatches += 1

    def apply_runtime_observation(
        self, report_id: str, run_id: str, *, state: str, lease_version: int, error_code: str | None
    ) -> bool | RuntimeObservation:
        result = self._store.apply_runtime_observation(
            report_id, run_id, state=state, lease_version=lease_version, error_code=error_code
        )
        if isinstance(result, RuntimeObservation) and result.disagreement is not None:
            self.mismatches += 1
        return result
