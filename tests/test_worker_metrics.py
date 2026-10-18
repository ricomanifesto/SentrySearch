"""The worker's standalone metric event (sentry.worker-metrics.v1) and its producers.

The readiness receipt stays byte for byte as it was: the metric event is a separate
line, plain JSON with no marker, so CloudWatch's JSON selectors apply to it and the
controller's receipt parser ignores it.
"""

from __future__ import annotations

from datetime import UTC, datetime
import io
import json
import math
import ssl
import subprocess
import threading
import time

import pytest

from dev import run_runtime_worker as runner
from release.readiness import parse_line
from src.execution import runtime_client
from src.execution.readiness_receipts import METRICS_KIND, RECEIPT_MARKER, ReadinessReceipts
from src.domain.execution import RuntimeObservation
from src.execution.reconciler import (
    ReconcileCounts,
    ReconciliationStorePort,
    reconcile_runtime_reports,
)
from src.execution.runtime_client import RuntimeClient, RuntimeRun
from src.execution.supervisor import WorkerSettings, WorkerStatus, WorkerSupervisor
from src.storage.report_service import ReportStorageService
from tests.test_runtime_transport import tls_server  # noqa: F401  (fixture)

RELEASE_ID = "0b9f7c1e-4d2a-4f6b-9a3e-2c1d0e9f8a7b"
METRIC_KEYS = {"kind", "release_id", "boot_id", "sequence", "observed_at", "backlog_size",
               "backlog_oldest_seconds", "runtime_certificate_days_left", "reconcile_checked",
               "reconcile_mismatches"}  # fmt: skip
SNAPSHOT = {"alive": True, "ready": True, "draining": False, "phase": "idle",
            "phase_elapsed_seconds": 1.0, "phase_budget_seconds": 60.0, "error_code": None}  # fmt: skip


class Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


def lines_of(sink: io.StringIO, receipts: ReadinessReceipts) -> list[str]:
    receipts.close({**SNAPSHOT, "alive": False, "phase": "stopped"}, timeout=1.0)
    return sink.getvalue().splitlines()


def metric_lines(sink: io.StringIO, receipts: ReadinessReceipts) -> list[str]:
    return [line for line in lines_of(sink, receipts) if not line.startswith(RECEIPT_MARKER)]


FIELDS = {"backlog_size": 2, "backlog_oldest_seconds": 41, "runtime_certificate_days_left": 30,
          "reconcile_checked": 5, "reconcile_mismatches": 1}  # fmt: skip


def test_the_metric_event_is_one_standalone_json_line_with_its_own_sequence():
    clock, sink = Clock(), io.StringIO()
    receipts = ReadinessReceipts(RELEASE_ID, sink, monotonic=clock, emit_metrics=True)
    receipts.observe(SNAPSHOT)
    receipts.observe_metrics(lambda: FIELDS)
    lines = lines_of(sink, receipts)
    metric = [line for line in lines if not line.startswith(RECEIPT_MARKER)]
    assert len(metric) == 1
    event = json.loads(metric[0])
    assert set(event) == METRIC_KEYS and "error_code" not in metric[0]
    assert event["kind"] == METRICS_KIND and event["release_id"] == RELEASE_ID
    assert event["boot_id"] == receipts.boot_id and event["sequence"] == 1
    assert {key: event[key] for key in FIELDS} == FIELDS
    # The receipt sequence is the receipts' own: no gap where the metric line went.
    marked = [
        json.loads(line.split(" ", 1)[1]) for line in lines if line.startswith(RECEIPT_MARKER)
    ]
    assert [receipt["sequence"] for receipt in marked] == list(range(1, len(marked) + 1))
    # The controller's parser reads the metric line as ordinary output.
    assert parse_line(metric[0]) is None


def test_the_readiness_receipt_is_byte_for_byte_unchanged_by_metrics():
    def receipts_line(emit_metrics: bool) -> str:
        sink = io.StringIO()
        receipts = ReadinessReceipts(RELEASE_ID, sink, monotonic=lambda: 5.0, emit_metrics=emit_metrics,
                                     wall=lambda: datetime(2026, 10, 18, tzinfo=UTC))  # fmt: skip
        receipts.boot_id = "0" * 32
        receipts.observe(SNAPSHOT)
        receipts.observe_metrics(lambda: FIELDS)
        return next(line for line in lines_of(sink, receipts) if line.startswith(RECEIPT_MARKER))

    assert receipts_line(True) == receipts_line(False)


def test_metrics_are_taken_once_per_interval_and_only_when_enabled():
    clock, sink = Clock(), io.StringIO()
    taken: list[int] = []
    receipts = ReadinessReceipts(RELEASE_ID, sink, monotonic=clock, interval_seconds=10,
                                 emit_metrics=True)  # fmt: skip

    def take() -> dict[str, int]:
        taken.append(1)
        return FIELDS

    receipts.observe_metrics(take)
    clock.now += 9.9
    receipts.observe_metrics(take)
    assert len(taken) == 1, "counts are taken, and reset, only when an event is due"
    clock.now += 0.2
    receipts.observe_metrics(take)
    assert len(taken) == 2
    events = [json.loads(line) for line in metric_lines(sink, receipts)]
    assert [event["sequence"] for event in events] == [1, 2]

    disabled = ReadinessReceipts(RELEASE_ID, io.StringIO(), monotonic=clock)
    disabled.observe_metrics(take)
    assert len(taken) == 2, "a receipts writer without metrics never takes them"


@pytest.mark.parametrize("value, written", [(None, None), (0, 0), (7, 7), (-1, None), (True, None),
                                            (2.9, 2), (math.nan, None), (math.inf, None)])  # fmt: skip
def test_metric_values_are_whole_non_negative_numbers_or_null(value, written):
    clock, sink = Clock(), io.StringIO()
    receipts = ReadinessReceipts(RELEASE_ID, sink, monotonic=clock, emit_metrics=True)
    receipts.observe_metrics(lambda: {**FIELDS, "backlog_oldest_seconds": value})
    (line,) = metric_lines(sink, receipts)
    assert json.loads(line)["backlog_oldest_seconds"] == written


# The supervisor's state ----------------------------------------------------------------


def status_at(monotonic: float, wall: float, monkeypatch) -> WorkerStatus:
    monkeypatch.setattr("src.execution.supervisor.time.monotonic", lambda: monotonic)
    monkeypatch.setattr("src.execution.supervisor.time.time", lambda: wall)
    return WorkerStatus(WorkerSettings())


def test_backlog_age_keeps_growing_while_the_worker_samples_nothing(monkeypatch):
    status = status_at(1000.0, 0.0, monkeypatch)
    status.observe({"event": "backlog", "at": 900.0,
                    "counts": {"pending_dispatches": 3, "oldest_pending_seconds": 50}})  # fmt: skip
    metrics = status.take_metrics()
    assert metrics["backlog_size"] == 3
    assert metrics["backlog_oldest_seconds"] == 150, "fifty seconds old a hundred seconds ago"


def test_an_empty_or_unsampled_backlog_is_not_aging(monkeypatch):
    status = status_at(1000.0, 0.0, monkeypatch)
    assert status.take_metrics()["backlog_oldest_seconds"] is None
    status.observe({"event": "backlog", "at": 900.0,
                    "counts": {"pending_dispatches": 0, "oldest_pending_seconds": 0}})  # fmt: skip
    assert status.take_metrics()["backlog_oldest_seconds"] == 0
    # A product service that reports no age (an older store) reports no age.
    status.observe({"event": "backlog", "at": 900.0, "counts": {"pending_dispatches": 2}})
    assert status.take_metrics()["backlog_oldest_seconds"] is None


def test_reconcile_counts_accumulate_until_taken(monkeypatch):
    status = status_at(1000.0, 0.0, monkeypatch)
    status.observe({"event": "reconcile", "checked": 4, "mismatches": 1})
    status.observe({"event": "reconcile", "checked": 2, "mismatches": 0})
    taken = status.take_metrics()
    assert (taken["reconcile_checked"], taken["reconcile_mismatches"]) == (6, 1)
    again = status.take_metrics()
    assert (again["reconcile_checked"], again["reconcile_mismatches"]) == (0, 0)


def test_certificate_days_left_count_down_and_stop_at_zero(monkeypatch):
    day = 86400.0
    status = status_at(1000.0, 10 * day, monkeypatch)
    assert status.take_metrics()["runtime_certificate_days_left"] is None
    status.observe({"event": "certificate", "not_after": 40.5 * day})
    assert status.take_metrics()["runtime_certificate_days_left"] == 30
    monkeypatch.setattr("src.execution.supervisor.time.time", lambda: 41 * day)
    # Expired: zero, still at or above the filter's floor, so the alarm keeps firing.
    assert status.take_metrics()["runtime_certificate_days_left"] == 0


@pytest.mark.parametrize("event", [
    {"event": "reconcile", "checked": -1, "mismatches": 0},
    {"event": "reconcile", "checked": 1, "mismatches": 2},
    {"event": "reconcile", "checked": True, "mismatches": 0},
    {"event": "reconcile", "checked": 1},
    {"event": "certificate", "not_after": math.nan},
    {"event": "certificate", "not_after": -5.0},
    {"event": "certificate", "not_after": "2026-11-01"},
    {"event": "backlog", "counts": {"pending_dispatches": 1, "oldest_pending_seconds": -3}},
])  # fmt: skip
def test_malformed_producer_events_are_protocol_errors(event, monkeypatch):
    # The supervisor fails the worker with worker_protocol_error on any of these.
    status = status_at(1000.0, 0.0, monkeypatch)
    with pytest.raises((KeyError, ValueError)):
        status.observe(event)


def metrics_worker(settings, stop, emit):
    emit({"event": "phase", "phase": "idle"})
    emit({"event": "ready", "value": True})
    emit({"event": "backlog", "counts": {"pending_dispatches": 2, "oldest_pending_seconds": 7}})
    emit({"event": "reconcile", "checked": 3, "mismatches": 1})
    emit({"event": "certificate", "not_after": time.time() + 20.5 * 86400})
    stop.wait(10)
    return 0


class SplitSink:
    def __init__(self) -> None:
        self.lines: list[str] = []
        self.lock = threading.Lock()

    def write(self, text: str) -> int:
        with self.lock:
            self.lines.extend(line for line in text.splitlines() if line)
        return len(text)

    def flush(self) -> None:
        pass

    def metrics(self) -> list[dict]:
        with self.lock:
            return [json.loads(line) for line in self.lines if not line.startswith(RECEIPT_MARKER)]


def test_the_supervisor_writes_the_workers_metrics_beside_its_receipts():
    sink = SplitSink()
    receipts = ReadinessReceipts(RELEASE_ID, sink, interval_seconds=0.1, emit_metrics=True)
    supervisor = WorkerSupervisor(WorkerSettings(drain_seconds=2, poll_seconds=5, startup_seconds=5),
                                  metrics_worker, receipts=receipts)  # fmt: skip
    thread = threading.Thread(target=supervisor.run, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not any(
            event["reconcile_checked"] for event in sink.metrics()
        ):
            time.sleep(0.05)
    finally:
        supervisor.request_drain()
        thread.join(10)
    events = sink.metrics()
    counted = [event for event in events if event["reconcile_checked"]]
    assert len(counted) == 1, "reconcile counts are reported once, then reset"
    assert counted[0]["reconcile_mismatches"] == 1
    latest = events[-1]
    assert latest["backlog_size"] == 2 and latest["backlog_oldest_seconds"] >= 7
    assert latest["runtime_certificate_days_left"] == 20
    assert [event["sequence"] for event in events] == list(range(1, len(events) + 1))


# The producers -------------------------------------------------------------------------


class Batch:
    """A reconciliation batch and its recorded check errors."""

    def __init__(self, batch) -> None:
        self.batch, self.errors = batch, []

    def get_runtime_reconciliation_batch(self, *, limit):
        return self.batch[:limit]

    def record_runtime_check_error(self, report_id, code):
        self.errors.append((report_id, code))


class Store(Batch):
    """A reconciliation store whose apply answers a plain bool, as older stores and the
    existing fakes do."""

    def __init__(self, batch, applied=True) -> None:
        super().__init__(batch)
        self.applied = applied

    def apply_runtime_observation(self, report_id, run_id, **_kwargs) -> bool:
        return self.applied


class ObservingStore(Batch):
    """A store answering the product store's structured result; a report whose terminal
    disagreement was recorded leaves the batch, as in the product store."""

    def __init__(self, batch, results: dict[str, RuntimeObservation]) -> None:
        super().__init__(batch)
        self.results = results

    def apply_runtime_observation(self, report_id, run_id, **_kwargs) -> RuntimeObservation:
        result = self.results[report_id]
        if result.applied:
            self.batch = [entry for entry in self.batch if entry[0] != report_id]
        return result


class Runtime:
    def __init__(self, runs) -> None:
        self.runs = runs

    def get_run(self, run_id):
        return self.runs[run_id]


def run(run_id: str, report_id: str, state: str) -> RuntimeRun:
    return RuntimeRun(run_id=run_id, state=state, attempt=1, lease_owner="", lease_version=1,
                      input_ref={"report_id": report_id})  # fmt: skip


def test_a_refused_observation_is_never_a_mismatch():
    runtime = Runtime({"run-1": run("run-1", "report-1", "succeeded"),
                       "run-2": run("run-2", "another-report", "failed"),
                       "run-3": run("run-3", "report-3", "running")})  # fmt: skip
    batch = [("report-1", "run-1"), ("report-2", "run-2"), ("report-3", "run-3")]
    # A plain-bool store (the existing fakes' contract): no structured disagreement.
    refused = ReconcileCounts(Store(batch, applied=False))
    assert reconcile_runtime_reports(runtime, refused) == 0
    # run-1 terminal but refused: no mismatch; run-2 names another report; run-3 runs.
    assert (refused.checked, refused.mismatches) == (3, 1)
    applied = ReconcileCounts(Store(batch, applied=True))
    assert reconcile_runtime_reports(runtime, applied) == 2
    assert (applied.checked, applied.mismatches) == (3, 1)


def test_a_store_disagreement_counts_once_and_a_reference_mismatch_every_pass():
    runtime = Runtime({"run-1": run("run-1", "report-1", "succeeded"),
                       "run-2": run("run-2", "another-report", "failed"),
                       "run-3": run("run-3", "report-3", "failed")})  # fmt: skip
    store = ObservingStore(
        [("report-1", "run-1"), ("report-2", "run-2"), ("report-3", "run-3")],
        {"report-1": RuntimeObservation(applied=True, disagreement="runtime_result_missing"),
         "report-3": RuntimeObservation(applied=True)},
    )  # fmt: skip
    first = ReconcileCounts(store)
    assert reconcile_runtime_reports(runtime, first) == 2
    assert (first.checked, first.mismatches) == (3, 2)
    second = ReconcileCounts(store)
    assert reconcile_runtime_reports(runtime, second) == 0
    # Only the reference mismatch is left in the batch, and it counts again.
    assert (second.checked, second.mismatches) == (1, 1)


@pytest.mark.parametrize("code, counted", [("runtime_reference_mismatch", 1),
                                           ("runtime_run_missing", 1),
                                           ("runtime_unavailable", 0)])  # fmt: skip
def test_only_disagreeing_check_errors_count(code, counted):
    counts = ReconcileCounts(Store([]))
    counts.record_runtime_check_error("report-1", code)
    assert counts.mismatches == counted


def admits(store: ReconciliationStorePort) -> ReconcileCounts:
    return ReconcileCounts(store)


def product_store_admitted(service: ReportStorageService) -> ReconcileCounts:
    # Never called: ty checks that the product store satisfies the port it is given to.
    return admits(service)


def test_the_reconciliation_port_admits_bool_and_structured_stores():
    # ty checks these calls against the port; at runtime both kinds of fake count.
    assert admits(Store([])).mismatches == 0
    assert admits(ObservingStore([], {})).mismatches == 0


def test_the_store_result_is_true_exactly_when_applied():
    assert RuntimeObservation(applied=True) and not RuntimeObservation(applied=False)
    assert RuntimeObservation(applied=True, disagreement="runtime_result_missing")


def test_the_worker_reports_reconcile_counts_and_the_runtime_certificate(monkeypatch):
    events: list[dict] = []
    stop = threading.Event()

    class LoopStore(ObservingStore):
        def __init__(self, batch) -> None:
            super().__init__(batch, {})

        def get_runtime_backlog(self):
            return {"pending_dispatches": 0, "oldest_pending_seconds": 0}

        def get_pending_runtime_evaluations(self, **_kwargs):
            return []

    class ClosedRuntime(Runtime):
        def close(self) -> None:
            pass

    store = LoopStore([("report-1", "run-1")])
    store.results = {
        "report-1": RuntimeObservation(
            applied=True, disagreement="runtime_failed_after_publication"
        )
    }
    producer = ClosedRuntime({"run-1": run("run-1", "report-1", "failed")})

    class Worker:
        def __init__(self, **_kwargs) -> None:
            pass

        def run_once(self) -> bool:
            return False

    worker_runtime = ClosedRuntime({})
    monkeypatch.setattr(runner, "load_jobs", lambda: (store, lambda *_a: None, lambda *_a: None))
    monkeypatch.setattr(runner, "runtime_clients_from_environment",
                        lambda: (producer, worker_runtime))  # fmt: skip
    monkeypatch.setattr(runner, "DurableGenerationWorker", Worker)
    monkeypatch.setattr(runner, "dispatch_pending_reports", lambda *_a, **_k: 0)
    monkeypatch.setattr(runtime_client, "_PEER_NOT_AFTER", 1_900_000_000.0)
    assert runner.run_worker_loop(WorkerSettings(once=True), stop, events.append) == 0
    counted = [event for event in events if event["event"] == "reconcile"]
    assert counted and all(event == {"event": "reconcile", "checked": 1, "mismatches": 1}
                           for event in counted)  # fmt: skip
    assert {"event": "certificate", "not_after": 1_900_000_000.0} in events


def test_the_runtime_client_records_the_verified_peer_certificates_expiry(tls_server):  # noqa: F811
    monkey_reset = runtime_client._PEER_NOT_AFTER
    runtime_client._PEER_NOT_AFTER = None
    try:
        url, cert, _requests = tls_server()
        client = RuntimeClient(url, remote=True, bearer_token="p" * 40, ca_file=str(cert.ca))
        try:
            assert runtime_client.peer_certificate_not_after() is None
            client.submit_report("report-1")
        finally:
            client.close()
        not_after = runtime_client.peer_certificate_not_after()
        assert not_after is not None
        printed = subprocess.run(["openssl", "x509", "-noout", "-enddate", "-in", str(cert.certificate)],
                                 capture_output=True, text=True, check=True).stdout  # fmt: skip
        assert not_after == ssl.cert_time_to_seconds(printed.strip().removeprefix("notAfter="))
    finally:
        runtime_client._PEER_NOT_AFTER = monkey_reset


def test_the_backlog_aged_through_generation_is_the_one_left_after_dispatch(monkeypatch):
    events: list[dict] = []
    pending = {"count": 1}

    class Reports:
        def get_runtime_backlog(self):
            return {"pending_dispatches": pending["count"], "oldest_pending_seconds": 5}

        def get_pending_runtime_evaluations(self, **_kwargs):
            return []

    class Worker:
        def __init__(self, **_kwargs) -> None:
            pass

        def run_once(self) -> bool:
            return False

    class Closed:
        def close(self) -> None:
            pass

    def dispatch(*_args, **_kwargs) -> int:
        pending["count"] = 0
        return 1

    monkeypatch.setattr(
        runner, "load_jobs", lambda: (Reports(), lambda *_a: None, lambda *_a: None)
    )
    monkeypatch.setattr(runner, "runtime_clients_from_environment", lambda: (Closed(), Closed()))
    monkeypatch.setattr(runner, "DurableGenerationWorker", Worker)
    monkeypatch.setattr(runner, "reconcile_runtime_reports", lambda *_args: 0)
    monkeypatch.setattr(runner, "dispatch_pending_reports", dispatch)
    assert runner.run_worker_loop(WorkerSettings(once=True), threading.Event(), events.append) == 0
    generation = events.index({"event": "phase", "phase": "generation"})
    before = [event for event in events[:generation] if event["event"] == "backlog"]
    assert before[-1]["counts"]["pending_dispatches"] == 0


def short_lived_worker(settings, stop, emit):
    emit({"event": "phase", "phase": "idle"})
    emit({"event": "ready", "value": True})
    time.sleep(0.3)
    emit({"event": "reconcile", "checked": 2, "mismatches": 1})
    time.sleep(0.3)
    return 0


def test_the_last_intervals_counts_are_written_before_the_stopped_receipt():
    sink = SplitSink()
    receipts = ReadinessReceipts(RELEASE_ID, sink, interval_seconds=60, emit_metrics=True)
    supervisor = WorkerSupervisor(WorkerSettings(drain_seconds=2, poll_seconds=5, startup_seconds=5),
                                  short_lived_worker, receipts=receipts)  # fmt: skip
    assert supervisor.run() == 0
    events = sink.metrics()
    assert len(events) == 2, "the first event at startup and the final one at exit"
    assert (events[-1]["reconcile_checked"], events[-1]["reconcile_mismatches"]) == (2, 1)
    with sink.lock:
        assert sink.lines[-1].startswith(RECEIPT_MARKER), "the stopped receipt comes last"


def test_a_reconcile_pass_that_fails_reports_no_counts(monkeypatch):
    # A store whose commit fails raises out of the pass: no reconcile event, and the
    # loop ends on the existing worker_error path.
    events: list[dict] = []

    class FailingStore(Store):
        def get_runtime_backlog(self):
            return {"pending_dispatches": 0, "oldest_pending_seconds": 0}

        def get_pending_runtime_evaluations(self, **_kwargs):
            return []

        def apply_runtime_observation(self, report_id, run_id, **_kwargs) -> bool:
            raise RuntimeError("commit failed")

    class Closed(Runtime):
        def close(self) -> None:
            pass

    class Worker:
        def __init__(self, **_kwargs) -> None:
            pass

        def run_once(self) -> bool:
            return False

    store = FailingStore([("report-1", "run-1")])
    producer = Closed({"run-1": run("run-1", "report-1", "failed")})
    monkeypatch.setattr(runner, "load_jobs", lambda: (store, lambda *_a: None, lambda *_a: None))
    monkeypatch.setattr(runner, "runtime_clients_from_environment", lambda: (producer, Closed({})))
    monkeypatch.setattr(runner, "DurableGenerationWorker", Worker)
    monkeypatch.setattr(runner, "dispatch_pending_reports", lambda *_a, **_k: 0)
    with pytest.raises(RuntimeError, match="commit failed"):
        runner.run_worker_loop(WorkerSettings(once=True), threading.Event(), events.append)
    assert not [event for event in events if event["event"] == "reconcile"]
