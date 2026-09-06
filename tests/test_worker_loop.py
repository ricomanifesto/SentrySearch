import threading
from types import SimpleNamespace

import pytest

from dev import run_runtime_worker as runner
from src.execution.supervisor import WorkerSettings


@pytest.mark.parametrize("stop_during", ["dispatch", "generation", "evaluation", None])
def test_drain_does_not_start_the_next_work_phase(monkeypatch, stop_during):
    stop = threading.Event()
    calls = []
    events = []
    closed = []
    producer = SimpleNamespace(close=lambda: closed.append("producer"))
    runtime = SimpleNamespace(close=lambda: closed.append("worker"))
    reports = SimpleNamespace(
        get_runtime_backlog=lambda: {"pending_dispatches": 1},
        get_pending_runtime_evaluations=lambda **_kwargs: [("report-1", "owner")],
    )

    def step(name):
        calls.append(name)
        if stop_during == name:
            stop.set()

    class Worker:
        def __init__(self, **kwargs):
            assert kwargs.get("after_complete") is None
            self.ready = kwargs["on_runtime_ready"]

        def run_once(self):
            self.ready()
            step("generation")
            return True

    monkeypatch.setattr(
        runner,
        "load_jobs",
        lambda: (reports, lambda *_args: None, lambda *_args: step("evaluation")),
    )
    monkeypatch.setattr(runner, "runtime_clients_from_environment", lambda: (producer, runtime))
    monkeypatch.setattr(runner, "DurableGenerationWorker", Worker)
    monkeypatch.setattr(runner, "reconcile_runtime_reports", lambda *_args: 0)
    monkeypatch.setattr(
        runner, "dispatch_pending_reports", lambda *_args, **_kwargs: step("dispatch") or 1
    )
    assert runner.run_worker_loop(WorkerSettings(once=True), stop, events.append) == 0
    expected = ["dispatch", "generation", "evaluation"]
    if stop_during:
        expected = expected[: expected.index(stop_during) + 1]
    assert calls == expected
    assert sorted(closed) == ["producer", "worker"]
    assert {e["event"] for e in events} >= {"phase", "backlog"}


def test_dispatch_stops_between_submissions():
    from src.execution.dispatcher import dispatch_pending_reports

    stop = threading.Event()
    calls = []

    class Runtime:
        def submit_report(self, report_id):
            calls.append(report_id)
            stop.set()
            return SimpleNamespace(run_id="run-1")

    class Reports:
        def get_pending_runtime_dispatches(self, *, limit):
            return ["report-1", "report-2"]

        def mark_runtime_dispatch_submitted(self, *_args, **_kwargs) -> bool:
            return True

        def record_runtime_dispatch_failure(self, *_args, **_kwargs) -> bool:
            raise AssertionError("must not fail a successful submission")

    assert dispatch_pending_reports(Runtime(), Reports(), should_stop=stop.is_set) == 1
    assert calls == ["report-1"]
