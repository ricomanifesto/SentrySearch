import threading
import time
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
from contextlib import contextmanager
from functools import partial

import httpx
import pytest

from src.execution.supervisor import WorkerSettings, WorkerStatus, WorkerSupervisor


def cooperative_worker(settings, stop, emit):
    emit({"event": "phase", "phase": "generation"})
    emit({"event": "ready", "value": True})
    emit({"event": "backlog", "counts": {"pending_dispatches": 2}})
    stop.wait(10)
    # A drain lets the current operation finish; no subsequent work is started.
    time.sleep(0.15)
    return 0


def hung_evaluator(settings, stop, emit):
    emit({"event": "phase", "phase": "evaluation"})
    emit({"event": "ready", "value": True})
    time.sleep(30)
    return 0


def failed_worker(settings, stop, emit):
    return 1


def hung_phase(phase, settings, stop, emit):
    emit({"event": "phase", "phase": phase})
    time.sleep(30)
    return 0


def private_failure(settings, stop, emit):
    raise RuntimeError("private provider response sentinel")


def malformed_worker(settings, stop, emit):
    emit({"event": "error", "code": "private provider response sentinel"})
    time.sleep(30)
    return 0


def malformed_then_exit(settings, stop, emit):
    emit({"event": "phase", "phase": "idle"})
    emit({"event": "unknown"})
    return 0


def unavailable_then_exit(recovered, settings, stop, emit):
    emit({"event": "error", "code": "runtime_unavailable"})
    if recovered:
        emit({"event": "recovered"})
    return 0


@pytest.mark.parametrize(
    "kwargs",
    [
        {"evaluation_seconds": 900},
        {"evaluation_seconds": 0},
        {"generation_seconds": float("nan")},
        {"drain_seconds": -1},
        {"maintenance_seconds": float("inf")},
        {"poll_seconds": 0},
        {"health_port": -1},
        {"lease_seconds": 2},
    ],
)
def test_settings_reject_unbounded_or_unsafe_deadlines(kwargs):
    with pytest.raises(ValueError):
        WorkerSettings(**kwargs)


def test_status_preserves_age_when_a_sample_or_phase_message_is_delayed():
    status = WorkerStatus(WorkerSettings())
    earlier = time.monotonic() - 10
    status.observe({"event": "backlog", "counts": {"pending_dispatches": 1}, "at": earlier})
    status.observe({"event": "phase", "phase": "generation", "at": earlier})
    snapshot = status.snapshot()
    assert snapshot["backlog"]["age_seconds"] >= 10
    assert snapshot["phase_elapsed_seconds"] >= 10


@pytest.mark.parametrize("stamp", [float("nan"), float("inf"), -1, "private text"])
def test_status_rejects_invalid_event_timestamps(stamp):
    status = WorkerStatus(WorkerSettings())
    with pytest.raises(ValueError):
        status.observe({"event": "phase", "phase": "evaluation", "at": stamp})


def start_supervisor(target, **kwargs):
    supervisor = WorkerSupervisor(WorkerSettings(**kwargs), target)
    result = []
    thread = threading.Thread(target=lambda: result.append(supervisor.run()), daemon=True)
    thread.start()
    return supervisor, thread, result


def wait_for(supervisor, predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        snapshot = supervisor.status.snapshot()
        if predicate(snapshot):
            return snapshot
        time.sleep(0.01)
    raise AssertionError(supervisor.status.snapshot())


def test_busy_worker_is_probeable_and_graceful_drain_drops_readiness():
    supervisor, thread, result = start_supervisor(cooperative_worker, drain_seconds=2)
    try:
        snapshot = wait_for(supervisor, lambda s: s["ready"] and s["backlog"] is not None)
        assert snapshot["phase"] == "generation"
        assert snapshot["backlog"]["counts"] == {"pending_dispatches": 2}
        assert supervisor.health_address is not None
        with httpx.Client(base_url=supervisor.health_address, trust_env=False) as client:
            assert client.get("/healthz").status_code == 200
            assert client.get("/readyz").status_code == 200
            assert client.get("/status").json()["backlog"]["age_seconds"] >= 0
            assert client.get("/unknown").status_code == 404
            assert client.post("/drain").status_code == 405
            supervisor.request_drain()
            assert client.get("/readyz").status_code == 503
        thread.join(5)
        assert result == [0]
        assert not supervisor.status.snapshot()["alive"]
    finally:
        supervisor.request_drain()
        thread.join(5)
        assert not thread.is_alive()


def test_evaluation_deadline_reaps_the_owned_child():
    supervisor, thread, result = start_supervisor(hung_evaluator, evaluation_seconds=0.2)
    thread.join(5)
    assert not thread.is_alive()
    assert result == [124]
    snapshot = supervisor.status.snapshot()
    assert snapshot["error_code"] == "evaluation_deadline_exceeded"
    assert snapshot["alive"] is False
    assert snapshot["ready"] is False


def test_drain_deadline_stops_an_uncooperative_child():
    supervisor, thread, result = start_supervisor(hung_evaluator, drain_seconds=0.1)
    try:
        wait_for(supervisor, lambda s: s["phase"] == "evaluation")
        supervisor.request_drain()
        thread.join(5)
        assert not thread.is_alive()
        assert result == [124]
        assert supervisor.status.snapshot()["error_code"] == "drain_deadline_exceeded"
    finally:
        supervisor.request_drain()
        thread.join(5)


def test_abnormal_child_exit_is_not_reported_as_success():
    supervisor, thread, result = start_supervisor(failed_worker)
    thread.join(5)
    assert result == [1]
    assert supervisor.status.snapshot()["error_code"] == "worker_exited"


@pytest.mark.parametrize("phase", ["starting", "maintenance", "generation"])
def test_other_work_phases_have_enforced_deadlines(phase):
    field = "startup_seconds" if phase == "starting" else phase + "_seconds"
    supervisor, thread, result = start_supervisor(partial(hung_phase, phase), **{field: 0.2})
    thread.join(5)
    assert result == [124]
    assert supervisor.status.snapshot()["error_code"] == phase + "_deadline_exceeded"


@pytest.mark.parametrize(
    "target,code", [(private_failure, "worker_error"), (malformed_worker, "worker_protocol_error")]
)
def test_worker_errors_cannot_expose_private_messages(target, code):
    supervisor, thread, result = start_supervisor(target)
    thread.join(5)
    assert result == [1]
    assert supervisor.status.snapshot()["error_code"] == code
    assert "sentinel" not in json.dumps(supervisor.status.snapshot())


def test_final_protocol_error_cannot_be_masked_by_a_zero_exit(monkeypatch):
    supervisor = WorkerSupervisor(WorkerSettings(), malformed_then_exit)
    observe = supervisor.status.observe

    def delayed_observe(event):
        observe(event)
        time.sleep(0.2)  # Let the child exit before its final event is drained.

    monkeypatch.setattr(supervisor.status, "observe", delayed_observe)
    assert supervisor.run() == 1
    assert supervisor.status.snapshot()["error_code"] == "worker_protocol_error"


@pytest.mark.parametrize("recovered,expected", [(False, 1), (True, 0)])
def test_exit_status_preserves_unrecovered_runtime_errors(recovered, expected):
    supervisor = WorkerSupervisor(WorkerSettings(), partial(unavailable_then_exit, recovered))
    assert supervisor.run() == expected


@contextmanager
def process_fixture(mode, *, check_ready=True):
    repo = Path(__file__).resolve().parents[1]
    process = subprocess.Popen(
        [sys.executable, "tests/worker_process_fixture.py", mode],
        cwd=repo,
        env={**os.environ, "PYTHONPATH": str(repo)},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )
    receipt = {}
    try:
        assert process.stdout is not None
        for _ in range(2):
            assert select.select([process.stdout], [], [], 8)[0], "fixture did not start"
            receipt.update(json.loads(process.stdout.readline()))
        with httpx.Client(base_url=receipt["health_url"], trust_env=False, timeout=1) as client:
            for _ in range(100):
                if not check_ready or client.get("/readyz").status_code == 200:
                    break
                time.sleep(0.02)
            else:
                raise AssertionError("fixture did not become ready")
        yield process, receipt
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        # The child is owned by this fixture, and must not survive its supervisor.
        pid = receipt.get("worker_pid")
        if pid:
            for _ in range(100):
                if not child_is_running(pid):
                    break
                time.sleep(0.02)
            else:
                os.kill(pid, signal.SIGKILL)
                raise AssertionError("fixture child survived its supervisor")
        process.communicate(timeout=5)


def child_is_running(pid):
    state = subprocess.run(["ps", "-p", str(pid), "-o", "stat="], capture_output=True, text=True)
    # A briefly unreaped zombie cannot execute work or keep provider sockets open.
    return bool(state.stdout.strip()) and not state.stdout.strip().startswith("Z")


@pytest.mark.skipif(os.name != "posix", reason="POSIX signal proof")
def test_sigterm_drains_the_real_supervisor_process():
    with process_fixture("cooperative") as (process, receipt):
        process.send_signal(signal.SIGTERM)
        with httpx.Client(base_url=receipt["health_url"], trust_env=False, timeout=1) as client:
            for _ in range(30):
                if client.get("/readyz").status_code == 503:
                    break
                time.sleep(0.01)
            else:
                raise AssertionError("readiness did not reflect drain")
        assert process.wait(timeout=5) == 0
        assert not child_is_running(receipt["worker_pid"])


@pytest.mark.skipif(os.name != "posix", reason="POSIX parent-death proof")
def test_killed_supervisor_does_not_leave_an_executing_child():
    with process_fixture("uncooperative") as (process, receipt):
        process.kill()
        process.wait(timeout=5)
        for _ in range(100):
            if not child_is_running(receipt["worker_pid"]):
                break
            time.sleep(0.02)
        assert not child_is_running(receipt["worker_pid"])


@pytest.mark.skipif(os.name != "posix", reason="POSIX signal proof")
def test_signal_does_not_reenter_the_status_lock():
    with process_fixture("locked-signal", check_ready=False) as (process, _receipt):
        assert process.wait(timeout=4) == 0
