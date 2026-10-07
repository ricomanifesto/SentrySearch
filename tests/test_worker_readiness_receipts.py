"""Supervisor readiness receipts: schema, cadence, gaps and non-blocking delivery."""

import io
import json
import os
import re
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from src.execution import readiness_receipts as receipts_module
from src.execution.readiness_receipts import (
    ERROR_CODES,
    MAX_RECEIPT_BYTES,
    RECEIPT_KIND,
    RECEIPT_MARKER,
    ReadinessReceipts,
    release_id_from_environment,
)
from src.execution.supervisor import WorkerSettings, WorkerSupervisor

RELEASE_ID = "0b9f7c1e-4d2a-4f6b-9a3e-2c1d0e9f8a7b"
FIXTURE = Path(__file__).resolve().parent / "receipt_shutdown_fixture.py"
FIELDS = {
    "kind",
    "release_id",
    "boot_id",
    "sequence",
    "observed_at",
    "uptime_seconds",
    "alive",
    "ready",
    "draining",
    "phase",
    "phase_elapsed_seconds",
    "phase_budget_seconds",
    "error_code",
}


class MemorySink:
    def __init__(self) -> None:
        self.lines: list[str] = []
        self.lock = threading.Lock()

    def write(self, text: str) -> int:
        with self.lock:
            self.lines.extend(line for line in text.splitlines() if line)
        return len(text)

    def flush(self) -> None:
        pass

    def receipts(self) -> list[dict]:
        with self.lock:
            lines = list(self.lines)
        return [json.loads(line.split(" ", 1)[1]) for line in lines]


class BlockedSink:
    """A log pipe nobody reads: every write blocks until released."""

    def __init__(self) -> None:
        self.release = threading.Event()
        self.writes = 0

    def write(self, text: str) -> int:
        self.writes += 1
        self.release.wait()
        return len(text)

    def flush(self) -> None:
        pass


class Clock:
    def __init__(self) -> None:
        self.monotonic_value = 100.0
        self.wall_value = datetime(2026, 10, 7, 12, 0, tzinfo=UTC)

    def monotonic(self) -> float:
        return self.monotonic_value

    def wall(self) -> datetime:
        return self.wall_value

    def advance(self, seconds: float) -> None:
        self.monotonic_value += seconds
        self.wall_value += timedelta(seconds=seconds)


def snapshot(**changes):
    value = {
        "alive": True,
        "ready": True,
        "draining": False,
        "drain_elapsed_seconds": 0.0,
        "phase": "idle",
        "phase_elapsed_seconds": 1.25,
        "phase_budget_seconds": 62.0,
        "error_code": None,
        "backlog": {"counts": {"pending_dispatches": 3}, "age_seconds": 1.0},
    }
    value.update(changes)
    return value


def emitter(sink, clock=None, **options):
    clock = clock or Clock()
    return ReadinessReceipts(
        RELEASE_ID, sink, monotonic=clock.monotonic, wall=clock.wall, **options
    )


def wait_until(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError("condition not reached")


# --- schema -------------------------------------------------------------------


def test_receipt_is_the_exact_bounded_schema_without_application_data():
    clock = Clock()
    receipts = emitter(MemorySink(), clock)
    clock.advance(12.3456)
    receipt = receipts.receipt(snapshot(error_code="runtime_unavailable", ready=False))
    assert set(receipt) == FIELDS
    assert receipt["kind"] == RECEIPT_KIND == "sentry.worker-readiness.v1"
    assert receipt["release_id"] == RELEASE_ID
    assert re.fullmatch(r"[0-9a-f]{32}", receipt["boot_id"])
    assert receipt["sequence"] == 0  # receipt() builds; only emission advances it
    assert receipt["observed_at"] == "2026-10-07T12:00:12.345600Z"
    # Microseconds: a burst of transitions keeps strictly ordered uptimes.
    assert receipt["uptime_seconds"] == 12.3456
    assert receipt["error_code"] == "runtime_unavailable"
    assert "backlog" not in json.dumps(receipt) and "pending" not in json.dumps(receipt)
    assert len(json.dumps(receipt, separators=(",", ":"))) <= MAX_RECEIPT_BYTES


def test_unknown_error_codes_and_phases_are_enumerated_not_echoed():
    receipts = emitter(MemorySink())
    receipt = receipts.receipt(snapshot(error_code="private provider text", phase="exotic"))
    assert receipt["error_code"] == "unknown" and receipt["phase"] == "unknown"
    assert "private" not in json.dumps(receipt)
    assert "evaluation_deadline_exceeded" in ERROR_CODES and "unknown" in ERROR_CODES


def test_each_process_boot_has_a_fresh_random_identity():
    assert emitter(MemorySink()).boot_id != emitter(MemorySink()).boot_id


@pytest.mark.parametrize(
    ("environ", "expected"),
    [
        ({}, None),
        ({"SENTRYSEARCH_RELEASE_ID": RELEASE_ID}, RELEASE_ID),
    ],
)
def test_release_identity_comes_only_from_the_task_definition(environ, expected):
    assert release_id_from_environment(environ) == expected


@pytest.mark.parametrize("value", ["", "latest", RELEASE_ID.upper(), RELEASE_ID + "\n"])
def test_invalid_release_identity_is_a_configuration_error(value):
    with pytest.raises(ValueError):
        release_id_from_environment({"SENTRYSEARCH_RELEASE_ID": value})


# --- cadence ------------------------------------------------------------------


def test_emits_at_startup_on_the_interval_and_on_readiness_transitions_only():
    sink, clock = MemorySink(), Clock()
    receipts = emitter(sink, clock, interval_seconds=10)
    receipts.observe(snapshot(phase="starting", ready=False))  # startup
    clock.advance(1)
    receipts.observe(snapshot(phase="maintenance", ready=False))  # enters a working phase
    clock.advance(1)
    receipts.observe(snapshot(phase="maintenance"))  # becomes ready
    # An idle poll cycle changes working phase several times every 2 s; that
    # churn rides the interval instead of emitting about two receipts a second.
    for phase in ("generation", "maintenance", "idle", "evaluation"):
        clock.advance(1)
        receipts.observe(snapshot(phase=phase, phase_elapsed_seconds=0.5))
    clock.advance(6)
    receipts.observe(snapshot(phase="idle"))  # interval
    clock.advance(1)
    receipts.observe(snapshot(phase="idle", error_code="runtime_unavailable", ready=False))
    clock.advance(1)
    receipts.observe(snapshot(phase="idle", draining=True, ready=False))
    receipts.close(snapshot(alive=False, ready=False, phase="stopped"), timeout=2)
    emitted = sink.receipts()
    assert [item["sequence"] for item in emitted] == [1, 2, 3, 4, 5, 6, 7]
    assert [item["uptime_seconds"] for item in emitted] == [0, 1, 2, 12, 13, 14, 14]
    assert [item["phase"] for item in emitted] == [
        "starting", "maintenance", "maintenance", "idle", "idle", "idle", "stopped",
    ]  # fmt: skip
    assert emitted[-1]["alive"] is False
    assert all(line.startswith(RECEIPT_MARKER + " ") for line in sink.lines)


def test_sequence_advances_before_a_full_queue_drops_receipts():
    sink, clock = BlockedSink(), Clock()
    receipts = emitter(sink, clock, queue_size=2)
    receipts.observe(snapshot())
    wait_until(lambda: sink.writes == 1)  # the writer now holds receipt 1
    for _ in range(5):
        clock.advance(10)
        receipts.observe(snapshot())
    assert receipts.sequence == 6
    # Two wait in the queue; three found it full and left gaps.
    assert receipts.dropped == 3
    started = time.monotonic()
    receipts.close(snapshot(alive=False), timeout=0.2)
    assert time.monotonic() - started < 1.0, "closing must never wait on a blocked sink"
    sink.release.set()


def test_a_broken_sink_never_raises_into_the_supervisor():
    class Broken:
        def write(self, text):
            raise BrokenPipeError

        def flush(self):
            raise BrokenPipeError

    receipts = emitter(Broken())
    receipts.observe(snapshot())
    receipts.close(snapshot(alive=False), timeout=0.5)


# --- supervisor integration -----------------------------------------------------


def generation_worker(settings, stop, emit):
    emit({"event": "phase", "phase": "generation"})
    emit({"event": "ready", "value": True})
    time.sleep(0.4)
    emit({"event": "error", "code": "runtime_unavailable"})
    time.sleep(0.4)
    emit({"event": "recovered"})
    emit({"event": "ready", "value": True})
    stop.wait(10)
    time.sleep(0.1)
    return 0


def run_supervisor(target, receipts, **settings):
    supervisor = WorkerSupervisor(WorkerSettings(**settings), target, receipts=receipts)
    result = []
    thread = threading.Thread(target=lambda: result.append(supervisor.run()), daemon=True)
    thread.start()
    return supervisor, thread, result


def test_receipts_report_the_same_cached_state_as_readyz_through_busy_error_and_drain():
    sink = MemorySink()
    receipts = ReadinessReceipts(RELEASE_ID, sink, interval_seconds=0.1)
    supervisor, thread, result = run_supervisor(generation_worker, receipts, drain_seconds=2)
    try:
        wait_until(lambda: any(r["error_code"] == "runtime_unavailable" for r in sink.receipts()))
        wait_until(
            lambda: sink.receipts()[-1]["ready"] and sink.receipts()[-1]["error_code"] is None
        )
        with httpx.Client(base_url=str(supervisor.health_address), trust_env=False) as client:
            assert client.get("/readyz").status_code == 200
            assert client.get("/status").json()["ready"] is sink.receipts()[-1]["ready"]
            supervisor.request_drain()
            wait_until(lambda: sink.receipts()[-1]["draining"])
            assert client.get("/readyz").status_code == 503
            assert sink.receipts()[-1]["ready"] is False
        thread.join(5)
        assert result == [0]
    finally:
        supervisor.request_drain()
        thread.join(5)
    emitted = sink.receipts()
    assert [item["sequence"] for item in emitted] == list(range(1, len(emitted) + 1))
    assert {item["boot_id"] for item in emitted} == {receipts.boot_id}
    phases = [(item["phase"], item["ready"], item["error_code"]) for item in emitted]
    assert ("generation", True, None) in phases
    assert ("generation", False, "runtime_unavailable") in phases
    assert emitted[-1]["alive"] is False, "the best-effort stopped receipt follows exit"


def stalling_worker(settings, stop, emit):
    emit({"event": "phase", "phase": "idle"})
    emit({"event": "ready", "value": True})
    time.sleep(0.3)
    emit({"event": "backlog", "counts": {"pending_dispatches": 1}})
    stop.wait(10)
    return 0


def test_a_stalled_supervisor_loop_stops_receipts_instead_of_looking_fresh(monkeypatch):
    sink = MemorySink()
    receipts = ReadinessReceipts(RELEASE_ID, sink, interval_seconds=0.1)
    supervisor = WorkerSupervisor(
        WorkerSettings(drain_seconds=2, poll_seconds=5, startup_seconds=5),
        stalling_worker,
        receipts=receipts,
    )
    observe = supervisor.status.observe

    def stall_on_backlog(event):
        observe(event)
        if event["event"] == "backlog":
            time.sleep(1.5)  # supervision is stuck; no timer may fake liveness

    monkeypatch.setattr(supervisor.status, "observe", stall_on_backlog)
    thread = threading.Thread(target=supervisor.run, daemon=True)
    thread.start()
    try:
        wait_until(lambda: len(sink.receipts()) >= 5, timeout=6)
        wait_until(
            lambda: any(
                later["uptime_seconds"] - earlier["uptime_seconds"] >= 1.4
                for earlier, later in zip(sink.receipts(), sink.receipts()[1:])
            ),
            timeout=6,
        )
    finally:
        supervisor.request_drain()
        thread.join(5)


def test_a_blocked_log_pipe_never_delays_drain_or_reaping():
    sink = BlockedSink()
    receipts = ReadinessReceipts(RELEASE_ID, sink, interval_seconds=0.01, queue_size=4)
    supervisor, thread, result = run_supervisor(generation_worker, receipts, drain_seconds=2)
    try:
        time.sleep(0.5)
        started = time.monotonic()
        supervisor.request_drain()
        thread.join(5)
        assert not thread.is_alive() and result == [0]
        assert time.monotonic() - started < 3
        assert receipts.dropped > 0 and receipts.sequence > receipts.dropped
    finally:
        sink.release.set()
        supervisor.request_drain()
        thread.join(5)


def test_a_descriptor_sink_writes_a_private_duplicate_and_closes_once():
    read_end, write_end = os.pipe()
    try:
        sink = receipts_module.DescriptorSink(write_end)
        sink.write("receipt\n")
        sink.close()
        reused = os.pipe()  # may reuse the closed duplicate's number
        sink.close()  # a second close must not close an unrelated descriptor
        for fd in reused:
            os.fstat(fd)
            os.close(fd)
        os.write(write_end, b"application\n")  # the original stays open
        assert os.read(read_end, 100) == b"receipt\napplication\n"
    finally:
        os.close(read_end)
        os.close(write_end)


def test_a_writer_still_blocked_after_close_keeps_its_descriptor():
    read_end, write_end = os.pipe()
    sink = receipts_module.DescriptorSink(write_end)
    receipts = ReadinessReceipts(RELEASE_ID, sink, queue_size=4)
    try:
        ready = True
        deadline = time.monotonic() + 10
        while receipts.dropped < 20 and time.monotonic() < deadline:
            ready = not ready
            receipts.observe(snapshot(ready=ready))
            time.sleep(0.001)
        assert receipts.dropped >= 20, "the unread pipe filled"
        receipts.close(snapshot(alive=False), timeout=0.1)
        assert receipts._writer.is_alive()
        os.fstat(sink._fd)  # not closed under the blocked writer
    finally:
        # Drain the pipe so the writer can finish, then stop it: a full queue may
        # have refused close()'s stop marker.
        drained = threading.Event()

        def drain():
            while not drained.is_set():
                if not os.read(read_end, 65536):
                    return

        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        receipts._queue.put(receipts_module._STOP, timeout=5)
        receipts._writer.join(5)
        drained.set()
        sink.close()
        os.close(write_end)  # ends the reader's blocking read
        reader.join(5)
        os.close(read_end)


@pytest.mark.parametrize("unbuffered", [False, True], ids=["buffered", "unbuffered"])
def test_the_worker_process_exits_cleanly_with_an_unread_full_stdout_pipe(tmp_path, unbuffered):
    """Real interpreter shutdown while the receipt writer is blocked on stdout."""
    env = {
        key: value for key, value in os.environ.items() if not key.startswith(("AWS_", "PYTHON"))
    }
    env.update({"PYTHON_DOTENV_DISABLED": "1", "SENTRYSEARCH_RELEASE_ID": RELEASE_ID})
    command = [sys.executable, *(["-u"] if unbuffered else []), str(FIXTURE)]
    stderr = tmp_path / "stderr.txt"
    with stderr.open("wb") as errors:
        # stdout is deliberately not read until the process has exited.
        # The fixture disables its own core dumps; no preexec_fn in a threaded parent.
        child = subprocess.Popen(
            command, cwd=tmp_path, env=env, stdout=subprocess.PIPE, stderr=errors
        )  # fmt: skip
        try:
            returncode = child.wait(timeout=30)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=10)
            output = child.stdout.read() if child.stdout else b""
            if child.stdout:
                child.stdout.close()
    log = stderr.read_text()
    assert "CLOSE_RETURNED" in log and "Fatal Python error" not in log, log
    assert returncode == 0, log
    assert "STDOUT_BLOCKING=True" in log, "application stdout keeps its blocking mode"
    assert "WRITER_ALIVE=True" in log, "the writer was still blocked at shutdown"
    assert output.startswith(b"APPLICATION_OUTPUT\n")
    assert RECEIPT_MARKER.encode() in output
    assert int(log.split("DROPPED=")[1].split()[0]) >= 100, "the pipe really filled"


def quick_exit(settings, stop, emit):
    return 0


def test_without_a_release_identity_the_supervisor_emits_nothing(capsys):
    supervisor = WorkerSupervisor(WorkerSettings(), quick_exit)
    assert supervisor.run() == 0
    assert RECEIPT_MARKER not in capsys.readouterr().out


def test_worker_entrypoint_wires_receipts_from_the_environment(monkeypatch):
    from dev import run_runtime_worker

    built = {}

    class Recorder:
        def __init__(self, settings, target, *, receipts=None):
            built["receipts"] = receipts

        def run(self):
            return 0

    monkeypatch.setattr(run_runtime_worker, "WorkerSupervisor", Recorder)
    monkeypatch.setattr(run_runtime_worker, "load_dotenv", lambda: None)
    monkeypatch.setattr("sys.argv", ["run_runtime_worker"])
    monkeypatch.setenv("SENTRYSEARCH_RELEASE_ID", RELEASE_ID)
    # Receipts go to the process's standard output descriptor, even when
    # sys.stdout has been replaced in-process by an object without one.
    monkeypatch.setattr("sys.stdout", io.StringIO())
    assert run_runtime_worker.main() == 0
    assert isinstance(built["receipts"], ReadinessReceipts)
    assert built["receipts"].release_id == RELEASE_ID
    assert isinstance(built["receipts"]._sink, receipts_module.DescriptorSink)
    monkeypatch.setenv("SENTRYSEARCH_RELEASE_ID", "not-a-release")
    with pytest.raises(SystemExit):
        run_runtime_worker.main()
    monkeypatch.delenv("SENTRYSEARCH_RELEASE_ID")
    assert run_runtime_worker.main() == 0 and built["receipts"] is None
    assert receipts_module.INTERVAL_SECONDS == 10
