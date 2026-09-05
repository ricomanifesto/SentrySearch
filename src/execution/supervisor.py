"""Local process lifetime, cached health, and bounded worker drain."""

from collections.abc import Callable
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
import math
import multiprocessing
from multiprocessing.connection import Connection
import os
import signal
import threading
import time
from typing import Any

from src.domain.execution import EVALUATION_LEASE_SECONDS

logger = logging.getLogger(__name__)
PHASES = {"starting", "maintenance", "generation", "evaluation", "idle", "stopped"}
BACKLOG_FIELDS = {
    "pending_dispatches",
    "submitted_dispatches",
    "ready_evaluations",
    "active_evaluations",
    "dispatch_errors",
}
Emit = Callable[[dict[str, Any]], None]
WorkerTarget = Callable[["WorkerSettings", threading.Event, Emit], int]


@dataclass(frozen=True)
class WorkerSettings:
    once: bool = False
    poll_seconds: float = 2.0
    lease_seconds: int = 60
    health_port: int = 0
    startup_seconds: float = 60.0
    maintenance_seconds: float = 120.0
    generation_seconds: float = 1800.0
    evaluation_seconds: float = 600.0
    drain_seconds: float = 30.0

    def __post_init__(self) -> None:
        for value in (
            self.poll_seconds,
            self.startup_seconds,
            self.maintenance_seconds,
            self.generation_seconds,
            self.evaluation_seconds,
        ):
            if not math.isfinite(value) or not 0 < value <= 86400:
                raise ValueError("worker time budgets must be finite, positive, and at most a day")
        if self.poll_seconds > 60 or not 3 <= self.lease_seconds <= 3600:
            raise ValueError(
                "poll interval must be at most 60 seconds; lease must be 3-3600 seconds"
            )
        # Leave publication/termination margin before product evaluation takeover.
        if self.evaluation_seconds > EVALUATION_LEASE_SECONDS - 60:
            raise ValueError(
                "evaluation deadline must leave 60 seconds before the 900-second lease"
            )
        if not math.isfinite(self.drain_seconds) or not 0 <= self.drain_seconds <= 3600:
            raise ValueError("drain budget must be finite and between 0 and 3600 seconds")
        if not 0 <= self.health_port <= 65535:
            raise ValueError("health port must be between 0 and 65535")

    def budget(self, phase: str) -> float:
        return {
            "starting": self.startup_seconds,
            "maintenance": self.maintenance_seconds,
            "generation": self.generation_seconds,
            "evaluation": self.evaluation_seconds,
            "idle": self.poll_seconds + self.startup_seconds,
            "stopped": self.startup_seconds,
        }[phase]


class WorkerStatus:
    """Supervisor-owned state; probe threads never call product dependencies."""

    def __init__(self, settings: WorkerSettings) -> None:
        self.settings = settings
        self._lock = threading.Lock()
        self._phase = "starting"
        self._phase_at = time.monotonic()
        self._alive = False
        self._ready = False
        self._draining_at: float | None = None
        self._error: str | None = None
        self._backlog: dict[str, int] | None = None
        self._backlog_at = 0.0

    def set_alive(self, alive: bool) -> None:
        with self._lock:
            self._alive = alive

    def drain(self) -> None:
        with self._lock:
            if self._draining_at is None:
                self._draining_at = time.monotonic()

    def fail(self, code: str) -> None:
        with self._lock:
            self._error = code
            self._ready = False

    def observe(self, event: dict[str, Any]) -> None:
        observed_at = event.get("at", time.monotonic())
        if (
            type(observed_at) not in {int, float}
            or not math.isfinite(observed_at)
            or not 0 <= observed_at <= time.monotonic()
        ):
            raise ValueError("invalid worker event timestamp")
        with self._lock:
            kind = event["event"]
            if kind == "phase":
                phase = event["phase"]
                if phase not in PHASES:
                    raise ValueError("unknown worker phase")
                self._phase = phase
                self._phase_at = observed_at
            elif kind == "ready":
                if type(event["value"]) is not bool:
                    raise ValueError("invalid readiness value")
                self._ready = event["value"]
            elif kind == "backlog":
                counts = event["counts"]
                if not isinstance(counts, dict) or not counts.keys() <= BACKLOG_FIELDS:
                    raise ValueError("invalid backlog fields")
                if any(type(value) is not int or value < 0 for value in counts.values()):
                    raise ValueError("invalid backlog counts")
                self._backlog = dict(counts)
                self._backlog_at = observed_at
            elif kind == "error":
                if event["code"] not in {
                    "runtime_unavailable",
                    "runtime_access_denied",
                    "worker_error",
                }:
                    raise ValueError("invalid worker error code")
                self._error = event["code"]
                self._ready = False
            elif kind == "recovered":
                self._error = None
            else:
                raise ValueError("unknown worker event")

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._phase_at
            budget = self.settings.budget(self._phase)
            return {
                "alive": self._alive,
                "ready": bool(
                    self._alive
                    and self._ready
                    and self._error is None
                    and self._draining_at is None
                    and self._phase not in {"starting", "stopped"}
                    and elapsed < budget
                ),
                "draining": self._draining_at is not None,
                "drain_elapsed_seconds": (
                    now - self._draining_at if self._draining_at is not None else 0.0
                ),
                "phase": self._phase,
                "phase_elapsed_seconds": elapsed,
                "phase_budget_seconds": budget,
                "error_code": self._error,
                "backlog": (
                    {"counts": dict(self._backlog), "age_seconds": now - self._backlog_at}
                    if self._backlog is not None
                    else None
                ),
            }


def _run_child(
    target: WorkerTarget, settings: WorkerSettings, control: Connection, events: Connection
) -> None:
    # All application clients, DB pools, and work threads are created here, never
    # forked from a parent that may already hold network clients or locks.
    stop = threading.Event()
    # The supervisor owns signals and sends drain over the control pipe. Calling
    # Event.set from a signal handler could reenter a lock held by this thread.
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)

    def watch_supervisor() -> None:
        while True:
            try:
                message = control.recv_bytes()
            except (EOFError, OSError):
                # The supervisor disappeared. Do not leave unowned execution or
                # provider threads alive. Durable leases recover interrupted work.
                os._exit(1)
            if message == b"drain":
                stop.set()

    threading.Thread(target=watch_supervisor, name="supervisor-control", daemon=True).start()

    def emit(event: dict[str, Any]) -> None:
        event = {"at": time.monotonic(), **event}
        if len(json.dumps(event)) > 2048:
            raise ValueError("worker event exceeds its bounded schema")
        events.send(event)

    try:
        result = target(settings, stop, emit)
        emit({"event": "phase", "phase": "stopped"})
    except Exception:
        # The supervisor channel must not carry provider responses, SQL, URLs,
        # tokens, or report contents through exception messages.
        emit({"event": "error", "code": "worker_error"})
        result = 1
    finally:
        events.close()
    raise SystemExit(result)


class WorkerSupervisor:
    def __init__(self, settings: WorkerSettings, target: WorkerTarget) -> None:
        self.settings = settings
        self.target = target
        self.status = WorkerStatus(settings)
        self.health_address: str | None = None
        self._drain = threading.Event()
        self._signal_drain = False

    def request_drain(self) -> None:
        self.status.drain()
        self._drain.set()

    def _health_server(self) -> ThreadingHTTPServer:
        status = self.status

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if self.path not in {"/healthz", "/readyz", "/status"}:
                    self.send_error(404)
                    return
                snapshot = status.snapshot()
                healthy = snapshot["ready"] if self.path == "/readyz" else snapshot["alive"]
                code = 200 if self.path == "/status" or healthy else 503
                payload = json.dumps(snapshot).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def do_POST(self) -> None:
                self.send_error(405)

            def log_message(self, format: str, *args: Any) -> None:
                pass

        # This deliberately is not a remotely exposed production HTTP service.
        return ThreadingHTTPServer(("127.0.0.1", self.settings.health_port), Handler)

    def run(self) -> int:
        context = multiprocessing.get_context("spawn")
        receive, send = context.Pipe(duplex=False)
        control_receive, control_send = context.Pipe(duplex=False)
        process = context.Process(
            target=_run_child, args=(self.target, self.settings, control_receive, send), daemon=True
        )
        server = self._health_server()
        self.health_address = f"http://127.0.0.1:{server.server_port}"
        server_thread = threading.Thread(
            target=lambda: server.serve_forever(poll_interval=0.05), daemon=True
        )
        old_handlers = {}
        if threading.current_thread() is threading.main_thread():

            def signal_drain(*_args: Any) -> None:
                # A signal can interrupt observe/snapshot while their lock is
                # held. Only set a flag here; perform drain on the main loop.
                self._signal_drain = True

            for signum in (signal.SIGINT, signal.SIGTERM):
                old_handlers[signum] = signal.signal(signum, signal_drain)
        result = 1
        started = False
        try:
            process.start()
            started = True
            send.close()
            control_receive.close()
            self.status.set_alive(True)
            server_thread.start()
            logger.info("Worker health available at %s", self.health_address)
            drain_sent = False
            channel_open = True
            while True:
                if self._signal_drain and not self._drain.is_set():
                    self.request_drain()
                if self._drain.is_set() and not drain_sent:
                    try:
                        control_send.send_bytes(b"drain")
                    except (BrokenPipeError, OSError):
                        pass
                    drain_sent = True
                if channel_open and receive.poll(0.05):
                    try:
                        self.status.observe(receive.recv())
                    except EOFError:
                        channel_open = False
                    except Exception:
                        self.status.fail("worker_protocol_error")
                        break
                elif not channel_open:
                    time.sleep(0.05)
                if not process.is_alive():
                    # Consume final error/status messages before reporting exit.
                    while channel_open and receive.poll():
                        try:
                            self.status.observe(receive.recv())
                        except EOFError:
                            channel_open = False
                        except Exception:
                            self.status.fail("worker_protocol_error")
                            break
                    result = (
                        0
                        if process.exitcode == 0 and self.status.snapshot()["error_code"] is None
                        else 1
                    )
                    if result and self.status.snapshot()["error_code"] is None:
                        self.status.fail("worker_exited")
                    break
                snapshot = self.status.snapshot()
                if (
                    snapshot["draining"]
                    and snapshot["drain_elapsed_seconds"] >= self.settings.drain_seconds
                ):
                    self.status.fail("drain_deadline_exceeded")
                    result = 124
                    break
                if snapshot["phase_elapsed_seconds"] >= snapshot["phase_budget_seconds"]:
                    self.status.fail(snapshot["phase"] + "_deadline_exceeded")
                    result = 124
                    break
        finally:
            if started:
                if process.is_alive():
                    # No application cleanup or shared lock is required in the
                    # child. PostgreSQL rolls back open transactions on disconnect.
                    process.kill()
                process.join(timeout=5)
                if process.is_alive():
                    raise RuntimeError("worker could not be reaped")
                process.close()
            self.status.set_alive(False)
            for connection in (receive, send, control_receive, control_send):
                connection.close()
            if server_thread.is_alive():
                server.shutdown()
                server_thread.join(timeout=2)
            server.server_close()
            for signum, handler in old_handlers.items():
                signal.signal(signum, handler)
            logger.info("Worker supervisor stopped: %s", json.dumps(self.status.snapshot()))
        return result
