"""Worker readiness receipts for the attended release gate (schema v1).

The supervisor main loop calls ``observe`` with its cached ``WorkerStatus``
snapshot, the same state /readyz serves. A receipt is emitted at startup, every
10 seconds and on each readiness transition (alive, ready, draining, error, or
entering or leaving a working phase). A stalled loop therefore stops emitting
instead of looking fresh. The sequence advances before a bounded, nonblocking
enqueue; a full queue drops the receipt and leaves a visible gap. A separate
writer thread owns its own duplicate of the stdout descriptor, so a blocked log
pipe never delays signals, drain, reaping or interpreter shutdown. Receipts carry no user, report, URL, credential or exception data.
"""

from __future__ import annotations

import json
import math
import os
import queue
import re
import secrets
import threading
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any, Protocol

RECEIPT_KIND = "sentry.worker-readiness.v1"
RECEIPT_MARKER = "SENTRY_WORKER_READINESS"
INTERVAL_SECONDS = 10
QUEUE_SIZE = 64
MAX_RECEIPT_BYTES = 2048
PHASES = frozenset({"starting", "maintenance", "generation", "evaluation", "idle", "stopped"})
WORKING_PHASES = frozenset({"maintenance", "generation", "evaluation", "idle"})
ERROR_CODES = frozenset(
    {
        "runtime_unavailable",
        "runtime_access_denied",
        "worker_error",
        "worker_protocol_error",
        "worker_exited",
        "drain_deadline_exceeded",
        *(f"{phase}_deadline_exceeded" for phase in PHASES),
        "unknown",
    }
)
_RELEASE_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_STOP = object()


class Sink(Protocol):
    def write(self, text: str, /) -> int: ...

    def flush(self) -> None: ...


class DescriptorSink:
    """Receipts written straight to a private duplicate of a file descriptor.

    It never uses the interpreter's buffered ``sys.stdout``, so a writer blocked
    on a full pipe holds no lock that interpreter shutdown needs, and application
    output keeps its own buffering and blocking mode. Each receipt is one write
    call (marker, JSON of at most 2 KiB and a newline). A pipe keeps a write
    whole only up to its atomic size (4096 bytes on Linux, 512 on macOS), so
    another writer's output could split a rare large receipt; the observer then
    sees an invalid line or a gap.
    """

    def __init__(self, fd: int) -> None:
        self._fd = os.dup(fd)

    def write(self, text: str, /) -> int:
        data = memoryview(text.encode())
        while data:
            data = data[os.write(self._fd, data) :]
        return len(text)

    def flush(self) -> None:
        pass

    def close(self) -> None:
        # Idempotent: a second close must never hit a reused descriptor number.
        if self._fd >= 0:
            fd, self._fd = self._fd, -1
            os.close(fd)


def release_id_from_environment(environ: Mapping[str, str]) -> str | None:
    """The release identity fixed in the task definition; absent locally."""
    if "SENTRYSEARCH_RELEASE_ID" not in environ:
        return None
    value = environ["SENTRYSEARCH_RELEASE_ID"]
    if not _RELEASE_ID.fullmatch(value):
        raise ValueError("SENTRYSEARCH_RELEASE_ID must be a lowercase release UUID")
    return value


def _seconds(value: object, digits: int = 3) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return 0.0
    return round(max(0.0, float(value)), digits)


class ReadinessReceipts:
    def __init__(
        self,
        release_id: str,
        sink: Sink,
        *,
        interval_seconds: float = INTERVAL_SECONDS,
        queue_size: int = QUEUE_SIZE,
        monotonic: Callable[[], float] = time.monotonic,
        wall: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if not _RELEASE_ID.fullmatch(release_id):
            raise ValueError("release identity must be a lowercase UUID")
        self.release_id = release_id
        self.boot_id = secrets.token_hex(16)
        self.sequence = 0
        self.dropped = 0
        self._sink = sink
        self._interval = interval_seconds
        self._monotonic = monotonic
        self._wall = wall
        self._started = monotonic()
        self._last_emit: float | None = None
        self._last_state: tuple[Any, ...] | None = None
        self._queue: queue.Queue[object] = queue.Queue(maxsize=queue_size)
        self._writer = threading.Thread(target=self._write, name="readiness-receipts", daemon=True)
        self._writer.start()

    def receipt(self, snapshot: Mapping[str, Any]) -> dict[str, Any]:
        phase = snapshot.get("phase")
        error = snapshot.get("error_code")
        observed = self._wall().astimezone(UTC)
        return {
            "kind": RECEIPT_KIND,
            "release_id": self.release_id,
            "boot_id": self.boot_id,
            "sequence": self.sequence,
            "observed_at": observed.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            # Microseconds keep a burst of transitions strictly ordered.
            "uptime_seconds": _seconds(self._monotonic() - self._started, 6),
            "alive": snapshot.get("alive") is True,
            "ready": snapshot.get("ready") is True,
            "draining": snapshot.get("draining") is True,
            "phase": phase if phase in PHASES else "unknown",
            "phase_elapsed_seconds": _seconds(snapshot.get("phase_elapsed_seconds")),
            "phase_budget_seconds": _seconds(snapshot.get("phase_budget_seconds")),
            "error_code": None if error is None else (error if error in ERROR_CODES else "unknown"),
        }

    def observe(self, snapshot: Mapping[str, Any]) -> None:
        """Emit if this is the first call, a readiness transition, or the interval elapsed.

        Moving between working phases is not a readiness transition: an idle poll
        cycle changes phase four times every two seconds, which measured about two
        receipts a second. That churn is reported on the interval instead.
        """
        now = self._monotonic()
        phase = snapshot.get("phase")
        state = (
            *(snapshot.get(key) for key in ("alive", "ready", "draining", "error_code")),
            "working" if phase in WORKING_PHASES else phase,
        )
        if (
            self._last_emit is None
            or state != self._last_state
            or now - self._last_emit >= self._interval
        ):
            self._last_emit, self._last_state = now, state
            self._emit(snapshot)

    def close(self, snapshot: Mapping[str, Any], *, timeout: float = 1.0) -> None:
        """Best-effort stopped receipt and flush, bounded by ``timeout``.

        A writer still blocked on its sink is left to process exit; its sink is
        only closed once the writer has stopped using it.
        """
        self._emit(snapshot)
        try:
            self._queue.put_nowait(_STOP)
        except queue.Full:
            pass
        self._writer.join(timeout)
        if not self._writer.is_alive() and isinstance(self._sink, DescriptorSink):
            self._sink.close()

    def _emit(self, snapshot: Mapping[str, Any]) -> None:
        # The sequence advances even when the receipt is dropped: the gap is the
        # evidence that delivery failed.
        self.sequence += 1
        line = json.dumps(self.receipt(snapshot), separators=(",", ":"))
        if len(line) > MAX_RECEIPT_BYTES:
            self.dropped += 1
            return
        try:
            self._queue.put_nowait(f"{RECEIPT_MARKER} {line}\n")
        except queue.Full:
            self.dropped += 1

    def _write(self) -> None:
        while True:
            item = self._queue.get()
            if item is _STOP:
                return
            try:
                self._sink.write(str(item))
                self._sink.flush()
            except (OSError, ValueError):
                # A closed or broken pipe loses receipts; the observer sees gaps.
                continue
