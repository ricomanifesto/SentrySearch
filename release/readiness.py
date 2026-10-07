"""Worker readiness gate: a bounded observation of supervisor receipts.

Pure policy and parsing. The controller supplies platform identity (deployment,
task, revision and digest from ECS) and the fixed log stream of the observed task;
nothing here trusts a worker-supplied log location or identity. Success is a
bounded observation of 60 seconds of consecutive, fresh, eligible receipts, not
continuing readiness, report completion or auth/S3 proof. Application receipts
are not proof against a compromised worker.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from release.ports import LogPort

WORKER_RECEIPT_KIND = "sentry.worker-readiness.v1"
# The one manifest operational check the controller proves from these receipts.
WORKER_READINESS_CHECK = "worker-readiness"
WORKER_RECEIPT_MARKER = "SENTRY_WORKER_READINESS"
# The worker's awslogs stream prefix (followed by its release id) and container
# name in deploy/aws-platform-fit.
WORKER_LOG_STREAM_PREFIX = "worker"
WORKER_CONTAINER = "app"
MAX_RECEIPT_BYTES = 2048
PHASES = frozenset(
    {"starting", "maintenance", "generation", "evaluation", "idle", "stopped", "unknown"}
)
WORKING_PHASES = frozenset({"maintenance", "generation", "evaluation", "idle"})
ERROR_CODES = frozenset(
    {
        "runtime_unavailable",
        "runtime_access_denied",
        "worker_error",
        "worker_protocol_error",
        "worker_exited",
        "drain_deadline_exceeded",
        *(f"{phase}_deadline_exceeded" for phase in PHASES - {"unknown"}),
        "unknown",
    }
)
FIELDS = frozenset(
    {
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
)
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_BOOT = re.compile(r"[0-9a-f]{32}")
_OBSERVED = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z")
_TASK_ID = re.compile(r"[0-9a-f]{32}")
MAX_SECONDS = 10 * 365 * 86400
MAX_SEQUENCE = 2**53


class InvalidReceipt(ValueError):
    """A marked line that is not an exact v1 receipt."""


@dataclass(frozen=True)
class GatePolicy:
    """Proposed gate policy (release-orchestration), not measured AWS guarantees."""

    max_age_seconds: float = 30.0
    max_future_skew_seconds: float = 5.0
    stable_seconds: float = 60.0
    max_sample_gap_seconds: float = 15.0
    gate_seconds: float = 600.0
    max_pages: int = 20
    max_bytes: int = 1_048_576
    page_limit: int = 100


@dataclass(frozen=True)
class WorkerReceipt:
    release_id: str
    boot_id: str
    sequence: int
    observed_at: datetime
    uptime: float
    alive: bool
    ready: bool
    draining: bool
    phase: str
    phase_elapsed: float
    phase_budget: float
    error_code: str | None
    canonical: str = field(repr=False)

    @property
    def eligible(self) -> bool:
        """Ready means alive, not draining or failed, working, within its budget."""
        return (
            self.alive
            and self.ready
            and not self.draining
            and self.error_code is None
            and self.phase in WORKING_PHASES
            and self.phase_elapsed < self.phase_budget
        )


def _reject_constant(value: str) -> float:
    raise InvalidReceipt("non-finite number")


def _number(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InvalidReceipt("number")
    number = float(value)  # an overflowing integer is an invalid receipt via parse_line
    if not math.isfinite(number) or not 0 <= number <= MAX_SECONDS:
        raise InvalidReceipt("number range")
    return number


def _flag(value: object) -> bool:
    if type(value) is not bool:
        raise InvalidReceipt("flag")
    return value


def parse_line(message: str) -> WorkerReceipt | None:
    """None for ordinary log lines; ``InvalidReceipt`` for any malformed marked line.

    The stream carries all worker output, so a marked line is untrusted input:
    no type or value in it may raise anything else.
    """
    if not message.startswith(WORKER_RECEIPT_MARKER):
        return None
    try:
        return _parse(message[len(WORKER_RECEIPT_MARKER) :])
    except InvalidReceipt:
        raise
    except (ValueError, TypeError, OverflowError, RecursionError) as error:
        raise InvalidReceipt("unparseable") from error


def _parse(body: str) -> WorkerReceipt:
    if not body.startswith(" ") or len(body) > MAX_RECEIPT_BYTES + 1:
        raise InvalidReceipt("marker or size")
    document = json.loads(body[1:], parse_constant=_reject_constant)
    if not isinstance(document, dict) or set(document) != FIELDS:
        raise InvalidReceipt("fields")
    sequence = document["sequence"]
    observed = document["observed_at"]
    if not all(
        isinstance(document[key], str) for key in ("kind", "release_id", "boot_id", "phase")
    ):
        raise InvalidReceipt("types")
    error_code = document["error_code"]
    if (
        document["kind"] != WORKER_RECEIPT_KIND
        or not _UUID.fullmatch(document["release_id"])
        or not _BOOT.fullmatch(document["boot_id"])
        or type(sequence) is not int
        or not 1 <= sequence < MAX_SEQUENCE
        or not isinstance(observed, str)
        or not _OBSERVED.fullmatch(observed)
        or document["phase"] not in PHASES
        or (
            error_code is not None
            and (not isinstance(error_code, str) or error_code not in ERROR_CODES)
        )
    ):
        raise InvalidReceipt("values")
    try:
        observed_at = datetime.strptime(observed, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError as error:
        raise InvalidReceipt("timestamp") from error
    budget = _number(document["phase_budget_seconds"])
    if budget <= 0:
        raise InvalidReceipt("budget")
    return WorkerReceipt(
        release_id=document["release_id"],
        boot_id=document["boot_id"],
        sequence=sequence,
        observed_at=observed_at,
        uptime=_number(document["uptime_seconds"]),
        alive=_flag(document["alive"]),
        ready=_flag(document["ready"]),
        draining=_flag(document["draining"]),
        phase=document["phase"],
        phase_elapsed=_number(document["phase_elapsed_seconds"]),
        phase_budget=budget,
        error_code=document["error_code"],
        canonical=json.dumps(document, sort_keys=True, separators=(",", ":")),
    )


def worker_stream(environment_name: str, release_id: str, task_arn: str) -> tuple[str, str]:
    """The observed task's configured stream; never a worker-supplied location.

    The approved manifest's release id and the ECS task identify it: each
    release's worker writes under its own immutable prefix.
    """
    task_id = task_arn.rsplit("/", 1)[-1]
    if not _UUID.fullmatch(release_id) or not _TASK_ID.fullmatch(task_id):
        raise ValueError("unexpected release or task identifier")
    return (
        f"/{environment_name}/worker",
        f"{WORKER_LOG_STREAM_PREFIX}/{release_id}/{WORKER_CONTAINER}/{task_id}",
    )


@dataclass(frozen=True)
class LogRead:
    messages: list[str]
    token: str | None
    complete: bool


def _millis(moment: datetime) -> int:
    return int(moment.timestamp() * 1000)


def read_stream(
    logs: LogPort,
    log_group: str,
    log_stream: str,
    *,
    token: str | None,
    start: datetime,
    end: datetime,
    policy: GatePolicy,
) -> LogRead:
    """Follow forward tokens from ``token`` to the stream end within fixed bounds.

    The end is a page that returns the caller's own token. Empty pages with a new
    token do not end a stream. Exhausting the page or byte bound is incomplete,
    which the gate treats as not proven for that poll.
    """
    messages: list[str] = []
    size = 0
    current = token
    for _ in range(policy.max_pages):
        page = logs.get_log_events(
            log_group,
            log_stream,
            start_time_ms=_millis(start),
            end_time_ms=_millis(end),
            next_token=current,
            limit=policy.page_limit,
        )
        events = page.get("events") if isinstance(page, dict) else None
        following = page.get("nextForwardToken") if isinstance(page, dict) else None
        if not isinstance(events, list) or not isinstance(following, str):
            raise ValueError("malformed log page")
        for event in events:
            message = event.get("message") if isinstance(event, dict) else None
            if not isinstance(message, str):
                raise ValueError("malformed log event")
            size += len(message.encode())
            if size > policy.max_bytes:
                return LogRead(messages, current, False)
            messages.append(message)
        if following == current:
            return LogRead(messages, following, True)
        current = following
    return LogRead(messages, current, False)


class ReadinessGate:
    """One gate attempt (epoch). Any anomaly restarts the stable window."""

    def __init__(
        self, policy: GatePolicy, *, release_id: str, epoch_start: datetime, task_arn: str
    ) -> None:
        self.policy = policy
        self.release_id = release_id
        self.epoch_start = epoch_start
        self.task_arn = task_arn
        self.reason: str | None = None
        self.received = 0
        self._last: WorkerReceipt | None = None
        self._window: WorkerReceipt | None = None
        # A worker clock may run ahead by the allowed skew, so a receipt observed
        # just after the epoch may have been emitted before the attempt began.
        skew = timedelta(seconds=policy.max_future_skew_seconds)
        self._floor = epoch_start + skew
        self._latest = epoch_start  # controller time never moves backwards
        self._seen: dict[tuple[str, int], bytes] = {}

    def _start(self, receipt: WorkerReceipt | None) -> WorkerReceipt | None:
        # A window starts only from an eligible receipt observed after the last clear.
        if receipt is None or not receipt.eligible or receipt.observed_at <= self._floor:
            return None
        return receipt

    def _reset(self, reason: str, *, restart: WorkerReceipt | None = None) -> None:
        self.reason = reason
        self._window = self._start(restart)

    def clear(self, reason: str, at: datetime) -> None:
        """Drop stability (ECS visibility, incomplete read, freshness); keep continuity.

        Recovery needs a full new window of receipts observed after ``at``, even
        when receipts from before it arrive late with consecutive sequences. A
        worker clock may run ahead by the allowed skew, so the floor includes it.
        """
        self._reset(reason)
        skew = timedelta(seconds=self.policy.max_future_skew_seconds)
        self._floor = max(self._floor, at + skew)
        self._latest = max(self._latest, at)

    def _advance(self, now: datetime) -> bool:
        """Record controller time; False if it moved backwards (and clear)."""
        if now < self._latest:
            self.clear("controller_clock_rollback", self._latest)
            return False
        self._latest = now
        return True

    def ingest(self, messages: Iterable[str], now: datetime) -> None:
        self._advance(now)
        for message in messages:
            try:
                receipt = parse_line(message)
            except InvalidReceipt:
                self._reset("receipt_invalid")
                continue
            if receipt is not None:
                self._accept(receipt, now)

    def _accept(self, receipt: WorkerReceipt, now: datetime) -> None:
        # Observation time, not ingestion time, decides eligibility; history from
        # before this attempt cannot seed its window.
        if receipt.observed_at < self.epoch_start:
            return
        key = (receipt.boot_id, receipt.sequence)
        digest = hashlib.sha256(receipt.canonical.encode()).digest()
        if key in self._seen:
            if self._seen[key] != digest:
                self._reset("receipt_conflict")
            return  # an identical replay never counts twice
        # Past the cap a replay looks reordered or like a gap: a reset, never a pass.
        if len(self._seen) < 8192:
            self._seen[key] = digest
        self.received += 1
        last = self._last
        if receipt.release_id != self.release_id:
            self._reset("receipt_release_mismatch")
            return
        if (receipt.observed_at - now).total_seconds() > self.policy.max_future_skew_seconds:
            self._reset("receipt_from_future")
            return
        if (
            last is not None
            and last.boot_id == receipt.boot_id
            and receipt.sequence < last.sequence
        ):
            self._reset("receipt_reordered")
            return
        self._last = receipt
        if last is None:
            self._window = self._start(receipt)
            if not receipt.eligible:
                self.reason = "receipt_not_ready"
            return
        if receipt.boot_id != last.boot_id:
            self._reset("worker_rebooted", restart=receipt)
            return
        if receipt.sequence != last.sequence + 1:
            self._reset("receipt_gap", restart=receipt)
            return
        monotonic = receipt.uptime - last.uptime
        wall = (receipt.observed_at - last.observed_at).total_seconds()
        # Equal values are a burst of transitions at one instant; backwards is not.
        if monotonic < 0 or wall < 0:
            self._reset("receipt_clock_anomaly")
            return
        if monotonic > self.policy.max_sample_gap_seconds:
            self._reset("receipt_interval_exceeded", restart=receipt)
            return
        if abs(wall - monotonic) > self.policy.max_future_skew_seconds:
            self._reset("receipt_clock_anomaly")
            return
        if not receipt.eligible:
            self._reset("receipt_not_ready")
            return
        if self._window is None:
            self._window = self._start(receipt)

    def stable(self, now: datetime) -> bool:
        if not self._advance(now):
            return False
        last, window = self._last, self._window
        if last is None or window is None:
            return False
        if (now - last.observed_at).total_seconds() > self.policy.max_age_seconds:
            self.clear("receipt_stale", now)
            return False
        # Both clocks must cover the window: reported uptime alone could be inflated
        # within the per-sample skew tolerance.
        wall = (last.observed_at - window.observed_at).total_seconds()
        return min(wall, last.uptime - window.uptime) >= self.policy.stable_seconds

    def summary(self) -> dict[str, Any]:
        assert self._last is not None and self._window is not None
        return {
            "boot_id": self._last.boot_id,
            "first_sequence": self._window.sequence,
            "last_sequence": self._last.sequence,
            "stable_seconds": round(self._last.uptime - self._window.uptime, 3),
        }
