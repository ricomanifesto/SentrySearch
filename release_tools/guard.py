"""Absolute job deadline and a watchdog that bounds and reaps the SQL client.

The deadline is the earlier of the release window's fixed end and the job budget,
both pinned in the task definition. The client runs in its own process group so
that expiry or a stop signal terminates every descendant, not just the leader.
"""

import enum
import os
import signal
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timedelta

from release_tools.config import JobConfig

MINIMUM_GRACE_SECONDS = 5.0
MAX_OUTPUT_BYTES = 1_000_000


def job_deadline(config: JobConfig, started: datetime) -> datetime:
    return min(config.not_after, started + timedelta(seconds=config.budget_seconds))


class Outcome(enum.Enum):
    COMPLETED = "completed"
    DEADLINE = "deadline"
    TERMINATED = "terminated"


@dataclass(frozen=True)
class ChildResult:
    outcome: Outcome
    returncode: int | None
    stdout: str
    stderr: str


class Watchdog:
    def __init__(self, deadline: float, grace: float | None = None) -> None:
        """``deadline`` is a time.monotonic() value."""
        self.deadline = deadline
        self.grace = MINIMUM_GRACE_SECONDS if grace is None else grace
        self._process: subprocess.Popen[str] | None = None
        self._terminated = False

    def _signal_group(self, signum: int) -> None:
        if self._process is not None:
            try:
                os.killpg(self._process.pid, signum)
            except ProcessLookupError:
                pass

    def _on_signal(self, signum: int, _frame: object) -> None:
        # A stop request (ECS StopTask reaches us through tini) ends the job
        # within the grace period, never later than the job deadline.
        if not self._terminated:
            self._terminated = True
            self.deadline = min(self.deadline, time.monotonic() + self.grace)
        self._signal_group(signal.SIGTERM)

    def _killed(self) -> tuple[str, str]:
        """Kill the group and collect output, bounded even if a descendant escaped it."""
        assert self._process is not None
        self._signal_group(signal.SIGKILL)
        try:
            return self._process.communicate(timeout=self.grace)
        except subprocess.TimeoutExpired:
            # Something outside the group still holds the pipes: stop reading and
            # reap the killed leader rather than wait for that process.
            for stream in (self._process.stdout, self._process.stderr):
                if stream is not None:
                    stream.close()
            try:
                self._process.wait(timeout=self.grace)
            except subprocess.TimeoutExpired:
                pass
            return "", ""

    def _stop(self) -> tuple[str, str]:
        self._signal_group(signal.SIGTERM)
        assert self._process is not None
        try:
            return self._process.communicate(timeout=self.grace)
        except subprocess.TimeoutExpired:
            return self._killed()

    def _wait(self) -> tuple[str, str] | None:
        assert self._process is not None
        while (remaining := self.deadline - time.monotonic()) > 0:
            try:
                return self._process.communicate(timeout=min(remaining, 0.25))
            except subprocess.TimeoutExpired:
                continue
        return None

    def run(self, argv: list[str], env: dict[str, str]) -> ChildResult:
        previous = {
            signum: signal.signal(signum, self._on_signal)
            for signum in (signal.SIGTERM, signal.SIGINT)
        }
        try:
            self._process = subprocess.Popen(
                argv,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            if self._terminated:
                # A stop request that arrived before the child existed.
                self._signal_group(signal.SIGTERM)
            finished = self._wait()
            if finished is None:
                if self._terminated:
                    stdout, stderr = self._killed()
                else:
                    stdout, stderr = self._stop()
            else:
                stdout, stderr = finished
            if self._terminated:
                outcome = Outcome.TERMINATED
            elif finished is None:
                outcome = Outcome.DEADLINE
            else:
                outcome = Outcome.COMPLETED
            # Reap anything left in the group, even after a clean leader exit.
            self._signal_group(signal.SIGKILL)
            return ChildResult(
                outcome,
                self._process.returncode,
                (stdout or "")[:MAX_OUTPUT_BYTES],
                (stderr or "")[:MAX_OUTPUT_BYTES],
            )
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)
