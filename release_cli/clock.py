"""Operator Clock: monotonic-anchored UTC that refuses to guess.

``now`` is the wall time sampled once at start plus elapsed monotonic time, so it
never moves backwards and a later wall-clock step cannot move a deadline. Every
reading also samples the wall clock: any backwards wall step, or wall and
anchored time drifting more than 5 s apart (a stepped clock, or a host that slept
with the monotonic clock stopped), makes the clock untrusted for good. The anchor
is bound to an external reference before any release action: an injected sample
whose live source is the ``Date`` header of the operator preflight
``sts:GetCallerIdentity`` response. Its whole-second resolution and the request's
round trip are uncertainty; the complete uncertainty interval must stay within
5 s, and a missing, malformed, slow or distant reference fails closed.
"""

from __future__ import annotations

import math
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime

from release.ports import ClockUntrusted

MAX_DIVERGENCE_SECONDS = 5.0
MAX_REFERENCE_OFFSET_SECONDS = 5.0
# A slower round trip widens the reference uncertainty past what it can prove.
MAX_REFERENCE_ROUND_TRIP_SECONDS = 2.0
REFERENCE_RESOLUTION = timedelta(seconds=1)
MAX_SLEEP_SECONDS = 60.0
# RFC 9110 IMF-fixdate, the only form the preflight reference accepts.
_IMF_FIXDATE = re.compile(
    r"(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} "
    r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} GMT"
)


def parse_reference_date(value: object) -> datetime:
    """The ``Date`` header as an aware UTC datetime, or ``ClockUntrusted``."""
    if not isinstance(value, str) or not _IMF_FIXDATE.fullmatch(value):
        raise ClockUntrusted("reference_time_malformed")
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        raise ClockUntrusted("reference_time_malformed") from None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ClockUntrusted("reference_time_malformed")
    return parsed.astimezone(UTC)


@dataclass(frozen=True)
class ReferenceSample:
    """One reference reading bracketed by this clock's own readings."""

    sent_at: datetime
    received_at: datetime
    reference: datetime


def reference_offset_bounds(sample: ReferenceSample) -> tuple[float, float]:
    """The interval containing (local - reference) at the moment the reference was cut.

    The reference instant lies in [reference, reference + 1 s) and was cut at some
    local moment within [sent_at, received_at].
    """
    lowest = (sample.sent_at - (sample.reference + REFERENCE_RESOLUTION)).total_seconds()
    highest = (sample.received_at - sample.reference).total_seconds()
    return lowest, highest


class MonotonicUtcClock:
    """The release ``Clock`` port for the operator CLI."""

    def __init__(
        self,
        *,
        wall: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
        wait: Callable[[float], None] = time.sleep,
    ) -> None:
        self._wall = wall
        self._monotonic = monotonic
        self._wait = wait
        self._anchor_wall = wall()
        self._anchor_monotonic = monotonic()
        self._last_wall = self._anchor_wall
        self._last_monotonic = self._anchor_monotonic
        self._fault: str | None = None
        self.reference_bound = False

    @property
    def fault(self) -> str | None:
        return self._fault

    def _untrusted(self, reason: str) -> ClockUntrusted:
        if self._fault is None:
            self._fault = reason
        return ClockUntrusted(self._fault)

    def _read(self) -> float:
        if self._fault is not None:
            raise ClockUntrusted(self._fault)
        wall, monotonic = self._wall(), self._monotonic()
        if not (math.isfinite(wall) and math.isfinite(monotonic)):
            raise self._untrusted("clock_reading_invalid")
        if monotonic < self._last_monotonic:
            raise self._untrusted("monotonic_regression")
        if wall < self._last_wall:
            raise self._untrusted("wall_clock_regression")
        anchored = self._anchor_wall + (monotonic - self._anchor_monotonic)
        if abs(wall - anchored) > MAX_DIVERGENCE_SECONDS:
            raise self._untrusted("wall_monotonic_divergence")
        self._last_wall, self._last_monotonic = wall, monotonic
        return anchored

    def now(self) -> datetime:
        return datetime.fromtimestamp(self._read(), UTC)

    def sleep(self, seconds: float) -> None:
        """Wait at least ``seconds`` of monotonic time; never moves time or deadlines."""
        if (
            isinstance(seconds, bool)
            or not isinstance(seconds, (int, float))
            or not math.isfinite(seconds)
            or not 0 <= seconds <= MAX_SLEEP_SECONDS
        ):
            raise ValueError("sleep outside the controller's poll bounds")
        self._read()
        end = self._monotonic() + seconds
        while (remaining := end - self._monotonic()) > 0:
            self._wait(remaining)
        self._read()

    def bind_reference(self, sample: ReferenceSample) -> tuple[float, float]:
        """Accept the anchor only if the whole reference uncertainty is within 5 s."""
        if self._fault is not None:
            raise ClockUntrusted(self._fault)
        round_trip = (sample.received_at - sample.sent_at).total_seconds()
        if not 0 <= round_trip <= MAX_REFERENCE_ROUND_TRIP_SECONDS:
            raise self._untrusted("reference_time_uncertain")
        lowest, highest = reference_offset_bounds(sample)
        if lowest < -MAX_REFERENCE_OFFSET_SECONDS or highest > MAX_REFERENCE_OFFSET_SECONDS:
            raise self._untrusted("reference_time_offset")
        self.reference_bound = True
        return lowest, highest
