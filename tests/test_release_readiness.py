"""Pure worker-readiness gate: receipt parsing, window policy and bounded reads."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from release.readiness import (
    ERROR_CODES,
    MAX_RECEIPT_BYTES,
    PHASES,
    WORKER_RECEIPT_KIND,
    WORKER_RECEIPT_MARKER,
    WORKING_PHASES,
    GatePolicy,
    InvalidReceipt,
    ReadinessGate,
    parse_line,
    read_stream,
    worker_stream,
)
from src.execution import readiness_receipts as producer

RELEASE_ID = "0b9f7c1e-4d2a-4f6b-9a3e-2c1d0e9f8a7b"
BOOT = "a" * 32
EPOCH = datetime(2026, 10, 7, 12, 0, tzinfo=UTC)
TASK = "arn:aws:ecs:us-east-1:111122223333:task/sentry-staging/" + "f" * 32


def line(sequence: int, at: float, *, boot: str = BOOT, uptime: float | None = None, **changes):
    receipt = {
        "kind": WORKER_RECEIPT_KIND,
        "release_id": RELEASE_ID,
        "boot_id": boot,
        "sequence": sequence,
        "observed_at": (EPOCH + timedelta(seconds=at)).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "uptime_seconds": 100.0 + at if uptime is None else uptime,
        "alive": True,
        "ready": True,
        "draining": False,
        "phase": "idle",
        "phase_elapsed_seconds": 1.0,
        "phase_budget_seconds": 62.0,
        "error_code": None,
    }
    receipt.update(changes)
    return f"{WORKER_RECEIPT_MARKER} " + json.dumps(receipt, separators=(",", ":"))


def steady(start: float, stop: float, *, first_sequence: int = 1, step: float = 10, **changes):
    lines, sequence, at = [], first_sequence, start
    while at <= stop:
        lines.append(line(sequence, at, **changes))
        sequence, at = sequence + 1, at + step
    return lines


def gate(**policy) -> ReadinessGate:
    return ReadinessGate(
        GatePolicy(**policy), release_id=RELEASE_ID, epoch_start=EPOCH, task_arn=TASK
    )


def at(seconds: float) -> datetime:
    return EPOCH + timedelta(seconds=seconds)


# --- producer/consumer contract and parsing ----------------------------------------


def test_producer_and_observer_share_the_receipt_contract():
    assert producer.RECEIPT_KIND == WORKER_RECEIPT_KIND
    assert producer.RECEIPT_MARKER == WORKER_RECEIPT_MARKER
    assert producer.WORKING_PHASES == WORKING_PHASES
    assert producer.MAX_RECEIPT_BYTES == MAX_RECEIPT_BYTES == 2048
    assert producer.PHASES | {"unknown"} == PHASES
    assert producer.ERROR_CODES == ERROR_CODES

    class Sink(list):
        def write(self, text):
            self.append(text)
            return len(text)

        def flush(self):
            pass

    sink = Sink()
    receipts = producer.ReadinessReceipts(RELEASE_ID, sink)
    snapshot = {"alive": True, "ready": True, "draining": False, "phase": "idle",
                "phase_elapsed_seconds": 1.0, "phase_budget_seconds": 62.0, "error_code": None}  # fmt: skip
    receipts.observe(snapshot)
    receipts.close(snapshot, timeout=2)
    parsed = [parse_line(text.rstrip("\n")) for text in sink]
    assert [item.sequence for item in parsed if item] == [1, 2]
    assert all(item and item.eligible for item in parsed)


def test_non_receipt_lines_are_ignored_and_malformed_receipts_are_invalid():
    assert parse_line("2026-10-07 INFO worker started") is None
    for bad in (
        WORKER_RECEIPT_MARKER + " {not json",
        WORKER_RECEIPT_MARKER + "{}",
        line(1, 0, extra="x"),
        line(1, 0, kind="sentry.worker-readiness.v2"),
        line(0, 0),
        line(1, 0).replace('"sequence":1,', '"sequence":true,'),
        line(1, 0, boot="xyz"),
        line(1, 0, uptime_seconds=float("nan")),
        line(1, 0, phase="exotic"),
        line(1, 0, error_code="private provider text"),
        line(1, 0, observed_at="2026-10-07T12:00:00Z"),
        WORKER_RECEIPT_MARKER + " " + json.dumps({"kind": WORKER_RECEIPT_KIND, "pad": "x" * 3000}),
        # Wrong JSON types and extreme values are invalid receipts, not crashes.
        line(1, 0, phase=[]),
        line(1, 0, error_code={}),
        line(1, 0, kind=[]),
        line(1, 0, uptime_seconds=10**400),
        line(1, 0).replace('"sequence":1,', '"sequence":' + "9" * 400 + ","),
        WORKER_RECEIPT_MARKER + " " + "[" * 1020 + "]" * 1020,
    ):
        with pytest.raises(InvalidReceipt):
            parse_line(bad)


@pytest.mark.parametrize(
    ("changes", "eligible"),
    [
        ({}, True),
        ({"ready": False}, False),
        ({"alive": False}, False),
        ({"draining": True}, False),
        ({"error_code": "runtime_unavailable"}, False),
        ({"phase": "starting"}, False),
        ({"phase": "stopped"}, False),
        ({"phase_elapsed_seconds": 62.0}, False),
    ],
)
def test_ready_requires_alive_no_drain_or_error_valid_phase_and_unexpired_budget(changes, eligible):
    receipt = parse_line(line(1, 0, **changes))
    assert receipt is not None and receipt.eligible is eligible


def test_the_stream_is_derived_from_the_manifest_release_and_observed_task_only():
    assert worker_stream("sentry-staging", RELEASE_ID, TASK) == (
        "/sentry-staging/worker",
        f"worker/{RELEASE_ID}/app/" + "f" * 32,
    )
    for release_id, task in (("../worker", TASK), (RELEASE_ID, TASK[:-1] + "*")):
        with pytest.raises(ValueError):
            worker_stream("sentry-staging", release_id, task)


# --- window policy -----------------------------------------------------------------


def test_sixty_seconds_of_consecutive_fresh_eligible_receipts_pass():
    readiness = gate()
    readiness.ingest(steady(11, 61), at(62))
    assert not readiness.stable(at(62))
    readiness.ingest([line(7, 71)], at(72))
    assert readiness.stable(at(72))
    assert readiness.summary() == {
        "boot_id": BOOT, "first_sequence": 1, "last_sequence": 7, "stable_seconds": 60.0,
    }  # fmt: skip


def test_pre_gate_history_cannot_seed_the_window():
    readiness = gate()
    # 150 s of continuous history, but only receipts from +9 s are after the epoch.
    readiness.ingest(steady(-121, 29), at(30))
    assert not readiness.stable(at(30))
    assert readiness.received == 3, "receipts observed before the epoch are not counted"
    readiness.ingest(steady(39, 59, first_sequence=17), at(60))
    assert not readiness.stable(at(60)), "only receipts observed after the epoch count"
    readiness.ingest([line(20, 69)], at(70))
    assert readiness.stable(at(70))


def stepped(first_sequence: int, start: float, uptime: float, count: int = 4):
    return [line(first_sequence + i, start + 10 * i, uptime=uptime + 10 * i) for i in range(count)]


GOOD_AFTER = steady(31, 71, first_sequence=8)


@pytest.mark.parametrize(
    ("bad", "reason", "later"),
    [
        (line(8, 31, ready=False), "receipt_not_ready", steady(41, 71, first_sequence=9)),
        (line(9, 31), "receipt_gap", steady(41, 71, first_sequence=10)),
        (
            line(8, 31, boot="b" * 32),
            "worker_rebooted",
            steady(41, 71, first_sequence=9, boot="b" * 32),
        ),
        # Another release's or a future receipt from another boot: its key must
        # not collide with the good receipts that follow.
        (
            line(8, 31, boot="c" * 32, release_id="11111111-2222-4333-8444-555555555555"),
            "receipt_release_mismatch",
            GOOD_AFTER,
        ),
        (line(8, 31, uptime=147.0), "receipt_interval_exceeded", stepped(9, 41, 157.0)),
        # Monotonic time went backwards while wall time stood still.
        (line(8, 21, uptime=120.0), "receipt_clock_anomaly", steady(31, 71, first_sequence=9)),
        (line(8, 31, uptime=122.0), "receipt_clock_anomaly", stepped(9, 41, 132.0)),
        (line(8, 400, boot="c" * 32), "receipt_from_future", GOOD_AFTER),
        (WORKER_RECEIPT_MARKER + " {broken", "receipt_invalid", GOOD_AFTER),
        (line(8, 31, phase=[]), "receipt_invalid", GOOD_AFTER),
        (line(6, 11, ready=False), "receipt_conflict", GOOD_AFTER),
        (line(4, 31), "receipt_reordered", GOOD_AFTER),
    ],
)
def test_any_negative_invalid_or_anomalous_receipt_restarts_the_window(bad, reason, later):
    readiness = gate()
    readiness.ingest(steady(1, 21, first_sequence=5), at(22))  # sequences 5-7
    readiness.ingest([bad], at(32))
    assert readiness.reason == reason
    # Without the reset, the receipts that follow would complete a 60 s window
    # (from +11 s, the first receipt after the epoch floor, to +71 s).
    readiness.ingest(later, at(72))
    assert not readiness.stable(at(72)), "a reset needs a complete new window"


def test_a_window_never_starts_on_a_receipt_that_is_not_ready():
    readiness = gate()
    readiness.ingest([line(1, 1, ready=False), *steady(11, 61, first_sequence=2)], at(62))
    assert not readiness.stable(at(62))
    readiness.ingest([line(8, 71)], at(72))
    assert readiness.stable(at(72)) and readiness.summary()["first_sequence"] == 2


def test_worker_reported_uptime_cannot_shorten_the_wall_clock_window():
    readiness = gate()
    # Each step is within the skew tolerance (14.9 s of uptime per 10 s of wall time).
    readiness.ingest([line(i + 1, 11 + 10 * i, uptime=100.0 + 14.9 * i) for i in range(6)], at(62))
    assert readiness.reason is None
    assert not readiness.stable(at(62)), "74.5 s of reported uptime in 50 s of wall time"
    readiness.ingest([line(7, 71, uptime=189.4)], at(72))
    assert readiness.stable(at(72))


def test_a_burst_of_transitions_at_one_instant_is_not_a_clock_anomaly():
    readiness = gate()
    burst = [line(5, 31, uptime=131.0, ready=False), line(6, 31, uptime=131.0)]
    readiness.ingest([*steady(1, 31), *burst], at(32))
    assert readiness.reason == "receipt_not_ready"
    readiness.ingest(steady(41, 91, first_sequence=7), at(92))
    assert readiness.reason == "receipt_not_ready", "equal uptimes are not an anomaly"
    assert readiness.stable(at(92)) and readiness.summary()["first_sequence"] == 6


def test_a_fast_worker_clock_cannot_seed_the_window_before_the_attempt():
    readiness = gate()
    # The worker runs 5 s ahead: receipt 1 was emitted 4 s before the attempt,
    # but its observed time is just after the epoch.
    for i in range(7):
        readiness.ingest([line(i + 1, 1 + i * 10)], at(max(0, -4 + i * 10)))
    assert not readiness.stable(at(56)), "a pre-attempt sample started the window"
    readiness.ingest([line(8, 71)], at(66))
    assert readiness.stable(at(66)) and readiness.summary()["first_sequence"] == 2


def test_controller_clock_rollback_is_never_stable():
    readiness = gate()
    readiness.ingest(steady(11, 71, first_sequence=2), at(72))
    assert readiness.stable(at(72))
    assert not readiness.stable(at(50)), "time moved backwards after ingestion"
    assert readiness.reason == "controller_clock_rollback"
    assert not readiness.stable(at(72)), "a rollback needs a complete new window"


def test_identical_replays_are_deduplicated_not_counted_twice():
    readiness = gate()
    history = steady(11, 71)
    readiness.ingest(history + history[:3], at(72))
    assert readiness.reason is None and readiness.stable(at(72))


def test_consecutive_sequences_across_a_stall_still_reset():
    readiness = gate()
    readiness.ingest(steady(1, 31) + steady(51, 101, first_sequence=5), at(102))
    assert readiness.reason == "receipt_interval_exceeded"
    assert not readiness.stable(at(102))
    readiness.ingest([line(11, 111)], at(112))
    assert readiness.stable(at(112))


def test_a_stale_last_receipt_clears_stability_even_without_new_events():
    readiness = gate()
    readiness.ingest(steady(11, 71), at(72))
    assert readiness.stable(at(101))
    assert not readiness.stable(at(102)), "older than 30 s by observation time"
    assert readiness.reason == "receipt_stale"
    readiness.ingest([line(8, 103)], at(104))
    assert not readiness.stable(at(104)), "freshness expiry restarts the window"
    assert readiness.received == 8


def test_delayed_ingestion_cannot_make_old_receipts_fresh():
    readiness = gate()
    readiness.ingest(steady(1, 61), at(200))
    assert not readiness.stable(at(200))


def test_an_explicit_clear_drops_stability_and_restarts_from_the_next_receipt():
    readiness = gate()
    readiness.ingest(steady(1, 61), at(62))
    readiness.clear("task_unhealthy", at(62))
    assert readiness.reason == "task_unhealthy" and not readiness.stable(at(62))
    readiness.ingest(steady(71, 121, first_sequence=8), at(122))
    assert not readiness.stable(at(122))
    readiness.ingest([line(14, 131)], at(132))
    assert readiness.stable(at(132))
    assert readiness.received == 14


def test_receipts_observed_before_a_clear_cannot_seed_the_next_window():
    readiness = gate()
    readiness.ingest(steady(1, 51), at(52))
    # Visibility was lost at +66 s; +61 s arrives late but predates recovery, and
    # +71 s is within the 5 s skew a worker clock may run ahead of the controller.
    readiness.clear("readiness_logs_incomplete", at(66))
    readiness.ingest(steady(61, 131, first_sequence=7), at(132))
    assert not readiness.stable(at(132)), "the new window starts after the clear"
    readiness.ingest([line(15, 141)], at(142))
    assert readiness.stable(at(142)) and readiness.summary()["first_sequence"] == 9


def test_a_restart_receipt_from_before_a_clear_cannot_seed_the_window():
    readiness = gate()
    readiness.ingest(steady(1, 51), at(52))
    readiness.clear("task_unhealthy", at(56))
    # A gap restarts at its receipt, but that receipt predates the clear.
    readiness.ingest([line(8, 61), *steady(71, 121, first_sequence=9)], at(122))
    assert readiness.reason == "receipt_gap" and not readiness.stable(at(122))
    readiness.ingest([line(15, 131)], at(132))
    assert readiness.stable(at(132)) and readiness.summary()["first_sequence"] == 9


def test_a_burst_of_late_receipts_after_freshness_expiry_needs_a_new_window():
    readiness = gate()
    readiness.ingest(steady(1, 21), at(22))
    assert not readiness.stable(at(55)) and readiness.reason == "receipt_stale"
    # Delivery resumes: consecutive, evenly spaced receipts observed during the gap.
    readiness.ingest(steady(31, 91, first_sequence=4), at(92))
    assert not readiness.stable(at(92))
    readiness.ingest(steady(101, 111, first_sequence=11), at(112))
    assert not readiness.stable(at(112))
    readiness.ingest([line(13, 121)], at(122))
    assert readiness.stable(at(122)) and readiness.summary()["first_sequence"] == 7


# --- bounded reads ------------------------------------------------------------------


class Pages:
    """GetLogEvents shape: the end of a stream repeats the caller's forward token."""

    def __init__(self, messages, *, size=2, empty_first=0, endless=False, broken=False):
        self.messages = messages
        self.size = size
        self.empty_first = empty_first
        self.endless = endless
        self.broken = broken
        self.calls = []

    def get_log_events(
        self, log_group, log_stream, *, start_time_ms, end_time_ms, next_token, limit
    ):
        self.calls.append((log_group, log_stream, start_time_ms, end_time_ms, next_token, limit))
        if self.broken:
            return {"events": "nope", "nextForwardToken": 7}
        index = int(next_token.split("/")[1]) if next_token else 0
        if self.empty_first:
            # A fresh token with no events: not the end of the stream.
            self.empty_first -= 1
            return {"events": [], "nextForwardToken": f"f/{index}/e{self.empty_first}"}
        if self.endless:
            return {"events": [], "nextForwardToken": f"f/{index + 1}"}
        page = self.messages[index : index + self.size]
        token = f"f/{index + len(page)}" if page else next_token or "f/0"
        return {
            "events": [{"timestamp": 1, "message": message} for message in page],
            "nextForwardToken": token,
        }


def test_reads_follow_forward_tokens_until_the_stream_end_within_bounds():
    pages = Pages([f"m{i}" for i in range(5)])
    read = read_stream(pages, "/g", "s", token=None, start=EPOCH, end=at(60), policy=GatePolicy())
    assert read.complete and read.messages == [f"m{i}" for i in range(5)] and read.token == "f/5"
    assert all(call[2:4] == (EPOCH.timestamp() * 1000, at(60).timestamp() * 1000)
               for call in pages.calls)  # fmt: skip


def test_empty_pages_do_not_end_a_stream():
    pages = Pages(["m0", "m1"], empty_first=2)
    read = read_stream(pages, "/g", "s", token=None, start=EPOCH, end=at(60), policy=GatePolicy())
    assert read.complete and read.messages == ["m0", "m1"]


@pytest.mark.parametrize(
    ("pages", "policy"),
    [
        (Pages([], endless=True), GatePolicy(max_pages=5)),
        (Pages(["x" * 600, "y" * 600]), GatePolicy(max_bytes=1000)),
    ],
)
def test_exhausted_page_or_byte_limits_mean_not_proven(pages, policy):
    read = read_stream(pages, "/g", "s", token=None, start=EPOCH, end=at(60), policy=policy)
    assert not read.complete


def test_malformed_read_responses_are_errors():
    with pytest.raises(ValueError):
        read_stream(Pages([], broken=True), "/g", "s", token=None, start=EPOCH, end=at(60),
                    policy=GatePolicy())  # fmt: skip
