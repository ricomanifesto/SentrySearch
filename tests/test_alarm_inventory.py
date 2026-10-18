"""The staging alarm inventory: every named alert is wired to a producer or says why not.

The foundation's mocked-plan tests assert what the plan renders. This module ties
that inventory to its sources instead: the alert list the platform proof names,
and the lines the log metric filters count: the worker's readiness receipts, its
metric event and the Runtime's operator events. A filter is checked against the
complete lines their writers emit, so a format change that would leave an alarm
counting nothing fails here. This models CloudWatch's published filter syntax;
only the platform's alert-delivery case proves CloudWatch's behavior.
"""

from __future__ import annotations

import io
import json
import re
from pathlib import Path

from release_kits.aws_08a import RUNTIME_EVENT_SAMPLES
from src.execution.readiness_receipts import (
    ERROR_CODES,
    METRIC_FIELDS,
    PHASES,
    RECEIPT_MARKER,
    ReadinessReceipts,
)

REPO = Path(__file__).resolve().parents[1]
MONITORING = (REPO / "deploy" / "aws-staging" / "foundation" / "monitoring.tf").read_text()
# The alerts the platform proof names, and the inventory entries that answer each.
ALERTS = {
    "missing workers": ["worker-missing"],
    "unready workers": ["worker-unready"],
    "aging backlog": ["backlog-age"],
    "lease exhaustion": ["lease-exhaustion"],
    "retry exhaustion": ["retry-exhaustion"],
    "phase deadlines": ["worker-phase-deadline", "release-phase-deadlines"],
    "certificate expiry": ["certificate-expiry"],
    "runtime and product terminal mismatches": ["terminal-mismatch"],
}
WIRED = {"worker-missing": "${name}-missing", "worker-unready": "worker-unready",
         "worker-phase-deadline": "worker-phase-deadline",
         "worker-runtime-unreachable": "worker-runtime-unreachable",
         "backlog-age": "backlog-age", "lease-exhaustion": "lease-exhaustion",
         "retry-exhaustion": "retry-exhaustion", "certificate-expiry": "certificate-expiry",
         "terminal-mismatch": "terminal-mismatch"}  # fmt: skip
# The filter patterns exactly as the foundation's mocked plan asserts Terraform renders
# them (an HCL string literal decodes as JSON for these escapes).
TFTEST = (
    REPO / "deploy" / "aws-staging" / "foundation" / "tests" / "foundation.tftest.hcl"
).read_text()
PATTERNS = {
    name: json.loads(literal)
    for name, literal in re.findall(
        r'aws_cloudwatch_log_metric_filter\.worker\["(\w+)"\]\.pattern == ("(?:[^"\\]|\\.)*")',
        TFTEST,
    )
}


EVENT_PATTERNS = {
    name: json.loads(literal)
    for name, literal in re.findall(
        r'aws_cloudwatch_log_metric_filter\.events\["(\w+)"\]\.pattern == ("(?:[^"\\]|\\.)*")',
        TFTEST,
    )
}
EVENT_VALUES = {
    name: json.loads(literal)
    for name, literal in re.findall(
        r'one\(aws_cloudwatch_log_metric_filter\.events\["(\w+)"\]\.metric_transformation\)'
        r'\.value == ("(?:[^"\\]|\\.)*")',
        TFTEST,
    )
}
# The Runtime's operator events as its JSON handler writes them (one source for the
# inventory and the platform case).
RUNTIME_LINES = RUNTIME_EVENT_SAMPLES


def terms(pattern: str) -> tuple[list[str], list[str]]:
    """CloudWatch's quoted-term subset: required terms, and ``?`` alternatives."""
    required, optional = [], []
    for marker, body in re.findall(r'(\??)"((?:[^"\\]|\\.)*)"', pattern):
        text = re.sub(r"\\(.)", r"\1", body)
        (optional if marker else required).append(text)
    return required, optional


def json_conditions(pattern: str) -> list[tuple[str, str, object]]:
    """CloudWatch's JSON-selector subset these filters use: ``{ $.f OP v && ... }``."""
    body = pattern.strip()
    assert body.startswith("{") and body.endswith("}"), pattern
    conditions = []
    for clause in body[1:-1].split("&&"):
        found = re.fullmatch(r'\s*\$\.(\w+)\s*(=|!=|>=|<=|>|<)\s*("[^"]*"|-?\d+(?:\.\d+)?)\s*',
                             clause)  # fmt: skip
        assert found, clause
        field, operator, raw = found.groups()
        conditions.append((field, operator, raw[1:-1] if raw.startswith('"') else float(raw)))
    return conditions


def matches(pattern: str, line: str) -> bool:
    """Whether a filter counts one complete log event: the exact line its writer wrote,
    only the trailing newline removed. JSON selectors apply only to an event that is
    one JSON object in its entirety; term patterns apply to any event's text."""
    if pattern.lstrip().startswith("{"):
        try:
            event = json.loads(line)
        except ValueError:
            return False
        if not isinstance(event, dict):
            return False
        for field, operator, wanted in json_conditions(pattern):
            if field not in event:
                return False
            value = event[field]
            if isinstance(wanted, str):
                if not isinstance(value, str) or (value == wanted) != (operator == "="):
                    return False
                continue
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                return False
            if not {"=": value == wanted, "!=": value != wanted, ">=": value >= wanted,
                    "<=": value <= wanted, ">": value > wanted, "<": value < wanted}[operator]:  # fmt: skip
                return False
        return True
    required, optional = terms(pattern)
    return all(term in line for term in required) and (
        not optional or any(term in line for term in optional)
    )


def metric_line(**fields) -> str:
    """The line the worker's metric writer itself puts on its sink."""
    sink = io.StringIO()
    receipts = ReadinessReceipts("0b9f7c1e-4d2a-4f6b-9a3e-2c1d0e9f8a7b", sink, emit_metrics=True)
    base = {"backlog_size": 0, "backlog_oldest_seconds": 0, "runtime_certificate_days_left": 90,
            "reconcile_checked": 0, "reconcile_mismatches": 0}  # fmt: skip
    receipts.observe_metrics(lambda: {**base, **fields})
    receipts.close({"alive": False, "ready": False, "phase": "stopped"}, timeout=1.0)
    (line,) = [line for line in sink.getvalue().splitlines() if not line.startswith(RECEIPT_MARKER)]
    return line


def receipt_line(**snapshot) -> str:
    """The line the worker's receipt writer itself puts on its sink."""
    sink = io.StringIO()
    receipts = ReadinessReceipts("0b9f7c1e-4d2a-4f6b-9a3e-2c1d0e9f8a7b", sink)
    receipts.observe({"alive": True, "ready": False, "draining": False, "phase": "idle",
                      "phase_elapsed_seconds": 1.0, "phase_budget_seconds": 60.0,
                      "error_code": None, **snapshot})  # fmt: skip
    receipts.close({"alive": False, "ready": False, "phase": "stopped"}, timeout=1.0)
    return sink.getvalue().splitlines()[0]


def test_every_named_alert_is_wired_or_explicitly_unwired_with_a_reason():
    unwired = dict(re.findall(r'^\s{4}([a-z-]+)\s+= "([^"]+)"$',
                              MONITORING.split("unwired_alerts = {", 1)[1].split("}", 1)[0],
                              re.M))  # fmt: skip
    for alert, entries in ALERTS.items():
        for entry in entries:
            wired = entry in WIRED and WIRED[entry] in MONITORING
            assert wired or entry in unwired, f"{alert}: {entry} is neither wired nor unwired"
            if entry in unwired:
                assert len(unwired[entry]) > 20, f"{entry} needs a reason"
    assert not set(unwired) & set(WIRED), "an alert cannot be both wired and unwired"


def test_the_three_filters_are_read_from_the_plans_assertions():
    assert set(PATTERNS) == {"WorkerReadyReceipts", "WorkerRuntimeErrors", "WorkerDeadlineErrors"}
    assert PATTERNS["WorkerReadyReceipts"] == '"SENTRY_WORKER_READINESS" "\\"ready\\":true"'


def test_the_worker_filters_count_exactly_the_receipts_they_name():
    ready = receipt_line(ready=True)
    unready = receipt_line(ready=False)
    assert matches(PATTERNS["WorkerReadyReceipts"], ready)
    assert not matches(PATTERNS["WorkerReadyReceipts"], unready)
    for code in sorted(ERROR_CODES):
        line = receipt_line(error_code=code)
        assert matches(PATTERNS["WorkerRuntimeErrors"], line) == (
            code in {"runtime_unavailable", "runtime_access_denied"}
        ), code
        assert matches(PATTERNS["WorkerDeadlineErrors"], line) == code.endswith(
            "_deadline_exceeded"
        ), code
    assert not matches(PATTERNS["WorkerRuntimeErrors"], ready)
    # Application output that is not a receipt is never counted as a ready worker.
    assert not matches(PATTERNS["WorkerReadyReceipts"], '{"ready":true}')


def test_the_rendered_deadline_codes_are_exactly_the_receipts_deadline_codes():
    produced = {code for code in ERROR_CODES if code.endswith("_deadline_exceeded")}
    assert produced == {f"{phase}_deadline_exceeded" for phase in [*PHASES, "drain"]}
    listed = re.search(r"for phase in \[([^\]]+)\]", MONITORING)
    assert listed is not None
    rendered = {
        f"{phase}_deadline_exceeded" for phase in re.findall(r'"([a-z]+)"', listed.group(1))
    }
    assert rendered == produced


def test_the_five_event_filters_are_read_from_the_plans_assertions():
    assert set(EVENT_PATTERNS) == set(EVENT_VALUES) == {
        "WorkerBacklogOldestSeconds", "WorkerReconcileMismatches", "WorkerCertificateDaysLeft",
        "RuntimeLeaseExpired", "RuntimeRetryExhausted",
    }  # fmt: skip
    for name, value in EVENT_VALUES.items():
        # A value selector reads a field the metric event really carries.
        assert value == "1" or value.removeprefix("$.") in METRIC_FIELDS, name


def test_the_worker_metric_filters_count_the_events_and_values_they_name():
    aging = metric_line(backlog_size=4, backlog_oldest_seconds=1200)
    assert matches(EVENT_PATTERNS["WorkerBacklogOldestSeconds"], aging)
    assert json.loads(aging)[EVENT_VALUES["WorkerBacklogOldestSeconds"].removeprefix("$.")] == 1200
    unknown = metric_line(backlog_size=None, backlog_oldest_seconds=None,
                          runtime_certificate_days_left=None)  # fmt: skip
    assert not matches(EVENT_PATTERNS["WorkerBacklogOldestSeconds"], unknown)
    assert not matches(EVENT_PATTERNS["WorkerCertificateDaysLeft"], unknown)
    clean = metric_line(reconcile_checked=5, reconcile_mismatches=0)
    assert not matches(EVENT_PATTERNS["WorkerReconcileMismatches"], clean)
    found = metric_line(reconcile_checked=5, reconcile_mismatches=2)
    assert matches(EVENT_PATTERNS["WorkerReconcileMismatches"], found)
    expired = metric_line(runtime_certificate_days_left=0)
    assert matches(EVENT_PATTERNS["WorkerCertificateDaysLeft"], expired)
    assert json.loads(expired)["runtime_certificate_days_left"] < 14


def test_the_runtime_filters_count_only_their_operator_event():
    leased, exhausted = RUNTIME_LINES["lease_expired"], RUNTIME_LINES["retry_exhausted"]
    assert matches(EVENT_PATTERNS["RuntimeLeaseExpired"], leased)
    assert not matches(EVENT_PATTERNS["RuntimeLeaseExpired"], exhausted)
    assert matches(EVENT_PATTERNS["RuntimeRetryExhausted"], exhausted)
    assert not matches(EVENT_PATTERNS["RuntimeRetryExhausted"], leased)
    # The Runtime's text startup line is no operator event.
    text = 'time=2026-10-18T02:00:00Z level=INFO msg="runtime listening" event=lease_expired'
    assert not any(matches(EVENT_PATTERNS[name], text)
                   for name in ("RuntimeLeaseExpired", "RuntimeRetryExhausted"))  # fmt: skip


def test_receipts_and_metric_events_never_count_for_each_other():
    receipts = [receipt_line(ready=True), receipt_line(ready=False),
                *(receipt_line(error_code=code) for code in sorted(ERROR_CODES))]  # fmt: skip
    metrics = [metric_line(backlog_size=4, backlog_oldest_seconds=1200, reconcile_checked=3,
                           reconcile_mismatches=1, runtime_certificate_days_left=0)]  # fmt: skip
    # A marker-prefixed readiness receipt is not JSON in its entirety: no JSON filter.
    for line in receipts:
        assert not any(matches(pattern, line) for pattern in EVENT_PATTERNS.values()), line
    # A metric event carries neither the marker nor an error_code phrase.
    for line in metrics:
        assert not any(matches(pattern, line) for pattern in PATTERNS.values()), line
        assert all(matches(EVENT_PATTERNS[name], line) for name in
                   ("WorkerBacklogOldestSeconds", "WorkerReconcileMismatches",
                    "WorkerCertificateDaysLeft"))  # fmt: skip
        # A prefix (a marker, a level, another driver's timestamp) makes it ordinary
        # text that nothing counts.
        for prefix in (f"{RECEIPT_MARKER} ", "INFO ", "2026-10-18T02:00:00.000Z "):
            assert not any(matches(pattern, prefix + line)
                           for pattern in [*PATTERNS.values(), *EVENT_PATTERNS.values()])  # fmt: skip
