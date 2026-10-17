"""The staging alarm inventory: every named alert is wired to a producer or says why not.

The foundation's mocked-plan tests assert what the plan renders. This module ties
that inventory to its sources instead: the alert list the platform proof names,
and the worker readiness receipts the log metric filters count. A filter is
checked against real receipt lines, so a receipt format change that would leave
an alarm counting nothing fails here.
"""

from __future__ import annotations

import io
import json
import re
from pathlib import Path

from src.execution.readiness_receipts import ERROR_CODES, PHASES, RECEIPT_MARKER, ReadinessReceipts

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
         "worker-runtime-unreachable": "worker-runtime-unreachable"}  # fmt: skip
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


def terms(pattern: str) -> tuple[list[str], list[str]]:
    """CloudWatch's quoted-term subset: required terms, and ``?`` alternatives."""
    required, optional = [], []
    for marker, body in re.findall(r'(\??)"((?:[^"\\]|\\.)*)"', pattern):
        text = re.sub(r"\\(.)", r"\1", body)
        (optional if marker else required).append(text)
    return required, optional


def matches(pattern: str, line: str) -> bool:
    required, optional = terms(pattern)
    return all(term in line for term in required) and (
        not optional or any(term in line for term in optional)
    )


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
