"""The controller's fixed receipt envelope and allowlisted, bounded log events.

Receipts go to stdout behind a marker; JSON log events go to stderr. Neither ever
carries driver text, SQL, credentials or verifiers.
"""

import json
import re
import sys
from collections.abc import Iterable, Mapping
from typing import Any

RECEIPT_MARKER = "SENTRY_RELEASE_RECEIPT"
RECEIPT_SCHEMA = "sentry.release-tools.job.v1"
LOG_FIELDS = frozenset(
    {
        "reason",
        "job_id",
        "release_id",
        "kind",
        "database",
        "sql_outcome",
        "outcome",
        "exit_code",
        "pid",
        "backend_start",
        "principal",
        "application_name",
        "state",
    }
)
_KEY = re.compile(r"[a-z][a-z_]{0,31}")
_EVENT = re.compile(r"[a-z][a-z_]{0,39}")
_VALUE = re.compile(r"[A-Za-z0-9_.:,/-]{1,256}")
_STATUSES = frozenset({"succeeded", "failed"})
ENVELOPE_FIELDS = frozenset({"schema", "release_id", "job_id", "task_arn", "status", "result"})


class ReceiptAmbiguous(ValueError):
    """More than one, malformed or non-envelope receipt: the controller holds."""


def _checked(fields: Mapping[str, object]) -> dict[str, str]:
    checked = {}
    for key, value in fields.items():
        text = str(value)
        if not _KEY.fullmatch(key) or not _VALUE.fullmatch(text):
            raise ValueError("value outside the receipt/log allowlist")
        checked[key] = text
    return checked


def emit_receipt(
    *, release_id: str, job_id: str, task_arn: str, status: str, result: dict[str, str]
) -> None:
    if status not in _STATUSES:
        raise ValueError("receipt status")
    envelope = {
        "schema": RECEIPT_SCHEMA,
        **_checked({"release_id": release_id, "job_id": job_id, "task_arn": task_arn}),
        "status": status,
        "result": _checked(result),
    }
    line = json.dumps(envelope, separators=(",", ":"), sort_keys=True)
    sys.stdout.write(f"{RECEIPT_MARKER} {line}\n")
    sys.stdout.flush()


def log(event: str, **fields: object) -> None:
    if not _EVENT.fullmatch(event) or set(fields) - LOG_FIELDS:
        raise ValueError("log event outside the allowlist")
    line = json.dumps({"event": event, **_checked(fields)}, separators=(",", ":"))
    sys.stderr.write(line + "\n")
    sys.stderr.flush()


def extract_receipt(lines: Iterable[str]) -> dict[str, Any] | None:
    """The single receipt in one task's log stream, None if absent.

    The log reader passes only the stream of the observed task. Absence is a
    missing receipt; duplicates or a malformed envelope are ambiguous. Both hold.
    """
    found = [line for line in lines if line.startswith(RECEIPT_MARKER)]
    if not found:
        return None
    if len(found) != 1 or not found[0].startswith(RECEIPT_MARKER + " "):
        raise ReceiptAmbiguous("receipt count or marker")
    try:
        document = json.loads(found[0][len(RECEIPT_MARKER) + 1 :])
    except ValueError as error:
        raise ReceiptAmbiguous("receipt is not JSON") from error
    if (
        not isinstance(document, dict)
        or set(document) != ENVELOPE_FIELDS
        or not isinstance(document["result"], dict)
    ):
        raise ReceiptAmbiguous("receipt envelope")
    return document
