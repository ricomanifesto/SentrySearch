"""The controller's fixed receipt envelopes and allowlisted, bounded log events.

Receipts go to stdout behind a marker; JSON log events go to stderr. Neither ever
carries driver text, SQL, credentials or verifiers. Three receipt kinds share one
line format and differ by schema and subject field:

- ``tools``: release-tools jobs, schema ``sentry.release-tools.job.v1``, ``job_id``;
- ``migration``: the Runtime and Search migration jobs, schema
  ``sentry.release-migration.v1``, ``job_id``;
- ``operational``: the Runtime and API observers, schema ``sentry.operational.v1``,
  ``check_id``.

Each parser accepts exactly its own envelope: another kind's schema, the other
subject field, an extra or missing field, a non-string result value or a value
outside the allowlist is ambiguous, never coerced. Producers in other languages
(the Runtime migration job in Go) write byte-identical lines; shared golden
fixtures pin that. This module imports only the standard library: the Search
image carries it.
"""

import json
import re
import sys
from collections.abc import Iterable, Mapping
from typing import Any

RECEIPT_MARKER = "SENTRY_RELEASE_RECEIPT"
RECEIPT_SCHEMA = "sentry.release-tools.job.v1"
MIGRATION_SCHEMA = "sentry.release-migration.v1"
OPERATIONAL_SCHEMA = "sentry.operational.v1"
KINDS: dict[str, tuple[str, str]] = {
    "tools": (RECEIPT_SCHEMA, "job_id"),
    "migration": (MIGRATION_SCHEMA, "job_id"),
    "operational": (OPERATIONAL_SCHEMA, "check_id"),
}
STATUSES: dict[str, frozenset[str]] = {
    "tools": frozenset({"succeeded", "failed"}),
    "migration": frozenset({"succeeded", "failed"}),
    "operational": frozenset({"passed", "failed"}),
}
# A failed receipt carries only why, and for jobs whether SQL may have run.
FAILURE_KEYS: dict[str, frozenset[str]] = {
    "tools": frozenset({"reason", "sql_outcome"}),
    "migration": frozenset({"reason", "sql_outcome"}),
    "operational": frozenset({"reason"}),
}
LOG_FIELDS = frozenset(
    {
        "reason",
        "job_id",
        "check_id",
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
        "target",
        "host",
    }
)
_KEY = re.compile(r"[a-z][a-z_]{0,31}")
_EVENT = re.compile(r"[a-z][a-z_]{0,39}")
_VALUE = re.compile(r"[A-Za-z0-9_.:,/-]{1,256}")
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


def receipt_line(
    kind: str, *, release_id: str, subject: str, task_arn: str, status: str, result: dict[str, str]
) -> str:
    """One receipt line: compact JSON with sorted keys behind the marker."""
    schema, subject_field = KINDS[kind]
    if status not in STATUSES[kind]:
        raise ValueError("receipt status")
    if status == "failed" and set(result) != FAILURE_KEYS[kind]:
        raise ValueError("failed receipt fields")
    envelope = {
        "schema": schema,
        **_checked({"release_id": release_id, subject_field: subject, "task_arn": task_arn}),
        "status": status,
        "result": _checked(result),
    }
    return f"{RECEIPT_MARKER} {json.dumps(envelope, separators=(',', ':'), sort_keys=True)}"


def emit(
    kind: str, *, release_id: str, subject: str, task_arn: str, status: str, result: dict[str, str]
) -> None:
    line = receipt_line(
        kind,
        release_id=release_id,
        subject=subject,
        task_arn=task_arn,
        status=status,
        result=result,
    )
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def emit_receipt(
    *, release_id: str, job_id: str, task_arn: str, status: str, result: dict[str, str]
) -> None:
    """A release-tools job receipt (``tools`` kind)."""
    emit(
        "tools", release_id=release_id, subject=job_id, task_arn=task_arn, status=status,
        result=result,
    )  # fmt: skip


def log(event: str, **fields: object) -> None:
    if not _EVENT.fullmatch(event) or set(fields) - LOG_FIELDS:
        raise ValueError("log event outside the allowlist")
    line = json.dumps({"event": event, **_checked(fields)}, separators=(",", ":"))
    sys.stderr.write(line + "\n")
    sys.stderr.flush()


def _unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document = dict(pairs)
    if len(document) != len(pairs):
        raise ValueError("duplicate receipt key")
    return document


def _marked(lines: Iterable[str]) -> str | None:
    found = [line for line in lines if line.startswith(RECEIPT_MARKER)]
    if not found:
        return None
    if len(found) != 1 or not found[0].startswith(RECEIPT_MARKER + " "):
        raise ReceiptAmbiguous("receipt count or marker")
    return found[0][len(RECEIPT_MARKER) + 1 :]


def parse_receipt(lines: Iterable[str], kind: str) -> dict[str, Any] | None:
    """The single receipt of this kind in one task's stream, None if absent.

    The reader passes only the stream of the observed task. Absence is a missing
    receipt; a duplicate, a malformed line or any envelope other than exactly
    this kind's is ``ReceiptAmbiguous``. Both hold.
    """
    schema, subject_field = KINDS[kind]
    text = _marked(lines)
    if text is None:
        return None
    try:
        document = json.loads(text, object_pairs_hook=_unique_keys)
    except (ValueError, RecursionError) as error:
        raise ReceiptAmbiguous("receipt is not JSON or repeats a key") from error
    fields = {"schema", "release_id", subject_field, "task_arn", "status", "result"}
    if not isinstance(document, dict) or set(document) != fields:
        raise ReceiptAmbiguous("receipt envelope")
    if document["schema"] != schema or document["status"] not in STATUSES[kind]:
        raise ReceiptAmbiguous("receipt schema or status")
    result = document["result"]
    if (
        not isinstance(result, dict)
        or not result
        or any(not isinstance(document[key], str) for key in fields - {"result"})
        or any(
            not isinstance(key, str)
            or not _KEY.fullmatch(key)
            or not isinstance(item, str)
            or not _VALUE.fullmatch(item)
            for key, item in result.items()
        )
        or (document["status"] == "failed" and set(result) != FAILURE_KEYS[kind])
    ):
        raise ReceiptAmbiguous("receipt result")
    return document


def extract_receipt(lines: Iterable[str]) -> dict[str, Any] | None:
    """A release-tools job receipt (``tools`` kind); see ``parse_receipt``."""
    return parse_receipt(lines, "tools")
