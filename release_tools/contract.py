"""The release-job contract every guarded release task shares, stdlib only.

Release-tools jobs, the observers and the Search migration job all read the same
identity settings from their reviewed task definition, end by the same absolute
deadline and learn their ECS task ARN the same way. This module has no imports
beyond the standard library so that the Search image can carry it (with
``receipt``) without the rest of the release-tools package.
"""

import json
import re
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
JOB_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
IDENTIFIER = re.compile(r"[a-z_][a-z0-9_]{0,62}")
TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
DIGITS = re.compile(r"[0-9]{1,5}")  # ASCII only: str.isdigit() also accepts other scripts
DNS_LABEL = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")
MIN_BUDGET_SECONDS, MAX_BUDGET_SECONDS = 60, 3600
MAX_APPLICATION_NAME = 63  # PostgreSQL truncates longer names (NAMEDATALEN - 1).
STOP_GRACE_SECONDS = 5.0

METADATA_HOSTS = frozenset({"169.254.170.2", "127.0.0.1"})
METADATA_TIMEOUT_SECONDS = 2
MAX_METADATA_BYTES = 65_536
_TASK_ARN = re.compile(
    r"arn:aws[a-z-]{0,16}:ecs:[a-z0-9-]{1,32}:\d{12}:task/[A-Za-z0-9_-]{1,255}/[0-9a-f]{32}"
)
_METADATA_URI = re.compile(r"http://([0-9.]{7,15})(?::(\d{1,5}))?/v4/[A-Za-z0-9_.-]{1,128}")


# Server-side session bounds: never above these caps or the remaining time less a
# reserve kept for receipts and reaping.
RESERVE_SECONDS = 2.0
MIN_STATEMENT_MS = 1_000
MAX_STATEMENT_MS, MAX_LOCK_MS, MAX_IDLE_MS = 60_000, 3_000, 10_000
CHECK_INTERVAL_MS = 1_000
# libpq connection failures, by message fragment, to bounded reasons.
CONNECT_FAILURES = (
    ("certificate verify failed", "tls_untrusted"),
    ("does not match host name", "tls_untrusted"),
    ("server does not support SSL", "tls_unavailable"),
    ("authentication method requirement", "auth_method_rejected"),
    ("password authentication failed", "auth_failed"),
    ("permission denied for database", "connect_denied"),
    ("no pg_hba.conf entry", "connect_denied"),
    ("does not exist", "target_missing"),
    ("could not translate host name", "unreachable"),
    ("Connection refused", "unreachable"),
    ("timeout expired", "unreachable"),
    ("No route to host", "unreachable"),
)
# Server SQLSTATEs a release session can end with, to bounded reasons.
SQLSTATE_REASONS = {
    "42501": "permission_denied",
    "57014": "statement_timeout",
    "55P03": "lock_timeout",
    "25P03": "idle_timeout",
    "57P01": "session_terminated",
    "40P01": "deadlock",
}


class ContractError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class ReleaseIdentity:
    """Which release and job (or check) this task is, and its absolute time bounds."""

    release_id: str
    subject: str
    not_after: datetime
    budget_seconds: int

    @property
    def application_name(self) -> str:
        return f"release:{self.release_id}:{self.subject}"

    def deadline(self, started: datetime) -> datetime:
        """The earlier of the fixed release-window end and start plus the budget."""
        return min(self.not_after, started + timedelta(seconds=self.budget_seconds))


def value(environ: dict[str, str], key: str, pattern: re.Pattern[str], reason: str) -> str:
    text = environ.get(key, "")
    if not pattern.fullmatch(text):
        raise ContractError(reason)
    return text


def load_identity(
    environ: dict[str, str],
    *,
    subject_key: str = "RELEASE_JOB_ID",
    budget_key: str = "RELEASE_JOB_BUDGET_SECONDS",
) -> ReleaseIdentity:
    release_id = value(environ, "RELEASE_ID", UUID, "release_id_invalid")
    subject = value(environ, subject_key, JOB_ID, "job_id_invalid")
    stamp = value(environ, "RELEASE_NOT_AFTER", TIMESTAMP, "not_after_invalid")
    try:
        not_after = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        raise ContractError("not_after_invalid") from None
    budget = environ.get(budget_key, "")
    if not DIGITS.fullmatch(budget) or not MIN_BUDGET_SECONDS <= int(budget) <= MAX_BUDGET_SECONDS:
        raise ContractError("budget_invalid")
    identity = ReleaseIdentity(release_id, subject, not_after, int(budget))
    if len(identity.application_name) > MAX_APPLICATION_NAME:
        raise ContractError("application_name_too_long")
    return identity


def task_identity(environ: dict[str, str]) -> str:
    """The running task's ARN from the ECS task metadata endpoint, without proxies."""
    match = _METADATA_URI.fullmatch(environ.get("ECS_CONTAINER_METADATA_URI_V4", ""))
    if match is None or match.group(1) not in METADATA_HOSTS:
        raise ValueError("metadata endpoint")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(match.group(0) + "/task", timeout=METADATA_TIMEOUT_SECONDS) as response:
        if response.status != 200:
            raise ValueError("metadata status")
        body = response.read(MAX_METADATA_BYTES + 1)
    if len(body) > MAX_METADATA_BYTES:
        raise ValueError("metadata size")
    document = json.loads(body)
    arn = document.get("TaskARN") if isinstance(document, dict) else None
    if not isinstance(arn, str) or not _TASK_ARN.fullmatch(arn):
        raise ValueError("metadata task arn")
    return arn


def session_limits(remaining_seconds: float) -> tuple[int, int, int]:
    """(statement, lock, idle-in-transaction) milliseconds for the time left."""
    usable_ms = int((remaining_seconds - RESERVE_SECONDS) * 1000)
    if usable_ms < MIN_STATEMENT_MS:
        raise ContractError("budget_exhausted")
    return (
        min(MAX_STATEMENT_MS, usable_ms),
        min(MAX_LOCK_MS, usable_ms),
        min(MAX_IDLE_MS, usable_ms),
    )


def connect_failure(message: str) -> str:
    for needle, reason in CONNECT_FAILURES:
        if needle in message:
            return reason
    return "connect_failed"
