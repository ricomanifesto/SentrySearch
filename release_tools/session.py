"""Bounded psql sessions: fixed client, explicit target, verified TLS and limits.

psql receives a constructed environment, never the job's own. Credentials pass
only through PGPASSWORD; argv carries file paths and validated identifiers.
"""

import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from release_tools import contract, guard
from release_tools.config import CA_FILE, Connection, JobConfig

PSQL = Path("/usr/lib/postgresql/16/bin/psql")
CA_PATH = Path(CA_FILE)
CONNECT_TIMEOUT_SECONDS = 5
# Time kept back from the server-side statement limit for receipts and reaping.
RESERVE_SECONDS = contract.RESERVE_SECONDS
MIN_STATEMENT_MS = contract.MIN_STATEMENT_MS
MAX_STATEMENT_MS, MAX_LOCK_MS, MAX_IDLE_MS = (
    contract.MAX_STATEMENT_MS,
    contract.MAX_LOCK_MS,
    contract.MAX_IDLE_MS,
)
CHECK_INTERVAL_MS = contract.CHECK_INTERVAL_MS
PSQL_ENVIRONMENT_KEYS = (
    "PGHOST",
    "PGPORT",
    "PGDATABASE",
    "PGUSER",
    "PGPASSWORD",
    "PGSSLMODE",
    "PGSSLROOTCERT",
    "PGSSLCERTMODE",
    "PGGSSENCMODE",
    "PGREQUIREAUTH",
    "PGCONNECT_TIMEOUT",
    "PGAPPNAME",
    "PGOPTIONS",
    "PGCLIENTENCODING",
    "PSQLRC",
    "PSQL_HISTORY",
    "LC_ALL",
    "RELEASE_OWNER_VERIFIER",
    "RELEASE_SERVICE_VERIFIER",
)
_VARIABLE_NAME = re.compile(r"[a-z][a-z_]{0,31}")
_VARIABLE_VALUE = re.compile(r"[A-Za-z0-9_.:-]{1,128}")
_RESULT = re.compile(r"result\|([a-z][a-z_]{0,31})\|([A-Za-z0-9_.:,/-]{1,256})")
_SQLSTATE = re.compile(r"^psql:[^\n]*?: (?:ERROR|FATAL):  ([0-9A-Z]{5})$", re.MULTILINE)
_CONNECT_FAILURES = contract.CONNECT_FAILURES
_SQLSTATES = {
    "RT001": "wrong_database",
    "RT002": "wrong_principal",
    "RT003": "tls_not_observed",
    "RT004": "session_identity_mismatch",
    "RT005": "session_limits_mismatch",
    "RT010": "budget_exhausted",
    **contract.SQLSTATE_REASONS,
}


class BudgetExhausted(RuntimeError):
    pass


class SessionError(RuntimeError):
    pass


@dataclass(frozen=True)
class Limits:
    statement_ms: int
    lock_ms: int
    idle_ms: int
    check_interval_ms: int = CHECK_INTERVAL_MS


@dataclass(frozen=True)
class PsqlResult:
    outcome: guard.Outcome
    returncode: int | None
    stdout: str
    stderr: str

    @property
    def connected(self) -> bool:
        """False only for psql's initial connection failure, before any SQL."""
        return not (self.returncode == 2 and self.stderr.startswith("psql: error: "))


def limits(remaining_seconds: float) -> Limits:
    """Per-session limits: never above the fixed caps or the remaining budget."""
    try:
        statement_ms, lock_ms, idle_ms = contract.session_limits(remaining_seconds)
    except contract.ContractError:
        raise BudgetExhausted("remaining job budget is too short for a statement") from None
    return Limits(statement_ms=statement_ms, lock_ms=lock_ms, idle_ms=idle_ms)


def psql_environment(
    connection: Connection,
    application_name: str,
    session_limits: Limits,
    extra: dict[str, str],
    *,
    dbname: str | None = None,
) -> dict[str, str]:
    options = (
        f"-c statement_timeout={session_limits.statement_ms} "
        f"-c lock_timeout={session_limits.lock_ms} "
        f"-c idle_in_transaction_session_timeout={session_limits.idle_ms} "
        f"-c client_connection_check_interval={session_limits.check_interval_ms}"
    )
    env = {
        "PGHOST": connection.host,
        "PGPORT": str(connection.port),
        "PGDATABASE": dbname or connection.dbname,
        "PGUSER": connection.user,
        "PGPASSWORD": connection.password,
        "PGSSLMODE": "verify-full",
        "PGSSLROOTCERT": str(CA_PATH),
        "PGSSLCERTMODE": "disable",
        "PGGSSENCMODE": "disable",
        "PGREQUIREAUTH": "scram-sha-256",
        "PGCONNECT_TIMEOUT": str(CONNECT_TIMEOUT_SECONDS),
        "PGAPPNAME": application_name,
        "PGOPTIONS": options,
        "PGCLIENTENCODING": "UTF8",
        "PSQLRC": "/dev/null",
        "PSQL_HISTORY": "/dev/null",
        "LC_ALL": "C",
        **extra,
    }
    unexpected = set(env) - set(PSQL_ENVIRONMENT_KEYS)
    if unexpected:
        raise ValueError(f"unexpected psql environment: {sorted(unexpected)}")
    return env


def psql_argv(
    files: list[Path], variables: dict[str, str], *, command: str | None = None
) -> list[str]:
    argv = [
        str(PSQL),
        "-X",
        "-w",
        "-q",
        "-A",
        "-t",
        "-v",
        "ON_ERROR_STOP=1",
        "-v",
        "VERBOSITY=sqlstate",
        "-v",
        "SHOW_CONTEXT=never",
        "-v",
        "ECHO=none",
    ]
    for name, value in sorted(variables.items()):
        if not _VARIABLE_NAME.fullmatch(name) or not _VARIABLE_VALUE.fullmatch(value):
            raise ValueError("psql variable rejected")
        argv += ["-v", f"{name}={value}"]
    if command is not None:
        argv += ["-c", command]
    for path in files:
        argv += ["-f", str(path)]
    return argv


def run_psql(
    config: JobConfig,
    files: list[Path],
    variables: dict[str, str],
    *,
    deadline: datetime,
    now: datetime,
    extra_env: dict[str, str] | None = None,
    dbname: str | None = None,
    command: str | None = None,
) -> PsqlResult:
    """Run one psql session under the watchdog; the job deadline bounds it.

    The session ends a stop grace before the job deadline: the server limits are
    derived from that earlier point, and the watchdog terminates the client there
    and kills its process group no later than the deadline itself.
    """
    grace = guard.MINIMUM_GRACE_SECONDS
    session_deadline = deadline - timedelta(seconds=grace)
    remaining = (session_deadline - now).total_seconds()
    session_limits = limits(remaining)
    env = psql_environment(
        config.connection, config.application_name, session_limits, extra_env or {}, dbname=dbname
    )
    session_variables = {
        **variables,
        "expect_database": dbname or config.expect_database,
        "expect_principal": config.expect_principal,
        "application_name": config.application_name,
        "deadline_epoch": f"{session_deadline.timestamp():.3f}",
        "remaining_ms": str(int(remaining * 1000)),
        "statement_ms": str(session_limits.statement_ms),
        "lock_ms": str(session_limits.lock_ms),
        "idle_ms": str(session_limits.idle_ms),
        "check_ms": str(session_limits.check_interval_ms),
    }
    argv = psql_argv(files, session_variables, command=command)
    child = guard.Watchdog(time.monotonic() + remaining, grace).run(argv, env)
    return PsqlResult(child.outcome, child.returncode, child.stdout, child.stderr)


def classify(stderr: str) -> str:
    """Map psql diagnostics to a fixed reason; raw server text is never logged."""
    match = _SQLSTATE.search(stderr)
    if match:
        state = match.group(1)
        if state in _SQLSTATES:
            return _SQLSTATES[state]
        if state.startswith("RT1"):
            return "privilege_inventory_mismatch" if state < "RT110" else "denial_failed"
        if state.startswith("RT2"):
            return "bootstrap_conflict"
        return "sql_error"
    if stderr.startswith("psql: error: "):
        for needle, reason in _CONNECT_FAILURES:
            if needle in stderr:
                return reason
        return "connection_failed"
    if "connection to server was lost" in stderr or "server closed the connection" in stderr:
        return "connection_lost"
    return "sql_error"


def parse_results(stdout: str) -> dict[str, str]:
    """Collect ``result|key|value`` lines. Other output is ignored, never echoed."""
    results: dict[str, str] = {}
    for line in stdout.splitlines():
        match = _RESULT.fullmatch(line)
        if match is None:
            continue
        key, value = match.groups()
        if key in results:
            raise SessionError("duplicate result")
        results[key] = value
    return results
