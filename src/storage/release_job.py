"""Guarded release-job mode for the product migration.

``python -m dev.migrate_storage --release-job`` runs the product migration as an
attended release job. Every precondition fails closed before a database
connection: the release-job contract, the storage settings, the absolute
deadline, the ECS task identity and the CA material. The job then opens one
verified-TLS session tagged ``release:<release>:<job>`` with server-side
statement, lock, idle and client-check limits, verifies that session, migrates
inside one transaction with limits re-derived from the deadline, and writes one
``sentry.release-migration.v1`` receipt. SIGTERM exits 143, the deadline 124, and
a failure after SQL may have run reports an unknown SQL outcome. Exit codes and
log events match the release-tools jobs and the Runtime migration job.

Only the standard-library release contract and receipt modules are shared with
the release-tools package; nothing else from it is in this image.
"""

from __future__ import annotations

import os
import signal
import stat
import re
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from release_tools import contract, receipt

EXIT_OK = 0
EXIT_CONFIG = 2
EXIT_DEADLINE_EXPIRED = 4
EXIT_MATERIAL = 5
EXIT_TASK_IDENTITY = 6
EXIT_CONNECTION = 10
EXIT_SQL = 11
EXIT_DEADLINE = 124
EXIT_TERMINATED = 143

CA_FILE: str = "/run/material/postgres-ca.pem"
MAX_CA_BYTES = 65_536
# Mirrors release_tools/sql/schema_product.sql, which the product proof job runs.
SCHEMA_SQL = (
    "SELECT 'sentrysearch:' || coalesce(string_agg(version::text || ':' || left(checksum, 16), "
    "',' ORDER BY version), 'none') FROM public.sentrysearch_schema_migrations"
)
_VERIFY_SQL = (
    "SELECT current_database(), current_user, "
    "coalesce((SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()), false), "
    "current_setting('application_name'), "
    "(SELECT setting::bigint FROM pg_settings WHERE name = 'statement_timeout'), "
    "(SELECT setting::bigint FROM pg_settings WHERE name = 'lock_timeout'), "
    "(SELECT setting::bigint FROM pg_settings WHERE name = 'idle_in_transaction_session_timeout'), "
    "(SELECT setting::bigint FROM pg_settings WHERE name = 'client_connection_check_interval')"
)


_RESULT_VALUE = re.compile(r"[A-Za-z0-9_.:,/-]{1,256}")


def contract_value(text: str) -> bool:
    return _RESULT_VALUE.fullmatch(text) is not None


class JobFailed(Exception):
    def __init__(self, reason: str, sql_outcome: str, code: int) -> None:
        super().__init__(reason)
        self.reason = reason
        self.sql_outcome = sql_outcome
        self.code = code


@dataclass(frozen=True)
class Expected:
    database: str
    principal: str


def _expected(environ: Mapping[str, str]) -> Expected:
    database = environ.get("RELEASE_EXPECT_DATABASE", "")
    principal = environ.get("RELEASE_EXPECT_PRINCIPAL", "")
    if not (contract.IDENTIFIER.fullmatch(database) and contract.IDENTIFIER.fullmatch(principal)):
        raise contract.ContractError("identifier_invalid")
    if environ.get("DB_USER") != principal:
        raise contract.ContractError("principal_mismatch")
    if environ.get("DB_NAME") != database:
        raise contract.ContractError("database_mismatch")
    # Verified TLS against the init profile's CA, from a deployed environment only.
    if (
        environ.get("DB_SSLMODE") != "verify-full"
        or environ.get("DB_SSLROOTCERT") != CA_FILE
        or environ.get("ENVIRONMENT") not in {"staging", "production"}
        or environ.get("DB_DEBUG", "false") != "false"
    ):
        raise contract.ContractError("storage_settings_invalid")
    return Expected(database, principal)


def _material_ok(path: str = CA_FILE) -> bool:
    """The CA: a regular, owner-only file of this job's user, read without following links."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return False
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
            or not 0 < info.st_size <= MAX_CA_BYTES
        ):
            return False
        data = os.read(descriptor, MAX_CA_BYTES + 1)
    except OSError:
        return False
    finally:
        os.close(descriptor)
    return b"-----BEGIN CERTIFICATE-----" in data


def _sqlstate(error: BaseException | None) -> str | None:
    seen = 0
    while error is not None and seen < 8:
        state = getattr(error, "sqlstate", None) or getattr(
            getattr(error, "orig", None), "sqlstate", None
        )
        if isinstance(state, str):
            return state
        error = error.__cause__ or error.__context__
        seen += 1
    return None


class ReleaseJob:
    """One guarded run; ``engine_factory`` builds the single bounded session."""

    def __init__(
        self,
        identity: contract.ReleaseIdentity,
        expected: Expected,
        task_arn: str,
        deadline: datetime,
        *,
        now: Callable[[], datetime],
        engine_factory: Callable[[dict[str, Any]], Any],
        exit: Callable[[int], None],
    ) -> None:
        self.identity = identity
        self.expected = expected
        self.task_arn = task_arn
        self.deadline = deadline
        self.session_end = deadline - timedelta(seconds=contract.STOP_GRACE_SECONDS)
        self.now = now
        self.engine_factory = engine_factory
        self.exit = exit
        self.sql_attempted = False
        self.terminated = threading.Event()
        self.expired = threading.Event()
        self.done = threading.Event()
        self._lock = threading.Lock()
        self._code: int | None = None
        self._dbapi: Any = None
        self.limits: tuple[int, int, int] = (0, 0, 0)

    # Receipts ---------------------------------------------------------------

    def _record(self, status: str, result: dict[str, str], code: int) -> int:
        """Write the one receipt; whoever records first decides the exit code."""
        with self._lock:
            if self._code is not None:
                return self._code
            self._code = code
            receipt.emit(
                "migration", release_id=self.identity.release_id, subject=self.identity.subject,
                task_arn=self.task_arn, status=status, result=result,
            )  # fmt: skip
        return code

    def fail(self, failure: JobFailed) -> int:
        code = self._record(
            "failed", {"reason": failure.reason, "sql_outcome": failure.sql_outcome}, failure.code
        )
        if code == failure.code:
            receipt.log(
                "job_failed", reason=failure.reason, sql_outcome=failure.sql_outcome,
                exit_code=failure.code, release_id=self.identity.release_id,
                job_id=self.identity.subject,
            )  # fmt: skip
        return code

    def outcome(self) -> str:
        return "unknown" if self.sql_attempted else "none"

    # Stop and deadline --------------------------------------------------------

    def _cancel(self) -> None:
        connection = self._dbapi
        if connection is not None:
            try:
                connection.cancel()
            except Exception:
                pass

    def stop(self, *_args: object) -> None:
        """SIGTERM/SIGINT: cancel the running statement and exit within the grace."""
        if self.terminated.is_set():
            return
        self.terminated.set()
        self._cancel()
        threading.Thread(target=self._watchdog, args=(contract.STOP_GRACE_SECONDS,),
                         daemon=True).start()  # fmt: skip

    def _watchdog(self, seconds: float) -> None:
        if self.done.wait(seconds):
            return
        code, reason = (
            (EXIT_TERMINATED, "terminated") if self.terminated.is_set()
            else (EXIT_DEADLINE, "deadline_exceeded")
        )  # fmt: skip
        self.exit(self.fail(JobFailed(reason, self.outcome(), code)))

    def _deadline_timer(self) -> None:
        # At the session end cancel any statement; at the absolute deadline stop waiting.
        if self.done.wait(max(0.0, (self.session_end - self.now()).total_seconds())):
            return
        self.expired.set()
        self._cancel()
        self._watchdog(max(0.0, (self.deadline - self.now()).total_seconds()))

    # Work ---------------------------------------------------------------------

    def _limits(self) -> tuple[int, int, int]:
        remaining = (self.session_end - self.now()).total_seconds()
        try:
            return contract.session_limits(remaining)
        except contract.ContractError:
            raise JobFailed("budget_exhausted", self.outcome(), EXIT_DEADLINE) from None

    def _connect_args(self) -> dict[str, Any]:
        statement_ms, lock_ms, idle_ms = self._limits()
        self.limits = (statement_ms, lock_ms, idle_ms)
        options = " ".join(
            [
                "-c search_path=public",
                f"-c statement_timeout={statement_ms}",
                f"-c lock_timeout={lock_ms}",
                f"-c idle_in_transaction_session_timeout={idle_ms}",
                f"-c client_connection_check_interval={contract.CHECK_INTERVAL_MS}",
            ]
        )
        return {"application_name": self.identity.application_name, "options": options}

    def _classify(self, error: BaseException, *, connected: bool) -> JobFailed:
        if self.terminated.is_set():
            return JobFailed("terminated", self.outcome(), EXIT_TERMINATED)
        if self.expired.is_set():
            return JobFailed("deadline_exceeded", self.outcome(), EXIT_DEADLINE)
        if not connected:
            message = str(getattr(error, "orig", None) or error)
            return JobFailed(contract.connect_failure(message), "none", EXIT_CONNECTION)
        state = _sqlstate(error)
        reason = contract.SQLSTATE_REASONS.get(state or "", "sql_error")
        return JobFailed(reason, self.outcome(), EXIT_SQL)

    def migrate(self) -> int:
        from sqlalchemy import text

        from src.storage import schema

        try:
            connect_args = self._connect_args()
        except JobFailed:
            # Reading the task identity and material used up the preflight's
            # margin: refuse before connecting, as the preflight would have.
            return self.fail(JobFailed("deadline_expired", "none", EXIT_DEADLINE_EXPIRED))
        engine = self.engine_factory(connect_args)
        connected = False
        try:
            with engine.connect() as connection:
                connected = True
                self._dbapi = connection.connection.dbapi_connection
                if self.terminated.is_set() or self.expired.is_set():
                    raise JobFailed("terminated" if self.terminated.is_set() else
                                    "deadline_exceeded", "none",
                                    EXIT_TERMINATED if self.terminated.is_set() else EXIT_DEADLINE)  # fmt: skip
                row = connection.execute(text(_VERIFY_SQL)).one()
                connection.rollback()
                statement_ms, lock_ms, idle_ms = self.limits
                checks = [
                    (row[0] == self.expected.database, "wrong_database"),
                    (row[1] == self.expected.principal, "wrong_principal"),
                    (row[2] is True, "tls_not_observed"),
                    (row[3] == self.identity.application_name, "session_identity_mismatch"),
                    (
                        tuple(row[4:8])
                        == (statement_ms, lock_ms, idle_ms, contract.CHECK_INTERVAL_MS),
                        "session_limits_mismatch",
                    ),
                ]
                for passed, reason in checks:
                    if not passed:
                        raise JobFailed(reason, "none", EXIT_SQL)
                statement_ms, lock_ms, _idle = self._limits()
                self.sql_attempted = True
                with connection.begin():
                    schema.migrate_connection(
                        connection, statement_timeout_ms=statement_ms,
                        lock_timeout_ms=min(lock_ms, statement_ms),
                    )  # fmt: skip
                observed = connection.execute(text(SCHEMA_SQL)).scalar_one()
                connection.rollback()
        except JobFailed as failure:
            return self.fail(failure)
        except Exception as error:
            failure = self._classify(error, connected=connected)
            return self.fail(failure)
        finally:
            self._dbapi = None
            engine.dispose()
        if self.terminated.is_set():
            return self.fail(JobFailed("terminated", self.outcome(), EXIT_TERMINATED))
        if not isinstance(observed, str) or not contract_value(observed):
            return self.fail(JobFailed("result_invalid", "unknown", EXIT_SQL))
        result = {
            "database": self.expected.database,
            "principal": self.expected.principal,
            "schema": observed,
        }
        code = self._record("succeeded", result, EXIT_OK)
        if code == EXIT_OK:
            receipt.log("job_succeeded", release_id=self.identity.release_id,
                        job_id=self.identity.subject)  # fmt: skip
        return code


def _default_engine(connect_args: dict[str, Any]) -> Any:
    from src.storage.database import release_engine

    return release_engine(connect_args)


def main(
    environ: Mapping[str, str],
    *,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
    engine_factory: Callable[[dict[str, Any]], Any] = _default_engine,
    exit: Callable[[int], None] = os._exit,
    install_signals: bool = True,
) -> int:
    started = now()
    environment = dict(environ)

    def preflight(reason: str, code: int, **fields: str) -> int:
        receipt.log("job_failed", reason=reason, sql_outcome="none", exit_code=code, **fields)
        return code

    try:
        identity = contract.load_identity(environment)
        expected = _expected(environment)
        # The storage URL itself: refuses plaintext, PGHOSTADDR/PGSERVICE and a missing CA.
        from src.storage.config import database_url

        database_url()
    except contract.ContractError as error:
        return preflight(error.reason, EXIT_CONFIG)
    except ValueError:
        return preflight("storage_settings_invalid", EXIT_CONFIG)
    common = {"release_id": identity.release_id, "job_id": identity.subject}
    deadline = identity.deadline(started)
    session_end = deadline - timedelta(seconds=contract.STOP_GRACE_SECONDS)
    try:
        contract.session_limits((session_end - started).total_seconds())
    except contract.ContractError:
        # Too little time for even one bounded statement: never connect.
        return preflight("deadline_expired", EXIT_DEADLINE_EXPIRED, **common)
    try:
        task_arn = contract.task_identity(environment)
    except Exception:
        return preflight("task_identity_unavailable", EXIT_TASK_IDENTITY, **common)
    receipt.log("job_started", kind="migrate", database="product", **common)
    job = ReleaseJob(identity, expected, task_arn, deadline, now=now,
                     engine_factory=engine_factory, exit=exit)  # fmt: skip
    if not _material_ok(environment.get("DB_SSLROOTCERT", CA_FILE)):
        return job.fail(JobFailed("material_invalid", "none", EXIT_MATERIAL))
    previous = {}
    if install_signals:
        previous = {
            signum: signal.signal(signum, job.stop) for signum in (signal.SIGTERM, signal.SIGINT)
        }
    timer = threading.Thread(target=job._deadline_timer, daemon=True)
    timer.start()
    try:
        return job.migrate()
    finally:
        job.done.set()
        for signum, handler in previous.items():
            signal.signal(signum, handler)
