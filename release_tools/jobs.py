"""Guarded release jobs: bootstrap, grant, proof and same-database reconciliation.

Every precondition fails closed before a database connection: configuration, the
bound program/SQL digests, the fixed deadline, the task identity and the trust
material. A failure after a connection attempt is never reported as success, and
a failure after SQL may have run is reported with an unknown SQL outcome: the
controller holds on anything but an exact success receipt.
"""

import http.client
import json
import os
import re
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from release_tools import config, digest, guard, receipt, scram, session

EXIT_OK = 0
EXIT_CONFIG = 2
EXIT_INTEGRITY = 3
EXIT_DEADLINE_EXPIRED = 4
EXIT_MATERIAL = 5
EXIT_TASK_IDENTITY = 6
EXIT_CONNECTION = 10
EXIT_SQL = 11
EXIT_DEADLINE = 124
EXIT_TERMINATED = 143

METADATA_HOSTS = frozenset({"169.254.170.2", "127.0.0.1"})
METADATA_TIMEOUT_SECONDS = 2
MAX_METADATA_BYTES = 65_536
MAX_CA_BYTES = 65_536
_TASK_ARN = re.compile(
    r"arn:aws[a-z-]{0,16}:ecs:[a-z0-9-]{1,32}:\d{12}:task/[A-Za-z0-9_-]{1,255}/[0-9a-f]{32}"
)
_METADATA_URI = re.compile(r"http://([0-9.]{7,15})(?::(\d{1,5}))?/v4/[A-Za-z0-9_.-]{1,128}")
_SESSION_FIELDS = ("pid", "backend_start", "database", "principal", "application_name", "state")
_SESSION_PATTERNS = {
    "pid": re.compile(r"\d{1,10}"),
    "backend_start": re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z|unknown"),
    "database": re.compile(r"[a-z_][a-z0-9_]{0,62}"),
    "principal": re.compile(r"[a-z_][a-z0-9_]{0,62}"),
    "application_name": re.compile(r"[A-Za-z0-9:_.-]{1,63}"),
    "state": re.compile(r"[a-z_]{1,40}"),
}
SQL = digest.PACKAGE_ROOT / "sql"


class JobFailed(Exception):
    def __init__(self, reason: str, sql_outcome: str, code: int) -> None:
        super().__init__(reason)
        self.reason = reason
        self.sql_outcome = sql_outcome
        self.code = code


def _preflight_failure(reason: str, code: int) -> int:
    receipt.log("job_failed", reason=reason, sql_outcome="none", exit_code=code)
    return code


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


def _material_ok() -> bool:
    """The init profile's CA file: a regular, owner-only file of this job's user."""
    path = session.CA_PATH
    try:
        if path.is_symlink() or not path.is_file():
            return False
        status = path.stat()
        if status.st_uid != os.geteuid() or status.st_mode & 0o077:
            return False
        data = path.read_bytes()
    except OSError:
        return False
    return 0 < len(data) <= MAX_CA_BYTES and b"-----BEGIN CERTIFICATE-----" in data


class Job:
    def __init__(
        self,
        loaded: config.JobConfig,
        task_arn: str,
        deadline: datetime,
        now: Callable[[], datetime],
    ) -> None:
        self.config = loaded
        self.task_arn = task_arn
        self.deadline = deadline
        self.now = now
        self.sql_attempted = False

    def _session(
        self,
        files: list[str],
        variables: dict[str, str] | None = None,
        *,
        extra_env: dict[str, str] | None = None,
        dbname: str | None = None,
        command: str | None = None,
    ) -> session.PsqlResult:
        try:
            result = session.run_psql(
                self.config,
                [SQL / name for name in files],
                variables or {},
                deadline=self.deadline,
                now=self.now(),
                extra_env=extra_env,
                dbname=dbname,
                command=command,
            )
        except session.BudgetExhausted:
            if self.sql_attempted:
                # An earlier session of this job may have run SQL.
                raise JobFailed("deadline_exceeded", "unknown", EXIT_DEADLINE) from None
            raise JobFailed("deadline_expired", "none", EXIT_DEADLINE_EXPIRED) from None
        self.sql_attempted = True
        return result

    @staticmethod
    def _checked(result: session.PsqlResult) -> dict[str, str]:
        if result.outcome is guard.Outcome.DEADLINE:
            raise JobFailed("deadline_exceeded", "unknown", EXIT_DEADLINE)
        if result.outcome is guard.Outcome.TERMINATED:
            raise JobFailed("terminated", "unknown", EXIT_TERMINATED)
        if result.returncode != 0:
            reason = session.classify(result.stderr)
            if not result.connected:
                raise JobFailed(reason, "none", EXIT_CONNECTION)
            raise JobFailed(reason, "unknown", EXIT_SQL)
        try:
            return session.parse_results(result.stdout)
        except session.SessionError:
            raise JobFailed("result_invalid", "unknown", EXIT_SQL) from None

    @staticmethod
    def _expect(observed: dict[str, str], wanted: dict[str, str]) -> dict[str, str]:
        if any(observed.get(key) != value for key, value in wanted.items()):
            raise JobFailed("observation_mismatch", "unknown", EXIT_SQL)
        return {key: observed[key] for key in wanted}

    def _identity(self) -> dict[str, str]:
        return {
            "database": self.config.expect_database,
            "principal": self.config.expect_principal,
        }

    def _schema_file(self) -> str:
        return f"schema_{self.config.database}.sql"

    def grant(self) -> dict[str, str]:
        main = Path(self.config.main_sql).relative_to("sql").as_posix()
        observed = self._checked(
            self._session(
                ["session_check.sql", "refresh.sql", main, "refresh.sql", "identity.sql"],
                {
                    "database_name": self.config.expect_database,
                    "service_role": str(self.config.service_role),
                },
            )
        )
        return {
            **self._expect(observed, self._identity()),
            "service_role": str(self.config.service_role),
            "sql_digest": self.config.sql_sha256,
        }

    def proof(self) -> dict[str, str]:
        main = Path(self.config.main_sql).relative_to("sql").as_posix()
        observed = self._checked(
            self._session(
                [
                    "session_check.sql",
                    "refresh.sql",
                    "identity.sql",
                    self._schema_file(),
                    "refresh.sql",
                    main,
                ],
                {"owner_role": str(self.config.owner_role)},
            )
        )
        result = self._expect(observed, self._identity())
        if "schema" not in observed:
            raise JobFailed("observation_mismatch", "unknown", EXIT_SQL)
        # The service login must not reach the instance's maintenance database.
        other = self._session([], dbname="postgres", command="SELECT 1")
        if other.outcome is not guard.Outcome.COMPLETED:
            self._checked(other)
        if other.returncode == 0:
            raise JobFailed("cross_database_access", "unknown", EXIT_SQL)
        if other.connected or session.classify(other.stderr) != "connect_denied":
            raise JobFailed("cross_database_unproven", "unknown", EXIT_SQL)
        return {**result, "schema": observed["schema"]}

    def reconcile(self) -> dict[str, str]:
        result = self._session(
            [
                "session_check.sql",
                "refresh.sql",
                "identity.sql",
                self._schema_file(),
                "reconcile.sql",
            ],
            {"release_id": self.config.release_id},
        )
        observed = self._checked(result)
        for line in result.stdout.splitlines():
            if line.startswith("session|"):
                values = line.split("|")[1:]
                if len(values) != len(_SESSION_FIELDS):
                    receipt.log("session_unparsed")
                    continue
                receipt.log(
                    "session_observed",
                    **{
                        name: value if _SESSION_PATTERNS[name].fullmatch(value) else "invalid"
                        for name, value in zip(_SESSION_FIELDS, values)
                    },
                )
        keys = ("schema", "release_sessions", "owner_sessions")
        if any(key not in observed for key in keys):
            raise JobFailed("observation_mismatch", "unknown", EXIT_SQL)
        return {**self._expect(observed, self._identity()), **{key: observed[key] for key in keys}}

    def bootstrap(self) -> dict[str, str]:
        assert self.config.owner_password and self.config.service_password
        observed = self._checked(
            self._session(
                ["session_check.sql", "refresh.sql", "bootstrap.sql"],
                {
                    "target_database": str(self.config.target_database),
                    "owner_role": str(self.config.owner_role),
                    "service_role": str(self.config.service_role),
                },
                extra_env={
                    "RELEASE_OWNER_VERIFIER": scram.verifier(self.config.owner_password),
                    "RELEASE_SERVICE_VERIFIER": scram.verifier(self.config.service_password),
                },
            )
        )
        return self._expect(
            observed,
            {
                "database": str(self.config.target_database),
                "principal": self.config.expect_principal,
                "owner_role": str(self.config.owner_role),
                "service_role": str(self.config.service_role),
            },
        )

    def run(self) -> int:
        common = {"release_id": self.config.release_id, "job_id": self.config.job_id}
        receipt.log("job_started", kind=self.config.kind, database=self.config.database, **common)
        try:
            if not _material_ok():
                raise JobFailed("material_invalid", "none", EXIT_MATERIAL)
            result = getattr(self, self.config.kind)()
        except JobFailed as failure:
            receipt.emit_receipt(
                **common,
                task_arn=self.task_arn,
                status="failed",
                result={"reason": failure.reason, "sql_outcome": failure.sql_outcome},
            )
            receipt.log(
                "job_failed",
                reason=failure.reason,
                sql_outcome=failure.sql_outcome,
                exit_code=failure.code,
            )
            return failure.code
        receipt.emit_receipt(**common, task_arn=self.task_arn, status="succeeded", result=result)
        receipt.log("job_succeeded", **common)
        return EXIT_OK


def main(
    argv: list[str],
    environ: dict[str, str],
    *,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> int:
    if argv == ["digest"]:
        print(json.dumps(digest.report(), sort_keys=True))
        return EXIT_OK
    if len(argv) != 1 or argv[0] not in config.KINDS:
        return _preflight_failure("command_invalid", EXIT_CONFIG)
    started = now()
    try:
        loaded = config.load(argv[0], environ)
    except config.ConfigError as error:
        return _preflight_failure(error.reason, EXIT_CONFIG)
    try:
        tools = digest.tools_sha256()
        sql = digest.file_sha256(digest.PACKAGE_ROOT / loaded.main_sql)
    except (digest.IntegrityError, OSError):
        return _preflight_failure("tools_integrity", EXIT_INTEGRITY)
    if tools != loaded.tools_sha256:
        return _preflight_failure("tools_hash_mismatch", EXIT_INTEGRITY)
    if sql != loaded.sql_sha256:
        return _preflight_failure("sql_hash_mismatch", EXIT_INTEGRITY)
    deadline = guard.job_deadline(loaded, started)
    if deadline <= started:
        return _preflight_failure("deadline_expired", EXIT_DEADLINE_EXPIRED)
    try:
        task_arn = task_identity(environ)
    except (OSError, ValueError, http.client.HTTPException):
        return _preflight_failure("task_identity_unavailable", EXIT_TASK_IDENTITY)
    return Job(loaded, task_arn, deadline, now).run()
