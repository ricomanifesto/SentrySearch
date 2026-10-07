"""Strict job configuration from the reviewed task definition's environment.

Names, hashes and deadlines are fixed per release. Credentials arrive only through
pinned secret versions. Anything unexpected fails closed before any connection.
"""

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import parse_qsl, unquote, urlsplit

KINDS = frozenset({"bootstrap", "grant", "proof", "reconcile"})
DATABASES = frozenset({"runtime", "product"})
# The job's principal SQL program; the tools digest covers every other file.
MAIN_SQL = {
    ("grant", "runtime"): "sql/runtime/service.sql",
    ("grant", "product"): "sql/product/grants.sql",
    ("proof", "runtime"): "sql/runtime/proof.sql",
    ("proof", "product"): "sql/product/proof.sql",
    ("reconcile", "runtime"): "sql/reconcile.sql",
    ("reconcile", "product"): "sql/reconcile.sql",
    ("bootstrap", "runtime"): "sql/bootstrap.sql",
    ("bootstrap", "product"): "sql/bootstrap.sql",
}
CA_FILE = "/run/material/postgres-ca.pem"
MIN_BUDGET_SECONDS, MAX_BUDGET_SECONDS = 60, 3600
MAX_APPLICATION_NAME = 63  # PostgreSQL truncates longer names (NAMEDATALEN - 1).

_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_JOB_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_IDENTIFIER = re.compile(r"[a-z_][a-z0-9_]{0,62}")
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_HOST = re.compile(
    r"[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*"
)
_PASSWORD = re.compile(r"[!-~]{24,128}")
_DIGITS = re.compile(r"[0-9]{1,5}")  # ASCII only: str.isdigit() also accepts other scripts
_DB_KEYS = ("DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD")


class ConfigError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class Connection:
    host: str
    port: int
    dbname: str
    user: str
    password: str = field(repr=False)


@dataclass(frozen=True)
class JobConfig:
    kind: str
    database: str
    release_id: str
    job_id: str
    not_after: datetime
    budget_seconds: int
    tools_sha256: str
    sql_sha256: str
    main_sql: str
    expect_database: str
    expect_principal: str
    connection: Connection
    service_role: str | None = None
    owner_role: str | None = None
    target_database: str | None = None
    owner_password: str | None = field(default=None, repr=False)
    service_password: str | None = field(default=None, repr=False)

    @property
    def application_name(self) -> str:
        return f"release:{self.release_id}:{self.job_id}"


def _value(environ: dict[str, str], key: str, pattern: re.Pattern[str], reason: str) -> str:
    value = environ.get(key, "")
    if not pattern.fullmatch(value):
        raise ConfigError(reason)
    return value


def _identifier(environ: dict[str, str], key: str) -> str:
    return _value(environ, key, _IDENTIFIER, "identifier_invalid")


def _port(value: str) -> int:
    if not _DIGITS.fullmatch(value) or not 1 <= int(value) <= 65535:
        raise ConfigError("port_invalid")
    return int(value)


def _from_url(url: str) -> Connection:
    try:
        parts = urlsplit(url)
        parsed_port = parts.port
        port = 5432 if parsed_port is None else _port(str(parsed_port))
        host = parts.hostname or ""
    except ValueError as error:
        raise ConfigError("database_url_invalid") from error
    allowed = {"sslmode": "verify-full", "sslrootcert": CA_FILE}
    try:
        query = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=bool(parts.query))
    except ValueError as error:
        raise ConfigError("database_url_invalid") from error
    dbname = unquote(parts.path[1:])
    if (
        parts.scheme not in {"postgres", "postgresql"}
        or parts.fragment
        or not parts.username
        or parts.password is None
        or not _HOST.fullmatch(host)
        or not _IDENTIFIER.fullmatch(dbname)
        or len({key for key, _ in query}) != len(query)
        or any(allowed.get(key) != value for key, value in query)
    ):
        raise ConfigError("database_url_invalid")
    return Connection(host, port, dbname, unquote(parts.username), unquote(parts.password))


def _connection(environ: dict[str, str]) -> Connection:
    url = environ.get("DATABASE_URL")
    present = [key for key in _DB_KEYS if key in environ]
    if url is not None:
        if present:
            raise ConfigError("credentials_ambiguous")
        return _from_url(url)
    if not present:
        raise ConfigError("credentials_missing")
    if len(present) != len(_DB_KEYS) or not all(environ[key] for key in _DB_KEYS):
        raise ConfigError("credentials_incomplete")
    if not _HOST.fullmatch(environ["DB_HOST"]):
        raise ConfigError("host_invalid")
    if not _IDENTIFIER.fullmatch(environ["DB_NAME"]):
        raise ConfigError("identifier_invalid")
    return Connection(
        environ["DB_HOST"],
        _port(environ["DB_PORT"]),
        environ["DB_NAME"],
        environ["DB_USER"],
        environ["DB_PASSWORD"],
    )


def load(kind: str, environ: dict[str, str]) -> JobConfig:
    if kind not in KINDS:
        raise ConfigError("command_invalid")
    release_id = _value(environ, "RELEASE_ID", _UUID, "release_id_invalid")
    job_id = _value(environ, "RELEASE_JOB_ID", _JOB_ID, "job_id_invalid")
    database = environ.get("RELEASE_DATABASE", "")
    if database not in DATABASES:
        raise ConfigError("database_invalid")
    stamp = _value(environ, "RELEASE_NOT_AFTER", _TIMESTAMP, "not_after_invalid")
    try:
        not_after = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as error:
        raise ConfigError("not_after_invalid") from error
    budget = environ.get("RELEASE_JOB_BUDGET_SECONDS", "")
    if not _DIGITS.fullmatch(budget) or not MIN_BUDGET_SECONDS <= int(budget) <= MAX_BUDGET_SECONDS:
        raise ConfigError("budget_invalid")
    tools = _value(environ, "RELEASE_TOOLS_SHA256", _SHA256, "tools_sha256_invalid")
    sql = _value(environ, "RELEASE_SQL_SHA256", _SHA256, "sql_sha256_invalid")
    expect_database = _identifier(environ, "RELEASE_EXPECT_DATABASE")
    expect_principal = _identifier(environ, "RELEASE_EXPECT_PRINCIPAL")
    extra: dict[str, str] = {}
    for key, name in (
        ("RELEASE_SERVICE_ROLE", "service_role"),
        ("RELEASE_OWNER_ROLE", "owner_role"),
        ("RELEASE_TARGET_DATABASE", "target_database"),
    ):
        required = {
            "service_role": kind in {"grant", "bootstrap"},
            "owner_role": kind in {"proof", "bootstrap"},
            "target_database": kind == "bootstrap",
        }[name]
        if required:
            extra[name] = _identifier(environ, key)
        elif key in environ:
            raise ConfigError("unexpected_setting")
    roles = [
        expect_principal,
        *(extra[name] for name in ("service_role", "owner_role") if name in extra),
    ]
    if len(set(roles)) != len(roles):
        raise ConfigError("roles_not_distinct")
    if extra.get("target_database") == expect_database:
        raise ConfigError("target_invalid")
    connection = _connection(environ)
    if connection.user != expect_principal:
        raise ConfigError("principal_mismatch")
    if connection.dbname != expect_database:
        raise ConfigError("database_mismatch")
    passwords: dict[str, str] = {}
    if kind == "bootstrap":
        for key, name in (
            ("RELEASE_OWNER_PASSWORD", "owner_password"),
            ("RELEASE_SERVICE_PASSWORD", "service_password"),
        ):
            value = environ.get(key, "")
            if not _PASSWORD.fullmatch(value):
                raise ConfigError("password_invalid")
            passwords[name] = value
        if passwords["owner_password"] == passwords["service_password"]:
            raise ConfigError("password_invalid")
    elif "RELEASE_OWNER_PASSWORD" in environ or "RELEASE_SERVICE_PASSWORD" in environ:
        raise ConfigError("unexpected_setting")
    loaded = JobConfig(
        kind=kind,
        database=database,
        release_id=release_id,
        job_id=job_id,
        not_after=not_after,
        budget_seconds=int(budget),
        tools_sha256=tools,
        sql_sha256=sql,
        main_sql=MAIN_SQL[(kind, database)],
        expect_database=expect_database,
        expect_principal=expect_principal,
        connection=connection,
        **extra,
        **passwords,
    )
    if len(loaded.application_name) > MAX_APPLICATION_NAME:
        raise ConfigError("application_name_too_long")
    return loaded
