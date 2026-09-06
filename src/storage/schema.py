"""Product release migration and read-only application compatibility gate."""

import hashlib
from pathlib import Path

from sqlalchemy import Connection, Engine, text
from sqlalchemy.orm import Session

from .models import Base

SCHEMA_VERSION = 1
MIGRATION_LOCK = 7392051801
MIGRATION_SQL = Path(__file__).with_name("migrations") / "001_release.sql"


def _revision() -> tuple[int, str]:
    return SCHEMA_VERSION, hashlib.sha256(MIGRATION_SQL.read_bytes()).hexdigest()


def _check_columns(connection: Connection) -> None:
    # No row reads or ORM materialization. Checks the columns the running binary
    # actually queries, not just a version marker left behind by a broken schema.
    for table in Base.metadata.sorted_tables:
        connection.execute(table.select().limit(0))


def _check_revision(connection: Connection) -> None:
    rows = connection.execute(
        text("SELECT version, checksum FROM sentrysearch_schema_migrations ORDER BY version")
    ).all()
    if rows != [_revision()]:
        raise RuntimeError("Unsupported storage schema")


def require_schema(engine: Engine) -> None:
    try:
        with engine.begin() as connection:
            connection.execute(text("SET TRANSACTION READ ONLY"))
            connection.execute(text("SET LOCAL search_path = public"))
            connection.execute(text("SET LOCAL statement_timeout = '2s'"))
            connection.execute(text("SET LOCAL lock_timeout = '250ms'"))
            _check_revision(connection)
            _check_columns(connection)
    except Exception:
        raise RuntimeError(
            "Storage schema unavailable or incompatible; run the release check"
        ) from None


def migrate(engine: Engine) -> None:
    # Import only in the release process; neither probing nor constructing an
    # engine needs product reconciliation or provider clients.
    from .report_service import ReportStorageService

    try:
        with engine.begin() as connection:
            connection.execute(text("SET LOCAL search_path = public"))
            connection.execute(text("SET LOCAL lock_timeout = '3s'"))
            connection.execute(text("SET LOCAL statement_timeout = '60s'"))
            if not connection.execute(
                text("SELECT pg_try_advisory_xact_lock(:key)"), {"key": MIGRATION_LOCK}
            ).scalar_one():
                raise RuntimeError("Another storage migration is running")
            connection.execute(
                text(
                    "CREATE TABLE IF NOT EXISTS sentrysearch_schema_migrations ("
                    "version INTEGER PRIMARY KEY, checksum VARCHAR(64) NOT NULL, "
                    "applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())"
                )
            )
            versions = connection.execute(
                text("SELECT version FROM sentrysearch_schema_migrations")
            ).all()
            if not versions:
                # This baseline contains simple DDL only, no procedural SQL or
                # semicolons inside literals. Future revisions need explicit steps.
                for statement in MIGRATION_SQL.read_text().split(";"):
                    if statement.strip():
                        connection.execute(text(statement))
                with Session(bind=connection) as session:
                    ReportStorageService().reconcile_reader_state(session=session)
                    session.flush()
                _check_columns(connection)
                version, checksum = _revision()
                connection.execute(
                    text(
                        "INSERT INTO sentrysearch_schema_migrations(version, checksum) VALUES (:version, :checksum)"
                    ),
                    {"version": version, "checksum": checksum},
                )
            _check_revision(connection)
            _check_columns(connection)
    except Exception:
        raise RuntimeError(
            "Storage migration failed; verify schema, role and release exclusivity"
        ) from None
