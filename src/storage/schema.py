"""Product release migration and read-only application compatibility gate."""

from dataclasses import dataclass
import hashlib
from pathlib import Path

from sqlalchemy import Connection, Engine, text
from sqlalchemy.orm import Session

from .models import Base

MIGRATION_LOCK = 7392051801
MIGRATIONS_DIR = Path(__file__).with_name("migrations")


@dataclass(frozen=True)
class Revision:
    """One applied-once SQL file. Applied SQL is never edited; append a revision."""

    version: int
    filename: str

    @property
    def path(self) -> Path:
        return MIGRATIONS_DIR / self.filename

    @property
    def checksum(self) -> str:
        return hashlib.sha256(self.path.read_bytes()).hexdigest()

    def statements(self) -> list[str]:
        # Revisions contain simple DDL only: no procedural SQL and no semicolons
        # inside literals. A revision that needs either must add explicit steps.
        return [statement for statement in self.path.read_text().split(";") if statement.strip()]


REVISIONS: tuple[Revision, ...] = (
    Revision(1, "001_release.sql"),
    Revision(2, "002_profile_rows.sql"),
)
SCHEMA_VERSION = REVISIONS[-1].version
# Retained for callers that referenced the baseline file directly.
MIGRATION_SQL = REVISIONS[0].path


def _expected_revisions() -> list[tuple[int, str]]:
    return [(revision.version, revision.checksum) for revision in REVISIONS]


def _revision() -> tuple[int, str]:
    """The newest supported revision and its checksum."""

    return REVISIONS[-1].version, REVISIONS[-1].checksum


def _check_columns(connection: Connection) -> None:
    # No row reads or ORM materialization. Checks the columns the running binary
    # actually queries on every mapped table, not just a version marker.
    for table in Base.metadata.sorted_tables:
        connection.execute(table.select().limit(0))


def _applied(connection: Connection) -> list[tuple[int, str]]:
    return [
        (int(version), str(checksum))
        for version, checksum in connection.execute(
            text("SELECT version, checksum FROM sentrysearch_schema_migrations ORDER BY version")
        ).all()
    ]


def _check_revision(connection: Connection) -> None:
    # Strict: exactly the supported sequence. Missing, unknown, newer, or
    # changed revisions all fail closed.
    if _applied(connection) != _expected_revisions():
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


def _pending_revisions(applied: list[tuple[int, str]]) -> list[Revision]:
    """Return revisions still to apply; the applied set must be an exact prefix."""

    expected = _expected_revisions()
    if applied != expected[: len(applied)]:
        raise RuntimeError("Applied storage revisions are unknown, newer, or changed")
    return list(REVISIONS[len(applied) :])


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
            pending = _pending_revisions(_applied(connection))
            if pending:
                # DDL for every pending revision, one reconciliation backfill,
                # and every version marker share this transaction.
                for revision in pending:
                    for statement in revision.statements():
                        connection.execute(text(statement))
                with Session(bind=connection) as session:
                    ReportStorageService().reconcile_reader_state(session=session)
                    session.flush()
                _check_columns(connection)
                for revision in pending:
                    connection.execute(
                        text(
                            "INSERT INTO sentrysearch_schema_migrations(version, checksum) "
                            "VALUES (:version, :checksum)"
                        ),
                        {"version": revision.version, "checksum": revision.checksum},
                    )
            _check_revision(connection)
            _check_columns(connection)
    except Exception:
        raise RuntimeError(
            "Storage migration failed; verify schema, role and release exclusivity"
        ) from None
