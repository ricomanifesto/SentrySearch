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
    # Tables the revision creates; the release withholds them from Data API roles.
    tables: tuple[str, ...] = ()

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
    Revision(
        1,
        "001_release.sql",
        (
            "report_searches",
            "report_tags",
            "reports",
            "report_disposition_events",
            "report_runtime_dispatches",
            "sentrysearch_schema_migrations",
        ),
    ),
    Revision(
        2,
        "002_profile_rows.sql",
        (
            "report_sources",
            "report_claims",
            "report_claim_support",
            "report_indicator_observations",
            "report_source_observations",
            "report_findings",
            "report_artifacts",
        ),
    ),
)
# Supabase's Data API serves the public schema to these roles, using the public
# anon key or a signed-in session, and its default privileges grant them every
# new table. Only the application role reads product tables.
DATA_API_ROLES = ("anon", "authenticated")
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


def _withhold_from_data_api(connection: Connection, tables: list[str]) -> None:
    """Revoke Data API and PUBLIC access to new tables inside the release transaction.

    The tables become visible to other sessions only when the release commits, so
    they are never readable by those roles. Any access still remaining, such as
    through a role they inherit from, fails the release instead.
    """

    roles = list(
        connection.execute(
            text("SELECT rolname FROM pg_roles WHERE rolname = ANY(:roles)"),
            {"roles": list(DATA_API_ROLES)},
        ).scalars()
    )
    for table in tables:
        # Names come from the fixed revision list, never from input.
        connection.execute(text(f'REVOKE ALL ON TABLE public."{table}" FROM PUBLIC'))
        for role in roles:
            connection.execute(text(f'REVOKE ALL ON TABLE public."{table}" FROM "{role}"'))
    exposed = connection.execute(
        text(
            "SELECT c.relname FROM pg_class c "
            "WHERE c.relnamespace = 'public'::regnamespace AND c.relname = ANY(:tables) "
            "AND (EXISTS (SELECT 1 FROM aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) a "
            "WHERE a.grantee = 0) "
            "OR EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname = ANY(:roles) "
            "AND has_table_privilege(r.oid, c.oid, "
            "'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')))"
        ),
        {"tables": tables, "roles": roles},
    ).first()
    if exposed is not None:
        raise RuntimeError("A new table remains reachable by a Data API role")


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
                # Before any row is backfilled, and in the same transaction.
                _withhold_from_data_api(
                    connection, [table for revision in pending for table in revision.tables]
                )
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
