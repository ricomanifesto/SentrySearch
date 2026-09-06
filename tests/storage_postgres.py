"""Disposable PostgreSQL release proofs; invoked by check_runtime_consistency."""

import os
import uuid
import subprocess
import sys

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker

from src.storage.database import DatabaseManager
from src.storage.models import Report
from src.storage.report_service import ReportStorageService


@pytest.fixture
def database():
    url = make_url(os.environ["SENTRYSEARCH_TEST_DATABASE_URL"])
    name = "release_test_" + uuid.uuid4().hex
    admin = create_engine(url, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    manager = DatabaseManager.__new__(DatabaseManager)
    manager.engine = create_engine(url.set(database=name), hide_parameters=True)
    manager.SessionLocal = sessionmaker(bind=manager.engine)
    try:
        yield manager
    finally:
        manager.engine.dispose()
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))
        admin.dispose()


def test_empty_database_is_unready_then_migrated_once(database, monkeypatch):
    assert database.check_schema() is False
    with pytest.raises(RuntimeError):
        database.require_schema()
    database.migrate_schema()
    assert database.check_schema() is True
    with database.engine.begin() as conn:
        assert conn.execute(
            text("SELECT version FROM sentrysearch_schema_migrations")
        ).scalars().all() == [1]
    monkeypatch.setattr(
        ReportStorageService,
        "reconcile_reader_state",
        lambda *args, **kwargs: pytest.fail("repeat backfill"),
    )
    database.migrate_schema()


def test_failed_backfill_rolls_back_schema_and_version(database, monkeypatch, caplog):
    def fail(*args, **kwargs):
        raise RuntimeError("private report data must not reach release output")

    monkeypatch.setattr(ReportStorageService, "reconcile_reader_state", fail)
    with pytest.raises(RuntimeError, match="Storage migration failed") as error:
        database.migrate_schema()
    assert "private report" not in str(error.value) + caplog.text
    with database.engine.connect() as conn:
        assert conn.execute(text("SELECT to_regclass('public.reports')")).scalar() is None
        assert (
            conn.execute(
                text("SELECT to_regclass('public.sentrysearch_schema_migrations')")
            ).scalar()
            is None
        )


@pytest.mark.parametrize(
    "drift",
    [
        "DELETE FROM sentrysearch_schema_migrations",
        "UPDATE sentrysearch_schema_migrations SET version=2",
        "UPDATE sentrysearch_schema_migrations SET checksum='changed'",
        "ALTER TABLE reports DROP COLUMN content_preview",
    ],
)
def test_missing_future_or_drifted_schema_is_unready_without_repair(database, drift):
    database.migrate_schema()
    with database.engine.begin() as conn:
        conn.execute(text(drift))
    assert database.check_schema() is False


def test_backfill_spans_batches_and_failed_release_preserves_existing_rows(database, monkeypatch):
    database.migrate_schema()
    with database.engine.begin() as conn:
        conn.execute(text("DELETE FROM sentrysearch_schema_migrations"))
        conn.execute(
            text(
                "INSERT INTO reports(id, tool_name, status) VALUES (:id, 'Synthetic', 'completed')"
            ),
            [{"id": uuid.uuid4()} for _ in range(301)],
        )
    original = ReportStorageService.reconcile_reader_state

    def fail_after_backfill(self, **kwargs):
        original(self, **kwargs)
        raise RuntimeError("fixture failure after flush")

    with monkeypatch.context() as scoped:
        scoped.setattr(ReportStorageService, "reconcile_reader_state", fail_after_backfill)
        with pytest.raises(RuntimeError):
            database.migrate_schema()
    with database.engine.connect() as conn:
        assert (
            conn.execute(text("SELECT count(*) FROM reports WHERE review_status IS NULL")).scalar()
            == 301
        )
        assert (
            conn.execute(text("SELECT count(*) FROM sentrysearch_schema_migrations")).scalar() == 0
        )
    database.migrate_schema()
    with database.engine.connect() as conn:
        assert (
            conn.execute(text("SELECT count(*) FROM reports WHERE review_status IS NULL")).scalar()
            == 0
        )
    assert database.check_schema() is True


def test_future_schema_migration_refused(database):
    database.migrate_schema()
    with database.engine.begin() as conn:
        conn.execute(text("UPDATE sentrysearch_schema_migrations SET version=2"))
    with pytest.raises(RuntimeError):
        database.migrate_schema()
    with database.engine.connect() as conn:
        assert (
            conn.execute(text("SELECT version FROM sentrysearch_schema_migrations")).scalar() == 2
        )


def test_concurrent_release_lock_fails_without_waiting(database):
    from src.storage.schema import MIGRATION_LOCK

    with database.engine.begin() as conn:
        conn.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": MIGRATION_LOCK})
        with pytest.raises(RuntimeError):
            database.migrate_schema()
        assert conn.execute(text("SELECT to_regclass('public.reports')")).scalar() is None
    database.migrate_schema()


def test_application_role_can_check_and_write_but_not_migrate(database):
    database.migrate_schema()
    role = "release_app_" + uuid.uuid4().hex
    with database.engine.begin() as conn:
        conn.execute(text(f'CREATE ROLE "{role}" LOGIN'))
        conn.execute(text(f'GRANT USAGE ON SCHEMA public TO "{role}"'))
        conn.execute(
            text(
                f'GRANT SELECT, INSERT, UPDATE, DELETE ON reports, report_runtime_dispatches, report_disposition_events, report_searches, report_tags TO "{role}"'
            )
        )
        conn.execute(text(f'GRANT SELECT ON sentrysearch_schema_migrations TO "{role}"'))
    app = DatabaseManager.__new__(DatabaseManager)
    app.engine = create_engine(database.engine.url.set(username=role))
    app.SessionLocal = sessionmaker(bind=app.engine)
    try:
        assert app.check_schema() is True
        with app.get_session() as session:
            session.add(Report(tool_name="Synthetic application-role proof"))
        with app.engine.connect() as conn:
            with pytest.raises(Exception):
                conn.execute(text("CREATE TABLE forbidden(id int)"))
        with app.engine.connect() as conn:
            with pytest.raises(Exception):
                conn.execute(text("DELETE FROM sentrysearch_schema_migrations"))
    finally:
        app.engine.dispose()
        with database.engine.begin() as conn:
            conn.execute(text(f'DROP OWNED BY "{role}"'))
            conn.execute(text(f'DROP ROLE "{role}"'))


def test_release_command_and_read_only_check(database, monkeypatch, capsys):
    from dev.migrate_storage import main
    from src.storage import database as module

    monkeypatch.setattr(module, "db_manager", database)
    assert main(["--check"]) == 1
    assert main([]) == 0
    assert main(["--check"]) == 0
    assert "Storage schema ready" in capsys.readouterr().out


def test_release_cli_in_separate_process(database):
    env = dict(os.environ)
    env.update(
        {
            "PYTHON_DOTENV_DISABLED": "1",
            "ENVIRONMENT": "test",
            "DB_HOST": str(database.engine.url.query["host"]),
            "DB_NAME": str(database.engine.url.database),
            "DB_USER": "postgres",
            "DB_PASSWORD": "",
            "DB_PORT": "5432",
            "DB_SSLMODE": "disable",
            "DB_SSLROOTCERT": "",
        }
    )
    command = [sys.executable, "-m", "dev.migrate_storage"]
    failed = subprocess.run(
        [*command, "--check"], env=env, text=True, capture_output=True, timeout=15
    )
    assert failed.returncode == 1
    assert "Traceback" not in failed.stderr
    assert subprocess.run(command, env=env, capture_output=True, timeout=15).returncode == 0
    assert (
        subprocess.run([*command, "--check"], env=env, capture_output=True, timeout=15).returncode
        == 0
    )
