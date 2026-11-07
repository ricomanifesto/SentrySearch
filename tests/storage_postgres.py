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

# The restricted application role's grants; docs/storage-release.md lists them.
APP_TABLES = (
    "reports, report_runtime_dispatches, report_disposition_events, report_searches, "
    "report_tags, report_sources, report_claims, report_claim_support, "
    "report_indicator_observations, report_source_observations, report_findings, "
    "report_artifacts"
)


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
        ).scalars().all() == [1, 2]
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
        "DELETE FROM sentrysearch_schema_migrations WHERE version=2",
        "UPDATE sentrysearch_schema_migrations SET version=3 WHERE version=2",
        "INSERT INTO sentrysearch_schema_migrations(version, checksum) VALUES (3, 'future')",
        "UPDATE sentrysearch_schema_migrations SET checksum='changed'",
        "UPDATE sentrysearch_schema_migrations SET checksum='changed' WHERE version=2",
        "ALTER TABLE reports DROP COLUMN content_preview",
        "ALTER TABLE reports DROP COLUMN eligible_for_handoff",
        "ALTER TABLE report_claims DROP COLUMN value",
        "DROP TABLE report_artifacts",
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
        conn.execute(text("UPDATE sentrysearch_schema_migrations SET version=3 WHERE version=2"))
    with pytest.raises(RuntimeError):
        database.migrate_schema()
    with database.engine.connect() as conn:
        assert conn.execute(
            text("SELECT version FROM sentrysearch_schema_migrations ORDER BY version")
        ).scalars().all() == [1, 3]


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
        conn.execute(text(f'GRANT SELECT, INSERT, UPDATE, DELETE ON {APP_TABLES} TO "{role}"'))
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


def _apply_revision_one_only(database) -> None:
    from src.storage.schema import REVISIONS

    baseline = REVISIONS[0]
    with database.engine.begin() as conn:
        for statement in baseline.statements():
            conn.execute(text(statement))
        conn.execute(
            text(
                "CREATE TABLE sentrysearch_schema_migrations (version INTEGER PRIMARY KEY, "
                "checksum VARCHAR(64) NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())"
            )
        )
        conn.execute(
            text("INSERT INTO sentrysearch_schema_migrations(version, checksum) VALUES (1, :c)"),
            {"c": baseline.checksum},
        )


def test_revision_one_database_upgrades_and_backfills_rows_from_jsonb(database):
    import json

    from tests.conftest import build_threat_profile_data

    _apply_revision_one_only(database)
    assert database.check_schema() is False
    profile = build_threat_profile_data("https://research.vendor-security.com/report")
    profile["evidenceAdmissibility"] = {
        "schemaVersion": "1",
        "status": "blocked",
        "sourceObservations": [{"sourceId": "S1", "purpose": "operational"}],
        "indicatorObservations": [
            {
                "claimField": "filenames",
                "claimIndex": 0,
                "value": "example.exe",
                "disposition": "admitted",
                "ruleId": "indicator.source-coverage-only",
            }
        ],
        "blockingFindings": ["Unsafe finding.", "Coverage finding."],
        "summary": {"safetyFindings": 1, "coverageFindings": 1},
    }
    report_id = uuid.uuid4()
    with database.engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO reports(id, tool_name, status, threat_data, web_sources, "
                "evidence_admissibility, markdown_s3_key, evaluation_status, quality_score) "
                "VALUES (:id, 'Retained', 'completed', CAST(:td AS JSONB), CAST(:ws AS JSONB), "
                "CAST(:ea AS JSONB), :key, 'completed', 4.0)"
            ),
            {
                "id": report_id,
                "td": json.dumps(profile),
                "ws": json.dumps(profile["webSearchSources"]["primarySources"]),
                "ea": json.dumps(profile["evidenceAdmissibility"]),
                "key": f"reports/{report_id}/artifacts/{'b' * 64}.md",
            },
        )

    database.migrate_schema()

    assert database.check_schema() is True
    with database.engine.connect() as conn:
        assert conn.execute(
            text("SELECT version FROM sentrysearch_schema_migrations ORDER BY version")
        ).scalars().all() == [1, 2]
        claims = conn.execute(
            text(
                "SELECT claim_field, ordinal, value, evidence_role FROM report_claims "
                "WHERE report_id=:id ORDER BY position"
            ),
            {"id": report_id},
        ).all()
        assert len(claims) == 10
        assert claims[0] == ("riskFactors", 0, "Remote access", "direct_evidence")
        assert (
            conn.execute(
                text("SELECT count(*) FROM report_claim_support WHERE report_id=:id AND verified"),
                {"id": report_id},
            ).scalar()
            == 8
        )
        assert conn.execute(
            text("SELECT kind FROM report_findings WHERE report_id=:id ORDER BY position"),
            {"id": report_id},
        ).scalars().all() == ["safety", "coverage"]
        assert (
            conn.execute(
                text(
                    "SELECT claim_id IS NOT NULL FROM report_indicator_observations "
                    "WHERE report_id=:id"
                ),
                {"id": report_id},
            ).scalar()
            is True
        )
        # No artifact client in the release process: unknown, never a failed release.
        assert conn.execute(
            text(
                "SELECT sha256, policy_status, policy_version FROM report_artifacts "
                "WHERE report_id=:id AND kind='markdown'"
            ),
            {"id": report_id},
        ).one() == ("b" * 64, "unknown", 1)
        assert conn.execute(
            text(
                "SELECT reader_state_version, eligible_for_judgment, eligible_for_acceptance, "
                "eligible_for_handoff FROM reports WHERE id=:id"
            ),
            {"id": report_id},
        ).one() == (1, True, False, False)


def test_writers_dual_write_rows_and_reader_state_in_their_transactions(database):
    from typing import Any, cast

    from src.core.markdown_generator import generate_markdown
    from src.core.source_ledger import canonicalize_profile_sources
    from src.storage.s3_manager import S3StorageManager
    from tests.conftest import build_threat_profile_data

    database.migrate_schema()
    service = ReportStorageService()
    service.db_manager = database

    class Client:
        def put_object(self, **kwargs):
            return None

    store = S3StorageManager()
    store._initialized = True
    store.s3_client = cast(Any, Client())
    service.s3_manager = store

    profile, sources = canonicalize_profile_sources(
        build_threat_profile_data("https://research.vendor-security.com/report")
    )
    profile["evidenceAdmissibility"] = {"schemaVersion": "1", "status": "passed"}
    report_id = str(uuid.uuid4())
    report_data = {
        "id": report_id,
        "tool_name": "Example",
        "threat_data": profile,
        "web_sources": sources,
        "markdown_content": generate_markdown(profile),
        "evaluation_status": "completed",
        "quality_score": 4.5,
        "quality_assessment": {
            "overall_score": 4.5,
            "summary": {"passed_sections": 3, "failed_sections": 0},
        },
    }
    service.store_report(report_data, user_id="owner")
    service.store_report(dict(report_data, id=str(uuid.uuid4())), user_id="owner")

    def state():
        with database.engine.connect() as conn:
            return conn.execute(
                text(
                    "SELECT review_status, eligible_for_acceptance, eligible_for_handoff, "
                    "(SELECT count(*) FROM report_claims c WHERE c.report_id=r.id), "
                    "(SELECT policy_status FROM report_artifacts a "
                    " WHERE a.report_id=r.id AND kind='markdown') "
                    "FROM reports r WHERE id=:id"
                ),
                {"id": report_id},
            ).one()

    assert state() == ("reviewable", True, False, 10, "allowed")
    service.append_report_disposition(
        report_id,
        disposition="accepted",
        note=None,
        reviewer_user_id="owner",
        owner_user_id="owner",
    )
    assert state() == ("reviewable", True, True, 10, "allowed")
    assert service.begin_report_evaluation(report_id, user_id="owner") is True
    # A new evaluation vintage has no judgment: handoff is withdrawn atomically.
    assert state()[2] is False


def test_collections_filter_policy_in_sql_and_never_read_artifacts(database):
    from typing import Any, cast
    from unittest.mock import Mock

    from src.core.markdown_generator import generate_markdown
    from src.core.source_ledger import canonicalize_profile_sources
    from src.storage.s3_manager import S3StorageManager
    from tests.conftest import build_threat_profile_data

    database.migrate_schema()
    service = ReportStorageService()
    service.db_manager = database

    class Client:
        def put_object(self, **kwargs):
            return None

    store = S3StorageManager()
    store._initialized = True
    store.s3_client = cast(Any, Client())
    service.s3_manager = store

    profile, sources = canonicalize_profile_sources(
        build_threat_profile_data("https://research.vendor-security.com/report")
    )
    ids = {}
    for name, score, tags in (
        ("clean", 5.0, ["rat", "loader"]),
        ("second", 2.5, ["rat"]),
        ("hidden", 4.6, ["rat", "hidden-tag"]),
    ):
        ids[name] = str(uuid.uuid4())
        service.store_report(
            {
                "id": ids[name],
                "tool_name": name,
                "threat_data": profile,
                "web_sources": sources,
                "markdown_content": generate_markdown(profile),
                "quality_score": score,
                "search_tags": tags,
            },
            user_id="owner",
        )
    with database.engine.begin() as conn:
        conn.execute(
            text("UPDATE report_artifacts SET policy_status='excluded' WHERE report_id=:id"),
            {"id": ids["hidden"]},
        )
    # Any artifact read from a collection path is a failure.
    artifact_reads = Mock(side_effect=AssertionError("artifact read"))
    cast(Any, service.s3_manager).download_content = artifact_reads

    listed = service.list_reports(user_id="owner")
    searched = service.search_reports(user_id="owner", search_query="e")

    assert {row["tool_name"] for row in listed} == {"clean", "second"}
    assert all(row["_markdown_policy_status"] == "allowed" for row in listed)
    assert {row["tool_name"] for row in searched} == {"clean", "second"}
    assert service.count_reports(user_id="owner") == 2
    assert service.get_popular_tags(user_id="owner") == ["rat", "loader"]
    distribution = service.get_quality_score_distribution(user_id="owner")
    assert distribution["distribution"] == {
        "0.0-1.0": 0,
        "1.0-2.0": 0,
        "2.0-3.0": 1,
        "3.0-4.0": 0,
        "4.0-5.0": 1,
    }
    assert distribution["total_scored"] == 2
    records = service.list_analytics_records(created_after=datetime_epoch(), user_id="owner")
    assert {record.review_status.value for record in records if record.review_status} <= {
        "needs_evaluation",
        "needs_attention",
        "reviewable",
    }
    artifact_reads.assert_not_called()


def datetime_epoch():
    from datetime import datetime, timezone

    return datetime(1970, 1, 1, tzinfo=timezone.utc)
