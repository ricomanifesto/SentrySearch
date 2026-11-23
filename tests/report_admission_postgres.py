"""Synthetic admission proofs; require an explicit disposable Unix-socket cluster."""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import os
from pathlib import Path
import threading
import uuid

import pytest
from sqlalchemy import create_engine, event, func, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker

from src.domain.report_admission import ReportAdmissionLimitError
from src.storage import schema
from src.storage.database import DatabaseManager
from src.storage.models import Report, ReportCreationAdmission, ReportRuntimeDispatch
from src.storage.report_service import ReportStorageService


@pytest.fixture
def database():
    url = make_url(os.environ["SENTRYSEARCH_TEST_DATABASE_URL"])
    # Refuse TCP and default sockets. This suite creates/drops synthetic databases.
    socket = url.query.get("host", "")
    assert url.host is None and isinstance(socket, str) and Path(socket).is_dir()
    assert socket.startswith("/tmp/") and url.database == "postgres"
    name = "admission_test_" + uuid.uuid4().hex
    admin = create_engine(url, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    manager = DatabaseManager.__new__(DatabaseManager)
    manager.engine = create_engine(url.set(database=name), hide_parameters=True)
    manager.SessionLocal = sessionmaker(bind=manager.engine, autoflush=False)
    try:
        yield manager
    finally:
        manager.engine.dispose()
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))
        admin.dispose()


@pytest.fixture
def service(database):
    database.migrate_schema()
    service = ReportStorageService.__new__(ReportStorageService)
    service.db_manager = database
    return service


def test_concurrent_reservations_share_one_user_budget(service, database):
    ready = threading.Barrier(8)

    def create(_):
        ready.wait(timeout=10)
        try:
            service.create_pending_report(
                str(uuid.uuid4()), "Synthetic target", "owner", runtime_dispatch=True
            )
            return True
        except ReportAdmissionLimitError:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        admitted = list(pool.map(create, range(8)))
    assert sum(admitted) == 2
    with database.get_session() as session:
        assert session.query(Report).count() == 2
        assert session.query(ReportRuntimeDispatch).count() == 2
        row = session.get(ReportCreationAdmission, "owner")
        assert len(row.request_times) == 2
    # A different owner has an independent budget.
    service.create_pending_report(str(uuid.uuid4()), "Synthetic target", "second-owner")


def test_rolling_budget_is_independent_of_retained_report_rows(service, database):
    for _ in range(6):
        report_id = service.create_pending_report(str(uuid.uuid4()), "Synthetic target", "owner")
        with database.get_session() as session:
            # Synthetic completed fixture; no generation or provider calls.
            session.query(Report).filter(Report.id == report_id).update({"status": "completed"})
    with database.get_session() as session:
        session.query(Report).delete()
        assert len(session.get(ReportCreationAdmission, "owner").request_times) == 6
    with pytest.raises(ReportAdmissionLimitError) as error:
        service.create_pending_report(str(uuid.uuid4()), "Synthetic target", "owner")
    assert 1 <= error.value.retry_after <= 3600
    with database.get_session() as session:
        assert session.query(Report).count() == 0
        assert len(session.get(ReportCreationAdmission, "owner").request_times) == 6


def test_failed_dispatch_write_rolls_back_the_admission(service, database):
    def interrupt(*_):
        raise RuntimeError("synthetic dispatch interruption")

    event.listen(ReportRuntimeDispatch, "before_insert", interrupt)
    try:
        with pytest.raises(RuntimeError, match="synthetic dispatch interruption"):
            service.create_pending_report(
                str(uuid.uuid4()), "Synthetic target", "owner", runtime_dispatch=True
            )
    finally:
        event.remove(ReportRuntimeDispatch, "before_insert", interrupt)
    with database.get_session() as session:
        assert session.query(Report).count() == 0
        assert session.query(ReportRuntimeDispatch).count() == 0
        assert session.get(ReportCreationAdmission, "owner") is None


def test_expired_history_resets_and_cleanup_is_bounded_and_skips_locks(service, database):
    with database.get_session() as session:
        now = session.scalar(select(func.clock_timestamp()))
        for index in range(201):
            session.add(
                ReportCreationAdmission(
                    user_id=f"expired-{index}",
                    request_times=[(now - timedelta(hours=2)).timestamp()],
                    updated_at=now - timedelta(hours=2),
                )
            )
    with database.get_session() as held:
        held.query(ReportCreationAdmission).filter_by(user_id="expired-0").with_for_update().one()
        service.create_pending_report(str(uuid.uuid4()), "Synthetic target", "expired-1")
        with database.get_session() as session:
            assert session.query(ReportCreationAdmission).count() == 101
            assert session.get(ReportCreationAdmission, "expired-0") is not None
            assert len(session.get(ReportCreationAdmission, "expired-1").request_times) == 1


def test_revision_three_backfills_recent_budget_and_checks_readiness(database):
    with database.engine.begin() as conn:
        conn.execute(
            text(
                "CREATE TABLE sentrysearch_schema_migrations (version INTEGER PRIMARY KEY, checksum VARCHAR(64) NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())"
            )
        )
        for revision in schema.REVISIONS[:2]:
            for statement in revision.statements():
                conn.execute(text(statement))
            conn.execute(
                text(
                    "INSERT INTO sentrysearch_schema_migrations(version, checksum) VALUES (:version, :checksum)"
                ),
                {"version": revision.version, "checksum": revision.checksum},
            )
        for _ in range(8):
            conn.execute(
                text(
                    "INSERT INTO reports (id, tool_name, user_id, status, created_at) VALUES (:id, 'Synthetic target', 'owner', 'completed', NOW() - INTERVAL '10 minutes')"
                ),
                {"id": uuid.uuid4()},
            )
        conn.execute(
            text(
                "INSERT INTO reports (id, tool_name, user_id, status, created_at) VALUES (:id, 'Synthetic old target', 'older-owner', 'completed', NOW() - INTERVAL '2 hours')"
            ),
            {"id": uuid.uuid4()},
        )
    assert database.check_schema() is False
    database.migrate_schema()
    database.require_schema()
    with database.get_session() as session:
        assert len(session.get(ReportCreationAdmission, "owner").request_times) == 6
        assert session.get(ReportCreationAdmission, "older-owner") is None
    database.migrate_schema()  # Repeated release does not rerun the backfill.
