"""Offline guards for report creation's durable per-user admission policy."""

import asyncio
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import Mock
import threading

from fastapi import BackgroundTasks, HTTPException
import pytest

from src.api import main as api
from src.api.contracts import ReportCreate
from src.auth.supabase_auth import AuthenticatedUser
from src.domain.report_admission import ReportAdmissionLimitError
from src.storage.models import ReportCreationAdmission
from src.storage.report_service import ReportStorageService


def test_creation_budget_lives_independently_of_report_deletion():
    table = ReportCreationAdmission.__table__
    assert list(table.primary_key.columns.keys()) == ["user_id"]
    assert not list(table.foreign_keys)


def test_report_creation_passes_a_rate_limit_as_429_and_schedules_nothing(monkeypatch):
    reports = Mock()
    reports.create_pending_report.side_effect = ReportAdmissionLimitError(retry_after=60)
    monkeypatch.setattr(api, "report_service", reports)
    monkeypatch.setattr(api, "require_execution_admission", lambda: "legacy")
    tasks = BackgroundTasks()
    with pytest.raises(HTTPException) as error:
        asyncio.run(
            api.create_report(
                ReportCreate(tool_name="Example"),
                tasks,
                AuthenticatedUser("owner", "owner@example.com"),
            )
        )
    assert error.value.status_code == 429
    assert error.value.headers == {"Retry-After": "60"}
    assert tasks.tasks == []


def test_creation_admission_precedes_all_report_or_dispatch_writes(monkeypatch):
    writes = []
    sessions = []

    @contextmanager
    def get_session():
        session = SimpleNamespace(add=writes.append)
        sessions.append(session)
        yield session

    service = ReportStorageService.__new__(ReportStorageService)
    service.db_manager = SimpleNamespace(get_session=get_session)

    def admission(session, user_id):
        assert session is sessions[0]
        assert user_id == "owner"
        raise ReportAdmissionLimitError(retry_after=60)

    monkeypatch.setattr(service, "_reserve_report_creation", admission, raising=False)
    with pytest.raises(ReportAdmissionLimitError):
        service.create_pending_report(
            "report-id", "Example", user_id="owner", runtime_dispatch=True
        )
    assert writes == []


def test_http_creation_runs_blocking_reservation_outside_the_event_loop(monkeypatch):
    calling_thread = threading.get_ident()
    reservation_threads = []
    reports = Mock()

    def reserve(*_args, **_kwargs):
        reservation_threads.append(threading.get_ident())
        return "report-id"

    reports.create_pending_report.side_effect = reserve
    monkeypatch.setattr(api, "report_service", reports)
    monkeypatch.setattr(api, "require_execution_admission", lambda: "runtime")
    asyncio.run(
        api.create_report(
            ReportCreate(tool_name="Example"),
            BackgroundTasks(),
            AuthenticatedUser("owner", "owner@example.com"),
        )
    )
    assert reservation_threads and reservation_threads[0] != calling_thread
