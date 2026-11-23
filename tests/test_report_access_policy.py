"""Offline guards for HTTP and report ownership policy boundaries."""

import asyncio
from contextlib import contextmanager
from types import SimpleNamespace
import threading
from unittest.mock import Mock
from typing import Any

import pytest
from fastapi import BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.dialects import postgresql

from src.api import main as api
from src.auth import supabase_auth
from src.auth.supabase_auth import AuthenticatedUser
from src.storage.report_service import ReportStorageService
from src.domain.report_access import ReportAccessScope, require_report_owner


@pytest.mark.parametrize("owner", [None, "", " "])
def test_report_owner_requires_an_explicit_identity_or_privileged_scope(owner):
    with pytest.raises(ValueError):
        require_report_owner(owner)


def test_trusted_system_access_is_explicit():
    assert require_report_owner(ReportAccessScope.ALL) is None


def test_cors_uses_explicit_frontend_origins():
    middleware = next(item for item in api.app.user_middleware if item.cls is CORSMiddleware)
    assert middleware.kwargs.get("allow_origin_regex") is None
    origins = middleware.kwargs["allow_origins"]
    assert isinstance(origins, list)
    assert "https://sentry-search.vercel.app" in origins
    assert "https://sentrysearch.ricomanifesto.com" in origins


def test_verified_auth_lookup_runs_outside_the_event_loop(monkeypatch):
    calling_thread = threading.get_ident()
    lookup_threads = []

    def get_user(_token):
        lookup_threads.append(threading.get_ident())
        return SimpleNamespace(
            user=SimpleNamespace(
                id="owner", email="owner@example.com", app_metadata={"role": "analyst"}
            )
        )

    monkeypatch.setattr(
        supabase_auth, "supabase", SimpleNamespace(auth=SimpleNamespace(get_user=get_user))
    )
    user = asyncio.run(supabase_auth.verify_jwt_token("Bearer test-token"))
    assert user.id == "owner"
    assert lookup_threads and lookup_threads[0] != calling_thread


def test_admin_scope_is_derived_from_verified_application_metadata(monkeypatch):
    response = SimpleNamespace(
        user=SimpleNamespace(
            id="admin", email="admin@example.com", app_metadata={"role": "admin"}, user_metadata={}
        )
    )
    monkeypatch.setattr(
        supabase_auth,
        "supabase",
        SimpleNamespace(auth=SimpleNamespace(get_user=lambda _: response)),
    )
    user = asyncio.run(supabase_auth.verify_jwt_token("Bearer test-token"))
    assert api.get_report_user_id(user) is None


@pytest.mark.parametrize("operation", ["get_report", "get_download_url", "delete_report"])
def test_report_id_operations_include_the_requested_owner_in_the_query(operation):
    filters = []
    locks = []

    class Query:
        def filter(self, *expressions):
            filters.extend(expressions)
            return self

        def with_for_update(self):
            locks.append(True)
            return self

        def first(self):
            return None

    @contextmanager
    def get_session():
        yield SimpleNamespace(query=lambda _: Query())

    service = ReportStorageService.__new__(ReportStorageService)
    service.db_manager = SimpleNamespace(get_session=get_session)
    getattr(service, operation)("report-id", owner_user_id="owner")
    compiled = [str(expr.compile(dialect=postgresql.dialect())) for expr in filters]
    assert any("reports.id =" in expr for expr in compiled)
    assert any("reports.user_id =" in expr for expr in compiled)
    assert any("owner" in expr.compile().params.values() for expr in filters)
    if operation == "delete_report":
        assert locks == [True]


@pytest.mark.parametrize(
    "operation",
    ["get_report", "append_report_disposition", "retry_report_evaluation", "delete_report"],
)
def test_http_report_id_reads_pass_the_verified_owner(monkeypatch, operation):
    reports = Mock()
    reports.get_report.return_value = None
    monkeypatch.setattr(api, "report_service", reports)
    monkeypatch.setattr(api, "require_execution_admission", lambda: "legacy")
    user = AuthenticatedUser("owner", "owner@example.com")
    kwargs: dict[str, Any] = {"report_id": "report-id", "user": user}
    if operation == "append_report_disposition":
        kwargs["request"] = api.AnalystDispositionCreate(disposition="rejected")
    if operation == "retry_report_evaluation":
        kwargs["background_tasks"] = BackgroundTasks()
    with pytest.raises(HTTPException) as error:
        asyncio.run(getattr(api, operation)(**kwargs))
    assert error.value.status_code == 404
    reports.get_report.assert_called_once_with(
        "report-id", include_content=False, owner_user_id="owner"
    )


def test_http_delete_passes_owner_into_the_mutating_operation(monkeypatch):
    reports = Mock()
    reports.get_report.return_value = {"user_id": "owner"}
    reports.delete_report.return_value = True
    monkeypatch.setattr(api, "report_service", reports)
    user = AuthenticatedUser("owner", "owner@example.com")
    asyncio.run(api.delete_report("report-id", user))
    reports.delete_report.assert_called_once_with("report-id", owner_user_id="owner")


def test_http_delete_returns_a_stable_error_when_cleanup_cannot_complete(monkeypatch):
    reports = Mock()
    reports.get_report.return_value = {"user_id": "owner"}
    reports.delete_report.side_effect = RuntimeError("synthetic cleanup interruption")
    monkeypatch.setattr(api, "report_service", reports)
    user = AuthenticatedUser("owner", "owner@example.com")
    with pytest.raises(HTTPException) as error:
        asyncio.run(api.delete_report("report-id", user))
    assert error.value.status_code == 500
    assert error.value.detail == "Failed to delete report"


def test_http_delete_runs_blocking_cleanup_outside_the_event_loop(monkeypatch):
    calling_thread = threading.get_ident()
    cleanup_threads = []
    reports = Mock()
    reports.get_report.return_value = {"user_id": "owner"}

    def delete(*_args, **_kwargs):
        cleanup_threads.append(threading.get_ident())
        return True

    reports.delete_report.side_effect = delete
    monkeypatch.setattr(api, "report_service", reports)
    asyncio.run(api.delete_report("report-id", AuthenticatedUser("owner", "owner@example.com")))
    assert cleanup_threads and cleanup_threads[0] != calling_thread
