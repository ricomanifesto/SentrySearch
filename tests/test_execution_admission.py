from __future__ import annotations

import asyncio
from unittest.mock import Mock

import httpx
import pytest

from src.api import main as api
from src.auth.supabase_auth import AuthenticatedUser


@pytest.fixture
def admission(monkeypatch):
    for name in (
        "SENTRYSEARCH_EXECUTION_MODE",
        "SENTRYRUNTIME_URL",
        "SENTRYRUNTIME_LOCAL_URL",
        "SENTRYRUNTIME_CA_FILE",
    ):
        monkeypatch.delenv(name, raising=False)
    user = AuthenticatedUser(user_id="owner", email="owner@example.com", metadata={})
    api.app.dependency_overrides[api.verify_jwt_token] = lambda: user
    reports = Mock()
    reports.get_report.return_value = {"id": "report-1", "user_id": "owner"}
    reports.create_pending_report.return_value = "report-1"
    reports.begin_report_evaluation.return_value = True
    reports.has_runtime_dispatch.return_value = True
    monkeypatch.setattr(api, "report_service", reports)
    monkeypatch.setattr(api, "run_report_generation", Mock())
    monkeypatch.setattr(api, "run_report_evaluation", Mock())
    try:
        yield reports
    finally:
        api.app.dependency_overrides.clear()


def request(method, path, **kwargs):
    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=api.app), base_url="http://test"
        ) as client:
            return await client.request(method, path, **kwargs)

    return asyncio.run(run())


@pytest.mark.parametrize("mode", [None, "paused", "unknown", "runtime"])
@pytest.mark.parametrize("path", ["/api/reports", "/api/reports/report-1/evaluation"])
def test_paused_or_invalid_admission_reserves_nothing(monkeypatch, admission, mode, path):
    if mode is not None:
        monkeypatch.setenv("SENTRYSEARCH_EXECUTION_MODE", mode)
    response = request("POST", path, json={"tool_name": "Example"})
    assert response.status_code == 503
    assert admission.mock_calls == []
    assert "runtime" not in response.text.lower()  # no configuration details


@pytest.mark.parametrize(
    "url",
    ["http://runtime.example", "https://secret@runtime.example", "https://runtime.example/path"],
)
def test_bad_remote_settings_do_not_fall_back(monkeypatch, admission, url):
    monkeypatch.setenv("SENTRYSEARCH_EXECUTION_MODE", "runtime")
    monkeypatch.setenv("SENTRYRUNTIME_URL", url)
    response = request("POST", "/api/reports", json={"tool_name": "Example"})
    assert response.status_code == 503
    assert admission.mock_calls == []
    assert url not in response.text


def test_runtime_admission_records_intent_without_network_or_inline_work(monkeypatch, admission):
    monkeypatch.setenv("SENTRYSEARCH_EXECUTION_MODE", "runtime")
    monkeypatch.setenv("SENTRYRUNTIME_URL", "https://runtime.example")
    monkeypatch.setattr(api, "run_report_generation", lambda *_: pytest.fail("inline generation"))
    response = request("POST", "/api/reports", json={"tool_name": "Example"})
    assert response.status_code == 200
    assert admission.create_pending_report.call_args.kwargs["runtime_dispatch"] is True
    assert len(admission.mock_calls) == 1


def test_runtime_mode_never_reserves_legacy_evaluation(monkeypatch, admission):
    monkeypatch.setenv("SENTRYSEARCH_EXECUTION_MODE", "runtime")
    monkeypatch.setenv("SENTRYRUNTIME_URL", "https://runtime.example")
    admission.has_runtime_dispatch.return_value = False
    response = request("POST", "/api/reports/report-1/evaluation")
    assert response.status_code == 409
    admission.begin_report_evaluation.assert_not_called()


def test_legacy_mode_cannot_override_durable_ownership(monkeypatch, admission):
    monkeypatch.setenv("SENTRYSEARCH_EXECUTION_MODE", "legacy")
    monkeypatch.setattr(api, "run_report_evaluation", lambda *_: pytest.fail("inline evaluation"))
    response = request("POST", "/api/reports/report-1/evaluation")
    assert response.status_code == 200
    admission.begin_report_evaluation.assert_called_once()


def test_pause_keeps_reads_available(monkeypatch, admission):
    monkeypatch.setenv("SENTRYSEARCH_EXECUTION_MODE", "paused")
    admission.list_reports.return_value = []
    admission.count_reports.return_value = 0
    response = request("GET", "/api/reports")
    assert response.status_code == 200
    admission.list_reports.assert_called_once()
