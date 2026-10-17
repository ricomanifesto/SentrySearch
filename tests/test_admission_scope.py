"""An explicit runtime admission scope over legacy or paused admission (AWS-08c).

The scope admits named identities' new reports to the runtime while every other
identity keeps the explicit mode. Without a scope nothing changes; a scope that
is not exactly the recorded one fails closed for everyone.
"""

from __future__ import annotations

import hashlib
from unittest.mock import Mock

import pytest

from src.api import main as api
from src.auth.supabase_auth import AuthenticatedUser
from src.execution import config
from tests.test_execution_admission import admission, request  # noqa: F401

SCOPED = "11111111-1111-4111-8111-111111111111"
OTHER = "22222222-2222-4222-8222-222222222222"


def scope_env(monkeypatch, *identities: str, mode: str | None = "legacy", digest=None) -> None:
    for name in (config.SCOPE_ENV, config.SCOPE_SHA256_ENV, "SENTRYSEARCH_EXECUTION_MODE"):
        monkeypatch.delenv(name, raising=False)
    if mode is not None:
        monkeypatch.setenv("SENTRYSEARCH_EXECUTION_MODE", mode)
    if identities:
        listed = ",".join(identities)
        monkeypatch.setenv(config.SCOPE_ENV, listed)
        monkeypatch.setenv(config.SCOPE_SHA256_ENV,
                           digest or hashlib.sha256(listed.encode()).hexdigest())  # fmt: skip
        monkeypatch.setenv("SENTRYRUNTIME_URL", "https://runtime.example")


def as_user(identity: str) -> None:
    user = AuthenticatedUser(user_id=identity, email="user@example.com", metadata={})
    api.app.dependency_overrides[api.verify_jwt_token] = lambda: user


def test_without_a_scope_explicit_legacy_admission_is_unchanged(monkeypatch, admission):
    scope_env(monkeypatch)
    as_user(SCOPED)
    response = request("POST", "/api/reports", json={"tool_name": "Example"})
    assert response.status_code == 200
    assert "runtime_dispatch" not in admission.create_pending_report.call_args.kwargs
    generation = api.run_report_generation
    assert isinstance(generation, Mock)
    generation.assert_called_once()  # the explicit legacy background job


def test_a_scoped_identity_is_admitted_to_the_runtime_and_others_keep_legacy(
    monkeypatch, admission
):
    scope_env(monkeypatch, SCOPED)
    monkeypatch.setattr(api, "run_report_generation", lambda *_: pytest.fail("inline generation"))
    as_user(SCOPED)
    response = request("POST", "/api/reports", json={"tool_name": "Example"})
    assert response.status_code == 200
    assert admission.create_pending_report.call_args.kwargs["runtime_dispatch"] is True
    called = []
    monkeypatch.setattr(api, "run_report_generation", lambda *args: called.append(args))
    as_user(OTHER)
    response = request("POST", "/api/reports", json={"tool_name": "Example"})
    assert response.status_code == 200
    assert "runtime_dispatch" not in admission.create_pending_report.call_args.kwargs
    assert called, "the other identity keeps legacy generation"


def test_a_paused_base_admits_only_the_scope(monkeypatch, admission):
    scope_env(monkeypatch, SCOPED, mode="paused")
    as_user(SCOPED)
    assert request("POST", "/api/reports", json={"tool_name": "Example"}).status_code == 200
    as_user(OTHER)
    assert request("POST", "/api/reports", json={"tool_name": "Example"}).status_code == 503


@pytest.mark.parametrize("change", [
    {"digest": "0" * 64},
    {"identities": (OTHER, SCOPED)[::-1] + ("not-a-uuid",)},
    {"mode": None},
    {"mode": "runtime"},
])  # fmt: skip
def test_a_scope_that_is_not_exactly_the_recorded_one_fails_closed(monkeypatch, admission, change):
    identities = change.pop("identities", (SCOPED,))
    scope_env(monkeypatch, *identities, **change)
    for identity in (SCOPED, OTHER):
        as_user(identity)
        response = request("POST", "/api/reports", json={"tool_name": "Example"})
        assert response.status_code == 503
    assert admission.create_pending_report.call_count == 0


def test_a_scope_out_of_canonical_order_or_without_an_endpoint_fails_closed(monkeypatch):
    unordered = f"{OTHER},{SCOPED}"
    env = {"SENTRYSEARCH_EXECUTION_MODE": "legacy", config.SCOPE_ENV: unordered,
           config.SCOPE_SHA256_ENV: hashlib.sha256(unordered.encode()).hexdigest(),
           "SENTRYRUNTIME_URL": "https://runtime.example"}  # fmt: skip
    with pytest.raises(ValueError, match="canonical"):
        config.execution_mode_for(SCOPED, env)
    ordered = config.canonical_scope([OTHER, SCOPED])
    env.update({config.SCOPE_ENV: ordered,
                config.SCOPE_SHA256_ENV: hashlib.sha256(ordered.encode()).hexdigest()})  # fmt: skip
    assert config.execution_mode_for(SCOPED, env) == "runtime"
    del env["SENTRYRUNTIME_URL"]
    with pytest.raises(ValueError):
        config.execution_mode_for(SCOPED, env)


def test_rollback_removes_the_scope_and_runtime_owned_work_stays_with_the_runtime(
    monkeypatch, admission
):
    scope_env(monkeypatch, SCOPED)
    as_user(SCOPED)
    assert request("POST", "/api/reports", json={"tool_name": "Example"}).status_code == 200
    # Rollback: the scope settings are removed; the explicit legacy mode remains.
    scope_env(monkeypatch)
    monkeypatch.delenv("SENTRYRUNTIME_URL", raising=False)
    monkeypatch.setattr(api, "run_report_evaluation", lambda *_: pytest.fail("inline evaluation"))
    admission.has_runtime_dispatch.return_value = True
    admission.get_report.return_value = {"id": "report-1", "user_id": SCOPED}
    response = request("POST", "/api/reports/report-1/evaluation")
    assert response.status_code == 200, "a runtime-owned report keeps queueing to the worker"
    admission.begin_report_evaluation.assert_called_once()
    called = []
    monkeypatch.setattr(api, "run_report_generation", lambda *args: called.append(args))
    assert request("POST", "/api/reports", json={"tool_name": "Example"}).status_code == 200
    assert called, "new work from the formerly scoped identity is legacy again"


def test_evaluation_retries_follow_the_explicit_mode_not_the_scope(monkeypatch, admission):
    scope_env(monkeypatch, SCOPED)
    as_user(SCOPED)
    admission.has_runtime_dispatch.return_value = False
    admission.get_report.return_value = {"id": "report-1", "user_id": SCOPED}
    response = request("POST", "/api/reports/report-1/evaluation")
    assert response.status_code == 200, "a legacy report of a scoped identity evaluates as legacy"
