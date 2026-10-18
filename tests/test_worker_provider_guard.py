"""The worker's provider policy, against fixture environments: no provider is called.

A deployed worker reaches no provider (the disabled scaffold) or reaches one only
through a canary manifest. Every other combination refuses the worker at startup
with ``provider_misconfigured``. The policy is installed by the worker entrypoint;
the API, legacy-generation and report-evaluation processes keep their contract.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import io
import json
import socket
import threading

import httpx
import pytest

from dev import check_worker_readiness, run_runtime_worker
from release.readiness import WorkerReceipt, parse_line
from src.core import openrouter_client
from src.core.openrouter_client import ModelClient, create_model_client
from src.execution import provider_canary
from src.execution.readiness_receipts import ERROR_CODES, ReadinessReceipts
from src.execution.supervisor import WorkerSettings, WorkerStatus

RELEASE_ID = "0b9f7c1e-4d2a-4f6b-9a3e-2c1d0e9f8a7b"


@pytest.fixture(autouse=True)
def no_network_and_fresh_policy(monkeypatch):
    def refused(*_args, **_kwargs):
        raise AssertionError("no connection or lookup may leave this test")

    for name in ("socket", "create_connection", "getaddrinfo"):
        monkeypatch.setattr(socket, name, refused)
    for name in (provider_canary.ENV, provider_canary.KEY_ENV, provider_canary.BASE_URL_ENV):
        monkeypatch.delenv(name, raising=False)
    provider_canary.reset_for_tests()
    yield
    provider_canary.reset_for_tests()


def manifest(**changes) -> str:
    document = {
        "schema": provider_canary.SCHEMA, "canary_id": "aws-08b-1",
        "not_after": (datetime.now(UTC) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "budget_usd": 25,
        "providers": {"openrouter": {"hosts": ["openrouter.ai"], "max_requests": 2}},
        "stop": {"max_consecutive_failures": 2},
    }  # fmt: skip
    document.update(changes)
    return json.dumps(document)


DISABLED = {provider_canary.KEY_ENV: provider_canary.SENTINEL_KEY,
            provider_canary.BASE_URL_ENV: provider_canary.DISCARD_BASE_URL}  # fmt: skip
LIVE_KEY = "sk-or-fixture-not-a-real-key"
EXPIRED = (datetime.now(UTC) - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.mark.parametrize("env, mode", [
    (DISABLED, "disabled"),
    ({provider_canary.BASE_URL_ENV: provider_canary.DISCARD_BASE_URL}, "disabled"),  # no key
    ({provider_canary.KEY_ENV: LIVE_KEY, provider_canary.ENV: manifest()}, "canary"),
    ({provider_canary.KEY_ENV: LIVE_KEY, provider_canary.BASE_URL_ENV: "https://openrouter.ai/api/v1",
      provider_canary.ENV: manifest()}, "canary"),
])  # fmt: skip
def test_the_worker_runs_disabled_or_under_a_valid_canary(env, mode):
    policy = provider_canary.worker_policy(env)
    assert policy.mode == mode
    assert (policy.caps is not None) == (mode == "canary")


@pytest.mark.parametrize("env, reason", [
    # Missing canary: a live key with no manifest.
    ({provider_canary.KEY_ENV: LIVE_KEY}, "a provider key without a canary manifest"),
    ({provider_canary.KEY_ENV: LIVE_KEY, provider_canary.BASE_URL_ENV: "https://openrouter.ai/api/v1"},
     "a provider key without a canary manifest"),
    # Malformed canary.
    ({provider_canary.KEY_ENV: LIVE_KEY, provider_canary.ENV: "{not json"}, "not usable"),
    ({provider_canary.KEY_ENV: LIVE_KEY, provider_canary.ENV: manifest(schema="other")}, "not usable"),
    ({provider_canary.KEY_ENV: LIVE_KEY, provider_canary.ENV: "[]"}, "not usable"),
    ({provider_canary.KEY_ENV: LIVE_KEY, provider_canary.ENV: manifest(providers=[])}, "not usable"),
    # Expired canary.
    ({provider_canary.KEY_ENV: LIVE_KEY, provider_canary.ENV: manifest(not_after=EXPIRED)}, "expired"),
    # A canary that cannot reach its model host: it would report ready and refuse everything.
    ({provider_canary.KEY_ENV: LIVE_KEY, provider_canary.ENV: manifest(
        providers={"sources": {"hosts": ["example.org"], "max_requests": 2}})},
     "does not name the provider address's host"),
    ({provider_canary.KEY_ENV: LIVE_KEY, provider_canary.BASE_URL_ENV: "https://other.example/api/v1",
      provider_canary.ENV: manifest()}, "does not name the provider address's host"),
    ({provider_canary.KEY_ENV: LIVE_KEY, provider_canary.BASE_URL_ENV: provider_canary.DISCARD_BASE_URL,
      provider_canary.ENV: manifest()}, "does not name the provider address's host"),
    # A manifest without a usable key.
    ({provider_canary.ENV: manifest()}, "a canary needs a provider key"),
    ({**DISABLED, provider_canary.ENV: manifest()}, "a canary needs a provider key"),
    # The sentinel key, or none, with a live provider address.
    ({provider_canary.KEY_ENV: provider_canary.SENTINEL_KEY,
      provider_canary.BASE_URL_ENV: "https://openrouter.ai/api/v1"}, "a placeholder key with a provider address"),
    ({provider_canary.KEY_ENV: provider_canary.SENTINEL_KEY}, "a placeholder key with a provider address"),
    ({}, "a placeholder key with a provider address"),
])  # fmt: skip
def test_every_other_combination_refuses_the_worker(env, reason):
    with pytest.raises(provider_canary.ProviderMisconfigured, match=reason) as refused:
        provider_canary.worker_policy(env)
    assert LIVE_KEY not in str(refused.value)


def test_without_an_installed_policy_the_factory_keeps_its_contract(monkeypatch):
    # Compatibility: the legacy API process with a live key and no canary.
    monkeypatch.setenv(provider_canary.KEY_ENV, LIVE_KEY)
    assert provider_canary.installed_policy() is None
    client = create_model_client()
    assert isinstance(client, ModelClient)
    assert (
        client.transport is None
        and client.base_url == openrouter_client.DEFAULT_OPENROUTER_BASE_URL
    )


def test_report_evaluation_retries_keep_the_unguarded_client(monkeypatch):
    # Compatibility: the API's report evaluation, run twice as a retry would.
    from src.core import report_evaluator

    monkeypatch.setenv(provider_canary.KEY_ENV, LIVE_KEY)
    seen: list[ModelClient] = []

    class Validator:
        def __init__(self, client):
            seen.append(client)

        def validate_complete_profile(self, *_args, **_kwargs):
            return {"overall_score": 1.0, "recommendations": []}

    monkeypatch.setattr(report_evaluator, "ParallelSectionValidator", Validator)
    monkeypatch.setattr(report_evaluator, "validate_quality_recommendations", lambda *a: None)
    for _attempt in range(2):
        report_evaluator.evaluate_saved_report({"webSearchSources": {"primarySources": []}})
    assert len(seen) == 2 and all(client.transport is None for client in seen)
    assert provider_canary.installed_policy() is None


def test_a_disabled_worker_builds_clients_that_refuse_every_request_unsent(monkeypatch):
    for name, value in DISABLED.items():
        monkeypatch.setenv(name, value)
    assert provider_canary.install_worker_policy().mode == "disabled"
    client = create_model_client()
    assert isinstance(client.transport, provider_canary.RefusedTransport)
    with pytest.raises(provider_canary.CanaryCapReached, match="disabled"):
        httpx.Client(transport=client.transport).get("http://127.0.0.1:9/api/v1/chat")


def test_a_disabled_worker_refuses_source_fetches_too(monkeypatch):
    # Outside the worker no policy is installed and sources keep the default transport.
    assert provider_canary.transport_for("sources") is None
    provider_canary.install_worker_policy(DISABLED)
    transport = provider_canary.transport_for("sources")
    assert isinstance(transport, provider_canary.RefusedTransport)
    with pytest.raises(provider_canary.CanaryCapReached):
        httpx.Client(transport=transport).get("https://example.org/")


def test_a_canary_worker_builds_every_client_on_the_one_set_of_caps(monkeypatch):
    monkeypatch.setenv(provider_canary.KEY_ENV, LIVE_KEY)
    monkeypatch.setenv(provider_canary.ENV, manifest())
    policy = provider_canary.install_worker_policy()
    first, second = create_model_client(), create_model_client()
    for client in (first, second):
        assert isinstance(client.transport, provider_canary.CappedTransport)
        assert client.transport.caps is policy.caps
    # Source fetches count against the same caps as model requests.
    assert provider_canary.configured() is policy.caps


def test_the_entrypoint_refuses_before_the_supervisor_and_reports_why(monkeypatch):
    monkeypatch.setenv(provider_canary.KEY_ENV, LIVE_KEY)  # a live key without a canary
    monkeypatch.setenv("SENTRYSEARCH_RELEASE_ID", RELEASE_ID)
    monkeypatch.setattr("sys.argv", ["run_runtime_worker"])
    monkeypatch.setattr(run_runtime_worker, "load_dotenv", lambda: None)
    sink = io.StringIO()
    monkeypatch.setattr(run_runtime_worker, "DescriptorSink", lambda _fd: sink)

    def no_supervisor(*_args, **_kwargs):
        raise AssertionError("the supervisor must not start")

    monkeypatch.setattr(run_runtime_worker, "WorkerSupervisor", no_supervisor)
    assert run_runtime_worker.main() == 1
    receipts = parsed_receipts(sink.getvalue())
    assert {receipt.error_code for receipt in receipts} == {"provider_misconfigured"}
    assert not any(receipt.ready for receipt in receipts)
    assert LIVE_KEY not in sink.getvalue()


class Recorder:
    started: dict = {}

    def __init__(self, settings, target, *, receipts=None):
        Recorder.started = {"target": target, "receipts": receipts}

    def run(self):
        return 0


def entrypoint(monkeypatch, env: dict[str, str], release_id: str | None) -> int:
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    if release_id is None:
        monkeypatch.delenv("SENTRYSEARCH_RELEASE_ID", raising=False)
    else:
        monkeypatch.setenv("SENTRYSEARCH_RELEASE_ID", release_id)
    monkeypatch.setattr(run_runtime_worker, "load_dotenv", lambda: None)
    monkeypatch.setattr(run_runtime_worker, "DescriptorSink", lambda _fd: io.StringIO())
    monkeypatch.setattr(run_runtime_worker, "WorkerSupervisor", Recorder)
    monkeypatch.setattr("sys.argv", ["run_runtime_worker"])
    Recorder.started = {}
    return run_runtime_worker.main()


def test_without_a_release_identity_a_key_without_a_canary_is_still_refused(monkeypatch):
    # A local run: no receipts, but the same provider policy as a release's worker.
    assert entrypoint(monkeypatch, {provider_canary.KEY_ENV: LIVE_KEY}, None) == 1
    assert Recorder.started == {}, "the supervisor must not start"
    assert provider_canary.installed_policy() is None


@pytest.mark.parametrize("env", [
    DISABLED,
    {provider_canary.KEY_ENV: "stand-in-key", provider_canary.ENV: manifest()},
], ids=["disabled", "stand-in-canary"])  # fmt: skip
def test_without_a_release_identity_the_worker_still_runs_behind_the_policy(monkeypatch, env):
    assert entrypoint(monkeypatch, env, None) == 0
    assert Recorder.started == {"target": run_runtime_worker.run_guarded_worker_loop,
                                "receipts": None}  # fmt: skip


def test_a_release_worker_runs_behind_the_policy(monkeypatch):
    for name, value in DISABLED.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("SENTRYSEARCH_RELEASE_ID", RELEASE_ID)
    monkeypatch.setattr(run_runtime_worker, "load_dotenv", lambda: None)
    monkeypatch.setattr(run_runtime_worker, "DescriptorSink", lambda _fd: io.StringIO())
    monkeypatch.setattr(run_runtime_worker, "WorkerSupervisor", Recorder)
    monkeypatch.setattr("sys.argv", ["run_runtime_worker"])
    assert run_runtime_worker.main() == 0
    assert Recorder.started["target"] is run_runtime_worker.run_guarded_worker_loop
    assert isinstance(Recorder.started["receipts"], ReadinessReceipts)


def test_the_worker_loop_installs_the_policy_before_any_client_exists(monkeypatch):
    events: list[dict] = []
    calls: list[str] = []
    monkeypatch.setattr(run_runtime_worker, "run_worker_loop",
                        lambda *_args: calls.append("loop") or 0)  # fmt: skip
    # Misconfigured: the loop and its jobs never run.
    monkeypatch.setenv(provider_canary.KEY_ENV, LIVE_KEY)
    settings = WorkerSettings(once=True)
    assert (
        run_runtime_worker.run_guarded_worker_loop(settings, threading.Event(), events.append) == 1
    )
    assert events == [{"event": "error", "code": "provider_misconfigured"}] and calls == []
    assert provider_canary.installed_policy() is None
    # Disabled scaffold: the policy is installed, then the loop runs.
    for name, value in DISABLED.items():
        monkeypatch.setenv(name, value)
    assert (
        run_runtime_worker.run_guarded_worker_loop(settings, threading.Event(), events.append) == 0
    )
    assert calls == ["loop"]
    policy = provider_canary.installed_policy()
    assert policy is not None and policy.mode == "disabled"


def parsed_receipts(text: str) -> list[WorkerReceipt]:
    """Every line a receipt the controller accepts."""
    parsed = [parse_line(line) for line in text.splitlines()]
    assert parsed and all(receipt is not None for receipt in parsed)
    return [receipt for receipt in parsed if receipt is not None]


def test_provider_misconfigured_is_a_readiness_error_everywhere():
    assert "provider_misconfigured" in ERROR_CODES
    status = WorkerStatus(WorkerSettings())
    status.set_alive(True)
    status.observe({"event": "phase", "phase": "idle"})
    status.observe({"event": "error", "code": "provider_misconfigured"})
    snapshot = status.snapshot()
    assert snapshot["error_code"] == "provider_misconfigured" and not snapshot["ready"]
    # The readiness probe reads it as a valid, unready worker.
    body = json.dumps({**snapshot, "backlog": None}).encode()
    assert check_worker_readiness._ready(body) is False
    # The controller's receipt parser accepts the code and never counts the worker ready.
    sink = io.StringIO()
    receipts = ReadinessReceipts(RELEASE_ID, sink)
    receipts.observe(snapshot)
    receipts.close({**snapshot, "alive": False, "phase": "stopped"}, timeout=1.0)
    parsed = parsed_receipts(sink.getvalue())
    assert {receipt.error_code for receipt in parsed} == {"provider_misconfigured"}


@pytest.mark.parametrize("module", ["tests.release_canary_stack", "tests.service_images"])
def test_the_local_stacks_run_their_worker_under_a_stand_in_canary(module):
    import importlib

    from tests.provider_stand_in import stand_in_canary

    stack = importlib.import_module(module)
    policy = provider_canary.worker_policy({
        provider_canary.KEY_ENV: "stand-in-key",
        provider_canary.BASE_URL_ENV: f"http://{stack.PROVIDER_HOST}:9000/api/v1",
        provider_canary.ENV: stand_in_canary(stack.PROVIDER_HOST, datetime.now(UTC)),
    })  # fmt: skip
    assert policy.mode == "canary" and policy.caps is not None
    assert set(policy.caps.providers) == {"openrouter"}
    assert policy.caps.providers["openrouter"].hosts == frozenset({stack.PROVIDER_HOST})
