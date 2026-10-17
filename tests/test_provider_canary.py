"""Real-provider canary caps (AWS-08b), against fixture transports: no provider is called.

The worker's model client and source fetcher send through ``CappedTransport``
when a canary manifest is configured. A request outside the manifest is refused
before it is sent and is never retried into one.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json

import httpx
import pytest

from src.core import source_snapshot
from src.core.openrouter_client import ModelClient, ModelRequestRejectedError
from src.execution import provider_canary


def manifest(**changes) -> dict:
    document = {
        "schema": provider_canary.SCHEMA, "canary_id": "aws-08b-1",
        "not_after": (datetime.now(UTC) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "budget_usd": 25,
        "providers": {"openrouter": {"hosts": ["openrouter.ai"], "max_requests": 2},
                      "sources": {"hosts": ["example.org"], "max_requests": 1}},
        "stop": {"max_consecutive_failures": 2},
    }  # fmt: skip
    document.update(changes)
    return document


@pytest.fixture(autouse=True)
def fresh_caps(monkeypatch):
    import socket

    def refused(*_args, **_kwargs):
        raise AssertionError("no connection or lookup may leave this test")

    monkeypatch.setattr(socket, "socket", refused)
    monkeypatch.setattr(socket, "create_connection", refused)
    provider_canary.reset_for_tests()
    yield
    provider_canary.reset_for_tests()


class Fixture(httpx.BaseTransport):
    def __init__(self, status: int = 200) -> None:
        self.sent: list[str] = []
        self.status = status

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.sent.append(str(request.url))
        return httpx.Response(self.status, json={"ok": True}, request=request)


def test_requests_inside_the_manifest_go_through_and_the_cap_refuses_the_next():
    caps = provider_canary.load(manifest())
    inner = Fixture()
    transport = caps.transport("openrouter", inner)
    with httpx.Client(transport=transport, base_url="https://openrouter.ai") as client:
        assert client.get("/api/v1/x").status_code == 200
        assert client.get("/api/v1/y").status_code == 200
        with pytest.raises(provider_canary.CanaryCapReached, match="request cap"):
            client.get("/api/v1/z")
    assert len(inner.sent) == 2, "the refused request was never sent"


def test_a_host_the_manifest_does_not_name_is_refused_unsent():
    caps = provider_canary.load(manifest())
    inner = Fixture()
    with httpx.Client(transport=caps.transport("openrouter", inner)) as client:
        with pytest.raises(provider_canary.CanaryCapReached, match="host"):
            client.get("https://api.other-provider.example/v1")
    assert inner.sent == []


def test_the_canary_stops_after_its_deadline_and_after_consecutive_failures():
    caps = provider_canary.load(manifest())
    caps.now = lambda: datetime.now(UTC) + timedelta(hours=2)
    with httpx.Client(transport=caps.transport("openrouter", Fixture())) as client:
        with pytest.raises(provider_canary.CanaryCapReached, match="not_after"):
            client.get("https://openrouter.ai/a")
    caps = provider_canary.load(manifest(providers={"openrouter": {"hosts": ["openrouter.ai"],
                                                                   "max_requests": 9}}))  # fmt: skip
    failing = Fixture(status=503)
    with httpx.Client(transport=caps.transport("openrouter", failing)) as client:
        for _ in range(2):
            client.get("https://openrouter.ai/a")
        with pytest.raises(provider_canary.CanaryCapReached, match="consecutive failure"):
            client.get("https://openrouter.ai/a")
    assert len(failing.sent) == 2


def test_the_model_client_turns_a_cap_into_a_final_rejection(monkeypatch):
    monkeypatch.setenv(provider_canary.ENV, json.dumps(manifest(
        providers={"openrouter": {"hosts": ["openrouter.ai"], "max_requests": 1}})))  # fmt: skip
    caps = provider_canary.configured()
    assert caps is not None
    inner = Fixture()
    client = ModelClient(api_key="fixture-key", base_url="https://openrouter.ai/api/v1",
                         transport=caps.transport("openrouter", inner))  # fmt: skip
    client._post({"model": "x", "messages": []})
    with pytest.raises(ModelRequestRejectedError, match="canary cap"):
        client._post({"model": "x", "messages": []})
    assert len(inner.sent) == 1


def test_a_configured_canary_wraps_the_clients_own_transports(monkeypatch):
    monkeypatch.setenv(provider_canary.ENV, json.dumps(manifest()))
    client = ModelClient(api_key="fixture-key")
    assert isinstance(client.transport, provider_canary.CappedTransport)
    assert client.transport.provider == "openrouter"
    # A public address without a lookup; the capped transport refuses before any connection.
    monkeypatch.setattr(source_snapshot.socket, "getaddrinfo",
                        lambda *_a, **_k: [(2, 1, 6, "", ("93.184.216.34", 443))])  # fmt: skip
    captured = source_snapshot.capture_source_snapshot({"url": "https://not-named.example/a"})
    assert captured["status"] == "unavailable", "a source the canary does not name is not fetched"


def test_outside_a_canary_nothing_is_wrapped(monkeypatch):
    monkeypatch.delenv(provider_canary.ENV, raising=False)
    assert ModelClient(api_key="fixture-key").transport is None


@pytest.mark.parametrize("change", [
    {"schema": "other"}, {"budget_usd": 0}, {"budget_usd": 5000},
    {"providers": {"openrouter": {"hosts": ["*.ai"], "max_requests": 1}}},
    {"providers": {"anthropic": {"hosts": ["api.example"], "max_requests": 1}}},
    {"providers": {"openrouter": {"hosts": ["openrouter.ai"], "max_requests": 0}}},
    {"stop": {"max_consecutive_failures": 0}}, {"not_after": "tomorrow"},
])  # fmt: skip
def test_a_manifest_outside_its_rules_is_refused(change):
    with pytest.raises(ValueError):
        provider_canary.load(manifest(**change))


def test_closing_one_request_client_never_closes_the_shared_pool():
    """A model client opens an httpx.Client per request over one capped transport."""

    class Pool(httpx.BaseTransport):
        closed = 0

        def handle_request(self, request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={}, request=request)

        def close(self) -> None:
            Pool.closed += 1

    caps = provider_canary.load(manifest(providers={"openrouter": {"hosts": ["openrouter.ai"],
                                                                   "max_requests": 9}}))  # fmt: skip
    transport = caps.transport("openrouter", Pool())
    for _ in range(3):
        with httpx.Client(transport=transport) as client:
            client.get("https://openrouter.ai/a")
    assert Pool.closed == 0, "a request's client exit closed the pool other requests share"
