import json

import httpx
import pytest

from src.core.opencode_client import (
    DEFAULT_MODEL,
    ModelClient,
    ModelClientError,
    ModelRateLimitError,
    parse_model_selection,
    resolve_model_name,
)


def test_default_model_uses_free_openrouter_agentic_model(monkeypatch):
    monkeypatch.delenv("SENTRYSEARCH_MODEL", raising=False)

    assert DEFAULT_MODEL == "openrouter/nex-agi/nex-n2-pro:free"
    assert resolve_model_name() == "openrouter/nex-agi/nex-n2-pro:free"


def test_model_selection_requires_provider_model():
    with pytest.raises(ValueError):
        parse_model_selection("claude-sonnet-4-5-20250929")


def test_model_selection_allows_openrouter_nested_model_id():
    model = parse_model_selection("openrouter/nex-agi/nex-n2-pro:free")

    assert model.provider_id == "openrouter"
    assert model.model_id == "nex-agi/nex-n2-pro:free"


def test_model_client_posts_to_opencode():
    requests = []

    def handler(request):
        requests.append(request)
        if request.url.path == "/session":
            return httpx.Response(200, json={"id": "session-1"})
        if request.url.path == "/session/session-1/message":
            payload = json.loads(request.content.decode())
            assert payload["model"] == {
                "providerID": "openrouter",
                "modelID": "nex-agi/nex-n2-pro:free",
            }
            return httpx.Response(
                200,
                json={"parts": [{"type": "text", "text": "threat report"}]},
            )
        return httpx.Response(404)

    client = ModelClient(
        base_url="http://opencode.test",
        transport=httpx.MockTransport(handler),
    )

    response = client.messages.create(
        model="openrouter/nex-agi/nex-n2-pro:free",
        messages=[{"role": "user", "content": "Generate a report"}],
    )

    assert response.content[0].text == "threat report"
    assert [request.url.path for request in requests] == [
        "/session",
        "/session/session-1/message",
    ]


def test_model_client_redacts_failed_response_body():
    def handler(request):
        if request.url.path == "/session":
            return httpx.Response(500, text="prompt and provider details")
        return httpx.Response(404)

    client = ModelClient(
        base_url="http://opencode.test",
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(ModelClientError) as raised:
        client.messages.create(
            model="openrouter/nex-agi/nex-n2-pro:free",
            messages=[{"role": "user", "content": "Generate a report"}],
        )

    assert "Failed to create OpenCode session: HTTP 500" in str(raised.value)
    assert "prompt and provider details" not in str(raised.value)


def test_model_client_redacts_rate_limit_response_body():
    def handler(request):
        if request.url.path == "/session":
            return httpx.Response(429, text="quota token details")
        return httpx.Response(404)

    client = ModelClient(
        base_url="http://opencode.test",
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(ModelRateLimitError) as raised:
        client.messages.create(
            model="openrouter/nex-agi/nex-n2-pro:free",
            messages=[{"role": "user", "content": "Generate a report"}],
        )

    assert str(raised.value) == "OpenCode rate limit exceeded"
