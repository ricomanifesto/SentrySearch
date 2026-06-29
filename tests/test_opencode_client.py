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
    resolve_openrouter_model,
)


def test_default_model_is_a_valid_openrouter_model(monkeypatch):
    monkeypatch.delenv("SENTRYSEARCH_MODEL", raising=False)

    assert DEFAULT_MODEL == "meta-llama/llama-3.3-70b-instruct"
    assert resolve_model_name() == "meta-llama/llama-3.3-70b-instruct"


def test_model_selection_requires_provider_model():
    with pytest.raises(ValueError):
        parse_model_selection("claude-sonnet-4-5-20250929")


def test_model_selection_allows_openrouter_nested_model_id():
    model = parse_model_selection("openrouter/nex-agi/nex-n2-pro:free")

    assert model.provider_id == "openrouter"
    assert model.model_id == "nex-agi/nex-n2-pro:free"


def test_resolve_openrouter_model_strips_route_prefix(monkeypatch):
    monkeypatch.delenv("SENTRYSEARCH_MODEL", raising=False)

    assert resolve_openrouter_model() == "meta-llama/llama-3.3-70b-instruct"
    assert (
        resolve_openrouter_model("openrouter/anthropic/claude-sonnet-4-5")
        == "anthropic/claude-sonnet-4-5"
    )


def test_model_client_posts_to_openrouter():
    requests = []

    def handler(request):
        requests.append(request)
        assert request.url.path == "/chat/completions"
        assert request.method == "POST"
        assert request.headers["authorization"] == "Bearer test-key"
        payload = json.loads(request.content.decode())
        assert payload["model"] == "nex-agi/nex-n2-pro:free"
        assert payload["messages"][-1]["content"].startswith("Analyze Cobalt Strike")
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "threat report"}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 20},
            },
        )

    client = ModelClient(
        base_url="http://openrouter.test",
        transport=httpx.MockTransport(handler),
        api_key="test-key",
    )

    response = client.messages.create(
        model="openrouter/nex-agi/nex-n2-pro:free",
        messages=[{"role": "user", "content": "Analyze Cobalt Strike"}],
        tools=[{"type": "available research tools", "name": "web_search"}],
    )

    assert len(requests) == 1
    assert response.content[0].type == "text"
    assert response.content[0].text == "threat report"
    assert response.usage.input_tokens == 10
    assert response.usage.output_tokens == 20


def test_model_client_raises_on_rate_limit():
    def handler(request):
        return httpx.Response(429, json={"error": "rate limited"})

    client = ModelClient(
        base_url="http://openrouter.test",
        transport=httpx.MockTransport(handler),
        api_key="test-key",
    )

    with pytest.raises(ModelRateLimitError):
        client.messages.create(
            model="openrouter/nex-agi/nex-n2-pro:free",
            messages=[{"role": "user", "content": "hello"}],
        )


def test_model_client_requires_api_key(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)

    def handler(request):  # pragma: no cover - should never be reached
        return httpx.Response(200, json={"choices": [{"message": {"content": "x"}}]})

    client = ModelClient(
        base_url="http://openrouter.test",
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(ModelClientError):
        client.messages.create(
            model="openrouter/nex-agi/nex-n2-pro:free",
            messages=[{"role": "user", "content": "hello"}],
        )
