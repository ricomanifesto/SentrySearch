import json

import httpx
import pytest

from src.core.opencode_client import ModelClient, parse_model_selection


def test_model_selection_requires_provider_model():
    with pytest.raises(ValueError):
        parse_model_selection("claude-sonnet-4-5-20250929")


def test_model_client_posts_to_opencode():
    requests = []

    def handler(request):
        requests.append(request)
        if request.url.path == "/session":
            return httpx.Response(200, json={"id": "session-1"})
        if request.url.path == "/session/session-1/message":
            payload = json.loads(request.content.decode())
            assert payload["model"] == {
                "providerID": "anthropic",
                "modelID": "claude-sonnet-4-5-20250929",
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
        model="anthropic/claude-sonnet-4-5-20250929",
        messages=[{"role": "user", "content": "Generate a report"}],
    )

    assert response.content[0].text == "threat report"
    assert [request.url.path for request in requests] == [
        "/session",
        "/session/session-1/message",
    ]
