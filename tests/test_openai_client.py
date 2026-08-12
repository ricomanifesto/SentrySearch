import json
from types import SimpleNamespace

import httpx
import openai
import pytest
from pydantic import BaseModel

from src.core.openai_client import (
    DEFAULT_MODEL,
    DEFAULT_OPENROUTER_BASE_URL,
    ModelClient,
    ModelClientError,
    ModelRateLimitError,
    resolve_model_name,
)
from src.core.threat_profile_schema import ThreatProfile


class FakeResponses:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = []
        self.parse_calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def parse(self, **kwargs):
        self.parse_calls.append(kwargs)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class FakeOpenAI:
    def __init__(self, outcomes):
        self.responses = FakeResponses(outcomes)


class StructuredResult(BaseModel):
    value: str


def response(
    text: str,
    *,
    input_tokens: int = 10,
    output_tokens: int = 20,
    cached_tokens: int = 0,
    cache_write_tokens: int = 0,
    reasoning_tokens: int = 0,
    web_search_requests: int = 0,
    output_parsed=None,
    output=None,
):
    return SimpleNamespace(
        output_text=text,
        output_parsed=output_parsed,
        output=output or [],
        id="resp_test",
        model="meta-llama/llama-3.3-70b-instruct",
        usage=SimpleNamespace(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=input_tokens + output_tokens,
            input_tokens_details=SimpleNamespace(
                cached_tokens=cached_tokens,
                cache_write_tokens=cache_write_tokens,
            ),
            output_tokens_details=SimpleNamespace(reasoning_tokens=reasoning_tokens),
            server_tool_use=SimpleNamespace(web_search_requests=web_search_requests),
        ),
    )


def test_defaults_restore_previous_openrouter_model(monkeypatch):
    monkeypatch.delenv("SENTRYSEARCH_MODEL", raising=False)

    assert DEFAULT_MODEL == "meta-llama/llama-3.3-70b-instruct"
    assert resolve_model_name() == "meta-llama/llama-3.3-70b-instruct"


def test_model_client_configures_openai_sdk_for_openrouter(monkeypatch):
    created = {}
    sdk_client = FakeOpenAI([])

    def create_sdk_client(**kwargs):
        created.update(kwargs)
        return sdk_client

    monkeypatch.setenv("OPENROUTER_API_KEY", "openrouter-key")
    monkeypatch.delenv("OPENROUTER_BASE_URL", raising=False)
    monkeypatch.setattr("src.core.openai_client.OpenAI", create_sdk_client)

    client = ModelClient(timeout=45.0)

    assert client._sdk_client is sdk_client
    assert created == {
        "api_key": "openrouter-key",
        "base_url": DEFAULT_OPENROUTER_BASE_URL,
        "timeout": 45.0,
        "default_headers": {
            "HTTP-Referer": "https://sentry-search.vercel.app",
            "X-OpenRouter-Title": "SentrySearch",
        },
    }


def test_model_client_uses_openrouter_responses_api_through_openai_sdk():
    sdk_client = FakeOpenAI([response("threat report")])
    client = ModelClient(sdk_client=sdk_client)

    result = client.messages.create(
        model="meta-llama/llama-3.3-70b-instruct",
        system="You are a threat analyst.",
        messages=[{"role": "user", "content": "Analyze Cobalt Strike"}],
        max_tokens=16_384,
        temperature=0.3,
        tools=[{"type": "web_search"}],
    )

    assert sdk_client.responses.calls == [
        {
            "model": "meta-llama/llama-3.3-70b-instruct",
            "instructions": "You are a threat analyst.",
            "input": [{"role": "user", "content": "Analyze Cobalt Strike"}],
            "max_output_tokens": 16_384,
            "tools": [{"type": "openrouter:web_search"}],
            "temperature": 0.3,
        }
    ]
    assert result.content[0].type == "text"
    assert result.content[0].text == "threat report"
    assert result.usage.input_tokens == 10
    assert result.usage.output_tokens == 20


def test_real_openai_sdk_serializes_openrouter_structured_output_request():
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            request=request,
            json={
                "id": "resp_test",
                "object": "response",
                "created_at": 1,
                "status": "completed",
                "model": "meta-llama/llama-3.3-70b-instruct",
                "output": [
                    {
                        "id": "msg_test",
                        "type": "message",
                        "status": "completed",
                        "role": "assistant",
                        "content": [
                            {
                                "type": "output_text",
                                "text": '{"value":"ok"}',
                                "annotations": [],
                                "logprobs": [],
                            }
                        ],
                    }
                ],
                "parallel_tool_calls": True,
                "tool_choice": "auto",
                "tools": [],
                "usage": {
                    "input_tokens": 10,
                    "input_tokens_details": {"cached_tokens": 0},
                    "output_tokens": 4,
                    "output_tokens_details": {"reasoning_tokens": 0},
                    "total_tokens": 14,
                },
            },
        )

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    sdk_client = openai.OpenAI(
        api_key="test-key",
        base_url="https://openrouter.test/api/v1",
        http_client=http_client,
    )
    client = ModelClient(sdk_client=sdk_client)

    result = client.messages.create(
        messages=[{"role": "user", "content": "Return a value"}],
        tools=[{"type": "web_search"}],
        response_format=StructuredResult,
    )

    assert result.parsed == StructuredResult(value="ok")
    assert len(requests) == 1
    assert requests[0].url == "https://openrouter.test/api/v1/responses"
    request_body = json.loads(requests[0].content)
    assert request_body["model"] == "meta-llama/llama-3.3-70b-instruct"
    assert request_body["tools"] == [{"type": "openrouter:web_search"}]
    assert request_body["text"]["format"]["type"] == "json_schema"
    assert request_body["text"]["format"]["strict"] is True


def test_model_client_parses_schema_and_captures_web_search_telemetry(threat_profile_data):
    parsed = ThreatProfile.model_validate(threat_profile_data)
    search_call = SimpleNamespace(
        type="web_search_call",
        id="ws_123",
        status="completed",
        action=SimpleNamespace(
            type="search",
            query="Example Threat analysis",
            sources=[SimpleNamespace(url="https://example.com/report")],
        ),
    )
    message = SimpleNamespace(
        type="message",
        content=[
            SimpleNamespace(
                annotations=[
                    SimpleNamespace(
                        type="url_citation",
                        url="https://example.com/report",
                        title="Example report",
                    )
                ]
            )
        ],
    )
    sdk_client = FakeOpenAI(
        [
            response(
                "",
                output_parsed=parsed,
                output=[search_call, message],
                cached_tokens=4,
                cache_write_tokens=3,
                reasoning_tokens=7,
            )
        ]
    )
    client = ModelClient(sdk_client=sdk_client)

    result = client.messages.create(
        messages=[{"role": "user", "content": "Analyze Example Threat"}],
        tools=[{"type": "web_search"}],
        response_format=ThreatProfile,
    )

    assert sdk_client.responses.calls == []
    assert sdk_client.responses.parse_calls == [
        {
            "model": "meta-llama/llama-3.3-70b-instruct",
            "input": [{"role": "user", "content": "Analyze Example Threat"}],
            "max_output_tokens": 16_384,
            "tools": [{"type": "openrouter:web_search"}],
            "text_format": ThreatProfile,
        }
    ]
    assert result.parsed == parsed
    assert result.response_id == "resp_test"
    assert result.web_search_sources == [
        {
            "url": "https://example.com/report",
            "title": "Example report",
            "page_age": "unknown",
            "origin": "web_search_call",
        }
    ]
    assert result.tool_events == [
        {
            "type": "web_search_call",
            "id": "ws_123",
            "status": "completed",
            "action_type": "search",
            "source_count": 1,
            "query": "Example Threat analysis",
        }
    ]
    assert [block.type for block in result.content] == [
        "web_search_tool_result",
        "text",
    ]
    assert result.usage.cached_tokens == 4
    assert result.usage.cache_write_tokens == 3
    assert result.usage.reasoning_tokens == 7
    assert result.usage.web_search_calls == 1
    assert result.usage.total_tokens == 30


def test_model_client_rejects_legacy_research_tool_declaration():
    client = ModelClient(sdk_client=FakeOpenAI([]))

    with pytest.raises(ModelClientError, match="Legacy research-tool declarations"):
        client.messages.create(
            messages=[{"role": "user", "content": "hello"}],
            tools=[{"type": "available research tools", "name": "unknown"}],
        )


def test_model_client_requires_openrouter_api_key(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)

    with pytest.raises(ModelClientError, match="OPENROUTER_API_KEY"):
        ModelClient()


def test_model_client_maps_openai_rate_limits():
    request = httpx.Request("POST", "https://api.openai.com/v1/responses")
    raw_response = httpx.Response(429, request=request)
    rate_limit = openai.RateLimitError(
        "rate limited", response=raw_response, body={"error": "rate limited"}
    )
    client = ModelClient(sdk_client=FakeOpenAI([rate_limit]))

    with pytest.raises(ModelRateLimitError):
        client.messages.create(
            model="meta-llama/llama-3.3-70b-instruct",
            messages=[{"role": "user", "content": "hello"}],
        )


def test_model_client_retries_empty_openai_response(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda *_args: None)
    sdk_client = FakeOpenAI([response(""), response("recovered report")])
    client = ModelClient(sdk_client=sdk_client)

    result = client.messages.create(
        model="meta-llama/llama-3.3-70b-instruct",
        messages=[{"role": "user", "content": "go"}],
    )

    assert len(sdk_client.responses.calls) == 2
    assert result.content[0].text == "recovered report"


def test_model_client_captures_openrouter_server_tool_usage():
    sdk_client = FakeOpenAI(
        [
            response(
                "grounded report",
                web_search_requests=2,
                output=[
                    SimpleNamespace(
                        type="message",
                        content=[
                            SimpleNamespace(
                                annotations=[
                                    SimpleNamespace(
                                        type="url_citation",
                                        url="https://example.com/report",
                                        title="Example report",
                                    )
                                ]
                            )
                        ],
                    )
                ],
            )
        ]
    )
    client = ModelClient(sdk_client=sdk_client)

    result = client.messages.create(
        messages=[{"role": "user", "content": "research"}],
        tools=[{"type": "web_search"}],
    )

    assert result.usage.web_search_calls == 2
    assert [event["type"] for event in result.tool_events] == [
        "web_search_call",
        "web_search_call",
    ]
    assert result.web_search_sources[0]["url"] == "https://example.com/report"
