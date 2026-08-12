from types import SimpleNamespace

import httpx
import openai
import pytest

from src.core.openai_client import (
    DEFAULT_MODEL,
    DEFAULT_REASONING_EFFORT,
    ModelClient,
    ModelClientError,
    ModelRateLimitError,
    resolve_model_name,
    resolve_reasoning_effort,
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


def response(
    text: str,
    *,
    input_tokens: int = 10,
    output_tokens: int = 20,
    cached_tokens: int = 0,
    cache_write_tokens: int = 0,
    reasoning_tokens: int = 0,
    output_parsed=None,
    output=None,
):
    return SimpleNamespace(
        output_text=text,
        output_parsed=output_parsed,
        output=output or [],
        id="resp_test",
        model="gpt-5.6-sol",
        usage=SimpleNamespace(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=input_tokens + output_tokens,
            input_tokens_details=SimpleNamespace(
                cached_tokens=cached_tokens,
                cache_write_tokens=cache_write_tokens,
            ),
            output_tokens_details=SimpleNamespace(reasoning_tokens=reasoning_tokens),
        ),
    )


def test_defaults_use_gpt_5_6_sol_with_xhigh_reasoning(monkeypatch):
    monkeypatch.delenv("SENTRYSEARCH_MODEL", raising=False)
    monkeypatch.delenv("OPENAI_REASONING_EFFORT", raising=False)

    assert DEFAULT_MODEL == "gpt-5.6-sol"
    assert DEFAULT_REASONING_EFFORT == "xhigh"
    assert resolve_model_name() == "gpt-5.6-sol"
    assert resolve_reasoning_effort() == "xhigh"


def test_rejects_unknown_reasoning_effort(monkeypatch):
    monkeypatch.setenv("OPENAI_REASONING_EFFORT", "extreme")

    with pytest.raises(ValueError, match="OPENAI_REASONING_EFFORT"):
        resolve_reasoning_effort()


def test_model_client_uses_openai_responses_api():
    sdk_client = FakeOpenAI([response("threat report")])
    client = ModelClient(sdk_client=sdk_client)

    result = client.messages.create(
        model="gpt-5.6-sol",
        system="You are a threat analyst.",
        messages=[{"role": "user", "content": "Analyze Cobalt Strike"}],
        max_tokens=16_384,
        temperature=0.3,
        tools=[{"type": "web_search"}],
    )

    assert sdk_client.responses.calls == [
        {
            "model": "gpt-5.6-sol",
            "instructions": "You are a threat analyst.",
            "input": [{"role": "user", "content": "Analyze Cobalt Strike"}],
            "max_output_tokens": 16_384,
            "reasoning": {"effort": "xhigh"},
            "tools": [{"type": "web_search"}],
            "include": ["web_search_call.action.sources"],
        }
    ]
    assert result.content[0].type == "text"
    assert result.content[0].text == "threat report"
    assert result.usage.input_tokens == 10
    assert result.usage.output_tokens == 20


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
            "model": "gpt-5.6-sol",
            "input": [{"role": "user", "content": "Analyze Example Threat"}],
            "max_output_tokens": 16_384,
            "reasoning": {"effort": "xhigh"},
            "tools": [{"type": "web_search"}],
            "include": ["web_search_call.action.sources"],
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
    assert result.usage.total_tokens == 30


def test_model_client_rejects_legacy_research_tool_declaration():
    client = ModelClient(sdk_client=FakeOpenAI([]))

    with pytest.raises(ModelClientError, match="Legacy research-tool declarations"):
        client.messages.create(
            messages=[{"role": "user", "content": "hello"}],
            tools=[{"type": "available research tools", "name": "unknown"}],
        )


def test_model_client_requires_openai_api_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    with pytest.raises(ModelClientError, match="OPENAI_API_KEY"):
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
            model="gpt-5.6-sol",
            messages=[{"role": "user", "content": "hello"}],
        )


def test_model_client_retries_empty_openai_response(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda *_args: None)
    sdk_client = FakeOpenAI([response(""), response("recovered report")])
    client = ModelClient(sdk_client=sdk_client)

    result = client.messages.create(
        model="gpt-5.6-sol",
        messages=[{"role": "user", "content": "go"}],
    )

    assert len(sdk_client.responses.calls) == 2
    assert result.content[0].text == "recovered report"
