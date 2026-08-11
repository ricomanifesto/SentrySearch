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


class FakeResponses:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class FakeOpenAI:
    def __init__(self, outcomes):
        self.responses = FakeResponses(outcomes)


def response(text: str, *, input_tokens: int = 10, output_tokens: int = 20):
    return SimpleNamespace(
        output_text=text,
        usage=SimpleNamespace(input_tokens=input_tokens, output_tokens=output_tokens),
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
        tools=[{"type": "available research tools", "name": "web_search"}],
    )

    assert sdk_client.responses.calls == [
        {
            "model": "gpt-5.6-sol",
            "instructions": "You are a threat analyst.",
            "input": [
                {
                    "role": "user",
                    "content": (
                        "Analyze Cobalt Strike\n\n"
                        "Available research tools requested by caller:\n"
                        "[{'type': 'available research tools', 'name': 'web_search'}]"
                    ),
                }
            ],
            "max_output_tokens": 16_384,
            "reasoning": {"effort": "xhigh"},
        }
    ]
    assert result.content[0].type == "text"
    assert result.content[0].text == "threat report"
    assert result.usage.input_tokens == 10
    assert result.usage.output_tokens == 20


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
