import json

import httpx
import pytest
from pydantic import BaseModel

from src.core.openrouter_client import (
    DEFAULT_EVALUATION_MODEL,
    DEFAULT_MODEL,
    DEFAULT_OPENROUTER_BASE_URL,
    ModelClient,
    ModelClientError,
    ModelRateLimitError,
    ModelRetryableError,
    evaluation_request_options,
    generation_request_options,
    resolve_evaluation_model_name,
    resolve_model_name,
)
from src.core.threat_profile_schema import ThreatProfile


class StructuredResult(BaseModel):
    value: str


def chat_response(
    text: str,
    *,
    annotations=None,
    finish_reason: str = "stop",
    prompt_tokens: int = 10,
    completion_tokens: int = 20,
    cached_tokens: int = 0,
    cache_write_tokens: int = 0,
    reasoning_tokens: int = 0,
    web_search_requests: int = 0,
):
    return {
        "id": "gen-test",
        "object": "chat.completion",
        "model": "google/gemma-4-26b-a4b-it:free",
        "provider": "TestProvider",
        "choices": [
            {
                "index": 0,
                "finish_reason": finish_reason,
                "message": {
                    "role": "assistant",
                    "content": text,
                    "annotations": annotations or [],
                },
            }
        ],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
            "prompt_tokens_details": {
                "cached_tokens": cached_tokens,
                "cache_write_tokens": cache_write_tokens,
            },
            "completion_tokens_details": {"reasoning_tokens": reasoning_tokens},
            "server_tool_use": {"web_search_requests": web_search_requests},
        },
    }


def model_client(outcomes, requests=None):
    queued = list(outcomes)

    def handler(request: httpx.Request) -> httpx.Response:
        if requests is not None:
            requests.append(request)
        status_code, body, headers = queued.pop(0)
        return httpx.Response(status_code, request=request, json=body, headers=headers)

    return ModelClient(
        base_url="https://openrouter.test/api/v1",
        api_key="test-key",
        transport=httpx.MockTransport(handler),
    )


def test_defaults_use_free_gemma_models(monkeypatch):
    monkeypatch.delenv("SENTRYSEARCH_MODEL", raising=False)
    monkeypatch.delenv("SENTRYSEARCH_EVALUATION_MODEL", raising=False)

    assert DEFAULT_MODEL == "google/gemma-4-26b-a4b-it:free"
    assert DEFAULT_EVALUATION_MODEL == "google/gemma-4-31b-it:free"
    assert DEFAULT_OPENROUTER_BASE_URL == "https://openrouter.ai/api/v1"
    assert resolve_model_name() == "google/gemma-4-26b-a4b-it:free"
    assert resolve_evaluation_model_name() == "google/gemma-4-31b-it:free"


def test_evaluation_model_can_be_overridden_independently(monkeypatch):
    monkeypatch.setenv("SENTRYSEARCH_MODEL", "example/generator")
    monkeypatch.setenv("SENTRYSEARCH_EVALUATION_MODEL", "example/evaluator")

    assert resolve_model_name() == "example/generator"
    assert resolve_evaluation_model_name() == "example/evaluator"
    assert generation_request_options() == {"model": "example/generator"}
    assert evaluation_request_options() == {"model": "example/evaluator"}


def test_default_generation_model_is_pinned_to_google_ai_studio(monkeypatch):
    monkeypatch.delenv("SENTRYSEARCH_MODEL", raising=False)

    assert generation_request_options() == {
        "model": "google/gemma-4-26b-a4b-it:free",
        "fallback_models": ["google/gemma-4-26b-a4b-it"],
        "provider": {
            "only": ["google-ai-studio"],
            "allow_fallbacks": False,
        },
    }


def test_default_evaluation_model_is_pinned_to_google_ai_studio(monkeypatch):
    monkeypatch.delenv("SENTRYSEARCH_EVALUATION_MODEL", raising=False)

    assert evaluation_request_options() == {
        "model": "google/gemma-4-31b-it:free",
        "fallback_models": ["google/gemma-4-31b-it"],
        "provider": {
            "only": ["google-ai-studio"],
            "allow_fallbacks": False,
        },
    }


def test_model_client_posts_native_openrouter_chat_completion():
    requests = []
    body = chat_response("threat report")
    body["openrouter_metadata"] = {"strategy": "direct", "attempt": 1}
    client = model_client([(200, body, {})], requests)

    result = client.messages.create(
        model="google/gemma-4-26b-a4b-it:free",
        system="You are a threat analyst.",
        messages=[{"role": "user", "content": "Analyze Cobalt Strike"}],
        max_tokens=16_384,
        temperature=0.3,
        tools=[{"type": "web_search"}],
    )

    assert len(requests) == 1
    assert requests[0].url == "https://openrouter.test/api/v1/chat/completions"
    assert requests[0].headers["authorization"] == "Bearer test-key"
    assert requests[0].headers["http-referer"] == "https://sentry-search.vercel.app"
    assert requests[0].headers["x-title"] == "SentrySearch"
    assert requests[0].headers["x-openrouter-metadata"] == "enabled"
    request_body = json.loads(requests[0].content)
    assert request_body == {
        "model": "google/gemma-4-26b-a4b-it:free",
        "messages": [
            {"role": "system", "content": "You are a threat analyst."},
            {"role": "user", "content": "Analyze Cobalt Strike"},
        ],
        "max_tokens": 16_384,
        "stream": False,
        "temperature": 0.3,
        "tools": [
            {
                "type": "openrouter:web_search",
                "parameters": {
                    "engine": "exa",
                    "max_results": 5,
                    "max_total_results": 15,
                    "search_context_size": "medium",
                },
            }
        ],
        "provider": {"require_parameters": True, "sort": "throughput"},
    }
    assert result.content[0].text == "threat report"
    assert result.usage.input_tokens == 10
    assert result.usage.output_tokens == 20
    assert result.router_metadata == {"strategy": "direct", "attempt": 1}


def test_model_client_uses_same_model_paid_fallback_after_rate_limit():
    requests = []
    client = model_client(
        [
            (
                429,
                {
                    "error": {
                        "code": 429,
                        "message": "Free quota exhausted",
                        "metadata": {"error_type": "rate_limit_exceeded"},
                    }
                },
                {},
            ),
            (200, chat_response("fallback report"), {}),
        ],
        requests,
    )

    result = client.messages.create(
        model="google/gemma-4-26b-a4b-it:free",
        fallback_models=["google/gemma-4-26b-a4b-it"],
        provider={"only": ["google-ai-studio"], "allow_fallbacks": False},
        messages=[{"role": "user", "content": "Analyze Sliver"}],
        tools=[{"type": "web_search"}],
    )

    assert result.content[0].text == "fallback report"
    request_bodies = [json.loads(request.content) for request in requests]
    assert [body["model"] for body in request_bodies] == [
        "google/gemma-4-26b-a4b-it:free",
        "google/gemma-4-26b-a4b-it",
    ]
    assert all("fallback_models" not in body for body in request_bodies)
    assert request_bodies[0]["provider"] == {
        "only": ["google-ai-studio"],
        "allow_fallbacks": False,
        "require_parameters": True,
        "sort": "throughput",
    }
    assert request_bodies[1]["provider"] == {
        "require_parameters": True,
        "sort": "throughput",
    }


def test_model_client_sends_strict_schema_and_parses_chat_completion():
    requests = []
    client = model_client([(200, chat_response('{"value":"ok"}'), {})], requests)

    result = client.messages.create(
        messages=[{"role": "user", "content": "Return a value"}],
        response_format=StructuredResult,
        provider={"only": ["google-ai-studio"], "allow_fallbacks": False},
    )

    assert result.parsed == StructuredResult(value="ok")
    request_body = json.loads(requests[0].content)
    assert request_body["response_format"]["type"] == "json_schema"
    assert request_body["response_format"]["json_schema"]["name"] == "StructuredResult"
    assert request_body["response_format"]["json_schema"]["strict"] is True
    assert request_body["response_format"]["json_schema"]["schema"] == (
        StructuredResult.model_json_schema()
    )
    assert request_body["provider"] == {
        "only": ["google-ai-studio"],
        "allow_fallbacks": False,
        "require_parameters": True,
        "sort": "throughput",
    }


def test_model_client_captures_chat_citations():
    annotations = [
        {
            "type": "url_citation",
            "url_citation": {
                "url": "https://example.com/report",
                "title": "Example report",
                "content": "Source excerpt",
            },
        }
    ]
    client = model_client(
        [
            (
                200,
                chat_response(
                    "Evidence-backed research",
                    annotations=annotations,
                    cached_tokens=4,
                    cache_write_tokens=3,
                    reasoning_tokens=7,
                    web_search_requests=2,
                ),
                {},
            )
        ]
    )

    result = client.messages.create(
        messages=[{"role": "user", "content": "Analyze Example Threat"}],
        tools=[{"type": "web_search"}],
    )

    assert result.parsed is None
    assert result.response_id == "gen-test"
    assert result.provider == "TestProvider"
    assert result.web_search_sources == [
        {
            "url": "https://example.com/report",
            "title": "Example report",
            "page_age": "unknown",
            "origin": "url_citation",
        }
    ]
    assert [event["type"] for event in result.tool_events] == [
        "web_search_call",
        "web_search_call",
    ]
    assert result.tool_events[0]["source_count"] == 1
    assert [block.type for block in result.content] == [
        "web_search_tool_result",
        "text",
    ]
    assert result.usage.cached_tokens == 4
    assert result.usage.cache_write_tokens == 3
    assert result.usage.reasoning_tokens == 7
    assert result.usage.web_search_calls == 2
    assert result.usage.total_tokens == 30


def test_model_client_rejects_server_tools_combined_with_structured_output():
    client = model_client([(200, chat_response('{"value":"unused"}'), {})])

    with pytest.raises(ModelClientError, match="separate OpenRouter requests"):
        client.messages.create(
            messages=[{"role": "user", "content": "Research and structure"}],
            tools=[{"type": "web_search"}],
            response_format=StructuredResult,
        )


def test_model_client_maps_http_rate_limit_and_preserves_retry_after():
    client = model_client(
        [
            (
                429,
                {
                    "error": {
                        "code": 429,
                        "message": "Rate limit exceeded",
                        "metadata": {"error_type": "rate_limit_exceeded"},
                    }
                },
                {"Retry-After": "12"},
            )
        ]
    )

    with pytest.raises(ModelRateLimitError) as captured:
        client.messages.create(messages=[{"role": "user", "content": "hello"}])

    assert captured.value.response is not None
    assert captured.value.response.headers["retry-after"] == "12"


def test_model_client_maps_typed_provider_error_to_retryable_failure():
    body = chat_response("")
    body["error"] = {
        "code": 502,
        "message": "Provider returned an empty response",
        "metadata": {"error_type": "provider_unavailable"},
    }
    client = model_client([(200, body, {})])

    with pytest.raises(ModelRetryableError, match="provider_unavailable"):
        client.messages.create(messages=[{"role": "user", "content": "hello"}])


def test_model_client_maps_http_service_unavailable_to_retryable_failure():
    client = model_client(
        [
            (
                503,
                {
                    "error": {
                        "code": 503,
                        "message": "Provider overloaded",
                        "metadata": {"error_type": "provider_overloaded"},
                    }
                },
                {"Retry-After": "5"},
            )
        ]
    )

    with pytest.raises(ModelRetryableError, match="provider_overloaded") as captured:
        client.messages.create(messages=[{"role": "user", "content": "hello"}])

    assert captured.value.response is not None
    assert captured.value.response.headers["retry-after"] == "5"


def test_model_client_maps_http_internal_server_error_to_retryable_failure():
    client = model_client(
        [
            (
                500,
                {"error": {"code": 500, "message": "Provider failed"}},
                {},
            )
        ]
    )

    with pytest.raises(ModelRetryableError, match="HTTP 500"):
        client.messages.create(messages=[{"role": "user", "content": "hello"}])


def test_model_client_rejects_incomplete_length_response():
    client = model_client([(200, chat_response('{"value":', finish_reason="length"), {})])

    with pytest.raises(ModelClientError, match="incomplete"):
        client.messages.create(
            messages=[{"role": "user", "content": "hello"}],
            response_format=StructuredResult,
        )


def test_model_client_marks_invalid_structured_output_retryable():
    client = model_client([(200, chat_response("not-json"), {})])

    with pytest.raises(ModelRetryableError, match="structured output was invalid"):
        client.messages.create(
            messages=[{"role": "user", "content": "hello"}],
            response_format=StructuredResult,
        )


def test_model_client_marks_cancelled_response_retryable():
    client = model_client([(200, chat_response("partial", finish_reason="cancelled"), {})])

    with pytest.raises(ModelRetryableError, match="cancelled"):
        client.messages.create(messages=[{"role": "user", "content": "hello"}])


def test_model_client_retries_empty_chat_completion(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda *_args: None)
    client = model_client(
        [
            (200, chat_response(""), {}),
            (200, chat_response("recovered report"), {}),
        ]
    )

    result = client.messages.create(messages=[{"role": "user", "content": "go"}])

    assert result.content[0].text == "recovered report"


def test_model_client_rotates_routing_session_for_empty_response_retries(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda *_args: None)
    requests = []
    client = model_client(
        [
            (200, chat_response(""), {}),
            (200, chat_response(""), {}),
            (200, chat_response("recovered report"), {}),
        ],
        requests,
    )

    result = client.messages.create(
        messages=[{"role": "user", "content": "go"}],
        tools=[{"type": "web_search"}],
    )

    request_bodies = [json.loads(request.content) for request in requests]
    assert result.content[-1].text == "recovered report"
    assert "session_id" not in request_bodies[0]
    assert request_bodies[1]["session_id"].startswith("sentrysearch-empty-retry-")
    assert request_bodies[2]["session_id"].startswith("sentrysearch-empty-retry-")
    assert request_bodies[1]["session_id"] != request_bodies[2]["session_id"]


def test_model_client_rejects_legacy_research_tool_declaration():
    client = model_client([(200, chat_response("unused"), {})])

    with pytest.raises(ModelClientError, match="Legacy research-tool declarations"):
        client.messages.create(
            messages=[{"role": "user", "content": "hello"}],
            tools=[{"type": "available research tools", "name": "unknown"}],
        )


def test_model_client_requires_openrouter_api_key(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)

    with pytest.raises(ModelClientError, match="OPENROUTER_API_KEY"):
        ModelClient()
