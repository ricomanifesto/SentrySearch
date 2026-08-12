"""OpenAI Responses API client for threat intelligence generation.

The compatibility surface used by the existing generators is intentionally
small: ``create_model_client``, ``resolve_model_name``, and
``client.messages.create``. Requests are executed by the official OpenAI SDK.
"""

from __future__ import annotations

import os
import time
from types import SimpleNamespace
from typing import Any, cast
from urllib.parse import urlsplit

import openai
from openai import OpenAI
from openai.types.shared_params.reasoning import Reasoning
from openai.types.shared_params.reasoning_effort import ReasoningEffort

EMPTY_RESPONSE_RETRIES = 3
EMPTY_RESPONSE_RETRY_DELAY = 1.5

DEFAULT_MODEL = "gpt-5.6-sol"
DEFAULT_REASONING_EFFORT = "xhigh"
MODEL_ENV_VAR = "SENTRYSEARCH_MODEL"
REASONING_EFFORT_ENV_VAR = "OPENAI_REASONING_EFFORT"
OPENAI_API_KEY_ENV_VAR = "OPENAI_API_KEY"
VALID_REASONING_EFFORTS = frozenset({"none", "low", "medium", "high", "xhigh", "max"})


class ModelRateLimitError(RuntimeError):
    """Raised when OpenAI reports a rate limit response."""


class ModelClientError(RuntimeError):
    """Raised when OpenAI cannot return usable model output."""


def resolve_model_name(model_name: str | None = None) -> str:
    """Return the configured OpenAI model ID."""
    return (model_name or os.getenv(MODEL_ENV_VAR, DEFAULT_MODEL)).strip()


def resolve_reasoning_effort() -> ReasoningEffort:
    """Return the configured OpenAI reasoning effort."""
    value = os.getenv(REASONING_EFFORT_ENV_VAR, DEFAULT_REASONING_EFFORT).strip()
    if value not in VALID_REASONING_EFFORTS:
        raise ValueError(
            f"{REASONING_EFFORT_ENV_VAR} must be one of: "
            + ", ".join(sorted(VALID_REASONING_EFFORTS))
        )
    return cast(ReasoningEffort, value)


def create_model_client() -> "ModelClient":
    """Create the configured OpenAI model client."""
    return ModelClient()


class ModelClient:
    """OpenAI client with the message-creation surface used by the app."""

    def __init__(
        self,
        timeout: float = 180.0,
        api_key: str | None = None,
        sdk_client: Any | None = None,
    ) -> None:
        if sdk_client is None:
            key = (api_key or os.getenv(OPENAI_API_KEY_ENV_VAR, "")).strip()
            if not key:
                raise ModelClientError(
                    f"{OPENAI_API_KEY_ENV_VAR} environment variable is required "
                    "for model generation"
                )
            sdk_client = OpenAI(api_key=key, timeout=timeout)

        self._sdk_client = sdk_client
        self.messages = _Messages(self)

    def create_message(self, **kwargs: Any) -> SimpleNamespace:
        """Generate a message through the OpenAI Responses API."""
        reasoning: Reasoning = {"effort": resolve_reasoning_effort()}
        tools = self._normalize_tools(kwargs.get("tools"))
        request: dict[str, Any] = {
            "model": resolve_model_name(kwargs.get("model")),
            "instructions": self._content_to_text(kwargs.get("system", "")),
            "input": self._build_input(kwargs),
            "max_output_tokens": int(kwargs.get("max_tokens") or 16_384),
            "reasoning": reasoning,
        }
        if not request["instructions"]:
            request.pop("instructions")
        if tools:
            request["tools"] = tools
        if self._uses_web_search(tools):
            request["include"] = self._merge_includes(
                kwargs.get("include"), "web_search_call.action.sources"
            )
        for optional_key in ("max_tool_calls", "parallel_tool_calls", "tool_choice"):
            if kwargs.get(optional_key) is not None:
                request[optional_key] = kwargs[optional_key]

        response_format = kwargs.get("response_format")

        last_empty_error: ModelClientError | None = None
        for attempt in range(EMPTY_RESPONSE_RETRIES):
            try:
                if response_format is not None:
                    response = self._sdk_client.responses.parse(
                        **request, text_format=response_format
                    )
                else:
                    response = self._sdk_client.responses.create(**request)
            except openai.RateLimitError as error:
                raise ModelRateLimitError("OpenAI rate limit exceeded") from error
            except openai.APIConnectionError as error:
                raise ModelClientError("OpenAI API unavailable") from error
            except openai.APIStatusError as error:
                raise ModelClientError(
                    f"OpenAI response failed: HTTP {error.status_code}"
                ) from error
            except openai.APIError as error:
                raise ModelClientError("OpenAI request failed") from error
            except openai.OpenAIError as error:
                raise ModelClientError("OpenAI response parsing failed") from error

            parsed = getattr(response, "output_parsed", None)
            text = self._response_text(response, parsed)
            if not text:
                last_empty_error = ModelClientError("OpenAI response did not include text output")
                if attempt + 1 < EMPTY_RESPONSE_RETRIES:
                    time.sleep(EMPTY_RESPONSE_RETRY_DELAY * (attempt + 1))
                    continue
                raise last_empty_error

            usage = getattr(response, "usage", None)
            input_details = getattr(usage, "input_tokens_details", None)
            output_details = getattr(usage, "output_tokens_details", None)
            input_tokens = int(getattr(usage, "input_tokens", 0) or 0)
            output_tokens = int(getattr(usage, "output_tokens", 0) or 0)
            web_search_sources, tool_events = self._extract_tool_telemetry(response)
            content: list[SimpleNamespace] = []
            if web_search_sources:
                content.append(
                    SimpleNamespace(
                        type="web_search_tool_result",
                        content=[
                            SimpleNamespace(type="web_search_result", **source)
                            for source in web_search_sources
                        ],
                    )
                )
            content.append(SimpleNamespace(type="text", text=text))
            return SimpleNamespace(
                content=content,
                parsed=parsed,
                web_search_sources=web_search_sources,
                tool_events=tool_events,
                response_id=str(getattr(response, "id", "") or ""),
                model=str(getattr(response, "model", request["model"]) or request["model"]),
                usage=SimpleNamespace(
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    cached_tokens=int(getattr(input_details, "cached_tokens", 0) or 0),
                    cache_write_tokens=int(getattr(input_details, "cache_write_tokens", 0) or 0),
                    reasoning_tokens=int(getattr(output_details, "reasoning_tokens", 0) or 0),
                    total_tokens=int(
                        getattr(usage, "total_tokens", input_tokens + output_tokens) or 0
                    ),
                ),
            )

        raise last_empty_error or ModelClientError("OpenAI response did not include text output")

    def _build_input(self, kwargs: dict[str, Any]) -> list[dict[str, str]]:
        messages: list[dict[str, str]] = []
        raw = kwargs.get("messages", []) or []
        for message in raw:
            role = str(message.get("role", "user"))
            content = self._content_to_text(message.get("content", ""))
            messages.append({"role": role, "content": content})

        if not messages:
            messages.append({"role": "user", "content": ""})
        return messages

    @staticmethod
    def _normalize_tools(raw_tools: Any) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []
        for raw_tool in raw_tools or []:
            if not isinstance(raw_tool, dict):
                raise ModelClientError("OpenAI tools must be dictionaries")

            tool = dict(raw_tool)
            tool_type = str(tool.get("type", ""))
            if tool_type == "available research tools":
                raise ModelClientError("Legacy research-tool declarations are not supported")
            normalized.append(tool)
        return normalized

    @staticmethod
    def _uses_web_search(tools: list[dict[str, Any]]) -> bool:
        return any(tool.get("type") == "web_search" for tool in tools)

    @staticmethod
    def _merge_includes(raw_includes: Any, required: str) -> list[str]:
        if isinstance(raw_includes, str):
            includes = [raw_includes]
        else:
            includes = list(raw_includes or [])
        if required not in includes:
            includes.append(required)
        return includes

    @staticmethod
    def _response_text(response: Any, parsed: Any) -> str:
        if parsed is not None:
            if hasattr(parsed, "model_dump_json"):
                return str(parsed.model_dump_json(by_alias=True)).strip()
            return str(parsed).strip()
        return str(getattr(response, "output_text", "") or "").strip()

    @classmethod
    def _extract_tool_telemetry(
        cls, response: Any
    ) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
        sources_by_url: dict[str, dict[str, str]] = {}
        tool_events: list[dict[str, Any]] = []

        def add_source(source: Any, origin: str) -> None:
            url = str(cls._value(source, "url", "") or "").strip()
            if not url:
                return
            current = sources_by_url.setdefault(
                url,
                {
                    "url": url,
                    "title": "",
                    "page_age": "unknown",
                    "origin": origin,
                },
            )
            title = str(cls._value(source, "title", "") or "").strip()
            if title:
                current["title"] = title
            page_age = str(
                cls._value(source, "page_age", "") or cls._value(source, "published_date", "") or ""
            ).strip()
            if page_age:
                current["page_age"] = page_age
            if not current["title"]:
                current["title"] = urlsplit(url).netloc or url

        for item in getattr(response, "output", []) or []:
            item_type = str(cls._value(item, "type", "") or "")
            if item_type == "web_search_call":
                action = cls._value(item, "action", None)
                action_sources = list(cls._value(action, "sources", []) or [])
                for source in action_sources:
                    add_source(source, "web_search_call")
                event: dict[str, Any] = {
                    "type": item_type,
                    "id": str(cls._value(item, "id", "") or ""),
                    "status": str(cls._value(item, "status", "") or ""),
                    "action_type": str(cls._value(action, "type", "") or ""),
                    "source_count": len(action_sources),
                }
                query = cls._value(action, "query", None)
                queries = cls._value(action, "queries", None)
                if query:
                    event["query"] = str(query)
                if queries:
                    event["queries"] = [str(value) for value in queries]
                tool_events.append(event)

            if item_type == "message":
                for content in cls._value(item, "content", []) or []:
                    for annotation in cls._value(content, "annotations", []) or []:
                        annotation_type = str(cls._value(annotation, "type", "") or "")
                        if annotation_type == "url_citation":
                            add_source(annotation, "url_citation")

        return list(sources_by_url.values()), tool_events

    @staticmethod
    def _value(value: Any, key: str, default: Any) -> Any:
        if isinstance(value, dict):
            return value.get(key, default)
        return getattr(value, key, default)

    @staticmethod
    def _content_to_text(content: Any) -> str:
        if isinstance(content, list):
            parts = [
                str(part.get("text", "")) if isinstance(part, dict) else str(part)
                for part in content
            ]
            return "\n".join(part for part in parts if part)
        return str(content)


class _Messages:
    def __init__(self, client: ModelClient) -> None:
        self.client = client

    def create(self, **kwargs: Any) -> SimpleNamespace:
        return self.client.create_message(**kwargs)
