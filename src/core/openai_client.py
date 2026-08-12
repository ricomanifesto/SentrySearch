"""OpenRouter Responses API client built on the official OpenAI SDK.

The compatibility surface used by the existing generators is intentionally
small: ``create_model_client``, ``resolve_model_name``, and
``client.messages.create``. OpenRouter executes the configured model while the
OpenAI SDK owns request handling and Pydantic structured-output parsing.
"""

from __future__ import annotations

import os
import time
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

import openai
from openai import OpenAI

EMPTY_RESPONSE_RETRIES = 3
EMPTY_RESPONSE_RETRY_DELAY = 1.5

DEFAULT_MODEL = "meta-llama/llama-3.3-70b-instruct"
MODEL_ENV_VAR = "SENTRYSEARCH_MODEL"
OPENROUTER_API_KEY_ENV_VAR = "OPENROUTER_API_KEY"
OPENROUTER_BASE_URL_ENV_VAR = "OPENROUTER_BASE_URL"
DEFAULT_OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
OPENROUTER_SITE_URL = "https://sentry-search.vercel.app"
OPENROUTER_APP_TITLE = "SentrySearch"


class ModelRateLimitError(RuntimeError):
    """Raised when OpenRouter reports a rate limit response."""

    def __init__(self, message: str, response: Any | None = None) -> None:
        super().__init__(message)
        self.response = response


class ModelClientError(RuntimeError):
    """Raised when OpenRouter cannot return usable model output."""


def resolve_model_name(model_name: str | None = None) -> str:
    """Return the configured OpenRouter model ID."""
    return (model_name or os.getenv(MODEL_ENV_VAR, DEFAULT_MODEL)).strip()


def create_model_client() -> "ModelClient":
    """Create the configured OpenRouter client backed by the OpenAI SDK."""
    return ModelClient()


class ModelClient:
    """OpenAI SDK adapter with the message-creation surface used by the app."""

    def __init__(
        self,
        base_url: str | None = None,
        timeout: float = 180.0,
        api_key: str | None = None,
        sdk_client: Any | None = None,
    ) -> None:
        if sdk_client is None:
            key = (api_key or os.getenv(OPENROUTER_API_KEY_ENV_VAR, "")).strip()
            if not key:
                raise ModelClientError(
                    f"{OPENROUTER_API_KEY_ENV_VAR} environment variable is required "
                    "for model generation"
                )
            resolved_base_url = (
                base_url or os.getenv(OPENROUTER_BASE_URL_ENV_VAR, DEFAULT_OPENROUTER_BASE_URL)
            ).rstrip("/")
            sdk_client = OpenAI(
                api_key=key,
                base_url=resolved_base_url,
                timeout=timeout,
                default_headers={
                    "HTTP-Referer": OPENROUTER_SITE_URL,
                    "X-OpenRouter-Title": OPENROUTER_APP_TITLE,
                },
            )

        self._sdk_client = sdk_client
        self.messages = _Messages(self)

    def create_message(self, **kwargs: Any) -> SimpleNamespace:
        """Generate a message through OpenRouter's Responses API."""
        tools = self._normalize_tools(kwargs.get("tools"))
        request: dict[str, Any] = {
            "model": resolve_model_name(kwargs.get("model")),
            "instructions": self._content_to_text(kwargs.get("system", "")),
            "input": self._build_input(kwargs),
            "max_output_tokens": int(kwargs.get("max_tokens") or 16_384),
        }
        if not request["instructions"]:
            request.pop("instructions")
        if tools:
            request["tools"] = tools
        for optional_key in (
            "temperature",
            "max_tool_calls",
            "parallel_tool_calls",
            "tool_choice",
        ):
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
                raise ModelRateLimitError(
                    "OpenRouter rate limit exceeded",
                    response=getattr(error, "response", None),
                ) from error
            except openai.APIConnectionError as error:
                raise ModelClientError("OpenRouter API unavailable") from error
            except openai.APIStatusError as error:
                raise ModelClientError(
                    f"OpenRouter response failed: HTTP {error.status_code}"
                ) from error
            except openai.APIError as error:
                raise ModelClientError("OpenRouter request failed") from error
            except openai.OpenAIError as error:
                raise ModelClientError("OpenAI SDK response parsing failed") from error

            parsed = getattr(response, "output_parsed", None)
            text = self._response_text(response, parsed)
            if not text:
                last_empty_error = ModelClientError(
                    "OpenRouter response did not include text output"
                )
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
            server_tool_use = getattr(usage, "server_tool_use", None)
            reported_web_search_calls = int(
                self._value(server_tool_use, "web_search_requests", 0) or 0
            )
            explicit_search_calls = sum(
                1 for event in tool_events if event.get("type") == "web_search_call"
            )
            web_search_calls = max(reported_web_search_calls, explicit_search_calls)
            for _ in range(max(0, web_search_calls - explicit_search_calls)):
                tool_events.append(
                    {
                        "type": "web_search_call",
                        "id": "",
                        "status": "completed",
                        "action_type": "openrouter:web_search",
                        "source_count": 0,
                    }
                )
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
                    web_search_calls=web_search_calls,
                    total_tokens=int(
                        getattr(usage, "total_tokens", input_tokens + output_tokens) or 0
                    ),
                ),
            )

        raise last_empty_error or ModelClientError(
            "OpenRouter response did not include text output"
        )

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
                raise ModelClientError("Model tools must be dictionaries")

            tool = dict(raw_tool)
            tool_type = str(tool.get("type", ""))
            if tool_type == "available research tools":
                raise ModelClientError("Legacy research-tool declarations are not supported")
            if tool_type == "web_search":
                tool["type"] = "openrouter:web_search"
            normalized.append(tool)
        return normalized

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
                            citation = cls._value(annotation, "url_citation", annotation)
                            add_source(citation, "url_citation")

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
