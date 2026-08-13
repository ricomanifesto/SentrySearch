"""Direct OpenRouter Chat Completions client for threat generation.

The generators depend on a deliberately small compatibility surface:
``create_model_client``, ``resolve_model_name``, and ``client.messages.create``.
This module owns OpenRouter's native HTTP contract, Pydantic validation, source
telemetry, and safe provider-error mapping without an intermediary model SDK.
"""

from __future__ import annotations

import json
import os
import time
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
from pydantic import ValidationError

EMPTY_RESPONSE_RETRIES = 3
EMPTY_RESPONSE_RETRY_DELAY = 1.5

DEFAULT_MODEL = "meta-llama/llama-3.3-70b-instruct"
MODEL_ENV_VAR = "SENTRYSEARCH_MODEL"
DEFAULT_EVALUATION_MODEL = "anthropic/claude-haiku-4.5"
EVALUATION_MODEL_ENV_VAR = "SENTRYSEARCH_EVALUATION_MODEL"
OPENROUTER_API_KEY_ENV_VAR = "OPENROUTER_API_KEY"
OPENROUTER_BASE_URL_ENV_VAR = "OPENROUTER_BASE_URL"
DEFAULT_OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
OPENROUTER_SITE_URL = "https://sentry-search.vercel.app"
OPENROUTER_APP_TITLE = "SentrySearch"

DEFAULT_WEB_SEARCH_PARAMETERS = {
    "engine": "exa",
    "max_results": 5,
    "max_total_results": 15,
    "search_context_size": "low",
}
RETRYABLE_ERROR_TYPES = {
    "provider_overloaded",
    "provider_unavailable",
    "rate_limit_exceeded",
    "server",
    "timeout",
}


class ModelClientError(RuntimeError):
    """Raised when OpenRouter cannot return usable model output."""


class ModelRetryableError(ModelClientError):
    """Raised when a transient OpenRouter failure can be retried safely."""

    def __init__(self, message: str, response: Any | None = None) -> None:
        super().__init__(message)
        self.response = response


class ModelRateLimitError(ModelRetryableError):
    """Raised when OpenRouter reports a rate limit response."""


def resolve_model_name(model_name: str | None = None) -> str:
    """Return the configured OpenRouter model ID."""
    return (model_name or os.getenv(MODEL_ENV_VAR, DEFAULT_MODEL)).strip()


def resolve_evaluation_model_name(model_name: str | None = None) -> str:
    """Return the independently configurable OpenRouter judge model ID."""

    return (model_name or os.getenv(EVALUATION_MODEL_ENV_VAR, DEFAULT_EVALUATION_MODEL)).strip()


def create_model_client() -> "ModelClient":
    """Create the direct OpenRouter HTTP client."""
    return ModelClient()


class ModelClient:
    """Native OpenRouter adapter with the message surface used by the app."""

    def __init__(
        self,
        base_url: str | None = None,
        timeout: float = 180.0,
        api_key: str | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        key = (api_key or os.getenv(OPENROUTER_API_KEY_ENV_VAR, "")).strip()
        if not key:
            raise ModelClientError(
                f"{OPENROUTER_API_KEY_ENV_VAR} environment variable is required "
                "for model generation"
            )

        self.base_url = (
            base_url or os.getenv(OPENROUTER_BASE_URL_ENV_VAR, DEFAULT_OPENROUTER_BASE_URL)
        ).rstrip("/")
        self.timeout = timeout
        self.transport = transport
        self._api_key = key
        self.messages = _Messages(self)

    def create_message(self, **kwargs: Any) -> SimpleNamespace:
        """Generate a message through OpenRouter's Chat Completions API."""
        tools = self._normalize_tools(kwargs.get("tools"))
        response_format = kwargs.get("response_format")
        if tools and response_format is not None:
            raise ModelClientError(
                "Tool use and structured output must use separate OpenRouter requests"
            )
        request: dict[str, Any] = {
            "model": resolve_model_name(kwargs.get("model")),
            "messages": self._build_messages(kwargs),
            "max_tokens": int(kwargs.get("max_tokens") or 16_384),
            "stream": False,
        }
        for optional_key in (
            "temperature",
            "parallel_tool_calls",
            "tool_choice",
            "stop_server_tools_when",
        ):
            if kwargs.get(optional_key) is not None:
                request[optional_key] = kwargs[optional_key]
        if tools:
            request["tools"] = tools
        if response_format is not None:
            request["response_format"] = self._structured_output_config(response_format)
        if tools or response_format is not None:
            provider = dict(kwargs.get("provider") or {})
            provider["require_parameters"] = True
            provider.setdefault("sort", "throughput")
            request["provider"] = provider

        last_empty_error: ModelClientError | None = None
        for attempt in range(EMPTY_RESPONSE_RETRIES):
            attempt_request = dict(request)
            if attempt:
                attempt_request["session_id"] = f"sentrysearch-empty-retry-{uuid4().hex}"
            response = self._post(attempt_request)
            body = self._response_body(response)
            self._raise_payload_error(body, response)

            choice = self._first_choice(body)
            finish_reason = str(choice.get("finish_reason") or "")
            if finish_reason in {"cancelled", "error"}:
                raise ModelRetryableError(
                    f"OpenRouter response was incomplete: {finish_reason or 'unknown'}",
                    response=response,
                )
            if finish_reason == "length":
                raise ModelClientError(
                    f"OpenRouter response was incomplete: {finish_reason or 'unknown'}"
                )

            text = self._extract_text(choice)
            if not text:
                last_empty_error = ModelClientError(
                    "OpenRouter response did not include text output"
                )
                if attempt + 1 < EMPTY_RESPONSE_RETRIES:
                    time.sleep(EMPTY_RESPONSE_RETRY_DELAY * (attempt + 1))
                    continue
                raise last_empty_error

            parsed = self._parse_structured_output(text, response_format)
            web_search_sources, tool_events, web_search_calls = self._extract_tool_telemetry(
                body, choice
            )
            usage = self._usage(body, web_search_calls)
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
                response_id=str(body.get("id") or ""),
                model=str(body.get("model") or request["model"]),
                provider=str(body.get("provider") or ""),
                router_metadata=(
                    dict(body["openrouter_metadata"])
                    if isinstance(body.get("openrouter_metadata"), dict)
                    else {}
                ),
                usage=usage,
            )

        raise last_empty_error or ModelClientError(
            "OpenRouter response did not include text output"
        )

    def _post(self, request: dict[str, Any]) -> httpx.Response:
        try:
            with httpx.Client(
                base_url=self.base_url,
                timeout=self.timeout,
                transport=self.transport,
            ) as client:
                response = client.post(
                    "/chat/completions",
                    json=request,
                    headers=self._headers(),
                )
        except httpx.TimeoutException as error:
            raise ModelClientError("OpenRouter request timed out") from error
        except httpx.RequestError as error:
            raise ModelClientError("OpenRouter API unavailable") from error

        error_type = self._response_error_type(response)
        if response.status_code == 429 or error_type == "rate_limit_exceeded":
            raise ModelRateLimitError("OpenRouter rate limit exceeded", response=response)
        if response.status_code in {502, 503, 504, 529} or error_type in RETRYABLE_ERROR_TYPES:
            detail = error_type or f"HTTP {response.status_code}"
            raise ModelRetryableError(
                f"OpenRouter retryable provider error: {detail}", response=response
            )
        if not response.is_success:
            detail = error_type or f"HTTP {response.status_code}"
            raise ModelClientError(f"OpenRouter request failed: {detail}")
        return response

    @staticmethod
    def _response_body(response: httpx.Response) -> dict[str, Any]:
        try:
            body = response.json()
        except json.JSONDecodeError as error:
            raise ModelClientError("OpenRouter returned invalid JSON") from error
        if not isinstance(body, dict):
            raise ModelClientError("OpenRouter returned an invalid response envelope")
        return body

    @classmethod
    def _raise_payload_error(cls, body: dict[str, Any], response: httpx.Response) -> None:
        errors = [body.get("error")]
        for choice in body.get("choices") or []:
            if isinstance(choice, dict):
                errors.append(choice.get("error"))

        for error in errors:
            if not isinstance(error, dict):
                continue
            error_type = cls._error_type(error)
            if error_type == "rate_limit_exceeded":
                raise ModelRateLimitError("OpenRouter rate limit exceeded", response=response)
            if error_type in RETRYABLE_ERROR_TYPES:
                raise ModelRetryableError(
                    f"OpenRouter retryable provider error: {error_type}", response=response
                )
            raise ModelClientError(f"OpenRouter provider error: {error_type or 'unknown'}")

    @staticmethod
    def _first_choice(body: dict[str, Any]) -> dict[str, Any]:
        for choice in body.get("choices") or []:
            if isinstance(choice, dict):
                return choice
        raise ModelClientError("OpenRouter response did not include a completion choice")

    @staticmethod
    def _extract_text(choice: dict[str, Any]) -> str:
        message = choice.get("message")
        if not isinstance(message, dict):
            return ""
        content = message.get("content")
        if isinstance(content, str):
            return content.strip()
        if isinstance(content, list):
            texts = [
                str(part.get("text") or "")
                for part in content
                if isinstance(part, dict) and part.get("type") in {None, "text", "output_text"}
            ]
            return "\n".join(text for text in texts if text.strip()).strip()
        return ""

    @staticmethod
    def _parse_structured_output(text: str, response_format: Any) -> Any:
        if response_format is None:
            return None
        if not hasattr(response_format, "model_validate_json"):
            raise ModelClientError("Structured output format must be a Pydantic model")
        try:
            return response_format.model_validate_json(text)
        except (ValidationError, ValueError, TypeError) as error:
            raise ModelRetryableError("OpenRouter structured output was invalid") from error

    def _build_messages(self, kwargs: dict[str, Any]) -> list[dict[str, str]]:
        messages: list[dict[str, str]] = []
        if system := self._content_to_text(kwargs.get("system", "")):
            messages.append({"role": "system", "content": system})
        for message in kwargs.get("messages") or []:
            messages.append(
                {
                    "role": str(message.get("role", "user")),
                    "content": self._content_to_text(message.get("content", "")),
                }
            )
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
            if tool_type in {"web_search", "openrouter:web_search"}:
                tool["type"] = "openrouter:web_search"
                parameters = dict(tool.get("parameters") or {})
                for key, value in DEFAULT_WEB_SEARCH_PARAMETERS.items():
                    parameters.setdefault(key, value)
                tool["parameters"] = parameters
            normalized.append(tool)
        return normalized

    @staticmethod
    def _structured_output_config(response_format: Any) -> dict[str, Any]:
        if not hasattr(response_format, "model_json_schema"):
            raise ModelClientError("Structured output format must be a Pydantic model")
        return {
            "type": "json_schema",
            "json_schema": {
                "name": str(getattr(response_format, "__name__", "structured_output")),
                "strict": True,
                "schema": response_format.model_json_schema(),
            },
        }

    @classmethod
    def _extract_tool_telemetry(
        cls, body: dict[str, Any], choice: dict[str, Any]
    ) -> tuple[list[dict[str, str]], list[dict[str, Any]], int]:
        sources_by_url: dict[str, dict[str, str]] = {}
        raw_message = choice.get("message")
        message: dict[str, Any] = raw_message if isinstance(raw_message, dict) else {}
        for annotation in message.get("annotations") or []:
            if not isinstance(annotation, dict) or annotation.get("type") != "url_citation":
                continue
            citation = annotation.get("url_citation") or annotation
            if not isinstance(citation, dict):
                continue
            url = str(citation.get("url") or "").strip()
            if not url:
                continue
            title = str(citation.get("title") or "").strip()
            sources_by_url[url] = {
                "url": url,
                "title": title or urlsplit(url).netloc or url,
                "page_age": str(
                    citation.get("page_age") or citation.get("published_date") or "unknown"
                ),
                "origin": "url_citation",
            }

        raw_usage = body.get("usage")
        usage: dict[str, Any] = raw_usage if isinstance(raw_usage, dict) else {}
        raw_server_tool_use = usage.get("server_tool_use")
        server_tool_use: dict[str, Any] = (
            raw_server_tool_use if isinstance(raw_server_tool_use, dict) else {}
        )
        web_search_calls = int(server_tool_use.get("web_search_requests") or 0)
        tool_events = [
            {
                "type": "web_search_call",
                "id": "",
                "status": "completed",
                "action_type": "openrouter:web_search",
                "source_count": len(sources_by_url) if index == 0 else 0,
            }
            for index in range(web_search_calls)
        ]
        return list(sources_by_url.values()), tool_events, web_search_calls

    @staticmethod
    def _usage(body: dict[str, Any], web_search_calls: int) -> SimpleNamespace:
        raw_usage = body.get("usage")
        usage: dict[str, Any] = raw_usage if isinstance(raw_usage, dict) else {}
        raw_input_details = usage.get("prompt_tokens_details")
        input_details: dict[str, Any] = (
            raw_input_details if isinstance(raw_input_details, dict) else {}
        )
        raw_output_details = usage.get("completion_tokens_details")
        output_details: dict[str, Any] = (
            raw_output_details if isinstance(raw_output_details, dict) else {}
        )
        input_tokens = int(usage.get("prompt_tokens") or 0)
        output_tokens = int(usage.get("completion_tokens") or 0)
        return SimpleNamespace(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cached_tokens=int(input_details.get("cached_tokens") or 0),
            cache_write_tokens=int(input_details.get("cache_write_tokens") or 0),
            reasoning_tokens=int(output_details.get("reasoning_tokens") or 0),
            web_search_calls=web_search_calls,
            total_tokens=int(usage.get("total_tokens") or input_tokens + output_tokens),
        )

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": OPENROUTER_SITE_URL,
            "X-Title": OPENROUTER_APP_TITLE,
            "X-OpenRouter-Metadata": "enabled",
        }

    @classmethod
    def _response_error_type(cls, response: httpx.Response) -> str:
        try:
            body = response.json()
        except json.JSONDecodeError:
            return ""
        if not isinstance(body, dict) or not isinstance(body.get("error"), dict):
            return ""
        return cls._error_type(body["error"])

    @staticmethod
    def _error_type(error: dict[str, Any]) -> str:
        raw_metadata = error.get("metadata")
        metadata: dict[str, Any] = raw_metadata if isinstance(raw_metadata, dict) else {}
        return str(metadata.get("error_type") or error.get("error_type") or "").strip()

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
