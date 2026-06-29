"""Model client for threat intelligence generation.

Calls a provider's OpenAI-compatible HTTP API (OpenRouter by default) directly, so
generation works in any deployment without a local model gateway. The public
surface (``create_model_client``, ``resolve_model_name``, ``ModelClient`` with a
``messages.create``/``create_message`` method, ``ModelRateLimitError``) is kept
stable for the generators that depend on it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

import httpx

DEFAULT_MODEL = "meta-llama/llama-3.3-70b-instruct:free"
MODEL_ENV_VAR = "SENTRYSEARCH_MODEL"
OPENROUTER_BASE_URL_ENV_VAR = "OPENROUTER_BASE_URL"
OPENROUTER_API_KEY_ENV_VAR = "OPENROUTER_API_KEY"
DEFAULT_OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
OPENROUTER_ROUTE_PREFIX = "openrouter/"


class ModelRateLimitError(RuntimeError):
    """Raised when the model provider reports a rate limit response."""


class ModelClientError(RuntimeError):
    """Raised when the model provider cannot return usable model output."""


@dataclass(frozen=True)
class ModelSelection:
    provider_id: str
    model_id: str

    def as_payload(self) -> dict[str, str]:
        return {"providerID": self.provider_id, "modelID": self.model_id}


def resolve_model_name(model_name: str | None = None) -> str:
    """Return an explicit provider/model value."""
    return (model_name or os.getenv(MODEL_ENV_VAR, DEFAULT_MODEL)).strip()


def parse_model_selection(model_name: str | None = None) -> ModelSelection:
    """Parse an explicit provider/model value."""
    value = resolve_model_name(model_name)
    if "/" not in value:
        raise ValueError("Model must use provider/model format")
    provider_id, model_id = value.split("/", 1)
    if not provider_id or not model_id:
        raise ValueError("Model must use provider/model format")
    return ModelSelection(provider_id=provider_id, model_id=model_id)


def resolve_openrouter_model(model_name: str | None = None) -> str:
    """Return the OpenRouter model id, dropping a leading ``openrouter/`` route prefix."""
    value = resolve_model_name(model_name)
    if value.startswith(OPENROUTER_ROUTE_PREFIX):
        return value[len(OPENROUTER_ROUTE_PREFIX) :]
    return value


def create_model_client() -> "ModelClient":
    """Create the configured model client."""
    return ModelClient()


class ModelClient:
    """Client with a small message-creation surface used by the app."""

    def __init__(
        self,
        base_url: str | None = None,
        timeout: float = 180.0,
        transport: httpx.BaseTransport | None = None,
        api_key: str | None = None,
    ) -> None:
        self.base_url = (
            base_url or os.getenv(OPENROUTER_BASE_URL_ENV_VAR, DEFAULT_OPENROUTER_BASE_URL)
        ).rstrip("/")
        self.timeout = timeout
        self.transport = transport
        self._api_key = api_key
        self.messages = _Messages(self)

    def create_message(self, **kwargs: Any) -> SimpleNamespace:
        """Generate a message through the provider's chat-completions endpoint."""
        payload: dict[str, Any] = {
            "model": resolve_openrouter_model(kwargs.get("model")),
            "messages": self._build_messages(kwargs),
        }
        if max_tokens := kwargs.get("max_tokens"):
            payload["max_tokens"] = max_tokens
        if (temperature := kwargs.get("temperature")) is not None:
            payload["temperature"] = temperature

        with httpx.Client(
            base_url=self.base_url,
            timeout=self.timeout,
            transport=self.transport,
        ) as client:
            response = client.post(
                "/chat/completions",
                json=payload,
                headers=self._headers(),
            )
            self._raise_for_status(response, "generate model message")

        body = response.json()
        text = self._extract_text(body)
        usage = body.get("usage") if isinstance(body.get("usage"), dict) else {}
        return SimpleNamespace(
            content=[SimpleNamespace(type="text", text=text)],
            usage=SimpleNamespace(
                input_tokens=int(usage.get("prompt_tokens", 0) or 0),
                output_tokens=int(usage.get("completion_tokens", 0) or 0),
            ),
        )

    def _api_key_value(self) -> str:
        key = self._api_key or os.getenv(OPENROUTER_API_KEY_ENV_VAR, "")
        if not key:
            raise ModelClientError(
                f"{OPENROUTER_API_KEY_ENV_VAR} environment variable is required for model generation"
            )
        return key

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_key_value()}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://sentry-search.vercel.app",
            "X-Title": "SentrySearch",
        }

    def _build_messages(self, kwargs: dict[str, Any]) -> list[dict[str, str]]:
        messages: list[dict[str, str]] = []
        if system := kwargs.get("system"):
            messages.append({"role": "system", "content": self._content_to_text(system)})

        raw = kwargs.get("messages", []) or []
        tools = kwargs.get("tools")
        last_index = len(raw) - 1
        for index, message in enumerate(raw):
            role = message.get("role", "user")
            content = self._content_to_text(message.get("content", ""))
            if tools and role == "user" and index == last_index:
                content = (
                    f"{content}\n\nAvailable research tools requested by caller:\n{tools}"
                )
            messages.append({"role": role, "content": content})

        if not messages:
            messages.append({"role": "user", "content": ""})
        return messages

    @staticmethod
    def _content_to_text(content: Any) -> str:
        if isinstance(content, list):
            parts = [
                str(part.get("text", "")) if isinstance(part, dict) else str(part)
                for part in content
            ]
            return "\n".join(part for part in parts if part)
        return str(content)

    def _raise_for_status(self, response: httpx.Response, action: str) -> None:
        if response.is_success:
            return
        if response.status_code == 429:
            raise ModelRateLimitError("Model provider rate limit exceeded")
        raise ModelClientError(f"Failed to {action}: HTTP {response.status_code}")

    def _extract_text(self, payload: dict[str, Any]) -> str:
        for choice in payload.get("choices", []):
            if not isinstance(choice, dict):
                continue
            message = choice.get("message")
            if not isinstance(message, dict):
                continue
            content = message.get("content")
            if isinstance(content, str) and content.strip():
                return content
            if isinstance(content, list):
                texts = [
                    str(part.get("text", ""))
                    for part in content
                    if isinstance(part, dict)
                ]
                joined = "\n".join(text for text in texts if text.strip())
                if joined.strip():
                    return joined
        raise ModelClientError("Model response did not include text output")


class _Messages:
    def __init__(self, client: ModelClient) -> None:
        self.client = client

    def create(self, **kwargs: Any) -> SimpleNamespace:
        return self.client.create_message(**kwargs)
