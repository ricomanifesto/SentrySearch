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
VALID_REASONING_EFFORTS = frozenset(
    {"none", "minimal", "low", "medium", "high", "xhigh", "max"}
)


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
        request: dict[str, Any] = {
            "model": resolve_model_name(kwargs.get("model")),
            "instructions": self._content_to_text(kwargs.get("system", "")),
            "input": self._build_input(kwargs),
            "max_output_tokens": int(kwargs.get("max_tokens") or 16_384),
            "reasoning": reasoning,
        }
        if not request["instructions"]:
            request.pop("instructions")

        last_empty_error: ModelClientError | None = None
        for attempt in range(EMPTY_RESPONSE_RETRIES):
            try:
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

            text = str(getattr(response, "output_text", "") or "").strip()
            if not text:
                last_empty_error = ModelClientError(
                    "OpenAI response did not include text output"
                )
                if attempt + 1 < EMPTY_RESPONSE_RETRIES:
                    time.sleep(EMPTY_RESPONSE_RETRY_DELAY * (attempt + 1))
                    continue
                raise last_empty_error

            usage = getattr(response, "usage", None)
            return SimpleNamespace(
                content=[SimpleNamespace(type="text", text=text)],
                usage=SimpleNamespace(
                    input_tokens=int(getattr(usage, "input_tokens", 0) or 0),
                    output_tokens=int(getattr(usage, "output_tokens", 0) or 0),
                ),
            )

        raise last_empty_error or ModelClientError(
            "OpenAI response did not include text output"
        )

    def _build_input(self, kwargs: dict[str, Any]) -> list[dict[str, str]]:
        messages: list[dict[str, str]] = []
        raw = kwargs.get("messages", []) or []
        tools = kwargs.get("tools")
        last_index = len(raw) - 1
        for index, message in enumerate(raw):
            role = str(message.get("role", "user"))
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


class _Messages:
    def __init__(self, client: ModelClient) -> None:
        self.client = client

    def create(self, **kwargs: Any) -> SimpleNamespace:
        return self.client.create_message(**kwargs)
