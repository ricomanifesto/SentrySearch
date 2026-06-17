"""OpenCode-backed model client for threat intelligence generation."""

from __future__ import annotations

import os
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

import httpx

DEFAULT_MODEL = "anthropic/claude-sonnet-4-5-20250929"
MODEL_ENV_VAR = "SENTRYSEARCH_MODEL"
OPENCODE_BASE_URL_ENV_VAR = "OPENCODE_BASE_URL"
OPENCODE_SERVER_USERNAME_ENV_VAR = "OPENCODE_SERVER_USERNAME"
OPENCODE_SERVER_PASSWORD_ENV_VAR = "OPENCODE_SERVER_PASSWORD"


class ModelRateLimitError(RuntimeError):
    """Raised when OpenCode reports a rate limit response."""


class ModelClientError(RuntimeError):
    """Raised when OpenCode cannot return usable model output."""


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
    ) -> None:
        self.base_url = (
            base_url or os.getenv(OPENCODE_BASE_URL_ENV_VAR, "http://127.0.0.1:4096")
        ).rstrip("/")
        self.timeout = timeout
        self.transport = transport
        self.messages = _Messages(self)

    def create_message(self, **kwargs: Any) -> SimpleNamespace:
        """Generate a message through an OpenCode server session."""
        selection = parse_model_selection(kwargs.get("model"))
        prompt = self._messages_to_prompt(kwargs.get("messages", []))
        if tools := kwargs.get("tools"):
            prompt = f"{prompt}\n\nAvailable research tools requested by caller:\n{tools}"

        auth = self._auth()
        with httpx.Client(
            base_url=self.base_url,
            timeout=self.timeout,
            transport=self.transport,
            auth=auth,
        ) as client:
            session_response = client.post(
                "/session",
                json={"title": "SentrySearch threat intelligence"},
            )
            self._raise_for_status(session_response, "create OpenCode session")
            session_id = session_response.json().get("id")
            if not session_id:
                raise ModelClientError("OpenCode did not return a session id")

            message_response = client.post(
                f"/session/{session_id}/message",
                json={
                    "model": selection.as_payload(),
                    "parts": [{"type": "text", "text": prompt}],
                },
            )
            self._raise_for_status(message_response, "generate OpenCode message")

        text = self._extract_text(message_response.json())
        return SimpleNamespace(
            content=[SimpleNamespace(type="text", text=text)],
            usage=SimpleNamespace(input_tokens=0, output_tokens=0),
        )

    def _auth(self) -> tuple[str, str] | None:
        password = os.getenv(OPENCODE_SERVER_PASSWORD_ENV_VAR, "")
        if not password:
            return None
        return (os.getenv(OPENCODE_SERVER_USERNAME_ENV_VAR, "opencode"), password)

    def _messages_to_prompt(self, messages: list[dict[str, Any]]) -> str:
        prompt_parts = []
        for message in messages:
            role = message.get("role", "user")
            content = message.get("content", "")
            if isinstance(content, list):
                content = "\n".join(
                    str(part.get("text", part)) for part in content if isinstance(part, dict)
                )
            prompt_parts.append(f"{role.upper()}:\n{content}")
        return "\n\n".join(prompt_parts)

    def _raise_for_status(self, response: httpx.Response, action: str) -> None:
        if response.is_success:
            return
        if response.status_code == 429:
            raise ModelRateLimitError(response.text)
        raise ModelClientError(f"Failed to {action}: HTTP {response.status_code} {response.text}")

    def _extract_text(self, payload: dict[str, Any]) -> str:
        text_parts = []
        for part in payload.get("parts", []):
            if not isinstance(part, dict):
                continue
            for key in ("text", "content"):
                value = part.get(key)
                if isinstance(value, str) and value.strip():
                    text_parts.append(value)
                    break

        if text_parts:
            return "\n".join(text_parts)

        info = payload.get("info", {})
        if isinstance(info, dict):
            for key in ("text", "content"):
                value = info.get(key)
                if isinstance(value, str) and value.strip():
                    return value

        raise ModelClientError("OpenCode response did not include text output")


class _Messages:
    def __init__(self, client: ModelClient) -> None:
        self.client = client

    def create(self, **kwargs: Any) -> SimpleNamespace:
        return self.client.create_message(**kwargs)
