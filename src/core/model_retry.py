"""One bounded retry policy for transient model-provider failures."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import logging
import random
import time
from typing import Any, TypeVar

from src.core.openrouter_client import ModelRetryableError

logger = logging.getLogger(__name__)

Result = TypeVar("Result")


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """Transient-provider retry bounds used by every model-backed pipeline."""

    max_attempts: int = 3
    base_delay_seconds: float = 5
    max_delay_seconds: float = 120

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be at least one")
        if self.base_delay_seconds < 0 or self.max_delay_seconds < 0:
            raise ValueError("retry delays cannot be negative")


DEFAULT_RETRY_POLICY = RetryPolicy()


def call_with_model_retry(
    request: Callable[[], Result],
    *,
    operation: str,
    policy: RetryPolicy = DEFAULT_RETRY_POLICY,
    sleep: Callable[[float], None] = time.sleep,
    jitter: Callable[[float, float], float] = random.uniform,
) -> Result:
    """Run a request, retrying only explicitly transient provider failures."""

    for attempt in range(policy.max_attempts):
        try:
            return request()
        except ModelRetryableError as error:
            if attempt + 1 == policy.max_attempts:
                raise

            retry_after = _retry_after_seconds(error)
            if retry_after is not None:
                delay = min(retry_after + jitter(1, 3), policy.max_delay_seconds)
            else:
                delay = min(
                    policy.base_delay_seconds * (2**attempt) + jitter(1, 5),
                    policy.max_delay_seconds,
                )

            logger.warning(
                "%s hit a retryable provider error; retrying in %.1f seconds (%d/%d)",
                operation,
                delay,
                attempt + 2,
                policy.max_attempts,
            )
            sleep(delay)

    raise AssertionError("retry loop exited without a result")


def _retry_after_seconds(error: ModelRetryableError) -> float | None:
    response = getattr(error, "response", None)
    headers = getattr(response, "headers", {}) if response else {}
    value = headers.get("retry-after")
    if value is None:
        return None
    try:
        return max(0, float(value))
    except (TypeError, ValueError):
        return None


class RetryingModelRequests:
    """Mixin for components that expose a model client as ``self.client``."""

    client: Any

    def _request_model(
        self,
        *,
        retry_policy: RetryPolicy = DEFAULT_RETRY_POLICY,
        **kwargs: Any,
    ) -> Any:
        return call_with_model_retry(
            lambda: self.client.messages.create(**kwargs),
            operation=type(self).__name__,
            policy=retry_policy,
        )
