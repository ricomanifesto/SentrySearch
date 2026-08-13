from types import SimpleNamespace
from typing import Any

import pytest

from src.core.model_retry import RetryPolicy, call_with_model_retry
from src.core.openrouter_client import ModelRateLimitError, ModelRetryableError


class RateLimitWithResponse(ModelRateLimitError):
    response: Any


def test_model_retry_uses_bounded_exponential_backoff():
    outcomes = [ModelRetryableError("busy"), ModelRetryableError("busy"), "ok"]
    delays = []

    def request():
        outcome = outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    result = call_with_model_retry(
        request,
        operation="test request",
        policy=RetryPolicy(max_attempts=3, base_delay_seconds=5, max_delay_seconds=120),
        sleep=delays.append,
        jitter=lambda _minimum, _maximum: 1,
    )

    assert result == "ok"
    assert delays == [6, 11]


def test_rate_limit_retry_honors_retry_after_header():
    error = RateLimitWithResponse("busy")
    error.response = SimpleNamespace(headers={"retry-after": "7.5"})
    outcomes = [error, "ok"]
    delays = []

    def request():
        outcome = outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    result = call_with_model_retry(
        request,
        operation="test request",
        sleep=delays.append,
        jitter=lambda _minimum, _maximum: 2,
    )

    assert result == "ok"
    assert delays == [9.5]


def test_rate_limit_retry_caps_retry_after_header():
    error = RateLimitWithResponse("busy")
    error.response = SimpleNamespace(headers={"retry-after": "600"})
    outcomes = [error, "ok"]
    delays = []

    def request():
        outcome = outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    result = call_with_model_retry(
        request,
        operation="test request",
        policy=RetryPolicy(max_delay_seconds=30),
        sleep=delays.append,
        jitter=lambda _minimum, _maximum: 2,
    )

    assert result == "ok"
    assert delays == [30]


def test_rate_limit_retry_does_not_retry_other_failures():
    attempts = 0

    def request():
        nonlocal attempts
        attempts += 1
        raise ValueError("invalid request")

    with pytest.raises(ValueError, match="invalid request"):
        call_with_model_retry(
            request,
            operation="test request",
            sleep=lambda _delay: None,
        )

    assert attempts == 1
