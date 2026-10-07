"""Injected-client checks and SDK error classification shared by the adapters.

An unknown outcome is ``AmbiguousResponse``: the request may have been applied,
so the controller reconciles or holds. A definite refusal is ``AwsRequestRejected``
carrying only the AWS error code; provider messages can quote request content
and are never repeated into release evidence.
"""

from __future__ import annotations

from typing import Any

from botocore.exceptions import BotoCoreError, ClientError, ParamValidationError

from release.ports import AmbiguousResponse

# The longest one SDK call may block the attended controller. Deadlines are
# checked between calls, so this bounds how late a deadline can be noticed.
MAX_CALL_TIMEOUT_SECONDS = 30
THROTTLING_CODES = frozenset(
    {
        "Throttling",
        "ThrottlingException",
        "ThrottledException",
        "RequestThrottled",
        "RequestThrottledException",
        "TooManyRequestsException",
        "RequestLimitExceeded",
        "SlowDown",
        "ProvisionedThroughputExceededException",
    }
)


class AwsRequestRejected(Exception):
    """AWS definitively refused the request; it was not applied."""

    def __init__(self, operation: str, code: str) -> None:
        super().__init__(f"{operation} rejected: {code}")
        self.operation = operation
        self.code = code


def require_client(client: Any, *, service: str, region: str) -> None:
    """Refuse a client that could retry, wait unboundedly or target another service/region."""
    meta = client.meta
    if meta.service_model.service_name != service:
        raise ValueError(f"expected an injected {service} client")
    if meta.region_name != region:
        raise ValueError("client region differs from the approved manifest region")
    config = meta.config
    if (config.retries or {}).get("total_max_attempts") != 1:
        raise ValueError("SDK retries must be disabled: the controller owns every retry")
    for name in ("connect_timeout", "read_timeout"):
        value = getattr(config, name)
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not 0 < value <= MAX_CALL_TIMEOUT_SECONDS
        ):
            raise ValueError(f"client {name} must be explicit and at most 30 seconds")


def error_code(error: ClientError) -> str:
    code = error.response.get("Error", {}).get("Code")
    return code if isinstance(code, str) and code else "Unknown"


def http_status(error: ClientError) -> int:
    status = error.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return status if isinstance(status, int) else 0


def classify(operation: str, error: Exception) -> Exception:
    """Map an SDK failure to an unknown outcome or a definite, sanitized refusal."""
    if isinstance(error, ClientError):
        code = error_code(error)
        if code in THROTTLING_CODES or http_status(error) >= 500 or http_status(error) == 0:
            return AmbiguousResponse(f"{operation}: {code}")
        return AwsRequestRejected(operation, code)
    if isinstance(error, ParamValidationError):
        # Raised before anything is sent.
        return AwsRequestRejected(operation, "ParamValidation")
    if isinstance(error, BotoCoreError):
        # Connection, timeout, parse and other transport failures: the request
        # may have reached AWS.
        return AmbiguousResponse(f"{operation}: {type(error).__name__}")
    return error


def call(client: Any, operation: str, **params: Any) -> dict[str, Any]:
    """Exactly one SDK request; the response without transport metadata."""
    try:
        response = getattr(client, operation)(**params)
    except (BotoCoreError, ClientError) as error:
        raise classify(operation, error) from None
    if not isinstance(response, dict):
        raise AmbiguousResponse(f"{operation}: malformed response")
    return {key: value for key, value in response.items() if key != "ResponseMetadata"}
