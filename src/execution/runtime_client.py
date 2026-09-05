"""Small synchronous client for the local SentryRuntime HTTP contract."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Mapping
from urllib.parse import urlsplit

import httpx

PRODUCT = "sentrysearch"
WORKFLOW_NAME = "generate_report"
WORKFLOW_VERSION = "v1"
DEFAULT_MAX_ATTEMPTS = 3
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


class RuntimeUnavailable(RuntimeError):
    """The local runtime could not accept a request."""


class RuntimeAccessDenied(RuntimeError):
    """Service credentials or scope need operator correction, not a retry."""


class RuntimeRunMissing(RuntimeError):
    """The bound run cannot be read; do not silently replace its identity."""


class RuntimeLeaseFenced(RuntimeError):
    """The runtime no longer grants this worker authority to mutate the run."""


@dataclass(frozen=True)
class RuntimeRun:
    """The runtime fields needed by the SentrySearch adapter."""

    run_id: str
    state: str
    attempt: int
    lease_owner: str
    lease_version: int
    input_ref: dict[str, Any]
    error_code: str | None = None

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "RuntimeRun":
        input_ref = payload.get("input_ref")
        if not isinstance(input_ref, dict):
            raise ValueError("runtime response is missing input_ref")
        return cls(
            run_id=str(payload["run_id"]),
            state=str(payload["state"]),
            attempt=int(payload["attempt"]),
            lease_owner=str(payload.get("lease_owner") or ""),
            lease_version=int(payload["lease_version"]),
            input_ref=dict(input_ref),
            error_code=payload.get("error_code"),
        )


class RuntimeClient:
    """Call a local runtime, optionally with scoped service credentials."""

    def __init__(
        self,
        base_url: str,
        *,
        bearer_token: str | None = None,
        http_client: httpx.Client | None = None,
    ) -> None:
        self.base_url = validate_local_runtime_url(base_url)
        validate_runtime_token(bearer_token)
        self._headers = {"Authorization": f"Bearer {bearer_token}"} if bearer_token else {}
        self._owns_client = http_client is None
        self._client = http_client or httpx.Client(
            timeout=httpx.Timeout(5.0, connect=2.0),
            trust_env=False,
        )

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def submit_report(self, report_id: str) -> RuntimeRun:
        return self._post_run(
            "/v1/runs",
            {
                "product": PRODUCT,
                "workflow_name": WORKFLOW_NAME,
                "workflow_version": WORKFLOW_VERSION,
                "idempotency_key": report_id,
                "input_ref": {"report_id": report_id},
                "max_attempts": DEFAULT_MAX_ATTEMPTS,
            },
        )

    def claim(self, worker_id: str, *, lease_seconds: int) -> RuntimeRun | None:
        response = self._post(
            "/v1/worker/claims",
            {
                "product": PRODUCT,
                "workflow_name": WORKFLOW_NAME,
                "workflow_version": WORKFLOW_VERSION,
                "lease_owner": worker_id,
                "lease_duration_seconds": lease_seconds,
            },
        )
        if response.status_code == httpx.codes.NO_CONTENT:
            return None
        response.raise_for_status()
        return RuntimeRun.from_payload(response.json())

    def get_run(self, run_id: str) -> RuntimeRun:
        response = self._request("GET", f"/v1/runs/{run_id}")
        if response.status_code == httpx.codes.NOT_FOUND:
            raise RuntimeRunMissing("bound runtime run is unavailable")
        response.raise_for_status()
        return RuntimeRun.from_payload(response.json())

    def heartbeat(
        self,
        run_id: str,
        lease_owner: str,
        lease_version: int,
        *,
        lease_seconds: int,
    ) -> RuntimeRun:
        return self._post_run(
            f"/v1/runs/{run_id}/heartbeat",
            {
                "lease_owner": lease_owner,
                "lease_version": lease_version,
                "lease_duration_seconds": lease_seconds,
            },
        )

    def complete(
        self,
        run_id: str,
        lease_owner: str,
        lease_version: int,
        output_ref: dict[str, Any],
    ) -> RuntimeRun:
        return self._post_run(
            f"/v1/runs/{run_id}/complete",
            {
                "lease_owner": lease_owner,
                "lease_version": lease_version,
                "output_ref": output_ref,
            },
        )

    def fail(
        self,
        run_id: str,
        lease_owner: str,
        lease_version: int,
        *,
        error_code: str,
        error_summary: str,
    ) -> RuntimeRun:
        return self._post_run(
            f"/v1/runs/{run_id}/fail",
            {
                "lease_owner": lease_owner,
                "lease_version": lease_version,
                "error_code": error_code,
                "error_summary": error_summary,
            },
        )

    def _post_run(self, path: str, payload: dict[str, Any]) -> RuntimeRun:
        response = self._post(path, payload)
        response.raise_for_status()
        return RuntimeRun.from_payload(response.json())

    def _post(self, path: str, payload: dict[str, Any]) -> httpx.Response:
        return self._request("POST", path, payload)

    def _request(
        self, method: str, path: str, payload: dict[str, Any] | None = None
    ) -> httpx.Response:
        try:
            response = self._client.request(
                method,
                f"{self.base_url}{path}",
                json=payload,
                headers=self._headers,
                follow_redirects=False,
            )
        except httpx.RequestError as error:
            raise RuntimeUnavailable("local runtime request failed") from error
        if response.status_code >= httpx.codes.INTERNAL_SERVER_ERROR:
            raise RuntimeUnavailable("local runtime is unavailable")
        if response.status_code in {httpx.codes.UNAUTHORIZED, httpx.codes.FORBIDDEN}:
            raise RuntimeAccessDenied("runtime credentials or scope were rejected")
        if response.status_code == httpx.codes.CONFLICT:
            try:
                body = response.json()
            except ValueError:
                body = {}
            if isinstance(body, dict) and body.get("code") == "lease_fenced":
                raise RuntimeLeaseFenced("runtime lease was superseded or finalized")
        return response


def validate_runtime_token(value: str | None) -> None:
    """Reject malformed bearer values without including secret material in errors."""

    if value is not None and (
        not 32 <= len(value) <= 512 or re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", value) is None
    ):
        raise ValueError("runtime bearer token must contain 32-512 valid token characters")


def validate_local_runtime_url(value: str) -> str:
    """Keep execution local until the product adapter passes its cutover gates."""

    # TODO(sentryruntime-cutover): Replace the loopback-only URL with authenticated
    # service configuration after report-write fencing, terminal reconciliation,
    # authenticated transport, and the deployed canary are verified.
    normalized = value.strip().rstrip("/")
    parsed = urlsplit(normalized)
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname not in LOOPBACK_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("SENTRYRUNTIME_LOCAL_URL must be an HTTP loopback URL")
    return normalized
