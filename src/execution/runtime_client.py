"""Small synchronous client for the SentryRuntime HTTP contract."""

from __future__ import annotations

from dataclasses import dataclass
import re
import ssl
from typing import Any, Mapping
from urllib.parse import urlsplit

import httpx

PRODUCT = "sentrysearch"
WORKFLOW_NAME = "generate_report"
WORKFLOW_VERSION = "v1"
DEFAULT_MAX_ATTEMPTS = 3
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


class RuntimeUnavailable(RuntimeError):
    """The runtime could not accept a request."""


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
    """Call an explicit runtime authority; remote transport is verified and owned."""

    def __init__(
        self,
        base_url: str,
        *,
        bearer_token: str | None = None,
        remote: bool = False,
        ca_file: str | None = None,
        http_client: httpx.Client | None = None,
    ) -> None:
        self.base_url = validate_runtime_url(base_url, remote=remote)
        validate_runtime_token(bearer_token)
        if remote and not bearer_token:
            raise ValueError("remote runtime requires a service token")
        if remote and http_client is not None:
            raise ValueError("remote runtime transport must be owned by RuntimeClient")
        if ca_file is not None and (
            not self.base_url.startswith("https://") or http_client is not None
        ):
            raise ValueError("runtime trust configuration requires owned HTTPS transport")
        verification: bool | ssl.SSLContext = True
        if ca_file is not None:
            if not ca_file:
                raise ValueError("runtime trust bundle must not be empty")
            try:
                verification = ssl.create_default_context(cafile=ca_file)
            except (OSError, ValueError):
                raise ValueError("runtime trust bundle could not be loaded") from None
            verification.minimum_version = ssl.TLSVersion.TLSv1_2
        self._headers = {"Authorization": f"Bearer {bearer_token}"} if bearer_token else {}
        self._owns_client = http_client is None
        self._client = http_client or httpx.Client(
            timeout=httpx.Timeout(5.0, connect=2.0),
            trust_env=False,
            verify=verification,
            follow_redirects=False,
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
        except httpx.RequestError:
            raise RuntimeUnavailable("runtime request failed") from None
        if response.status_code >= httpx.codes.INTERNAL_SERVER_ERROR:
            raise RuntimeUnavailable("runtime is unavailable")
        if response.status_code in {httpx.codes.UNAUTHORIZED, httpx.codes.FORBIDDEN}:
            raise RuntimeAccessDenied("runtime credentials or scope were rejected")
        if response.is_redirect:
            raise RuntimeAccessDenied("runtime redirects are not permitted")
        if response.status_code == httpx.codes.CONFLICT:
            try:
                body = response.json()
            except ValueError:
                body = {}
            if isinstance(body, dict) and body.get("code") == "lease_fenced":
                raise RuntimeLeaseFenced("runtime lease was superseded or finalized")
        if response.is_client_error and not (method == "GET" and response.status_code == 404):
            raise RuntimeAccessDenied("runtime request was rejected")
        return response


def validate_runtime_token(value: str | None) -> None:
    """Reject malformed bearer values without including secret material in errors."""

    if value is not None and (
        not 32 <= len(value) <= 512 or re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", value) is None
    ):
        raise ValueError("runtime bearer token must contain 32-512 valid token characters")


def validate_runtime_url(value: str, *, remote: bool = False) -> str:
    """Accept one unambiguous operator-configured authority, never a base path."""

    message = (
        "runtime URL must be an HTTPS authority"
        if remote
        else "runtime URL must be an HTTP(S) loopback authority"
    )
    try:
        parsed = urlsplit(value)
        invalid = (
            not value
            or any(
                character.isspace() or ord(character) < 32 or ord(character) == 127
                for character in value
            )
            or any(character in value for character in ("?", "#", "\\", "%"))
            or parsed.scheme not in ({"https"} if remote else {"http", "https"})
            or not parsed.hostname
            or (not remote and parsed.hostname not in LOOPBACK_HOSTS)
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.netloc.endswith(":")
            or (parsed.port is not None and not 1 <= parsed.port <= 65535)
        )
        # Check HTTPX agrees with urllib before attaching credentials.
        url = httpx.URL(value)
        default_port = 80 if parsed.scheme == "http" else 443
        normalized_port = None if parsed.port == default_port else parsed.port
        invalid = invalid or url.host != parsed.hostname or url.port != normalized_port
    except (ValueError, httpx.InvalidURL):
        raise ValueError(message) from None
    if invalid:
        raise ValueError(message)
    return str(url).removesuffix("/")
