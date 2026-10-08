"""Operational observers: one bounded in-VPC check of the Runtime or the API.

``observe-runtime`` and ``observe-api`` run as release tasks that the controller
launches after the services start. Each resolves its target's private DNS name
once, requires exactly one address, and sends every request to that address, so
the receipt can name the actual connection peer. The controller, not this task,
compares that peer with the network interface of the service task it recorded:
DNS that still points at another healthy task cannot pass.

- Runtime: verified HTTPS against only the mounted private CA with the expected
  hostname (SNI and SAN), the probe token on ``/healthz`` and ``/readyz``, and two
  required denials: ``/readyz`` without the token (401) and the platform's public
  trust store refusing the certificate.
- API: plain HTTP on the private port (no credentials in this milestone):
  liveness ``/``, readiness ``/api/ready`` and an unauthenticated protected route
  that must be refused (401, 403, or 503 while authentication is not configured).

The receipt is the ``operational`` kind: ``check_id``, this task's ARN and a
result naming the target, host, peer, port, TLS mode, checks and denials. Nothing
is retried; any unexpected answer fails the check. Response bodies, tokens and
certificates are never printed.
"""

import http.client
import json
import os
import socket
import ssl
import stat
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

from release_tools import contract, receipt

EXIT_OK = 0
EXIT_CONFIG = 2
EXIT_DEADLINE_EXPIRED = 4
EXIT_MATERIAL = 5
EXIT_TASK_IDENTITY = 6
EXIT_OBSERVATION = 12

COMMANDS = {"observe-runtime": "runtime", "observe-api": "api"}
RUNTIME_CA = Path("/run/material/runtime-ca.pem")
PROBE_TOKEN = Path("/run/material/probe-token")
MAX_MATERIAL_BYTES = 65_536
MAX_TOKEN_BYTES = 4096
MAX_BODY_BYTES = 4096
REQUEST_TIMEOUT_SECONDS = 5.0
API_DENIALS = frozenset({401, 403, 503})


class CheckFailed(Exception):
    def __init__(self, reason: str, code: int = EXIT_OBSERVATION) -> None:
        super().__init__(reason)
        self.reason = reason
        self.code = code


def _material(path: Path, limit: int) -> bytes:
    """An owner-only regular file of this user, read without following links."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise CheckFailed("material_invalid", EXIT_MATERIAL) from None
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
            or not 0 < info.st_size <= limit
        ):
            raise CheckFailed("material_invalid", EXIT_MATERIAL)
        return os.read(descriptor, limit + 1)
    finally:
        os.close(descriptor)


class _PinnedHTTPS(http.client.HTTPSConnection):
    """HTTPS to one address while verifying the certificate for the expected name."""

    def __init__(self, peer: str, host: str, port: int, context: ssl.SSLContext, timeout: float):
        super().__init__(host, port, context=context, timeout=timeout)
        self._peer = peer
        self._verifying = context

    def connect(self) -> None:
        raw = socket.create_connection((self._peer, self.port), self.timeout)
        self.observed_peer = raw.getpeername()[0]
        self.sock = self._verifying.wrap_socket(raw, server_hostname=self.host)


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, peer: str, host: str, port: int, timeout: float):
        super().__init__(host, port, timeout=timeout)
        self._peer = peer

    def connect(self) -> None:
        self.sock = socket.create_connection((self._peer, self.port), self.timeout)
        self.observed_peer = self.sock.getpeername()[0]


class Observer:
    def __init__(self, target: str, host: str, port: int, deadline: datetime,
                 now: Callable[[], datetime],
                 resolve: Callable[[str, int], list] = socket.getaddrinfo) -> None:  # fmt: skip
        self.target = target
        self.host = host
        self.port = port
        self.deadline = deadline
        self.now = now
        self.resolve = resolve
        self.peer = ""

    def _timeout(self) -> float:
        remaining = (self.deadline - self.now()).total_seconds()
        if remaining <= 0:
            raise CheckFailed("deadline_exceeded")
        return min(REQUEST_TIMEOUT_SECONDS, remaining)

    def resolve_once(self) -> None:
        try:
            infos = self.resolve(self.host, self.port)
        except OSError:
            raise CheckFailed("target_unresolved") from None
        addresses = {
            info[4][0]
            for info in infos
            if info[0] == socket.AF_INET and info[1] == socket.SOCK_STREAM
        }
        if len(addresses) != 1:
            # Zero or several answers: which task would answer is not knowable.
            raise CheckFailed("target_unresolved" if not addresses else "target_ambiguous")
        self.peer = addresses.pop()

    def _get(self, connection: http.client.HTTPConnection, path: str,
             headers: dict[str, str] | None = None) -> tuple[int, bytes]:  # fmt: skip
        try:
            connection.request("GET", path, headers=headers or {})
            # The address actually connected to, recorded before any reply is read.
            observed = getattr(connection, "observed_peer", None)
            response = connection.getresponse()
            body = response.read(MAX_BODY_BYTES + 1)
        except ssl.SSLCertVerificationError:
            raise CheckFailed("tls_untrusted") from None
        except (OSError, http.client.HTTPException):
            raise CheckFailed("target_unreachable") from None
        finally:
            connection.close()
        if observed != self.peer:
            raise CheckFailed("peer_changed")
        if len(body) > MAX_BODY_BYTES:
            raise CheckFailed("response_too_large")
        return response.status, body

    @staticmethod
    def _status(body: bytes) -> object:
        try:
            document = json.loads(body)
        except (ValueError, RecursionError):
            return None
        return document.get("status") if isinstance(document, dict) else None

    def runtime(self, trusted: ssl.SSLContext, token: str) -> dict[str, str]:
        trusted.minimum_version = ssl.TLSVersion.TLSv1_2
        auth = {"Authorization": f"Bearer {token}"}
        for path, wanted in (("/healthz", "alive"), ("/readyz", "ready")):
            connection = _PinnedHTTPS(self.peer, self.host, self.port, trusted, self._timeout())
            status, body = self._get(connection, path, auth)
            if status != 200 or self._status(body) != wanted:
                raise CheckFailed(f"{path.strip('/')}_failed")
        connection = _PinnedHTTPS(self.peer, self.host, self.port, trusted, self._timeout())
        if self._get(connection, "/readyz")[0] != 401:
            raise CheckFailed("unauthenticated_accepted")
        # The certificate must not be trusted by the platform's public store.
        public = ssl.create_default_context()
        connection = _PinnedHTTPS(self.peer, self.host, self.port, public, self._timeout())
        try:
            self._get(connection, "/healthz", auth)
        except CheckFailed as failure:
            if failure.reason != "tls_untrusted":
                raise
        else:
            raise CheckFailed("wrong_ca_accepted")
        return {"tls": "verified", "checks": "healthz,readyz", "denials": "no_token,wrong_ca"}

    def api(self) -> dict[str, str]:
        for path, wanted in (("/", "operational"), ("/api/ready", "ready")):
            status, body = self._get(
                _PinnedHTTP(self.peer, self.host, self.port, self._timeout()), path
            )
            if status != 200 or self._status(body) != wanted:
                raise CheckFailed("liveness_failed" if path == "/" else "ready_failed")
        status, _ = self._get(_PinnedHTTP(self.peer, self.host, self.port, self._timeout()),
                              "/api/reports")  # fmt: skip
        if status not in API_DENIALS:
            raise CheckFailed("unauthenticated_accepted")
        return {
            "tls": "none",
            "checks": "liveness,api_ready",
            "denials": f"unauthenticated:{status}",
        }

    def result(self, outcome: dict[str, str]) -> dict[str, str]:
        return {"target": self.target, "host": self.host, "peer": self.peer,
                "port": str(self.port), **outcome}  # fmt: skip


def _target(environ: dict[str, str]) -> tuple[str, int]:
    host = environ.get("RELEASE_TARGET_HOST", "")
    port = environ.get("RELEASE_TARGET_PORT", "")
    labels = host.split(".")
    if (
        len(host) > 253
        or len(labels) < 2
        or not all(contract.DNS_LABEL.fullmatch(label) for label in labels)
        or labels[-1].isdigit()  # a name, never an address: DNS decides the peer
        or not contract.DIGITS.fullmatch(port)
        or not 1 <= int(port) <= 65535
    ):
        raise contract.ContractError("target_invalid")
    return host, int(port)


def main(argv: list[str], environ: dict[str, str], *,
         now: Callable[[], datetime] = lambda: datetime.now(UTC),
         resolve: Callable[[str, int], list] = socket.getaddrinfo) -> int:  # fmt: skip
    if len(argv) != 1 or argv[0] not in COMMANDS:
        receipt.log("job_failed", reason="command_invalid", exit_code=EXIT_CONFIG)
        return EXIT_CONFIG
    target = COMMANDS[argv[0]]
    started = now()
    try:
        identity = contract.load_identity(
            environ, subject_key="RELEASE_CHECK_ID", budget_key="RELEASE_CHECK_BUDGET_SECONDS"
        )
        host, port = _target(environ)
    except contract.ContractError as error:
        receipt.log("job_failed", reason=error.reason, exit_code=EXIT_CONFIG)
        return EXIT_CONFIG
    common = {"release_id": identity.release_id, "check_id": identity.subject}
    deadline = identity.deadline(started) - timedelta(seconds=contract.STOP_GRACE_SECONDS)
    if deadline <= started:
        receipt.log("job_failed", reason="deadline_expired", exit_code=EXIT_DEADLINE_EXPIRED,
                    **common)  # fmt: skip
        return EXIT_DEADLINE_EXPIRED
    try:
        task_arn = contract.task_identity(environ)
    except Exception:
        receipt.log("job_failed", reason="task_identity_unavailable",
                    exit_code=EXIT_TASK_IDENTITY, **common)  # fmt: skip
        return EXIT_TASK_IDENTITY
    receipt.log("job_started", kind=argv[0], target=target, **common)
    observer = Observer(target, host, port, deadline, now, resolve)
    try:
        if target == "runtime":
            ca = _material(RUNTIME_CA, MAX_MATERIAL_BYTES)
            try:
                trusted = ssl.create_default_context(cadata=ca.decode("ascii"))
            except (ssl.SSLError, ValueError):
                raise CheckFailed("material_invalid", EXIT_MATERIAL) from None
            token = _material(PROBE_TOKEN, MAX_TOKEN_BYTES).decode("ascii", "replace").strip()
            if not token or any(not "!" <= char <= "~" for char in token):
                raise CheckFailed("material_invalid", EXIT_MATERIAL)
            observer.resolve_once()
            outcome = observer.runtime(trusted, token)
        else:
            observer.resolve_once()
            outcome = observer.api()
    except Exception as error:
        # Anything else that went wrong is a failed observation, never a traceback.
        failure = error if isinstance(error, CheckFailed) else CheckFailed("observation_error")
        receipt.emit("operational", release_id=identity.release_id, subject=identity.subject,
                     task_arn=task_arn, status="failed", result={"reason": failure.reason})  # fmt: skip
        receipt.log("job_failed", reason=failure.reason, exit_code=failure.code, **common)
        return failure.code
    receipt.emit("operational", release_id=identity.release_id, subject=identity.subject,
                 task_arn=task_arn, status="passed", result=observer.result(outcome))  # fmt: skip
    receipt.log("job_succeeded", **common)
    return EXIT_OK
