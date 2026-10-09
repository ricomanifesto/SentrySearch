"""Signed control requests to the release's Durable Objects (CF-D016).

The operator signs ``sentry.control.v1`` canonical bytes with Ed25519, exactly
as ``deploy/cloudflare/worker/src/shared/control.ts`` verifies them: ten lines
(version, method, target, action, body SHA-256, release id, session, fence,
command id, expiry in Unix seconds) joined by newlines, every text field within
``[A-Za-z0-9._:/-]{1,128}``. The object recomputes the target from its own name,
checks the expiry and lifetime, the release, the session's fence and the command
id's novelty before it acts.

The client sends one request per call through an injected transport: no retry,
no redirect, no proxy, no credential lookup. It refuses to sign without a bound
session and re-checks the command's last valid moment immediately before
transmitting, after signing, so a slow caller cannot send late (CommandNotSent).
A transport failure after transmission may or may not have been delivered
(TransportAmbiguous); reconciliation is the caller's.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import re
from typing import Any, Protocol

CONTROL_VERSION = "sentry.control.v1"
MAX_LIFETIME_SECONDS = 300
MAX_BODY_BYTES = 16 * 1024
MAX_REPLY_BYTES = 2 * 1024 * 1024
FIELD = re.compile(r"[A-Za-z0-9._:/-]{1,128}")
SHA256 = re.compile(r"[0-9a-f]{64}")
METHODS = frozenset({"GET", "POST"})
SERVICES = frozenset({"api", "worker", "runtime", "jobs"})
NAME = re.compile(r"[a-z0-9-]{1,96}")
ACTION = re.compile(r"[a-z]{1,16}")
HEADERS = {
    "command_id": "x-sentry-command-id",
    "release_id": "x-sentry-release-id",
    "session": "x-sentry-session",
    "fence": "x-sentry-fence",
    "expires_at": "x-sentry-expires-at",
    "signature": "x-sentry-signature",
}


class CommandNotSent(Exception):
    """Nothing was transmitted: the command could no longer be sent in time."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class TransportAmbiguous(Exception):
    """The request may have reached the object; only an observation can tell."""


@dataclass(frozen=True)
class ControlCommand:
    method: str
    target: str
    action: str
    body_sha256: str
    release_id: str
    session: str
    fence: str
    command_id: str
    expires_at: int


def canonical_bytes(command: ControlCommand) -> bytes:
    """The exact bytes control.ts's ``canonicalBytes`` builds for the same command."""
    for name in ("method", "target", "action", "release_id", "session", "fence", "command_id"):
        if not FIELD.fullmatch(getattr(command, name)):
            raise ValueError(f"invalid {name}")
    if not SHA256.fullmatch(command.body_sha256):
        raise ValueError("invalid body_sha256")
    if type(command.expires_at) is not int or not 0 < command.expires_at < 2**53:
        raise ValueError("invalid expires_at")
    lines = [
        CONTROL_VERSION,
        command.method,
        command.target,
        command.action,
        command.body_sha256,
        command.release_id,
        command.session,
        command.fence,
        command.command_id,
        str(command.expires_at),
    ]
    return "\n".join(lines).encode("utf-8")


class Signer(Protocol):
    """Signs canonical bytes with the operator's Ed25519 key; never exposes the key."""

    def sign(self, message: bytes) -> bytes: ...


class Ed25519Signer:
    """A signer over an in-memory ``cryptography`` Ed25519 private key object.

    Loading the key (keychain, hardware token) is the operator CLI's job, outside
    this module; nothing here reads files, environment variables or keyrings.
    """

    def __init__(self, private_key: Any) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        if not isinstance(private_key, Ed25519PrivateKey):
            raise TypeError("an Ed25519 private key object is required")
        self._key = private_key

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)


@dataclass(frozen=True)
class ControlRequest:
    """What a transport sends: the edge route, headers and exact body bytes."""

    method: str
    path: str
    headers: Mapping[str, str]
    body: bytes


class Transport(Protocol):
    """One HTTP exchange with the edge's control route; no retries or redirects.

    Raises ``TransportAmbiguous`` for any failure after the request may have
    left, and ``CommandNotSent`` only when it certainly did not.
    """

    def send(self, request: ControlRequest, *, timeout: float) -> tuple[int, bytes]: ...


@dataclass(frozen=True)
class ControlReply:
    status: int
    body: dict[str, Any] | None

    @property
    def error(self) -> str | None:
        if self.body is None:
            return None
        value = self.body.get("error")
        return value if isinstance(value, str) else None


def body_bytes(body: Mapping[str, Any] | None) -> bytes:
    if body is None:
        return b""
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


class ControlClient:
    def __init__(
        self,
        transport: Transport,
        signer: Signer,
        clock: Any,
        *,
        release_id: str,
        timeout_seconds: float = 10.0,
    ) -> None:
        if not FIELD.fullmatch(release_id):
            raise ValueError("invalid release id")
        self.transport = transport
        self.signer = signer
        self.clock = clock
        self.release_id = release_id
        self.timeout = timeout_seconds
        self._session: str | None = None
        self._fence: int | None = None

    def bind(self, session: str, fence: int) -> None:
        if not FIELD.fullmatch(session) or type(fence) is not int or not 0 < fence < 2**31:
            raise ValueError("invalid session authority")
        self._session, self._fence = session, fence

    def send(
        self,
        *,
        method: str,
        service: str,
        name: str,
        action: str,
        body: Mapping[str, Any] | None,
        command_id: str,
        not_after: datetime,
    ) -> ControlReply:
        """Sign and send one command valid until ``not_after`` (at most 300 s ahead)."""
        if self._session is None or self._fence is None:
            raise CommandNotSent("session_not_bound")
        if method not in METHODS or service not in SERVICES:
            raise ValueError("invalid method or service")
        if not NAME.fullmatch(name) or not ACTION.fullmatch(action):
            raise ValueError("invalid target name or action")
        if (method == "GET") != (body is None):
            raise ValueError("GET carries no body; POST carries one")
        payload = body_bytes(body)
        if len(payload) > MAX_BODY_BYTES:
            raise ValueError("control body too large")
        now = self.clock.now()
        expires_at = int(not_after.timestamp())
        if expires_at <= int(now.timestamp()):
            raise CommandNotSent("command_window_passed")
        if expires_at - now.timestamp() > MAX_LIFETIME_SECONDS:
            raise ValueError("command lifetime exceeds the object's limit")
        command = ControlCommand(
            method=method,
            target=f"{service}/{name}",
            action=action,
            body_sha256=hashlib.sha256(payload).hexdigest(),
            release_id=self.release_id,
            session=self._session,
            fence=str(self._fence),
            command_id=command_id,
            expires_at=expires_at,
        )
        signature = self.signer.sign(canonical_bytes(command))
        if len(signature) != 64:
            raise ValueError("Ed25519 signatures are 64 bytes")
        headers = {
            HEADERS["command_id"]: command.command_id,
            HEADERS["release_id"]: command.release_id,
            HEADERS["session"]: command.session,
            HEADERS["fence"]: command.fence,
            HEADERS["expires_at"]: str(command.expires_at),
            HEADERS["signature"]: base64.b64encode(signature).decode("ascii"),
        }
        if body is not None:
            headers["content-type"] = "application/json"
        request = ControlRequest(method, f"/control/{service}/{name}/{action}", headers, payload)
        # Last check after any slow signing or caller work: never transmit late.
        if self.clock.now() >= not_after:
            raise CommandNotSent("command_window_passed")
        status, raw = self.transport.send(request, timeout=self.timeout)
        return ControlReply(status, _reply(raw))


def _reply(raw: bytes) -> dict[str, Any] | None:
    if not raw or len(raw) > MAX_REPLY_BYTES:
        return None
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    return value if isinstance(value, dict) else None
