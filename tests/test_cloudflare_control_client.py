"""Signed control client: canonical bytes, signing, sending and its refusals."""

from __future__ import annotations

import ast
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

from typing import Any

import pytest

from release_cloudflare import control_client
from release_cloudflare.control_client import (
    CommandNotSent,
    ControlClient,
    ControlCommand,
    Ed25519Signer,
    TransportAmbiguous,
    canonical_bytes,
)
from tests.cloudflare_control_vectors import FIXTURE, RELEASE, build, private_key
from tests.release_fakes import FakeClock


class Transport:
    def __init__(self, reply=(200, b'{"ok":true}'), error: Exception | None = None):
        self.reply = reply
        self.error = error
        self.sent = []

    def send(self, request, *, timeout):
        self.sent.append((request, timeout))
        if self.error is not None:
            raise self.error
        return self.reply


class SlowSigner:
    """Signs correctly but lets the clock run on while doing so."""

    def __init__(self, clock: FakeClock, seconds: float) -> None:
        self.clock, self.seconds = clock, seconds
        self.inner = Ed25519Signer(private_key())

    def sign(self, message: bytes) -> bytes:
        self.clock.advance(seconds=self.seconds)
        return self.inner.sign(message)


def client(transport=None, signer=None, clock=None, *, bind=True):
    clock = clock or FakeClock()
    made = ControlClient(
        transport or Transport(), signer or Ed25519Signer(private_key()), clock, release_id=RELEASE
    )
    if bind:
        made.bind("session-a", 1)
    return made, clock


def send(made, clock, *, seconds=60, **changes):
    arguments = {
        "method": "POST",
        "service": "worker",
        "name": "worker-0",
        "action": "start",
        "body": {"release_id": RELEASE},
        "command_id": "start-worker-" + RELEASE,
        "expires_at": clock.now() + timedelta(seconds=seconds),
        **changes,
    }
    return made.send(**arguments)


def test_the_committed_cross_language_vectors_are_what_python_builds():
    assert json.loads(FIXTURE.read_text()) == build()


def changed(command: ControlCommand, field: str, value: Any) -> ControlCommand:
    """A copy with one field replaced by a deliberately invalid value."""
    values: dict[str, Any] = {**command.__dict__, field: value}
    return ControlCommand(**values)


def test_canonical_bytes_are_ten_fixed_lines_and_refuse_injected_newlines():
    command = ControlCommand(
        "POST", "api/api-0", "stop", "0" * 64, RELEASE, "session-a", "2", "stop-x", 1_800_000_000
    )
    lines = canonical_bytes(command).decode().split("\n")
    assert lines == [
        "sentry.control.v1", "POST", "api/api-0", "stop", "0" * 64, RELEASE, "session-a", "2",
        "stop-x", "1800000000",
    ]  # fmt: skip
    for field in ("target", "session", "fence", "command_id", "release_id", "action", "method"):
        for bad in ("a\nb", "", "x" * 129, "a b", "ä"):
            with pytest.raises(ValueError):
                canonical_bytes(changed(command, field, bad))
    for bad in ("0" * 63, "G" * 64):
        with pytest.raises(ValueError):
            canonical_bytes(changed(command, "body_sha256", bad))
    for bad in (0, -1, 2**53, 1.5, True):
        with pytest.raises(ValueError):
            canonical_bytes(changed(command, "expires_at", bad))


def test_a_sent_command_is_signed_over_exactly_its_headers_target_and_body():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    transport = Transport()
    made, clock = client(transport)
    reply = send(made, clock)
    assert (reply.status, reply.body) == (200, {"ok": True})
    [(request, timeout)] = transport.sent
    assert (request.method, request.path, timeout) == (
        "POST",
        "/control/worker/worker-0/start",
        10.0,
    )
    assert request.body == b'{"release_id":"' + RELEASE.encode() + b'"}'
    headers = request.headers
    expires = int((clock.now() + timedelta(seconds=60)).timestamp())
    command = ControlCommand(
        "POST",
        "worker/worker-0",
        "start",
        hashlib.sha256(request.body).hexdigest(),
        RELEASE,
        "session-a",
        "1",
        "start-worker-" + RELEASE,
        expires,
    )
    assert headers["x-sentry-expires-at"] == str(expires)
    assert (headers["x-sentry-session"], headers["x-sentry-fence"]) == ("session-a", "1")
    public = Ed25519PublicKey.from_public_bytes(
        base64.b64decode(json.loads(FIXTURE.read_text())["publicKey"])
    )
    public.verify(base64.b64decode(headers["x-sentry-signature"]), canonical_bytes(command))


def test_nothing_is_sent_without_a_bound_session_or_after_the_window():
    transport = Transport()
    made, clock = client(transport, bind=False)
    with pytest.raises(CommandNotSent) as error:
        send(made, clock)
    assert error.value.code == "session_not_bound"
    made.bind("session-a", 1)
    with pytest.raises(CommandNotSent):
        send(made, clock, seconds=0)
    with pytest.raises(ValueError):
        send(made, clock, seconds=301)
    assert transport.sent == []


def test_the_window_is_rechecked_after_signing_so_a_slow_caller_never_sends_late():
    clock = FakeClock()
    transport = Transport()
    made, _ = client(transport, SlowSigner(clock, 61), clock)
    with pytest.raises(CommandNotSent) as error:
        send(made, clock, seconds=60)
    assert error.value.code == "command_window_passed"
    assert transport.sent == []


def test_a_transport_failure_is_ambiguous_and_never_retried():
    transport = Transport(error=TransportAmbiguous())
    made, clock = client(transport)
    with pytest.raises(TransportAmbiguous):
        send(made, clock)
    assert len(transport.sent) == 1


@pytest.mark.parametrize(
    "raw, body",
    [(b"", None), (b"not json", None), (b"[1]", None), (b'{"error":"superseded"}', None)],
)
def test_replies_are_parsed_strictly(raw, body):
    made, clock = client(Transport(reply=(409, raw)))
    reply = send(made, clock)
    assert reply.status == 409
    if raw.startswith(b"{"):
        assert reply.error == "superseded"
    else:
        assert reply.body is body


@pytest.mark.parametrize(
    "changes",
    [
        {"method": "GET"},
        {"method": "DELETE"},
        {"service": "edge"},
        {"name": "Worker-0"},
        {"action": "start/../stop"},
        {"body": {"blob": "x" * 20_000}},
    ],
)
def test_malformed_requests_are_refused_before_signing(changes):
    transport = Transport()
    made, clock = client(transport)
    with pytest.raises(ValueError):
        send(made, clock, **changes)
    assert transport.sent == []


def test_session_authority_is_validated():
    made, _ = client(bind=False)
    for session, fence in (("a b", 1), ("s", 0), ("s", "1"), ("s", 2**31)):
        with pytest.raises(ValueError):
            made.bind(session, fence)


def test_the_client_module_has_no_network_or_credential_access_of_its_own():
    source = Path(control_client.__file__).read_text()
    imported = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    assert imported <= {"__future__", "base64", "collections", "dataclasses", "datetime",
                        "hashlib", "json", "re", "typing", "cryptography"}  # fmt: skip
    assert "getenv" not in source and "open(" not in source


def test_the_signed_expiry_is_exactly_the_journaled_command_expiry():
    """The intent's command_expires_at (ISO, whole seconds) is the signed expiry."""
    transport = Transport()
    made, clock = client(transport)
    journaled = "2026-10-07T12:02:00Z"
    send(made, clock, expires_at=datetime.fromisoformat(journaled))
    [(request, _)] = transport.sent
    assert request.headers["x-sentry-expires-at"] == str(
        int(datetime(2026, 10, 7, 12, 2, tzinfo=timezone.utc).timestamp())
    )
    for bad in (clock.now() + timedelta(seconds=60, microseconds=1), datetime(2026, 10, 7, 12, 2)):
        with pytest.raises(ValueError):
            send(made, clock, expires_at=bad)


def test_nothing_is_sent_at_or_after_the_operation_deadline():
    transport = Transport()
    made, clock = client(transport)
    with pytest.raises(CommandNotSent):
        send(made, clock, send_before=clock.now())
    clock_two = FakeClock()
    slow = Transport()
    made_two, _ = client(slow, SlowSigner(clock_two, 20), clock_two)
    with pytest.raises(CommandNotSent):
        send(made_two, clock_two, send_before=clock_two.now() + timedelta(seconds=10))
    assert transport.sent == [] and slow.sent == []
    send(made, clock, send_before=clock.now() + timedelta(seconds=30))
    assert len(transport.sent) == 1
