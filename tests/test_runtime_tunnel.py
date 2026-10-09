"""RuntimeClient's TLS session carried over a WebSocket relay, against local servers only.

A local TLS HTTP server stands in for the runtime listener and a local
WebSocket server stands in for the Cloudflare relay (Worker plus Runtime
Durable Object). The relay only moves bytes; every check below is end to end.
"""

from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import ssl
import threading
import time
from typing import Iterator

import httpcore
import pytest
from websockets.sync.client import connect as real_connect
from websockets.sync.server import serve

from dev.tls_fixtures import create_certificates
from src.execution import runtime_tunnel
from src.execution.config import runtime_endpoint_from_environment
from src.execution.runtime_client import RuntimeAccessDenied, RuntimeClient, RuntimeUnavailable

TOKEN = "producer-token-" + "x" * 32
TUNNEL = "ws://runtime.internal/v1/tunnel"
RUN = {
    "run_id": "run-1",
    "state": "queued",
    "attempt": 0,
    "lease_owner": "",
    "lease_version": 0,
    "input_ref": {"report_id": "report-1"},
}


class RuntimeHandler(BaseHTTPRequestHandler):
    seen: list[dict] = []

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        RuntimeHandler.seen.append(
            {"path": self.path, "authorization": self.headers.get("Authorization")}
        )
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            self.send_response(401)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = json.dumps(RUN).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - http.server API
        pass


@contextmanager
def tls_runtime(certs) -> Iterator[int]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), RuntimeHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certs.certificate, certs.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()


class Relay:
    """Bytes in both directions between one WebSocket and one TCP connection."""

    def __init__(self, target_port: int, *, mode: str = "relay") -> None:
        self.target_port, self.mode = target_port, mode
        self.carried = bytearray()
        self.paths: list[str] = []
        self.calls: list[dict] = []

    def handler(self, websocket) -> None:
        self.paths.append(websocket.request.path)
        if self.mode == "text":
            websocket.send("not bytes")
            return
        if self.mode in {"drop", "stall"}:
            if self.mode == "stall":
                time.sleep(3)
            return
        upstream = socket.create_connection(("127.0.0.1", self.target_port))

        def upstream_to_client() -> None:
            try:
                while data := upstream.recv(65536):
                    self.carried.extend(data)
                    websocket.send(data)
                    if self.mode == "once" and b"\r\n\r\n" in bytes(self.carried):
                        # Close the tunnel after one response, as a relay restart would.
                        time.sleep(0.1)
                        websocket.close(1011)
                        return
            except Exception:
                pass
            finally:
                websocket.close()

        threading.Thread(target=upstream_to_client, daemon=True).start()
        try:
            for message in websocket:
                assert isinstance(message, bytes)
                self.carried.extend(message)
                upstream.sendall(message)
        except Exception:
            pass
        finally:
            upstream.close()


@contextmanager
def relay(target_port: int, monkeypatch, *, mode: str = "relay") -> Iterator[Relay]:
    instance = Relay(target_port, mode=mode)
    with serve(instance.handler, "127.0.0.1", 0) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        port = server.socket.getsockname()[1]

        def connect(uri, **kwargs):
            instance.calls.append({"uri": uri, **kwargs})
            # runtime.internal resolves only inside a Cloudflare container.
            return real_connect(uri.replace("runtime.internal", f"127.0.0.1:{port}"), **kwargs)

        monkeypatch.setattr(runtime_tunnel, "websocket_connect", connect)
        try:
            yield instance
        finally:
            server.shutdown()


@pytest.fixture
def certs(tmp_path):
    return create_certificates(tmp_path / "runtime", hostname="runtime.test")


def client(ca: Path, port: int, token: str | None = TOKEN) -> RuntimeClient:
    return RuntimeClient(
        f"https://runtime.test:{port}",
        bearer_token=token,
        remote=True,
        ca_file=str(ca),
        tunnel_url=TUNNEL,
    )


def test_verified_tls_session_crosses_the_relay_end_to_end(certs, monkeypatch):
    RuntimeHandler.seen.clear()
    for name in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "all_proxy"):
        monkeypatch.setenv(name, "http://192.0.2.1:9")
    with tls_runtime(certs) as port, relay(port, monkeypatch) as path:
        runtime = client(certs.ca, port)
        try:
            assert runtime.get_run("run-1").input_ref == {"report_id": "report-1"}
            assert runtime.get_run("run-1").run_id == "run-1"
        finally:
            runtime.close()
    assert RuntimeHandler.seen[0] == {"path": "/v1/runs/run-1", "authorization": f"Bearer {TOKEN}"}
    assert path.paths and set(path.paths) == {"/v1/tunnel"}
    assert path.carried and TOKEN.encode() not in bytes(path.carried)
    assert all(call["proxy"] is None and call["compression"] is None for call in path.calls)


def test_wrong_trust_or_server_name_never_sends_the_request(certs, tmp_path, monkeypatch):
    other = create_certificates(tmp_path / "other", hostname="runtime.test")
    wrong_name = create_certificates(tmp_path / "name", hostname="evil.test")
    cases = [(other.ca, certs), (wrong_name.ca, wrong_name)]
    for ca, served in cases:
        RuntimeHandler.seen.clear()
        with tls_runtime(served) as port, relay(port, monkeypatch):
            runtime = client(ca, port)
            with pytest.raises(RuntimeUnavailable):
                runtime.get_run("run-1")
            runtime.close()
        assert RuntimeHandler.seen == []


def test_missing_token_is_refused_by_the_runtime_not_the_relay(certs, monkeypatch):
    with tls_runtime(certs) as port, relay(port, monkeypatch):
        runtime = RuntimeClient(
            f"https://runtime.test:{port}",
            bearer_token="worker-token-" + "y" * 32,
            remote=True,
            ca_file=str(certs.ca),
            tunnel_url=TUNNEL,
        )
        with pytest.raises(RuntimeAccessDenied):
            runtime.get_run("run-1")
        runtime.close()


@pytest.mark.parametrize("mode", ["drop", "text", "stall"])
def test_relay_failures_become_unavailable(certs, monkeypatch, mode):
    with tls_runtime(certs) as port, relay(port, monkeypatch, mode=mode):
        runtime = client(certs.ca, port)
        started = time.monotonic()
        with pytest.raises(RuntimeUnavailable):
            runtime.get_run("run-1")
        assert time.monotonic() - started < 10
        runtime.close()


def test_relay_unreachable_is_unavailable(certs, monkeypatch):
    def refuse(uri, **kwargs):
        raise ConnectionRefusedError()

    monkeypatch.setattr(runtime_tunnel, "websocket_connect", refuse)
    runtime = client(certs.ca, 8443)
    with pytest.raises(RuntimeUnavailable):
        runtime.get_run("run-1")
    runtime.close()


def test_the_tunnel_connects_only_to_the_configured_runtime(monkeypatch):
    def unreachable(uri, **kwargs):
        raise AssertionError("must not connect")

    monkeypatch.setattr(runtime_tunnel, "websocket_connect", unreachable)
    backend = runtime_tunnel.TunnelBackend(TUNNEL, "runtime.test", 8443)
    for host, port in (("other.test", 8443), ("runtime.test", 443), ("127.0.0.1", 8443)):
        with pytest.raises(httpcore.ConnectError):
            backend.connect_tcp(host, port)
    with pytest.raises(httpcore.ConnectError):
        backend.connect_unix_socket("/var/run/docker.sock")


def test_plaintext_or_unverified_tls_is_refused_on_the_stream():
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    class Silent(runtime_tunnel._TunnelStream):
        def __init__(self) -> None:
            pass

        def close(self) -> None:
            pass

    with pytest.raises(httpcore.ConnectError):
        runtime_tunnel._TLSStream(Silent(), context, "runtime.test", 1)


@pytest.mark.parametrize(
    "url",
    [
        "wss://runtime.internal/v1/tunnel",
        "http://runtime.internal/v1/tunnel",
        "ws://runtime.internal:8080/v1/tunnel",
        "ws://evidence.internal/v1/tunnel",
        "ws://user@runtime.internal/v1/tunnel",
        "ws://runtime.internal/v1/tunnel?x=1",
        "ws://runtime.internal/v1/../admin",
        "ws://runtime.internal",
        "ws://runtime.internal/v1/tun nel",
    ],
)
def test_tunnel_url_must_be_the_relay_address(url):
    with pytest.raises(ValueError):
        runtime_tunnel.validate_tunnel_url(url)


def test_client_and_configuration_require_remote_verified_https(certs):
    with pytest.raises(ValueError):
        RuntimeClient("http://127.0.0.1:8080", tunnel_url=TUNNEL)
    with pytest.raises(ValueError):
        RuntimeClient("https://runtime.test", bearer_token=TOKEN, remote=True, tunnel_url=TUNNEL)
    remote = {
        "SENTRYRUNTIME_URL": "https://runtime.test:8443",
        "SENTRYRUNTIME_CA_FILE": str(certs.ca),
        "SENTRYRUNTIME_TUNNEL_URL": TUNNEL,
    }
    assert runtime_endpoint_from_environment(remote).tunnel_url == TUNNEL
    for broken in (
        {**remote, "SENTRYRUNTIME_CA_FILE": ""},
        {"SENTRYRUNTIME_LOCAL_URL": "http://127.0.0.1:8080", "SENTRYRUNTIME_TUNNEL_URL": TUNNEL},
        {**remote, "SENTRYRUNTIME_TUNNEL_URL": "ws://example.com/v1/tunnel"},
    ):
        with pytest.raises(ValueError):
            runtime_endpoint_from_environment(broken)
    assert (
        runtime_endpoint_from_environment({**remote, "SENTRYRUNTIME_TUNNEL_URL": ""}).tunnel_url
        is None
    )


def test_text_frames_are_refused_by_the_stream_itself():
    class TextConnection:
        state = None

        def recv(self, timeout=None):
            return "not binary"

    stream = runtime_tunnel._TunnelStream(TextConnection())  # ty: ignore[invalid-argument-type]
    with pytest.raises(httpcore.ReadError):
        stream.read(10)


def test_a_write_to_a_relay_that_stopped_reading_fails_within_its_timeout():
    # A peer that completes the upgrade and then never reads again (a library
    # server would keep draining frames into its own queue).
    import base64
    import hashlib
    import socket as socket_module

    listener = socket_module.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    accepted: list = []

    def upgrade_then_stall() -> None:
        peer, _ = listener.accept()
        accepted.append(peer)
        request = b""
        while b"\r\n\r\n" not in request:
            request += peer.recv(4096)
        key = next(
            line.split(b":", 1)[1].strip()
            for line in request.split(b"\r\n")
            if line.lower().startswith(b"sec-websocket-key:")
        )
        accept = base64.b64encode(
            hashlib.sha1(key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest()
        )
        peer.sendall(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
            b"Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept + b"\r\n\r\n"
        )

    threading.Thread(target=upgrade_then_stall, daemon=True).start()
    port = listener.getsockname()[1]
    connection = real_connect(
        f"ws://127.0.0.1:{port}/v1/tunnel", proxy=None, max_size=runtime_tunnel.MAX_MESSAGE_BYTES
    )
    stream = runtime_tunnel._TunnelStream(connection)
    started = time.monotonic()
    try:
        with pytest.raises(httpcore.WriteError):
            stream.write(b"x" * (64 * 1024 * 1024), timeout=1.0)
        assert time.monotonic() - started < 5
        assert stream.get_extra_info("is_readable") is True
    finally:
        stream.close()
        for peer in accepted:
            peer.close()
        listener.close()


def test_a_closed_pooled_tunnel_is_not_reused(certs, monkeypatch):
    with tls_runtime(certs) as port, relay(port, monkeypatch, mode="once") as path:
        runtime = client(certs.ca, port)
        try:
            assert runtime.get_run("run-1").run_id == "run-1"
            time.sleep(0.5)  # the relay has closed the first tunnel
            assert runtime.get_run("run-1").run_id == "run-1"
        finally:
            runtime.close()
    assert len(path.paths) == 2
