"""Carry RuntimeClient's verified TLS session to SentryRuntime over a WebSocket.

On Cloudflare, a Search container reaches the runtime only by plain HTTP to
``runtime.internal``, which the Worker intercepts and relays to the runtime's
Durable Object; that object connects to the runtime container's TLS listener.
This module replaces only the TCP layer under ``httpcore``: the WebSocket
carries opaque bytes, and the TLS handshake, private CA and server-name checks
and the bearer token stay end to end, owned by ``RuntimeClient``. The relay
never sees the token and cannot inject one.

The tunnel connects for exactly one configured runtime authority, uses no
environment proxy, bounds message sizes and maps every failure to an
``httpcore`` connection, read or write error, which ``RuntimeClient`` reports
as ``RuntimeUnavailable``.
"""

from __future__ import annotations

import contextlib
import socket
import ssl
import threading
from typing import Any, Callable, Iterable
from urllib.parse import urlsplit

import httpcore
import httpx
from websockets.exceptions import ConnectionClosedOK, WebSocketException
from websockets.protocol import State
from websockets.sync.client import ClientConnection
from websockets.sync.client import connect as websocket_connect

TUNNEL_HOST = "runtime.internal"
# One TLS record is at most 16 KiB plus overhead; allow a few per message.
MAX_MESSAGE_BYTES = 256 * 1024
WRITE_CHUNK_BYTES = 64 * 1024
TLS_RECORD_BYTES = 16384
# Keepalive pings detect a vanished relay between requests; a write blocked on a
# relay that stopped reading is bounded by the write's own timeout instead.
KEEPALIVE_SECONDS = 5.0


def validate_tunnel_url(value: str) -> str:
    """Accept only ``ws://runtime.internal/<path>``: the intercepted relay address."""
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise ValueError("runtime tunnel URL is invalid") from None
    if (
        parsed.scheme != "ws"
        or parsed.hostname != TUNNEL_HOST
        or parsed.netloc != TUNNEL_HOST
        or port is not None
        or parsed.username is not None
        or not parsed.path.startswith("/")
        or parsed.query
        or parsed.fragment
        or any(not character.isalnum() and character not in "/-_." for character in parsed.path)
        or ".." in parsed.path
    ):
        raise ValueError(f"runtime tunnel URL must be ws://{TUNNEL_HOST}/<path>")
    return value


class _TunnelStream(httpcore.NetworkStream):
    """A byte stream over one WebSocket connection (binary messages only)."""

    def __init__(self, connection: ClientConnection) -> None:
        self._connection = connection
        self._buffer = b""
        self._closed = False

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        if not self._buffer and not self._closed:
            try:
                # Text frames arrive as str and are refused below; TLS is binary.
                message = self._connection.recv(timeout=timeout)
            except TimeoutError:
                raise httpcore.ReadTimeout("runtime tunnel read timed out") from None
            except ConnectionClosedOK:
                self._closed = True
                return b""
            except (WebSocketException, OSError):
                raise httpcore.ReadError("runtime tunnel closed unexpectedly") from None
            if not isinstance(message, bytes):
                raise httpcore.ReadError("runtime tunnel sent a text message")
            self._buffer = message
        data, self._buffer = self._buffer[:max_bytes], self._buffer[max_bytes:]
        return data

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        # A relay that stops reading blocks sendall inside send(); shutting the
        # socket down at the deadline turns that into a write error.
        deadline = None if timeout is None else threading.Timer(timeout, self._abort)
        if deadline is not None:
            deadline.start()
        try:
            for start in range(0, len(buffer), WRITE_CHUNK_BYTES):
                self._connection.send(bytes(buffer[start : start + WRITE_CHUNK_BYTES]))
        except (WebSocketException, OSError):
            raise httpcore.WriteError("runtime tunnel write failed") from None
        finally:
            if deadline is not None:
                deadline.cancel()

    def _abort(self) -> None:
        self._closed = True
        with contextlib.suppress(OSError):
            self._connection.socket.shutdown(socket.SHUT_RDWR)

    def close(self) -> None:
        self._closed = True
        try:
            self._connection.close()
        except (WebSocketException, OSError):
            pass

    def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.NetworkStream:
        return _TLSStream(self, ssl_context, server_hostname, timeout)

    def get_extra_info(self, info: str) -> Any:
        if info == "is_readable":
            # httpcore drops a pooled connection that reports readable: a closed
            # relay must never be reused for the next request.
            return self._closed or bool(self._buffer) or self._connection.state is not State.OPEN
        return None


class _TLSStream(httpcore.NetworkStream):
    """TLS over a non-socket stream with memory BIOs (cf. httpcore's TLS-in-TLS)."""

    def __init__(
        self,
        inner: _TunnelStream,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None,
        timeout: float | None,
    ) -> None:
        if ssl_context.verify_mode != ssl.CERT_REQUIRED or not ssl_context.check_hostname:
            raise httpcore.ConnectError("runtime tunnel requires verified TLS")
        self._inner = inner
        self._incoming = ssl.MemoryBIO()
        self._outgoing = ssl.MemoryBIO()
        self._tls = ssl_context.wrap_bio(
            self._incoming, self._outgoing, server_hostname=server_hostname
        )
        try:
            self._perform(self._tls.do_handshake, timeout)
        except ssl.SSLError:
            inner.close()
            raise httpcore.ConnectError("runtime TLS verification failed") from None

    def _perform(self, operation: Callable[[], Any], timeout: float | None) -> Any:
        while True:
            want_read = False
            try:
                result = operation()
            except ssl.SSLWantReadError:
                want_read = True
            pending = self._outgoing.read()
            if pending:
                self._inner.write(pending, timeout)
            if not want_read:
                return result
            data = self._inner.read(TLS_RECORD_BYTES, timeout)
            if data:
                self._incoming.write(data)
            else:
                self._incoming.write_eof()

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        try:
            return self._perform(lambda: self._tls.read(max_bytes), timeout)
        except ssl.SSLZeroReturnError:
            return b""
        except ssl.SSLError:
            raise httpcore.ReadError("runtime TLS session failed") from None

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        view = memoryview(buffer)
        try:
            while view:
                written = self._perform(lambda: self._tls.write(view), timeout)
                view = view[written:]
        except ssl.SSLError:
            raise httpcore.WriteError("runtime TLS session failed") from None

    def close(self) -> None:
        self._inner.close()

    def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.NetworkStream:
        raise httpcore.ConnectError("nested TLS is not supported")

    def get_extra_info(self, info: str) -> Any:
        if info == "ssl_object":
            return self._tls
        if info == "is_readable":
            return bool(self._inner.get_extra_info("is_readable")) or self._incoming.pending > 0
        return None


class TunnelBackend(httpcore.NetworkBackend):
    """Open each connection to the one configured runtime through the relay."""

    def __init__(self, tunnel_url: str, host: str, port: int) -> None:
        self._url = validate_tunnel_url(tunnel_url)
        self._authority = (host, port)

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.NetworkStream:
        if (host, port) != self._authority:
            raise httpcore.ConnectError("runtime tunnel serves only the configured runtime")
        try:
            connection = websocket_connect(
                self._url,
                proxy=None,
                compression=None,
                user_agent_header=None,
                open_timeout=timeout,
                close_timeout=timeout,
                ping_interval=KEEPALIVE_SECONDS,
                ping_timeout=KEEPALIVE_SECONDS,
                max_size=MAX_MESSAGE_BYTES,
            )
        except (WebSocketException, OSError, TimeoutError):
            raise httpcore.ConnectError("runtime tunnel unavailable") from None
        return _TunnelStream(connection)

    def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.NetworkStream:
        raise httpcore.ConnectError("runtime tunnel does not use Unix sockets")


class TunnelTransport(httpx.HTTPTransport):
    """HTTPX's transport with its connection pool opening tunnel streams."""

    def __init__(self, ssl_context: ssl.SSLContext, backend: TunnelBackend) -> None:
        super().__init__(verify=ssl_context, trust_env=False, retries=0)
        # httpx 0.28 keeps its httpcore pool in _pool; only the network backend differs.
        self._pool = httpcore.ConnectionPool(
            ssl_context=ssl_context,
            network_backend=backend,
            http1=True,
            http2=False,
            retries=0,
        )
