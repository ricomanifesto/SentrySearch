"""Readiness receipts posted to the Cloudflare intake, against a local server only."""

from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import json
import os
import threading
import time
from typing import Callable, Iterator

import pytest

from src.execution.readiness_receipts import (
    RECEIPT_MARKER,
    DescriptorSink,
    HttpReceiptSink,
    ReadinessReceipts,
    TeeSink,
    receipt_url_from_environment,
)

RELEASE = "0b6f7d2e-5a64-4c43-9d0b-0a3f4c6e8d21"
SNAPSHOT = {"alive": True, "ready": True, "draining": False, "phase": "idle", "error_code": None}


class Intake(BaseHTTPRequestHandler):
    received: list[tuple[str, dict]] = []
    status = 204
    delay = 0.0

    def do_POST(self) -> None:  # noqa: N802 - http.server API
        time.sleep(Intake.delay)
        body = self.rfile.read(int(self.headers["Content-Length"]))
        Intake.received.append((self.path, json.loads(body)))
        self.send_response(Intake.status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - http.server API
        pass


@contextmanager
def intake(
    status: int = 204, delay: float = 0.0
) -> Iterator[tuple[Callable[..., http.client.HTTPConnection], list[str]]]:
    Intake.received, Intake.status, Intake.delay = [], status, delay
    server = ThreadingHTTPServer(("127.0.0.1", 0), Intake)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    hosts: list[str] = []

    def connection(host, port, timeout):
        hosts.append(f"{host}:{port}")
        # evidence.internal resolves only inside a Cloudflare container.
        return http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=timeout)

    try:
        yield connection, hosts
    finally:
        server.shutdown()
        server.server_close()


def test_receipts_reach_both_stdout_and_the_intake():
    read_fd, write_fd = os.pipe()
    with intake() as (connection, hosts):
        sink = TeeSink(
            DescriptorSink(write_fd),
            HttpReceiptSink("http://evidence.internal/v1/receipts", connection=connection),
        )
        receipts = ReadinessReceipts(RELEASE, sink)
        receipts.observe(SNAPSHOT)
        receipts.close({**SNAPSHOT, "phase": "stopped", "ready": False})
    os.close(write_fd)
    stdout = os.read(read_fd, 65536).decode()
    os.close(read_fd)
    lines = [
        json.loads(line.split(" ", 1)[1])
        for line in stdout.splitlines()
        if line.startswith(RECEIPT_MARKER)
    ]
    posted = [body for path, body in Intake.received if path == "/v1/receipts"]
    assert [receipt["sequence"] for receipt in lines] == [1, 2]
    assert posted == lines
    assert set(hosts) == {"evidence.internal:80"}


def test_a_refused_or_slow_intake_leaves_gaps_without_stalling(monkeypatch):
    read_fd, write_fd = os.pipe()
    with intake(status=500) as (connection, _):
        sink = TeeSink(
            DescriptorSink(write_fd),
            HttpReceiptSink("http://evidence.internal/r", connection=connection),
        )
        receipts = ReadinessReceipts(RELEASE, sink, interval_seconds=0)
        for _ in range(3):
            receipts.observe(SNAPSHOT)
        receipts.close({**SNAPSHOT, "phase": "stopped"})
    os.close(write_fd)
    stdout = os.read(read_fd, 65536).decode()
    os.close(read_fd)
    # Stdout still carries every receipt even though the intake refused them all.
    assert stdout.count(RECEIPT_MARKER) == 4
    with intake(delay=5.0) as (connection, _):
        sink = HttpReceiptSink("http://evidence.internal/r", connection=connection, timeout=0.2)
        receipts = ReadinessReceipts(RELEASE, sink)
        started = time.monotonic()
        receipts.observe(SNAPSHOT)
        receipts.close({**SNAPSHOT, "phase": "stopped"}, timeout=0.5)
        assert time.monotonic() - started < 2.0


def test_the_intake_sink_accepts_only_receipt_lines():
    with intake() as (connection, _):
        with pytest.raises(ValueError):
            HttpReceiptSink("http://evidence.internal/r", connection=connection).write("hello\n")
        assert Intake.received == []


@pytest.mark.parametrize(
    "url",
    [
        "https://evidence.internal/v1/receipts",
        "http://evidence.internal:8080/v1/receipts",
        "http://runtime.internal/v1/receipts",
        "http://evidence.internal/",
        "http://evidence.internal/v1/receipts?x=1",
        "http://evidence.internal/V1/Receipts",
        "http://user@evidence.internal/v1",
    ],
)
def test_receipt_url_must_be_the_intercepted_intake(url):
    with pytest.raises(ValueError):
        receipt_url_from_environment({"SENTRYSEARCH_RECEIPT_URL": url})


def test_receipt_url_is_optional():
    assert receipt_url_from_environment({}) is None
    assert receipt_url_from_environment(
        {"SENTRYSEARCH_RECEIPT_URL": "http://evidence.internal/v1/receipts"}
    )


def test_worker_entrypoint_requires_a_release_for_the_intake(monkeypatch):
    from dev import run_runtime_worker

    monkeypatch.delenv("SENTRYSEARCH_RELEASE_ID", raising=False)
    monkeypatch.setenv("SENTRYSEARCH_RECEIPT_URL", "http://evidence.internal/v1/receipts")
    monkeypatch.setattr(run_runtime_worker, "parse_args", lambda: type("A", (), {})())
    monkeypatch.setattr(run_runtime_worker, "WorkerSettings", lambda **kwargs: object())
    with pytest.raises(SystemExit, match="requires SENTRYSEARCH_RELEASE_ID"):
        run_runtime_worker.main()


def test_a_malformed_intake_reply_loses_only_that_receipt():
    class Broken:
        def __init__(self, *args, **kwargs):
            pass

        def request(self, *args, **kwargs):
            pass

        def getresponse(self):
            raise http.client.BadStatusLine("garbage")

        def close(self):
            pass

    read_fd, write_fd = os.pipe()
    intake = HttpReceiptSink(
        "http://evidence.internal/r", connection=Broken  # ty: ignore[invalid-argument-type]
    )
    sink = TeeSink(DescriptorSink(write_fd), intake)
    receipts = ReadinessReceipts(RELEASE, sink, interval_seconds=0)
    for _ in range(3):
        receipts.observe(SNAPSHOT)
    receipts.close({**SNAPSHOT, "phase": "stopped"})
    os.close(write_fd)
    stdout = os.read(read_fd, 65536).decode()
    os.close(read_fd)
    assert stdout.count(RECEIPT_MARKER) == 4


def test_a_trickling_intake_reply_is_cut_off_at_the_timeout():
    import socket as socket_module

    server = socket_module.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)

    def trickle() -> None:
        connection, _ = server.accept()
        connection.recv(65536)
        for byte in b"HTTP/1.1 204 No Content\r\n\r\n":
            time.sleep(0.4)
            try:
                connection.sendall(bytes([byte]))
            except OSError:
                break
        connection.close()

    threading.Thread(target=trickle, daemon=True).start()

    def connection(host, port, timeout):
        return http.client.HTTPConnection("127.0.0.1", server.getsockname()[1], timeout=timeout)

    sink = HttpReceiptSink("http://evidence.internal/r", connection=connection, timeout=1.0)
    started = time.monotonic()
    with pytest.raises(OSError):
        sink.write(f"{RECEIPT_MARKER} {{}}\n")
    assert time.monotonic() - started < 2.5
    server.close()
