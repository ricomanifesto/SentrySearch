"""One-shot loopback readiness checks; all HTTP peers are disposable local fixtures."""

from contextlib import contextmanager
import json
import signal
import socket
import threading
import time

import pytest

from dev.check_worker_readiness import main
from dev import check_worker_readiness
from src.execution.supervisor import WorkerSettings, WorkerStatus


def snapshot(**changes):
    status = WorkerStatus(WorkerSettings())
    status.set_alive(True)
    status.observe({"event": "phase", "phase": "idle"})
    status.observe({"event": "ready", "value": True})
    return {**status.snapshot(), **changes}


def response(body, status=200, headers=None):
    payload = body if isinstance(body, bytes) else json.dumps(body).encode()
    fields = headers or [
        ("Content-Type", "application/json"),
        ("Content-Length", str(len(payload))),
    ]
    head = f"HTTP/1.1 {status} Fixture\r\n" + "".join(f"{k}: {v}\r\n" for k, v in fields)
    return head.encode() + b"\r\n" + payload


@contextmanager
def local_peer(payload, *, trickle=False, body_trickle=False):
    """Serve one reply, with explicit cancellation even for the slow-peer cases."""
    stop = threading.Event()
    requests = []
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(2)
    address = f"127.0.0.1:{listener.getsockname()[1]}"

    def serve():
        try:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(2)
                requests.append(connection.recv(4096))
                remaining = payload
                if body_trickle:
                    header, remaining = payload.split(b"\r\n\r\n", 1)
                    connection.sendall(header + b"\r\n\r\n")
                if trickle or body_trickle:
                    for value in remaining:
                        if stop.wait(0.03):
                            break
                        connection.sendall(bytes([value]))
                else:
                    connection.sendall(payload)
        except OSError:
            pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield address, requests
    finally:
        stop.set()
        listener.close()
        thread.join(3)
        assert not thread.is_alive()


def receipt(capsys, expected_result, ready=False):
    captured = capsys.readouterr()
    assert captured.err == ""
    assert json.loads(captured.out) == {
        "check": "worker_readiness",
        "ready": ready,
        "result": expected_result,
    }


def test_ready_snapshot_passes_and_only_readyz_is_requested(capsys, monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://untrusted.invalid:1234")
    monkeypatch.setenv("ALL_PROXY", "http://untrusted.invalid:1234")
    with local_peer(response(snapshot())) as (address, requests):
        assert main(["--address", address]) == 0
    assert requests[0].startswith(b"GET /readyz HTTP/1.1\r\n")
    assert b"Authorization:" not in requests[0]
    receipt(capsys, "ready", ready=True)


def test_live_draining_worker_is_not_ready(capsys):
    body = snapshot(ready=False, draining=True)
    with local_peer(response(body, status=503)) as (address, _):
        assert main(["--address", address]) == 1
    receipt(capsys, "unready")


@pytest.mark.parametrize(
    "changes",
    [
        {"ready": "true"},
        {"ready": 1},
        {"alive": False},
        {"draining": True},
        {"phase": "starting"},
        {"phase": "stopped"},
        {"phase": "private provider response"},
        {"error_code": "private provider response"},
        {"error_code": "runtime_unavailable"},
        {"phase": []},
        {"phase_elapsed_seconds": float("nan")},
        {"phase_budget_seconds": 0},
        {"phase_elapsed_seconds": 100, "phase_budget_seconds": 1},
    ],
)
def test_contradictory_or_malformed_ready_snapshot_fails_closed(changes, capsys):
    with local_peer(response(snapshot(**changes))) as (address, _):
        assert main(["--address", address]) == 1
    receipt(capsys, "invalid_response")


@pytest.mark.parametrize(
    "body",
    [b"not JSON: private provider response", b"[]", b"{}", b'{"ready":true,"ready":false}'],
)
def test_malformed_or_duplicate_json_is_redacted(body, capsys):
    with local_peer(response(body)) as (address, _):
        assert main(["--address", address]) == 1
    receipt(capsys, "invalid_response")


@pytest.mark.parametrize(
    "payload",
    [
        response(snapshot(), status=302),
        response(snapshot(), status=503),
        response(b"x" * 4097),
        response(b"{}", headers=[("Content-Type", "text/plain"), ("Content-Length", "2")]),
        response(b"{}", headers=[("Content-Type", "application/json")]),
        response(b"{}", headers=[("Content-Length", "2"), ("Content-Length", "2")]),
        response(b"{}", headers=[("Content-Type", "application/json"), ("Content-Length", "9")]),
        response(b"{}", headers=[("Transfer-Encoding", "chunked"), ("Content-Length", "2")]),
    ],
)
def test_http_contract_rejects_redirect_oversize_and_bad_framing(payload, capsys):
    with local_peer(payload) as (address, _):
        assert main(["--address", address]) == 1
    receipt(capsys, "invalid_response")


@pytest.mark.parametrize(
    "address",
    [
        "localhost:8081",
        "example.com:8081",
        "192.0.2.1:8081",
        "0.0.0.0:8081",
        "http://127.0.0.1:8081",
        "127.0.0.1:8081/healthz",
        "127.0.0.1:0",
        "127.0.0.1:65536",
        "127.0.0.1: 8081",
        "[::]:8081",
        "[::1%lo0]:8081",
        "127.1:8081",
        "2130706433:8081",
        "127.0.0.1:8081\nprivate-token",
    ],
)
def test_invalid_target_never_opens_a_connection(address, capsys, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("invalid target attempted network access")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    assert main(["--address", address]) == 2
    receipt(capsys, "invalid_configuration")


@pytest.mark.parametrize("budget", ["0", "-1", "11", "nan", "inf", "private-token"])
def test_invalid_deadline_is_redacted(budget, capsys):
    assert main(["--address", "127.0.0.1:8081", "--deadline-seconds", budget]) == 2
    receipt(capsys, "invalid_configuration")


def test_unknown_arguments_are_not_echoed(capsys):
    assert main(["--private-token", "must-not-be-printed"]) == 2
    receipt(capsys, "invalid_configuration")


def test_connection_failure_is_redacted(capsys, monkeypatch):
    def fail(*args, **kwargs):
        raise OSError("private endpoint and token")

    monkeypatch.setattr(socket, "create_connection", fail)
    assert main(["--address", "127.0.0.1:8081"]) == 1
    receipt(capsys, "unavailable")


def test_deadline_expiring_after_response_never_emits_ready(capsys, monkeypatch):
    @contextmanager
    def expires_at_boundary(seconds):
        yield
        raise TimeoutError

    monkeypatch.setattr(check_worker_readiness, "_deadline", expires_at_boundary)
    monkeypatch.setattr(check_worker_readiness, "_probe", lambda *args: True)
    assert main([]) == 1
    receipt(capsys, "timeout")


@pytest.mark.parametrize("body_trickle", [False, True])
def test_slow_peer_has_total_deadline_and_restores_signal_handler(capsys, body_trickle):
    previous = signal.getsignal(signal.SIGALRM)
    started = time.monotonic()
    with local_peer(response(snapshot()), trickle=not body_trickle, body_trickle=body_trickle) as (
        address,
        _,
    ):
        assert main(["--address", address, "--deadline-seconds", "0.15"]) == 1
    assert time.monotonic() - started < 1
    assert signal.getsignal(signal.SIGALRM) == previous
    assert signal.getitimer(signal.ITIMER_REAL)[0] == 0
    receipt(capsys, "timeout")
