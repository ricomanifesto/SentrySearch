"""Operational observers against local fixture servers on loopback.

A fixture HTTPS server stands in for the Runtime (private CA, the expected SAN,
token-protected probes) and a plain HTTP server for the API. Name resolution is
injected, so the test controls which single address "DNS" returns. Nothing here
touches a network beyond loopback.
"""

from __future__ import annotations

import json
import socket
import ssl
import threading
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from dev.tls_fixtures import create_certificates
from release_tools import observe
from release_tools.receipt import parse_receipt
from tests.test_release_migration_job import _Metadata, TASK

RELEASE = "0b9f7c1e-4d2a-4f6b-9a3e-2c1d0e9f8a7b"
HOST = "runtime.staging.internal"
TOKEN = "fixture-probe-token-0123456789abcdef"


class Behaviour:
    def __init__(self) -> None:
        self.status = {"/healthz": (200, "alive"), "/readyz": (200, "ready"), "/": (200, "operational"),
                       "/api/ready": (200, "ready"), "/api/reports": (503, "unavailable")}  # fmt: skip
        self.require_token = True
        self.requests: list[str] = []
        # Path -> a raw body sent instead of the JSON status.
        self.bodies: dict[str, bytes] = {}


def handler(behaviour: Behaviour, *, runtime: bool):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - http.server API
            behaviour.requests.append(self.path)
            if (
                runtime
                and behaviour.require_token
                and self.headers.get("Authorization") != (f"Bearer {TOKEN}")
            ):
                code, status = 401, "unauthorized"
            else:
                code, status = behaviour.status.get(self.path, (404, "missing"))
            body = behaviour.bodies.get(self.path) or json.dumps({"status": status}).encode()
            self.send_response(code)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            pass

    return Handler


@pytest.fixture
def metadata():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Metadata)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}/v4/fixture"
    server.shutdown()


def serve(behaviour: Behaviour, *, cert=None) -> int:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler(behaviour, runtime=cert is not None))
    if cert is not None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert.certificate, cert.key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server.server_address[1]


def owner_only(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    path.chmod(0o400)
    return path


@pytest.fixture
def material(tmp_path, monkeypatch):
    cert = create_certificates(tmp_path / "runtime", hostname=HOST)
    monkeypatch.setattr(observe, "RUNTIME_CA", owner_only(tmp_path / "runtime-ca.pem",
                                                          cert.ca.read_bytes()))  # fmt: skip
    monkeypatch.setattr(observe, "PROBE_TOKEN", owner_only(tmp_path / "probe-token",
                                                           f"{TOKEN}\n".encode()))  # fmt: skip
    return cert


def answers(*addresses: str):
    def resolve(host: str, port: int) -> list:
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port)) for address in addresses
        ]

    return resolve


def environment(metadata: str, port: int, *, check: str = "runtime-observe", host: str = HOST,
                **changes: str) -> dict[str, str]:  # fmt: skip
    base = {
        "RELEASE_ID": RELEASE,
        "RELEASE_CHECK_ID": check,
        "RELEASE_NOT_AFTER": (datetime.now(UTC) + timedelta(minutes=10)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "RELEASE_CHECK_BUDGET_SECONDS": "300",
        "RELEASE_TARGET_HOST": host,
        "RELEASE_TARGET_PORT": str(port),
        "ECS_CONTAINER_METADATA_URI_V4": metadata,
    }
    base.update(changes)
    return base


def observed(capsys, command: str, env: dict[str, str], resolve) -> tuple[int, dict | None]:
    code = observe.main([command], env, resolve=resolve)
    out = capsys.readouterr().out.splitlines()
    assert len(out) <= 1, out
    assert TOKEN not in "\n".join(out)
    return code, parse_receipt(out, "operational") if out else None


def test_runtime_observer_passes_against_the_verified_target(material, metadata, capsys):
    behaviour = Behaviour()
    port = serve(behaviour, cert=material)
    code, receipt = observed(capsys, "observe-runtime", environment(metadata, port),
                             answers("127.0.0.1"))  # fmt: skip
    assert code == 0
    assert receipt == {
        "schema": "sentry.operational.v1",
        "release_id": RELEASE,
        "check_id": "runtime-observe",
        "task_arn": TASK,
        "status": "passed",
        "result": {"target": "runtime", "host": HOST, "peer": "127.0.0.1", "port": str(port),
                   "tls": "verified", "checks": "healthz,readyz", "denials": "no_token,wrong_ca"},
    }  # fmt: skip
    assert behaviour.requests == ["/healthz", "/readyz", "/readyz"]


def failure(capsys, command, env, resolve) -> str:
    code, receipt = observed(capsys, command, env, resolve)
    assert code != 0 and receipt is not None and receipt["status"] == "failed", (code, receipt)
    return receipt["result"]["reason"]


def test_a_certificate_for_another_name_or_from_another_ca_is_refused(material, metadata, capsys,
                                                                      tmp_path):  # fmt: skip
    wrong_name = create_certificates(tmp_path / "other-name", hostname="api.staging.internal")
    port = serve(Behaviour(), cert=wrong_name)
    assert failure(capsys, "observe-runtime", environment(metadata, port),
                   answers("127.0.0.1")) == "tls_untrusted"  # fmt: skip
    other_ca = create_certificates(tmp_path / "other-ca", hostname=HOST)
    port = serve(Behaviour(), cert=other_ca)
    assert failure(capsys, "observe-runtime", environment(metadata, port),
                   answers("127.0.0.1")) == "tls_untrusted"  # fmt: skip


def test_plaintext_where_tls_is_required_is_refused(material, metadata, capsys):
    port = serve(Behaviour())  # plain HTTP
    assert failure(capsys, "observe-runtime", environment(metadata, port),
                   answers("127.0.0.1")) == "target_unreachable"  # fmt: skip


@pytest.mark.parametrize(
    "configure, reason",
    [
        (lambda b: setattr(b, "require_token", False), "unauthenticated_accepted"),
        (lambda b: b.status.update({"/readyz": (503, "unready")}), "readyz_failed"),
        (lambda b: b.status.update({"/healthz": (200, "starting")}), "healthz_failed"),
    ],
)
def test_runtime_answers_other_than_exactly_required_fail(material, metadata, capsys, configure,
                                                          reason):  # fmt: skip
    behaviour = Behaviour()
    configure(behaviour)
    port = serve(behaviour, cert=material)
    assert failure(capsys, "observe-runtime", environment(metadata, port),
                   answers("127.0.0.1")) == reason  # fmt: skip


def test_a_publicly_trusted_certificate_fails_the_wrong_ca_denial(material, metadata, capsys,
                                                                  monkeypatch):  # fmt: skip
    port = serve(Behaviour(), cert=material)
    original = ssl.create_default_context
    ca_text = observe.RUNTIME_CA.read_text()

    def everything_trusted(*args, **kwargs):
        return original(cadata=ca_text) if not kwargs else original(*args, **kwargs)

    monkeypatch.setattr(observe.ssl, "create_default_context", everything_trusted)
    assert failure(capsys, "observe-runtime", environment(metadata, port),
                   answers("127.0.0.1")) == "wrong_ca_accepted"  # fmt: skip


@pytest.mark.parametrize(
    "resolve, reason",
    [(answers(), "target_unresolved"), (answers("127.0.0.1", "127.0.0.2"), "target_ambiguous")],
)
def test_dns_must_name_exactly_one_peer(material, metadata, capsys, resolve, reason):
    port = serve(Behaviour(), cert=material)
    assert failure(capsys, "observe-runtime", environment(metadata, port), resolve) == reason


def test_missing_or_shared_material_fails_before_any_request(material, metadata, capsys):
    behaviour = Behaviour()
    port = serve(behaviour, cert=material)
    observe.PROBE_TOKEN.chmod(0o444)
    assert failure(capsys, "observe-runtime", environment(metadata, port),
                   answers("127.0.0.1")) == "material_invalid"  # fmt: skip
    assert behaviour.requests == []


def test_api_observer_requires_liveness_readiness_and_a_refused_protected_route(metadata, capsys):
    behaviour = Behaviour()
    port = serve(behaviour)
    env = environment(metadata, port, check="api-observe", host="api.staging.internal")
    code, receipt = observed(capsys, "observe-api", env, answers("127.0.0.1"))
    assert code == 0 and receipt is not None
    assert receipt["result"] == {"target": "api", "host": "api.staging.internal",
                                 "peer": "127.0.0.1", "port": str(port), "tls": "none",
                                 "checks": "liveness,api_ready",
                                 "denials": "unauthenticated:503"}  # fmt: skip
    behaviour.status["/api/reports"] = (200, "listing")
    assert failure(capsys, "observe-api", env, answers("127.0.0.1")) == "unauthenticated_accepted"
    behaviour.status.update({"/api/reports": (401, "unauthorized"), "/api/ready": (503, "unready")})
    assert failure(capsys, "observe-api", env, answers("127.0.0.1")) == "ready_failed"


@pytest.mark.parametrize(
    "changes",
    [
        {"RELEASE_TARGET_HOST": "10.0.0.5"},
        {"RELEASE_TARGET_HOST": "runtime"},
        {"RELEASE_TARGET_HOST": "Runtime.Staging.Internal"},
        {"RELEASE_TARGET_PORT": "0"},
        {"RELEASE_CHECK_ID": ""},
        {"RELEASE_CHECK_BUDGET_SECONDS": "30"},
    ],
)
def test_configuration_errors_fail_before_any_request(metadata, capsys, changes):
    behaviour = Behaviour()
    port = serve(behaviour)
    code, receipt = observed(capsys, "observe-api", environment(metadata, port, **changes),
                             answers("127.0.0.1"))  # fmt: skip
    assert code == observe.EXIT_CONFIG and receipt is None and behaviour.requests == []


def test_an_oversized_answer_fails_without_being_read_further(material, metadata, capsys):
    behaviour = Behaviour()
    behaviour.bodies["/healthz"] = b'{"status":"alive","pad":"' + b"x" * 8192 + b'"}'
    port = serve(behaviour, cert=material)
    assert failure(capsys, "observe-runtime", environment(metadata, port),
                   answers("127.0.0.1")) == "response_too_large"  # fmt: skip


def test_a_connection_that_reaches_another_peer_fails(material, metadata, capsys, monkeypatch):
    """DNS named one address; the socket reached another (a redirect): no receipt passes."""
    port = serve(Behaviour(), cert=material)
    original = socket.create_connection

    def redirected(address, *args, **kwargs):
        return original(("127.0.0.1", address[1]), *args, **kwargs)

    monkeypatch.setattr(observe.socket, "create_connection", redirected)
    assert failure(capsys, "observe-runtime", environment(metadata, port),
                   answers("127.0.0.2")) == "peer_changed"  # fmt: skip


def test_the_check_ends_inside_its_deadline(material, metadata, capsys):
    behaviour = Behaviour()
    port = serve(behaviour, cert=material)
    start = datetime.now(UTC)
    readings = iter([start, start, start + timedelta(seconds=296)])

    def now() -> datetime:
        return next(readings, start + timedelta(seconds=296))

    # 300 s budget less the 5 s stop grace: no request starts after 295 s.
    code = observe.main(["observe-runtime"], environment(metadata, port), now=now,
                        resolve=answers("127.0.0.1"))  # fmt: skip
    out = capsys.readouterr().out.splitlines()
    assert code == observe.EXIT_OBSERVATION
    receipt = parse_receipt(out, "operational")
    assert receipt is not None and receipt["result"] == {"reason": "deadline_exceeded"}
    assert behaviour.requests == ["/healthz"]
    # Too little time at start: no request and no receipt.
    late = (start + timedelta(seconds=4)).strftime("%Y-%m-%dT%H:%M:%SZ")
    code, receipt = observed(capsys, "observe-runtime",
                             environment(metadata, port, RELEASE_NOT_AFTER=late),
                             answers("127.0.0.1"))  # fmt: skip
    assert (code, receipt) == (observe.EXIT_DEADLINE_EXPIRED, None)
    assert behaviour.requests == ["/healthz"]


@pytest.mark.parametrize("token", [b"", b"\n", "t\u00f6ken".encode(), b"two words"])
def test_an_unusable_probe_token_fails_before_any_request(material, metadata, capsys, token):
    behaviour = Behaviour()
    port = serve(behaviour, cert=material)
    observe.PROBE_TOKEN.chmod(0o600)
    observe.PROBE_TOKEN.write_bytes(token)
    observe.PROBE_TOKEN.chmod(0o400)
    assert failure(capsys, "observe-runtime", environment(metadata, port),
                   answers("127.0.0.1")) == "material_invalid"  # fmt: skip
    assert behaviour.requests == []


def test_without_a_task_identity_nothing_is_requested(metadata, capsys):
    behaviour = Behaviour()
    port = serve(behaviour)
    env = environment(metadata, port, check="api-observe", host="api.staging.internal")
    env["ECS_CONTAINER_METADATA_URI_V4"] = "http://192.0.2.1/v4/x"
    code, receipt = observed(capsys, "observe-api", env, answers("127.0.0.1"))
    assert (code, receipt, behaviour.requests) == (observe.EXIT_TASK_IDENTITY, None, [])


def test_the_manifests_own_check_ids_run_in_the_real_observers(material, metadata, capsys):
    """Each observer check id the manifest approves is one the observer accepts and echoes."""
    from release.manifest import ObserverCheck, load_manifest
    from release.machine import evaluate_observation
    from tests.release_fakes import encode, manifest_document

    manifest = load_manifest(encode(manifest_document())).manifest
    checks = {c.target: c for c in manifest.operational_checks if isinstance(c, ObserverCheck)}
    runtime = checks["runtime"]
    port = serve(Behaviour(), cert=material)
    env = environment(metadata, port, check=runtime.id, RELEASE_ID=manifest.release_id)
    code, observed = observed_receipt(capsys, "observe-runtime", env)
    assert code == 0 and observed is not None and observed["check_id"] == runtime.id
    api = checks["api"]
    port = serve(Behaviour())
    env = environment(metadata, port, check=api.id, host="api.staging.internal",
                      RELEASE_ID=manifest.release_id)  # fmt: skip
    code, observed = observed_receipt(capsys, "observe-api", env)
    assert code == 0 and observed is not None and observed["check_id"] == api.id
    # The controller's own evaluation accepts the envelope apart from the target it names.
    assert evaluate_observation(api, release_id=manifest.release_id, task_arn=TASK,
                                peer="127.0.0.1", receipt=observed) == "operational_receipt_mismatch"  # fmt: skip


def observed_receipt(capsys, command, env):
    return observed(capsys, command, env, answers("127.0.0.1"))


@pytest.mark.parametrize(
    "content",
    [
        "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\n".encode(),
        "café not ascii".encode(),
    ],
)
def test_unusable_ca_material_is_a_material_failure_with_a_receipt(material, metadata, capsys,
                                                                    content):  # fmt: skip
    behaviour = Behaviour()
    port = serve(behaviour, cert=material)
    observe.RUNTIME_CA.chmod(0o600)
    observe.RUNTIME_CA.write_bytes(content)
    observe.RUNTIME_CA.chmod(0o400)
    code, receipt = observed(capsys, "observe-runtime", environment(metadata, port),
                             answers("127.0.0.1"))  # fmt: skip
    assert code == observe.EXIT_MATERIAL and receipt is not None
    assert receipt["result"] == {"reason": "material_invalid"} and behaviour.requests == []


def test_a_deeply_nested_answer_fails_the_check_with_a_receipt(metadata, capsys):
    behaviour = Behaviour()
    behaviour.bodies["/"] = b"[" * 2000 + b"]" * 2000
    port = serve(behaviour)
    env = environment(metadata, port, check="api-observe", host="api.staging.internal")
    code, receipt = observed(capsys, "observe-api", env, answers("127.0.0.1"))
    assert code == observe.EXIT_OBSERVATION and receipt is not None
    assert receipt["result"] == {"reason": "liveness_failed"}


def test_an_unexpected_error_is_a_failed_observation_never_a_traceback(
    material, metadata, capsys, monkeypatch
):
    port = serve(Behaviour(), cert=material)

    def broken(*_args, **_kwargs):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(observe.Observer, "runtime", broken)
    code, receipt = observed(capsys, "observe-runtime", environment(metadata, port),
                             answers("127.0.0.1"))  # fmt: skip
    assert code == observe.EXIT_OBSERVATION and receipt is not None
    assert receipt["result"] == {"reason": "observation_error"}


# The whole check has one deadline, whatever it is waiting on ---------------------------


def test_a_final_answer_that_arrives_after_the_deadline_is_not_a_pass(metadata, capsys):
    # The last reply made slow progress: no socket timeout fired, the total did.
    start = datetime.now(UTC)
    moment = [start]
    behaviour = Behaviour()
    port = serve(behaviour)
    env = environment(metadata, port, check="api-observe", host="api.staging.internal")
    original = observe.Observer._get

    def slow_last_answer(self, connection, path, headers=None):
        answer = original(self, connection, path, headers)
        if path == "/api/reports":
            moment[0] = self.deadline + timedelta(seconds=1)
        return answer

    observe.Observer._get, restore = slow_last_answer, original
    try:
        code = observe.main(["observe-api"], env, now=lambda: moment[0],
                            resolve=answers("127.0.0.1"))  # fmt: skip
    finally:
        observe.Observer._get = restore
    out = capsys.readouterr().out.splitlines()
    receipt = parse_receipt(out, "operational")
    assert code == observe.EXIT_OBSERVATION and len(out) == 1
    assert receipt is not None and receipt["status"] == "failed"
    assert receipt["result"] == {"reason": "deadline_exceeded"}
    assert behaviour.requests == ["/", "/api/ready", "/api/reports"]


def test_the_runtime_checks_last_denial_cannot_pass_after_the_deadline(material, metadata):
    start = datetime.now(UTC)
    moment = [start]
    port = serve(Behaviour(), cert=material)
    deadline = start + timedelta(seconds=60)
    observer = observe.Observer("runtime", HOST, port, deadline, lambda: moment[0],
                                answers("127.0.0.1"))  # fmt: skip
    observer.resolve_once()
    original = observe.Observer._get

    def slow_refusal(self, connection, path, headers=None):
        try:
            return original(self, connection, path, headers)
        except observe.CheckFailed as failure:
            if failure.reason == "tls_untrusted":
                # The public trust store's refusal, the last step, came too late.
                moment[0] = deadline + timedelta(seconds=1)
            raise

    observe.Observer._get, restore = slow_refusal, original
    try:
        trusted = ssl.create_default_context(cadata=material.ca.read_text())
        with pytest.raises(observe.CheckFailed) as failed:
            observer.runtime(trusted, TOKEN)
    finally:
        observe.Observer._get = restore
    assert failed.value.reason == "deadline_exceeded"


def soon(seconds: int) -> dict[str, str]:
    """A fixed clock and a deadline ``seconds`` away: the 5 s stop grace is taken off."""
    start = datetime(2026, 10, 7, 12, 0, tzinfo=UTC)
    not_after = (start + timedelta(seconds=seconds + 5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"start": start, "not_after": not_after}  # type: ignore[dict-item]


def run_until_ended(command: str, env: dict[str, str], resolve, start: datetime
                    ) -> tuple[list[int], float, threading.Thread]:  # fmt: skip
    """Run the observer on its own thread and wait for its hard exit."""
    exits: list[int] = []
    ended = threading.Event()

    def exit(code: int) -> None:
        exits.append(code)
        ended.set()

    began = time.monotonic()
    worker = threading.Thread(
        target=lambda: observe.main([command], env, now=lambda: start, resolve=resolve, exit=exit),
        daemon=True,
    )
    worker.start()
    assert ended.wait(4), "the check did not end at its deadline"
    return exits, time.monotonic() - began, worker


def test_name_resolution_that_never_answers_ends_the_check_at_its_deadline(metadata, capsys):
    clock = soon(1)
    entered, release = threading.Event(), threading.Event()

    def blocked(host: str, port: int) -> list:
        entered.set()
        release.wait()
        raise OSError("resolution abandoned")

    env = environment(metadata, 8001, check="api-observe", host="api.staging.internal",
                      RELEASE_NOT_AFTER=clock["not_after"])  # fmt: skip
    try:
        exits, elapsed, worker = run_until_ended("observe-api", env, blocked, clock["start"])
        assert entered.is_set() and worker.is_alive(), "resolution was still blocked"
        assert exits == [observe.EXIT_OBSERVATION] and 1.0 <= elapsed < 2.5, (exits, elapsed)
    finally:
        release.set()
    worker.join(2)
    out = capsys.readouterr().out.splitlines()
    receipt = parse_receipt(out, "operational")
    # One receipt: the late resolution failure after the exit writes no second one.
    assert len(out) == 1 and receipt is not None
    assert (receipt["status"], receipt["result"]) == ("failed", {"reason": "deadline_exceeded"})


def test_a_reply_that_keeps_trickling_ends_the_check_at_its_deadline(metadata, capsys):
    # Each read gets a byte well inside the 5 s socket timeout, so no single
    # operation ever times out; the reply would take minutes in total.
    clock = soon(1)
    stop = threading.Event()
    server = socket.create_server(("127.0.0.1", 0))

    def trickle() -> None:
        connection, _ = server.accept()
        with connection:
            connection.recv(4096)
            connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n")
            while not stop.wait(0.05):
                try:
                    connection.sendall(b" ")
                except OSError:
                    return

    threading.Thread(target=trickle, daemon=True).start()
    env = environment(metadata, server.getsockname()[1], check="api-observe",
                      host="api.staging.internal", RELEASE_NOT_AFTER=clock["not_after"])  # fmt: skip
    try:
        exits, elapsed, worker = run_until_ended("observe-api", env, answers("127.0.0.1"),
                                                 clock["start"])  # fmt: skip
        assert worker.is_alive(), "the reply was still arriving"
        assert exits == [observe.EXIT_OBSERVATION] and 1.0 <= elapsed < 2.5, (exits, elapsed)
    finally:
        stop.set()
        server.close()
    worker.join(7)
    out = capsys.readouterr().out.splitlines()
    receipt = parse_receipt(out, "operational")
    assert len(out) == 1 and receipt is not None
    assert (receipt["status"], receipt["result"]) == ("failed", {"reason": "deadline_exceeded"})


def test_a_check_that_finishes_in_time_is_never_ended_by_the_deadline(metadata, capsys):
    exits: list[int] = []
    port = serve(Behaviour())
    env = environment(metadata, port, check="api-observe", host="api.staging.internal")
    code = observe.main(["observe-api"], env, resolve=answers("127.0.0.1"), exit=exits.append)
    receipt = parse_receipt(capsys.readouterr().out.splitlines(), "operational")
    assert code == 0 and receipt is not None and receipt["status"] == "passed"
    time.sleep(0.1)
    assert exits == []
