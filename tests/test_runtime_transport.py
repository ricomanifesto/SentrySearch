from __future__ import annotations

import ssl
import traceback
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading

import httpx
import pytest

from src.execution.runtime_client import RuntimeClient
from dev.tls_fixtures import create_certificates


@pytest.mark.parametrize(
    "url",
    [
        "http://runtime.example",
        "https://user:secret@runtime.example",
        "https://runtime.example/path",
        "https://runtime.example//",
        "https://runtime.example?",
        "https://runtime.example#",
        "https://runtime.example:0",
        "https://runtime.example:65536",
        "https://runtime.example:bad",
        "https://runtime.example:",
        "https://runtime.example\n",
        "https://runtime.example\\evil",
        "https://runtime%2eexample",
        "file:///runtime",
        "https://[::1",
    ],
)
def test_remote_authority_rejects_ambiguous_or_unsafe_urls(url):
    with pytest.raises(ValueError) as error:
        RuntimeClient(url, remote=True, bearer_token="p" * 40)
    assert url not in str(error.value)


def test_remote_client_requires_token_and_owned_verified_transport():
    with pytest.raises(ValueError, match="token"):
        RuntimeClient("https://runtime.example", remote=True)
    with httpx.Client(verify=False) as injected:
        with pytest.raises(ValueError, match="owned"):
            RuntimeClient(
                "https://runtime.example", remote=True, bearer_token="p" * 40, http_client=injected
            )


def test_remote_client_disables_environment_and_preserves_verification(monkeypatch):
    options = {}
    monkeypatch.setattr(
        "src.execution.runtime_client.httpx.Client",
        lambda **kwargs: options.update(kwargs) or object(),
    )
    RuntimeClient("https://runtime.example", remote=True, bearer_token="p" * 40)
    assert options["trust_env"] is False
    assert options["verify"] is True
    assert options["follow_redirects"] is False


def test_bad_ca_file_fails_before_transport_is_created(monkeypatch):
    monkeypatch.setattr(
        "src.execution.runtime_client.httpx.Client", lambda **_: pytest.fail("transport created")
    )
    with pytest.raises(ValueError, match="trust") as error:
        RuntimeClient(
            "https://runtime.example",
            remote=True,
            bearer_token="p" * 40,
            ca_file="private-sentinel",
        )
    assert "private-sentinel" not in str(error.value)


def test_empty_explicit_bundle_never_loads_ambient_trust():
    with pytest.raises(ValueError, match="trust"):
        RuntimeClient("https://runtime.example", remote=True, bearer_token="p" * 40, ca_file="")


def test_tls_context_requires_certificates_and_hostname(monkeypatch, tmp_path):
    # An explicit empty bundle must fail, never revert to default trust.
    bundle = tmp_path / "empty.pem"
    bundle.write_text("")
    with pytest.raises(ValueError, match="trust"):
        RuntimeClient(
            "https://runtime.example", remote=True, bearer_token="p" * 40, ca_file=str(bundle)
        )


@pytest.mark.parametrize("status", [302, 400, 409, 422, 500])
def test_transport_rejections_never_expose_private_authority(status):
    from src.execution.runtime_client import RuntimeAccessDenied, RuntimeUnavailable

    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(status))) as transport:
        client = RuntimeClient("http://localhost:45678", http_client=transport)
        with pytest.raises((RuntimeAccessDenied, RuntimeUnavailable)) as error:
            client.submit_report("report-1")
        assert "localhost:45678" not in "".join(traceback.format_exception(error.value))


def test_network_failure_does_not_chain_private_url_or_headers():
    from src.execution.runtime_client import RuntimeUnavailable

    def unavailable(request):
        raise httpx.ConnectError("private-server-sentinel", request=request)

    with httpx.Client(transport=httpx.MockTransport(unavailable)) as transport:
        client = RuntimeClient("http://localhost:45678", http_client=transport)
        with pytest.raises(RuntimeUnavailable) as error:
            client.submit_report("report-1")
        assert "private-server-sentinel" not in "".join(traceback.format_exception(error.value))


@pytest.fixture
def tls_server(tmp_path):
    servers = []

    def start(*, hostname="localhost", expired=False, status=201):
        cert = create_certificates(tmp_path / str(len(servers)), hostname=hostname, expired=expired)
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                requests.append((self.path, self.headers.get("Authorization")))
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                self.send_response(status)
                if 300 <= status < 400:
                    self.send_header("Location", "http://127.0.0.1:1/secret-leak")
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(
                    json.dumps(
                        {
                            "run_id": "run-1",
                            "state": "queued",
                            "attempt": 0,
                            "lease_version": 0,
                            "input_ref": {"report_id": "report-1"},
                        }
                    ).encode()
                )

            def log_message(self, format: str, *args) -> None:
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert.certificate, cert.key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        )
        thread.start()
        servers.append((server, thread))
        return f"https://127.0.0.1:{server.server_port}", cert, requests

    yield start
    for server, thread in servers:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()


def test_real_verified_tls_ignores_proxy_and_ambient_trust(monkeypatch, tls_server, tmp_path):
    from src.execution.runtime_client import RuntimeUnavailable

    url, cert, requests = tls_server()
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.setenv(name, "http://127.0.0.1:1")
    monkeypatch.setenv("SSL_CERT_FILE", str(cert.ca))
    monkeypatch.setenv("SSL_CERT_DIR", str(cert.ca.parent))
    # Ambient trust cannot authorize the test CA when no explicit bundle is set.
    client = RuntimeClient(url, remote=True, bearer_token="p" * 40)
    try:
        with pytest.raises(RuntimeUnavailable):
            client.submit_report("report-1")
    finally:
        client.close()
    assert requests == []
    client = RuntimeClient(url, remote=True, bearer_token="p" * 40, ca_file=str(cert.ca))
    try:
        assert client.submit_report("report-1").run_id == "run-1"
    finally:
        client.close()
    assert requests == [("/v1/runs", "Bearer " + "p" * 40)]


@pytest.mark.parametrize("case", ["wrong-ca", "wrong-host", "expired", "redirect"])
def test_real_tls_rejects_untrusted_identity_and_redirects(tls_server, tmp_path, case):
    from src.execution.runtime_client import RuntimeAccessDenied, RuntimeUnavailable

    url, cert, requests = tls_server(
        hostname="wrong.example" if case == "wrong-host" else "localhost",
        expired=case == "expired",
        status=307 if case == "redirect" else 201,
    )
    ca = create_certificates(tmp_path / "other").ca if case == "wrong-ca" else cert.ca
    client = RuntimeClient(url, remote=True, bearer_token="p" * 40, ca_file=str(ca))
    try:
        with pytest.raises(RuntimeAccessDenied if case == "redirect" else RuntimeUnavailable):
            client.submit_report("report-1")
    finally:
        client.close()
    assert len(requests) == (1 if case == "redirect" else 0)
