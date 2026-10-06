"""Offline dependency security regressions with disposable inputs and loopback TLS.

GHSA-ffc3-869f-jxw9 describes a PyJWT guard bypass when a caller mixes HMAC and
asymmetric algorithms with mutated raw PEM. These tests deliberately exercise
that dependency boundary; they do not assert that the application's Supabase
get_user authentication path has that configuration.
https://github.com/jpadilla/pyjwt/security/advisories/GHSA-ffc3-869f-jxw9
"""

import base64
import hashlib
import hmac
import json
import gc
import socket
import ssl
import threading
import weakref

import anyio
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)
import jwt
import pytest
import httpx
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import RequestReceived
from h2.exceptions import ProtocolError
from hpack import Decoder, Encoder, HPACKDecodingError, InvalidTableIndexError
from multidict import CIMultiDict
from supabase_auth import SyncGoTrueClient
from supabase_auth.errors import AuthApiError

from dev.tls_fixtures import create_certificates


@pytest.fixture(scope="module", params=["RS256", "ES256"])
def signing_key(request):
    key = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        if request.param == "RS256"
        else ec.generate_private_key(ec.SECP256R1())
    )
    return request.param, key


@pytest.fixture(params=["canonical", "tab-before-end", "cr-only", "folded"])
def public_pem(signing_key, request):
    public_key = signing_key[1].public_key()
    pem = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    if request.param == "tab-before-end":
        pem = pem.replace(b"-----END", b"\t-----END")
    elif request.param == "cr-only":
        pem = pem.replace(b"\n", b"\r")
    elif request.param == "folded":
        pem = b" ".join(pem.splitlines())
    # This precondition is important: rejected junk would not exercise the
    # loader/guard mismatch. All variants must retain the original public key.
    loaded = load_pem_public_key(pem)
    assert isinstance(loaded, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey))
    assert loaded.public_numbers() == public_key.public_numbers()
    return pem


def hmac_fixture_token(public_pem):
    """Construct an HS256 test token independently of PyJWT's signing guard."""

    def encoded(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=")

    message = encoded({"alg": "HS256", "typ": "JWT"}) + b"." + encoded({"sub": "fixture-user"})
    signature = hmac.new(public_pem, message, hashlib.sha256).digest()
    return (message + b"." + base64.urlsafe_b64encode(signature).rstrip(b"=")).decode()


def test_pem_public_key_cannot_sign_hmac_token(public_pem):
    with pytest.raises(jwt.InvalidKeyError):
        jwt.encode({"sub": "fixture-user"}, public_pem, algorithm="HS256")


def test_pem_public_key_cannot_verify_hmac_even_with_mixed_allowlist(signing_key, public_pem):
    with pytest.raises(jwt.InvalidKeyError):
        jwt.decode(hmac_fixture_token(public_pem), public_pem, algorithms=[signing_key[0], "HS256"])


def test_asymmetric_round_trip_and_single_algorithm_allowlist(signing_key, public_pem):
    algorithm, private_key = signing_key
    token = jwt.encode({"sub": "fixture-user"}, private_key, algorithm=algorithm)
    assert jwt.decode(token, public_pem, algorithms=[algorithm]) == {"sub": "fixture-user"}
    with pytest.raises(jwt.InvalidAlgorithmError):
        jwt.decode(hmac_fixture_token(public_pem), public_pem, algorithms=[algorithm])


def test_jws_signature_accepts_padding_but_rejects_non_alphabet_junk(signing_key):
    # PyJWT 2.15.1 restored compatibility with padded JWS signatures while
    # retaining strict rejection of junk; no ALB or network service is involved.
    algorithm, private_key = signing_key
    token = jwt.encode({"sub": "fixture-user"}, private_key, algorithm=algorithm)
    message, signature = token.rsplit(".", 1)
    padded_signature = signature + "=" * (-len(signature) % 4)
    assert padded_signature != signature
    assert jwt.decode(
        message + "." + padded_signature, private_key.public_key(), algorithms=[algorithm]
    ) == {"sub": "fixture-user"}
    with pytest.raises(jwt.DecodeError):
        jwt.decode(token + "!!!!", private_key.public_key(), algorithms=[algorithm])


@pytest.mark.parametrize("accepted", [True, False], ids=["accepted", "rejected"])
def test_real_supabase_auth_client_preserves_get_user_server_verdict(accepted):
    requests = []

    def auth_server(request):
        requests.append(request)
        assert request.method == "GET"
        assert str(request.url) == "https://auth.fixture.invalid/auth/v1/user"
        assert request.headers["Authorization"] == "Bearer fixture-access-token"
        assert request.headers["apikey"] == "fixture-api-key"
        if not accepted:
            return httpx.Response(401, json={"msg": "Invalid JWT", "code": "bad_jwt"})
        return httpx.Response(
            200,
            json={
                "id": "00000000-0000-4000-8000-000000000001",
                "aud": "authenticated",
                "email": "fixture@example.invalid",
                "app_metadata": {"role": "member"},
                "user_metadata": {},
                "created_at": "2026-01-01T00:00:00Z",
            },
        )

    # Exercise the actual installed Auth SDK parser and request path. The
    # transport cannot contact the network, and no session is persisted/refreshed.
    with httpx.Client(transport=httpx.MockTransport(auth_server), trust_env=False) as http:
        auth = SyncGoTrueClient(
            url="https://auth.fixture.invalid/auth/v1",
            headers={"apikey": "fixture-api-key"},
            http_client=http,
            auto_refresh_token=False,
            persist_session=False,
        )
        if accepted:
            response = auth.get_user("fixture-access-token")
            assert response is not None
            assert response.user.id == "00000000-0000-4000-8000-000000000001"
            assert response.user.email == "fixture@example.invalid"
            assert response.user.app_metadata == {"role": "member"}
        else:
            with pytest.raises(AuthApiError) as error:
                auth.get_user("fixture-access-token")
            assert error.value.status == 401
    assert len(requests) == 1


@pytest.mark.parametrize("certificate_name", ["xn--fa-hia.example", "fass.example"])
def test_anyio_tls_uses_idna2008_identity_on_numeric_loopback(tmp_path, certificate_name):
    # GHSA-82r6-8w77-94w6: faß.example must retain its IDNA2008 identity,
    # not verify against the distinct IDNA2003-mapped fass.example certificate.
    certificates = create_certificates(tmp_path / "tls", hostname=certificate_name)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(certificates.certificate, certificates.key)
    client_context = ssl.create_default_context(cafile=certificates.ca)
    server_errors = []
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(5)
        port = listener.getsockname()[1]

        def serve_once():
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(5)
                    with server_context.wrap_socket(connection, server_side=True) as tls:
                        tls.sendall(b"ok")
            except (OSError, ssl.SSLError) as error:
                server_errors.append(error)

        async def probe():
            with anyio.fail_after(5):
                async with await anyio.connect_tcp(
                    "127.0.0.1",
                    port,
                    tls=True,
                    tls_hostname="faß.example",
                    ssl_context=client_context,
                    tls_standard_compatible=False,
                ) as stream:
                    assert await stream.receive(2) == b"ok"

        server = threading.Thread(target=serve_once, daemon=True)
        server.start()
        try:
            if certificate_name == "xn--fa-hia.example":
                anyio.run(probe)
            else:
                with pytest.raises(ssl.SSLCertVerificationError):
                    anyio.run(probe)
        finally:
            server.join(timeout=6)
        assert not server.is_alive(), "disposable TLS server did not terminate"
    if certificate_name == "xn--fa-hia.example":
        assert not server_errors


def test_h2_hpack_round_trip_and_duplicate_host_rejection():
    headers = [
        (":method", "GET"),
        (":scheme", "https"),
        (":path", "/fixture"),
        ("host", "fixture.example"),
    ]
    assert list(Decoder().decode(Encoder().encode(headers))) == headers

    def receive(request_headers):
        # A deliberately unchecked fixture sender models an untrusted peer;
        # the receiving side retains all default protocol validation.
        sender = H2Connection(H2Configuration(client_side=True, validate_outbound_headers=False))
        receiver = H2Connection(H2Configuration(client_side=False, header_encoding="utf-8"))
        sender.initiate_connection()
        receiver.initiate_connection()
        receiver.receive_data(sender.data_to_send())
        sender.send_headers(1, request_headers, end_stream=True)
        return receiver.receive_data(sender.data_to_send())

    events = receive(headers)
    request = next(event for event in events if isinstance(event, RequestReceived))
    assert request.headers == headers
    # GHSA-6hr6-w5qg-qmwg: reject ambiguity before forwarding headers.
    with pytest.raises(ProtocolError):
        receive([*headers, ("host", "other.example")])


def test_hpack_oversized_integer_is_rejected_before_index_lookup():
    # GHSA-8v8h-hg4w-mvq2: a seven-byte indexed-field integer exceeds uint32.
    # No large allocation, timing threshold or resource-exhaustion loop is used.
    with pytest.raises(HPACKDecodingError) as error:
        Decoder().decode(b"\xff" * 6 + b"\x00")
    assert not isinstance(
        error.value, InvalidTableIndexError
    ), "oversized integer reached table lookup instead of bounded decoding"


def test_multidict_items_view_operations_release_operand_values():
    # GHSA-54p9-h82j-f925: small weakref lifetime proof, not an RSS/refcount
    # benchmark or a private C-extension assertion.
    class Value:
        pass

    for operation in ("union", "subtract"):
        dictionary = CIMultiDict({"seed": "seed-value"})
        value = Value()
        reference = weakref.ref(value)
        operand = [("fixture", value)]
        if operation == "union":
            result = operand | dictionary.items()
            assert result == {("fixture", value), ("seed", "seed-value")}
        else:
            result = dictionary.items() - operand
            assert result == {("seed", "seed-value")}
        del result, operand, value
        gc.collect()
        assert reference() is None, f"{operation} retained an otherwise unreachable operand value"
