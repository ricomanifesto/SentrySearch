"""Client-side SCRAM-SHA-256 verifiers, so plaintext passwords never reach SQL."""

import base64
import hashlib
import hmac
import secrets

ITERATIONS = 4096


def keys(password: str, salt: bytes, iterations: int) -> tuple[bytes, bytes]:
    # Passwords are validated as printable ASCII, so SASLprep is the identity.
    salted = hashlib.pbkdf2_hmac("sha256", password.encode("ascii"), salt, iterations)
    client_key = hmac.new(salted, b"Client Key", "sha256").digest()
    server_key = hmac.new(salted, b"Server Key", "sha256").digest()
    return hashlib.sha256(client_key).digest(), server_key


def verifier(password: str) -> str:
    salt = secrets.token_bytes(16)
    stored, server = keys(password, salt, ITERATIONS)
    encode = lambda value: base64.b64encode(value).decode("ascii")  # noqa: E731
    return f"SCRAM-SHA-256${ITERATIONS}:{encode(salt)}${encode(stored)}:{encode(server)}"
