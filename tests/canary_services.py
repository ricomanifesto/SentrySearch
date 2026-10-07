"""Disposable auth/object HTTP fixtures. Never included in the service image.

This implements only the calls used by this canary, not Supabase or S3 security.
It must run on the test's internal Docker network without a published port.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import threading
from urllib.parse import parse_qs, urlsplit
from xml.etree import ElementTree
from xml.sax.saxutils import escape

import jwt

USER = "11111111-1111-4111-8111-111111111111"
OTHER_USER = "22222222-2222-4222-8222-222222222222"
BUCKET = "image-check-bucket"
MAX_OBJECT_BYTES = 2 * 1024 * 1024


def verified_user(token: str, key: str) -> dict:
    claims = jwt.decode(
        token,
        key,
        algorithms=["HS256"],
        audience="authenticated",
        issuer="local-canary",
        options={"require": ["sub", "exp", "aud", "iss"]},
    )
    if claims["sub"] not in {USER, OTHER_USER}:
        raise ValueError("unknown fixture identity")
    return {
        "id": claims["sub"],
        "email": "canary@example.invalid",
        "aud": "authenticated",
        "role": "authenticated",
        "created_at": "2026-01-01T00:00:00Z",
        "app_metadata": {},
        # Deliberately untrusted: production authorization must ignore this.
        "user_metadata": {"role": "admin"},
    }


def serve(key: str, address: tuple[str, int] = ("0.0.0.0", 9001)) -> None:
    objects: dict[str, bytes] = {}
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def respond(self, status: int, body: bytes, content_type="application/json"):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            url = urlsplit(self.path)
            path = url.path
            if path == "/health":
                self.respond(200, b"{}")
            elif path == "/auth/v1/user":
                try:
                    auth = self.headers.get("Authorization", "")
                    if not auth.startswith("Bearer "):
                        raise ValueError("missing bearer")
                    user = verified_user(auth[7:], key)
                except (ValueError, jwt.PyJWTError):
                    self.respond(401, b'{"msg":"Invalid or expired fixture token"}')
                else:
                    self.respond(200, json.dumps(user).encode())
            elif path == f"/{BUCKET}":
                prefix = parse_qs(url.query).get("prefix", [""])[0]
                if not prefix.startswith("reports/"):
                    self.respond(400, b"{}")
                    return
                with lock:
                    keys = [
                        name[len(BUCKET) + 2 :]
                        for name in objects
                        if name.startswith(f"/{BUCKET}/{prefix}")
                    ]
                body = (
                    "<ListBucketResult><IsTruncated>false</IsTruncated>"
                    + "".join(f"<Contents><Key>{escape(name)}</Key></Contents>" for name in keys)
                    + "</ListBucketResult>"
                )
                self.respond(200, body.encode(), "application/xml")
            elif path.startswith(f"/{BUCKET}/reports/"):
                with lock:
                    body = objects.get(path)
                if body is None:
                    self.respond(404, b"<Error><Code>NoSuchKey</Code></Error>", "application/xml")
                else:
                    self.respond(200, body, "application/octet-stream")
            else:
                self.respond(404, b"{}")

        def do_PUT(self):
            path = urlsplit(self.path).path
            try:
                size = int(self.headers.get("Content-Length", "-1"))
            except ValueError:
                size = -1
            if not path.startswith(f"/{BUCKET}/reports/") or not 0 <= size <= MAX_OBJECT_BYTES:
                self.respond(400, b"{}")
                return
            content = self.rfile.read(size)
            if len(content) != size:
                self.respond(400, b"{}")
                return
            with lock:
                objects[path] = content
            self.respond(200, b"", "application/xml")

        def do_POST(self):
            url = urlsplit(self.path)
            if url.path != f"/{BUCKET}" or url.query != "delete":
                self.respond(404, b"{}")
                return
            try:
                size = int(self.headers.get("Content-Length", "-1"))
                if not 0 < size <= MAX_OBJECT_BYTES:
                    raise ValueError
                payload = self.rfile.read(size)
                if len(payload) != size:
                    raise ValueError
                tree = ElementTree.fromstring(payload)
                keys = [
                    str(node.text) for node in tree.iter() if node.tag.rsplit("}", 1)[-1] == "Key"
                ]
                if not keys or not all(name.startswith("reports/") for name in keys):
                    raise ValueError
            except (ValueError, ElementTree.ParseError):
                self.respond(400, b"{}")
                return
            with lock:
                for name in keys:
                    objects.pop(f"/{BUCKET}/{name}", None)
            self.respond(200, b"<DeleteResult/>", "application/xml")

    server = ThreadingHTTPServer(address, Handler)
    print("canary fixture listening", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    serve(os.environ["CANARY_AUTH_KEY"])
