"""In-memory model of the R2 S3-API behavior the release store relies on.

The model answers botocore's ``before-send`` event, so real request
serialization and SigV4 signing run but nothing leaves the process. It follows
R2's documented S3 compatibility: conditional ``PutObject`` with ``If-Match`` and
``If-None-Match`` (HTTP 412 on failure), strongly consistent reads, and no
conditional ``DeleteObject``. Behavior the documentation does not establish is
modeled pessimistically and is configurable:

* ``etags="md5"`` (default) derives ETags from content, the case in which a
  repeated body would repeat an ETag; ``"random"`` shows independence from it.
* ``conditional_delete="ignore"`` (default) deletes whatever is present even
  when ``If-Match`` is sent; ``"reject"`` refuses the request. Either way the
  request is logged so tests can prove the store never sends one.
* Streaming checksum trailers (``aws-chunked`` bodies, ``x-amz-trailer``) are
  refused, because R2's PutObject compatibility row does not list them. Plain
  checksum headers are accepted and logged so tests can assert their absence.
* ``DeleteObjects`` (``POST ?delete``), which R2 documents as supported, deletes
  the listed keys and, like ``DeleteObject``, enforces no condition. Every
  deleting request is logged whatever its form.

Conditional writes are linearized under one lock. Hooks run outside that lock
so a test can interleave another client's request at an exact point.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import io
import json
import re
import threading
from typing import Any, Callable
from urllib.parse import parse_qs, unquote, urlsplit
import uuid
from xml.etree import ElementTree
from xml.sax.saxutils import escape

import botocore.session
from botocore.awsrequest import AWSResponse, HeadersDict
from botocore.config import Config
from botocore.exceptions import ConnectTimeoutError, ReadTimeoutError

from release_cloudflare.r2_client import R2Target, endpoint_for
from tests.release_fakes import SimulatedCrash, Trace

ACCOUNT_ID = "0123456789abcdef0123456789abcdef"
CONTROL = R2Target(account_id=ACCOUNT_ID, bucket="sentry-staging-control")
SAFE_CONFIG: dict[str, Any] = {
    "request_checksum_calculation": "when_required",
    "response_checksum_validation": "when_required",
    "ignore_configured_endpoint_urls": True,
    "retries": {"mode": "standard", "total_max_attempts": 1},
    "connect_timeout": 5,
    "read_timeout": 10,
    "s3": {"addressing_style": "path"},
    "signature_version": "s3v4",
    "proxies": {},
}
CHECKSUM_HEADERS = ("x-amz-trailer", "x-amz-sdk-checksum-algorithm")
AMBIENT = "ambient"
VERSIONS_PREFIX = "journal-versions/"


def make_client(
    backend: "R2Backend",
    target: R2Target = CONTROL,
    *,
    endpoint: str | None = None,
    credentials: dict[str, str] | None = None,
    verify: Any = True,
    **config: Any,
) -> Any:
    """A botocore S3 client for ``target`` wired to ``backend``.

    The session ignores ``AWS_PROFILE`` so a poisoned environment cannot select
    a profile; credentials are passed explicitly. ``config`` overrides
    ``SAFE_CONFIG`` (``None`` removes a key) to build deliberately broken clients.
    """
    settings = {**SAFE_CONFIG, **config}
    settings = {key: value for key, value in settings.items() if value is not None}
    session = botocore.session.Session(session_vars={"profile": (None, None, None, None)})
    secrets = credentials or {
        "aws_access_key_id": "fixture-access-key-id",
        "aws_secret_access_key": "fixture-secret-access-key",
    }
    # endpoint=AMBIENT omits endpoint_url so configured endpoints can apply.
    explicit = {} if endpoint == AMBIENT else {"endpoint_url": endpoint or endpoint_for(target)}
    client = session.create_client(
        "s3",
        region_name="auto",
        config=Config(**settings),
        verify=verify,
        **explicit,
        **secrets,
    )
    client.meta.events.register("before-send.s3", backend.handle)
    return client


@dataclass
class Logged:
    method: str
    bucket: str
    key: str
    headers: dict[str, str]
    status: int
    envelope_state: str | None = None
    query: str = ""

    @property
    def deleting(self) -> bool:
        return self.method == "DELETE" or (self.method == "POST" and "delete" in self.query)


@dataclass
class Fault:
    """One injected failure: ``lost_response`` commits then times out,
    ``timeout_before`` never commits, ``http_500`` and ``http_status`` answer
    ``status``/``code`` without committing, ``crash_after`` commits then loses
    the controller process. ``skip`` lets that many matches pass."""

    method: str
    key: str
    kind: str
    count: int = 1
    match_state: str | None = None
    skip: int = 0
    status: int = 500
    code: str = "InternalError"


class _Raw(io.BytesIO):
    def stream(self, amt: int = 65536, decode_content: bool | None = None):
        while chunk := self.read(amt):
            yield chunk


def _error(code: str, status: int, url: str) -> AWSResponse:
    body = (
        f'<?xml version="1.0" encoding="UTF-8"?><Error><Code>{code}</Code>'
        f"<Message>{code}</Message></Error>"
    ).encode()
    headers = HeadersDict({"Content-Type": "application/xml", "Content-Length": str(len(body))})
    return AWSResponse(url, status, headers, _Raw(body))


def _envelope_state(body: bytes) -> str | None:
    try:
        document = json.loads(body)
    except ValueError:
        return None
    return document.get("state") if isinstance(document, dict) else None


@dataclass
class R2Backend:
    etags: str = "md5"
    conditional_delete: str = "ignore"
    trace: Trace | None = None
    target: R2Target = CONTROL
    objects: dict[tuple[str, str], tuple[bytes, str]] = field(default_factory=dict)
    log: list[Logged] = field(default_factory=list)
    faults: list[Fault] = field(default_factory=list)
    before: Callable[[str, str, bytes], None] | None = None

    def __post_init__(self) -> None:
        self._lock = threading.Lock()
        self._host = urlsplit(endpoint_for(self.target)).hostname

    # Test helpers ----------------------------------------------------------------

    def get(self, key: str, bucket: str | None = None) -> tuple[bytes, str] | None:
        return self.objects.get((bucket or self.target.bucket, key))

    def require(self, key: str) -> tuple[bytes, str]:
        found = self.get(key)
        assert found is not None, f"no object at {key}"
        return found

    def raw(self, key: str) -> bytes:
        return self.require(key)[0]

    def etag(self, key: str) -> str:
        return self.require(key)[1]

    def put_raw(self, key: str, raw: bytes, etag: str) -> None:
        self.objects[(self.target.bucket, key)] = (raw, etag)

    def keys(self, prefix: str = "") -> list[str]:
        return sorted(key for _, key in self.objects if key.startswith(prefix))

    def requests(self, method: str | None = None) -> list[Logged]:
        return [entry for entry in self.log if method is None or entry.method == method]

    def deleting_requests(self) -> list[Logged]:
        return [entry for entry in self.log if entry.deleting]

    # Wire --------------------------------------------------------------------------

    def _etag(self, body: bytes) -> str:
        if self.etags == "md5":
            return '"' + hashlib.md5(body).hexdigest() + '"'
        return '"' + uuid.uuid4().hex + '"'

    def _fault(self, method: str, key: str, state: str | None) -> Fault | None:
        for fault in self.faults:
            if (
                fault.count > 0
                and fault.method == method
                and re.fullmatch(fault.key, key)
                and (fault.match_state is None or fault.match_state == state)
            ):
                if fault.skip > 0:
                    fault.skip -= 1
                    continue
                fault.count -= 1
                return fault
        return None

    def handle(self, request: Any, **kwargs: Any) -> AWSResponse:
        url = request.url
        parts = urlsplit(url)
        if parts.hostname != self._host:
            raise AssertionError(f"request left the configured R2 endpoint: {parts.hostname}")
        path = unquote(parts.path).lstrip("/")
        bucket, _, key = path.partition("/")
        query = parse_qs(parts.query, keep_blank_values=True)
        headers = {name.lower(): value for name, value in request.headers.items()}
        headers = {
            name: value.decode() if isinstance(value, bytes) else str(value)
            for name, value in headers.items()
        }
        body = request.body
        if hasattr(body, "read"):
            body = body.read()
        body = body or b""
        if isinstance(body, str):
            body = body.encode()
        method = request.method
        state = _envelope_state(body) if method == "PUT" else None
        if self.before is not None:
            self.before(method, key, body)

        trailer = "x-amz-trailer" in headers or "aws-chunked" in headers.get("content-encoding", "")
        if trailer:
            response = _error("InvalidRequest", 400, url)
            self._record(method, bucket, key, headers, response, query=parts.query)
            return response
        if bucket != self.target.bucket:
            response = _error("NoSuchBucket", 404, url)
            self._record(method, bucket, key, headers, response, query=parts.query)
            return response

        fault = self._fault(method, key, state)
        if fault is not None and fault.kind == "timeout_before":
            self._record(method, bucket, key, headers, None, status=0, query=parts.query)
            raise ConnectTimeoutError(endpoint_url=url)
        if fault is not None and fault.kind in ("http_500", "http_status"):
            code = "InternalError" if fault.kind == "http_500" else fault.code
            status = 500 if fault.kind == "http_500" else fault.status
            response = _error(code, status, url)
            self._record(method, bucket, key, headers, response, query=parts.query)
            return response

        with self._lock:
            if method == "PUT" and key and not query:
                response = self._put(bucket, key, headers, body, url)
            elif method in ("GET", "HEAD") and key and not query:
                response = self._get(bucket, key, url, head=method == "HEAD")
            elif method == "DELETE" and key and not query:
                response = self._delete(bucket, key, url)
            elif method == "POST" and not key and "delete" in query:
                response = self._delete_objects(bucket, body, url)
            else:
                response = _error("NotImplemented", 501, url)
        self._record(method, bucket, key, headers, response, state=state, query=parts.query)
        if fault is not None and fault.kind == "lost_response":
            raise ReadTimeoutError(endpoint_url=url)
        if fault is not None and fault.kind == "crash_after":
            raise SimulatedCrash(f"controller lost after {method} {key}")
        return response

    def _record(
        self,
        method: str,
        bucket: str,
        key: str,
        headers: dict[str, str],
        response: AWSResponse | None,
        *,
        status: int | None = None,
        state: str | None = None,
        query: str = "",
    ) -> None:
        code = status if response is None else response.status_code
        kept = {
            name: value
            for name, value in headers.items()
            if name in ("if-match", "if-none-match", "content-encoding", "content-type")
            or name in CHECKSUM_HEADERS
            or name.startswith("x-amz-checksum-")
        }
        self.log.append(Logged(method, bucket, key, kept, code or 0, state, query))

    def _put(self, bucket: str, key: str, headers: dict, body: bytes, url: str) -> AWSResponse:
        current = self.objects.get((bucket, key))
        if headers.get("if-none-match") == "*" and current is not None:
            return _error("PreconditionFailed", 412, url)
        if "if-match" in headers and (current is None or current[1] != headers["if-match"]):
            return _error("PreconditionFailed", 412, url)
        etag = self._etag(body)
        self.objects[(bucket, key)] = (body, etag)
        self._trace(key, body)
        return AWSResponse(url, 200, HeadersDict({"ETag": etag, "Content-Length": "0"}), _Raw(b""))

    def _get(self, bucket: str, key: str, url: str, *, head: bool) -> AWSResponse:
        current = self.objects.get((bucket, key))
        if current is None:
            return _error("NoSuchKey", 404, url)
        body, etag = current
        headers = HeadersDict(
            {
                "ETag": etag,
                "Content-Length": str(len(body)),
                "Content-Type": "application/json",
            }
        )
        return AWSResponse(url, 200, headers, _Raw(b"" if head else body))

    def _delete(self, bucket: str, key: str, url: str) -> AWSResponse:
        if self.conditional_delete == "reject":
            return _error("NotImplemented", 501, url)
        # Pessimistic model: a condition R2 does not document is not enforced.
        self.objects.pop((bucket, key), None)
        if self.trace is not None:
            self.trace.append(("store-delete", key, None))
        return AWSResponse(url, 204, HeadersDict({"Content-Length": "0"}), _Raw(b""))

    def _delete_objects(self, bucket: str, body: bytes, url: str) -> AWSResponse:
        # Pessimistic model: every listed key is deleted unconditionally.
        root = ElementTree.fromstring(body)
        deleted = []
        for element in root.iter():
            if element.tag.rsplit("}", 1)[-1] == "Key" and element.text:
                self.objects.pop((bucket, element.text), None)
                if self.trace is not None:
                    self.trace.append(("store-delete", element.text, None))
                deleted.append(f"<Deleted><Key>{escape(element.text)}</Key></Deleted>")
        result = (
            '<?xml version="1.0" encoding="UTF-8"?><DeleteResult>'
            + "".join(deleted)
            + "</DeleteResult>"
        ).encode()
        headers = HeadersDict(
            {"Content-Type": "application/xml", "Content-Length": str(len(result))}
        )
        return AWSResponse(url, 200, headers, _Raw(result))

    def _trace(self, key: str, body: bytes) -> None:
        if self.trace is None or key.startswith(VERSIONS_PREFIX):
            return
        try:
            envelope = json.loads(body)
            if envelope.get("state") == "released":
                self.trace.append(("store-delete", key, None))
            else:
                self.trace.append(("store", key, json.loads(envelope["body"])))
        except (ValueError, KeyError, TypeError, AttributeError):
            self.trace.append(("store", key, None))
