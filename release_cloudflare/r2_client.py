"""R2 S3-API target identity and fail-closed validation of an injected client.

The adapter never constructs a client. It checks that the caller's botocore
client talks to exactly one R2 endpoint over verified TLS without a proxy, uses
explicit static credentials, and has the request shape R2's S3 compatibility
documents: region ``auto``, no flexible-checksum trailers, path-style
addressing, and no SDK retries (the release controller owns every retry
decision). Botocore's S3 region redirector can still resend once, and only
after a redirect-shaped error response, which did not apply the request.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

ACCOUNT_ID = re.compile(r"[0-9a-f]{32}")
# R2 bucket names: 3-63 lowercase letters, digits and hyphens, not at the ends.
BUCKET = re.compile(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]")
JURISDICTIONS = frozenset({"eu", "fedramp", "us"})
MAX_CONNECT_TIMEOUT_SECONDS = 10.0
MAX_READ_TIMEOUT_SECONDS = 30.0


class R2ClientRejected(ValueError):
    """The injected client or target does not meet the R2 adapter contract."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class R2Target:
    """One R2 bucket reached through its account (and optional jurisdiction) endpoint."""

    account_id: str
    bucket: str
    jurisdiction: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.account_id, str) or not ACCOUNT_ID.fullmatch(self.account_id):
            raise R2ClientRejected("account_id")
        if not isinstance(self.bucket, str) or not BUCKET.fullmatch(self.bucket):
            raise R2ClientRejected("bucket")
        if self.jurisdiction is not None and self.jurisdiction not in JURISDICTIONS:
            raise R2ClientRejected("jurisdiction")


def endpoint_for(target: R2Target) -> str:
    """The S3 API endpoint for the target's account and jurisdiction."""
    if target.jurisdiction is None:
        return f"https://{target.account_id}.r2.cloudflarestorage.com"
    return f"https://{target.account_id}.{target.jurisdiction}.r2.cloudflarestorage.com"


def _timeout(value: Any, limit: float) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and 0 < value <= limit


MAX_IDEMPOTENT_ATTEMPTS = 3


def validate_client(
    client: Any, target: R2Target, *, ca_bundle: str | None = None, max_attempts: int = 1
) -> None:
    """Raise ``R2ClientRejected`` unless ``client`` meets the adapter contract.

    ``ca_bundle`` names the trust bundle the caller configured; without it the
    client must use the default trust store, so a bundle substituted through
    ``AWS_CA_BUNDLE`` or ``REQUESTS_CA_BUNDLE`` is rejected. The release-control
    store requires exactly one attempt per call; callers whose every operation
    is idempotent (content-addressed artifacts) may allow up to
    ``MAX_IDEMPOTENT_ATTEMPTS``.
    """
    if (
        not isinstance(max_attempts, int)
        or isinstance(max_attempts, bool)
        or not 1 <= max_attempts <= MAX_IDEMPOTENT_ATTEMPTS
    ):
        raise R2ClientRejected("max_attempts")
    try:
        meta = client.meta
        config = meta.config
        service = meta.service_model.service_name
        credentials = client._get_credentials()
        http_session = client._endpoint.http_session
        verify = http_session._verify
        proxies = http_session._proxy_config._proxies
    except AttributeError:
        raise R2ClientRejected("client") from None
    if service != "s3":
        raise R2ClientRejected("service")
    if meta.region_name != "auto":
        raise R2ClientRejected("region")
    # An endpoint taken from ambient configuration (for example
    # AWS_ENDPOINT_URL_S3) differs from the target's and is rejected here; the
    # client's ignore_configured_endpoint_urls setting is not readable back.
    if meta.endpoint_url != endpoint_for(target):
        raise R2ClientRejected("endpoint")
    # Exactly the default trust store, or exactly the named bundle. botocore
    # disables certificate checking for any falsy verify, and a relative path
    # would resolve against the working directory at connect time, so only an
    # absolute, unpadded path is a bundle name. Exact types rule out values that
    # merely compare equal (1 == True, or an object overriding __eq__).
    if ca_bundle is None:
        if verify is not True:
            raise R2ClientRejected("tls_verification")
    elif (
        type(ca_bundle) is not str
        or not ca_bundle.startswith("/")
        or ca_bundle != ca_bundle.strip()
        or type(verify) is not str
        or verify != ca_bundle
    ):
        raise R2ClientRejected("tls_verification")
    # Includes proxies taken from HTTP(S)_PROXY when the client did not set none.
    if proxies != {}:
        raise R2ClientRejected("proxies")
    if getattr(config, "request_checksum_calculation", None) != "when_required":
        raise R2ClientRejected("request_checksum")
    if getattr(config, "response_checksum_validation", None) != "when_required":
        raise R2ClientRejected("response_checksum")
    retries = getattr(config, "retries", None) or {}
    attempts = retries.get("total_max_attempts")
    legacy = retries.get("max_attempts")
    if attempts is None and isinstance(legacy, int) and not isinstance(legacy, bool):
        attempts = legacy + 1
    if not isinstance(attempts, int) or isinstance(attempts, bool):
        raise R2ClientRejected("retries")
    if not 1 <= attempts <= max_attempts:
        raise R2ClientRejected("retries")
    if not _timeout(getattr(config, "connect_timeout", None), MAX_CONNECT_TIMEOUT_SECONDS):
        raise R2ClientRejected("connect_timeout")
    if not _timeout(getattr(config, "read_timeout", None), MAX_READ_TIMEOUT_SECONDS):
        raise R2ClientRejected("read_timeout")
    if (getattr(config, "s3", None) or {}).get("addressing_style") != "path":
        raise R2ClientRejected("addressing_style")
    if getattr(config, "signature_version", None) not in (None, "s3v4", "v4"):
        raise R2ClientRejected("signature_version")
    # Static credentials supplied to the client itself, never the SDK chain.
    if credentials is None or getattr(credentials, "method", None) != "explicit":
        raise R2ClientRejected("credentials")


def pin_requests(client: Any, target: R2Target) -> None:
    """Refuse, before sending, any request that is not for ``target``'s bucket.

    ``validate_client`` checks the endpoint the client was given, but botocore
    resolves each request URL through its endpoint rules, which a data file
    (``AWS_DATA_PATH`` or ``~/.aws/models``) can replace. This guard runs first
    on every send and compares the final URL with the exact endpoint and bucket.
    """
    base = f"{endpoint_for(target)}/{target.bucket}"

    def guard(request: Any = None, **_: Any) -> None:
        url = getattr(request, "url", None)
        if not isinstance(url, str) or not url.startswith(base):
            raise R2ClientRejected("request_endpoint")
        if url != base and url[len(base)] not in "/?":
            raise R2ClientRejected("request_endpoint")

    client.meta.events.register_first("before-send.s3", guard, unique_id="r2-request-pin")
