"""Report artifacts in Cloudflare R2 through its S3-compatible API.

Keys, metadata and content addressing match ``S3StorageManager``. Differences
are deliberate and follow R2's documented S3 compatibility:

* The client is built from explicit inputs only: an ``R2Target`` (account,
  bucket, optional jurisdiction) and an ``R2Credentials`` object. Profiles,
  shared config and credential files, ambient endpoints, proxies and CA-bundle
  environment variables are ignored. ``release_cloudflare.r2_client``
  validates the result.
* Checksums are calculated only when an operation requires one, so uploads send
  no ``aws-chunked`` body or checksum trailer.
* Presigned URLs are on the S3 API domain and limited to R2's one second to
  seven days; a longer request is refused rather than shortened.
* Report deletion pages through the prefix listing and deletes each key with
  ``DeleteObject``. ``DeleteObjects`` requires a request checksum that R2 does
  not document for that operation, and per-key calls make every failure
  explicit. A partial deletion raises after attempting every key.

This module never reads the process environment; ``src.storage.artifacts``
owns configuration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import logging
import os
import re
from typing import Any, Callable
from urllib.parse import urlsplit

import botocore.session
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from release_cloudflare.r2_client import R2ClientRejected, R2Target, endpoint_for, validate_client

from .artifact_store import MAX_PRESIGN_SECONDS, artifact_key, report_prefix

logger = logging.getLogger(__name__)

# Idempotent operations only: uploads are content addressed and reads, lists
# and single-key deletes may repeat safely.
MAX_ATTEMPTS = 3
LIST_PAGE_KEYS = 1000
MAX_LIST_PAGES = 50
MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024
REPORT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
ARTIFACT_KEY = re.compile(
    r"reports/[A-Za-z0-9][A-Za-z0-9_-]{0,127}/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*"
)
CREDENTIAL = re.compile(r"[\x21-\x7e]{1,512}")
UNAVAILABLE = "Artifact storage unavailable; verify R2 configuration"


class ArtifactDeletionIncomplete(RuntimeError):
    """Some report objects could not be deleted; the rest were attempted."""


@dataclass(frozen=True)
class R2Credentials:
    """An R2 API token's S3 access key id and secret (the token value's SHA-256)."""

    access_key_id: str
    secret_access_key: str = field(repr=False)

    def __post_init__(self) -> None:
        for value in (self.access_key_id, self.secret_access_key):
            if not isinstance(value, str) or not CREDENTIAL.fullmatch(value):
                raise ValueError("R2 credentials must be non-empty printable strings")


def client_config() -> Config:
    return Config(
        request_checksum_calculation="when_required",
        response_checksum_validation="when_required",
        retries={"mode": "standard", "total_max_attempts": MAX_ATTEMPTS},
        connect_timeout=5,
        read_timeout=30,
        s3={"addressing_style": "path"},
        signature_version="s3v4",
        ignore_configured_endpoint_urls=True,
        proxies={},
    )


def build_client(target: R2Target, credentials: R2Credentials, *, ca_bundle: str | None) -> Any:
    """A botocore S3 client for exactly ``target``, isolated from ambient settings."""
    session = botocore.session.Session(
        session_vars={
            "profile": (None, None, None, None),
            "config_file": (None, None, os.devnull, None),
            "credentials_file": (None, None, os.devnull, None),
        }
    )
    return session.create_client(
        "s3",
        region_name="auto",
        endpoint_url=endpoint_for(target),
        aws_access_key_id=credentials.access_key_id,
        aws_secret_access_key=credentials.secret_access_key,
        # An explicit value: None would consult REQUESTS_CA_BUNDLE.
        verify=ca_bundle if ca_bundle is not None else True,
        config=client_config(),
    )


def _report_id(report_id: str) -> str:
    if not isinstance(report_id, str) or not REPORT_ID.fullmatch(report_id):
        raise ValueError("Invalid report id for artifact storage")
    return report_id


def _object_key(key: str) -> str:
    if (
        not isinstance(key, str)
        or not ARTIFACT_KEY.fullmatch(key)
        or any(part in (".", "..") for part in key.split("/"))
    ):
        raise ValueError("Invalid artifact key")
    return key


class R2ArtifactStore:
    """``ArtifactStore`` over one R2 bucket."""

    def __init__(
        self,
        target: R2Target,
        credentials: R2Credentials,
        *,
        ca_bundle: str | None = None,
        client_factory: Callable[[], Any] | None = None,
    ) -> None:
        self.target = target
        self._credentials = credentials
        self._ca_bundle = ca_bundle
        self._client_factory = client_factory or (
            lambda: build_client(target, credentials, ca_bundle=ca_bundle)
        )
        self._client: Any = None
        self._host = urlsplit(endpoint_for(target)).hostname

    # Client --------------------------------------------------------------------------

    def require_available(self) -> None:
        """Build and validate the client; performs no object access."""
        self._ensure_client()

    def _ensure_client(self) -> Any:
        if self._client is None:
            try:
                client = self._client_factory()
                validate_client(
                    client, self.target, ca_bundle=self._ca_bundle, max_attempts=MAX_ATTEMPTS
                )
            except (R2ClientRejected, BotoCoreError, ValueError):
                logger.warning("Artifact storage initialization failed")
                raise RuntimeError(UNAVAILABLE) from None
            self._client = client
        return self._client

    # ArtifactStore -------------------------------------------------------------------

    def upload_markdown_report(self, report_id: str, markdown_content: str) -> str:
        content = markdown_content.encode("utf-8")
        return self._put(report_id, content, "md", "text/markdown", "markdown_report")

    def upload_trace_data(self, report_id: str, trace_data: dict[Any, Any]) -> str:
        content = json.dumps(trace_data, indent=2, sort_keys=True).encode("utf-8")
        return self._put(report_id, content, "json", "application/json", "trace_data")

    def download_content(self, s3_key: str) -> str:
        client = self._ensure_client()
        key = _object_key(s3_key)
        try:
            response = client.get_object(Bucket=self.target.bucket, Key=key)
            content = response["Body"].read(MAX_DOWNLOAD_BYTES + 1)
        except (ClientError, BotoCoreError):
            logger.error("Error downloading artifact content")
            raise
        if len(content) > MAX_DOWNLOAD_BYTES:
            raise ValueError("Artifact exceeds the download bound")
        return content.decode("utf-8")

    def get_presigned_url(self, s3_key: str, expiration: int = 3600) -> str:
        client = self._ensure_client()
        key = _object_key(s3_key)
        if (
            not isinstance(expiration, int)
            or isinstance(expiration, bool)
            or not 1 <= expiration <= MAX_PRESIGN_SECONDS
        ):
            raise ValueError("Presigned URL lifetime must be 1 second to 7 days")
        url = client.generate_presigned_url(
            "get_object",
            Params={"Bucket": self.target.bucket, "Key": key},
            ExpiresIn=expiration,
        )
        if urlsplit(url).hostname != self._host:
            raise RuntimeError("Presigned URL is not on the R2 S3 API domain")
        return url

    def delete_report_files(self, report_id: str) -> None:
        client = self._ensure_client()
        keys = self._list(client, _report_id(report_id))
        failed = 0
        for key in keys:
            try:
                client.delete_object(Bucket=self.target.bucket, Key=key)
            except (ClientError, BotoCoreError):
                failed += 1
        if failed:
            logger.error("Could not delete %d of %d report objects", failed, len(keys))
            raise ArtifactDeletionIncomplete(f"{failed} of {len(keys)} report objects remain")
        logger.info("Deleted %d files for report", len(keys))

    def list_report_files(self, report_id: str) -> list:
        return self._list(self._ensure_client(), _report_id(report_id))

    # Wire ----------------------------------------------------------------------------

    def _put(
        self, report_id: str, content: bytes, extension: str, content_type: str, kind: str
    ) -> str:
        client = self._ensure_client()
        key = artifact_key(_report_id(report_id), content, extension)
        try:
            client.put_object(
                Bucket=self.target.bucket,
                Key=key,
                Body=content,
                ContentType=content_type,
                Metadata={
                    "report_id": report_id,
                    "uploaded_at": datetime.now(timezone.utc).isoformat(),
                    "content_type": kind,
                },
            )
        except (ClientError, BotoCoreError):
            logger.error("Error uploading %s artifact", kind)
            raise
        return key

    def _list(self, client: Any, report_id: str) -> list[str]:
        prefix = report_prefix(report_id)
        keys: list[str] = []
        token: str | None = None
        for _ in range(MAX_LIST_PAGES):
            request: dict[str, Any] = {
                "Bucket": self.target.bucket,
                "Prefix": prefix,
                "MaxKeys": LIST_PAGE_KEYS,
            }
            if token is not None:
                request["ContinuationToken"] = token
            try:
                page = client.list_objects_v2(**request)
            except (ClientError, BotoCoreError):
                logger.error("Error listing report files")
                raise
            for item in page.get("Contents") or []:
                key = item.get("Key")
                if not isinstance(key, str) or not key.startswith(prefix):
                    raise RuntimeError("Listing returned a key outside the report prefix")
                keys.append(key)
            if not page.get("IsTruncated"):
                return keys
            token = page.get("NextContinuationToken")
            if not isinstance(token, str) or not token:
                raise RuntimeError("Truncated listing without a continuation token")
        raise RuntimeError("Report listing exceeded its page bound")
