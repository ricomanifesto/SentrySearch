"""ObjectStore over an injected S3 client: conditional writes on the control bucket.

Create uses If-None-Match: *; replace and delete use If-Match with the ETag the
controller read. A 412, or a 409 from a concurrent conditional write, is a lost
race: ``PreconditionFailed``. A write whose outcome is unknown is
``AmbiguousResponse``. The controller's next conditional write then fails if
that write had landed, so neither case can fork the journal or steal the lock.
Every request names the expected bucket owner. Versioned objects are
recoverable evidence, not tamper-proof attestation.
"""

from __future__ import annotations

import re
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from release.journal import PreconditionFailed
from release.ports import AmbiguousResponse
from release_aws.errors import (
    AwsRequestRejected,
    call,
    classify,
    error_code,
    http_status,
    require_client,
)

# Only the two object kinds the controller writes, under the prefixes the
# bootstrap policies grant: the release journal and the environment lock.
KEY = re.compile(
    r"releases/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/journal\.json"
    r"|locks/[a-z0-9]+(?:-[a-z0-9]+)*\.json"
)
MAX_OBJECT_BYTES = 4 * 1024 * 1024
LOST_RACE_CODES = frozenset({"PreconditionFailed", "ConditionalRequestConflict"})
MISSING_CODES = frozenset({"NoSuchKey", "NotFound"})


def _key(key: str) -> str:
    if not KEY.fullmatch(key):
        raise ValueError("object key outside the release journal and lock prefixes")
    return key


def _etag(response: dict[str, Any], operation: str) -> str:
    etag = response.get("ETag")
    if not isinstance(etag, str) or not etag:
        raise AmbiguousResponse(f"{operation}: response without an ETag")
    return etag


class S3ObjectStore:
    def __init__(self, client: Any, *, region: str, bucket: str, expected_owner: str) -> None:
        require_client(client, service="s3", region=region)
        if not re.fullmatch(r"[0-9]{12}", expected_owner):
            raise ValueError("expected bucket owner must be a 12-digit account ID")
        self.client = client
        self.bucket = bucket
        self.owner = expected_owner

    def _write(self, operation: str, **params: Any) -> dict[str, Any]:
        try:
            return getattr(self.client, operation)(
                Bucket=self.bucket, ExpectedBucketOwner=self.owner, **params
            )
        except ClientError as error:
            code = error_code(error)
            if (
                code in LOST_RACE_CODES
                or http_status(error) in (409, 412)
                # A conditional replace/delete of an object that is gone did not match.
                or ("IfMatch" in params and (code in MISSING_CODES or http_status(error) == 404))
            ):
                raise PreconditionFailed(code) from None
            raise classify(operation, error) from None
        except BotoCoreError as error:
            raise classify(operation, error) from None

    def create(self, key: str, body: bytes) -> str:
        response = self._write(
            "put_object", Key=_key(key), Body=body, IfNoneMatch="*", ContentType="application/json"
        )
        return _etag(response, "PutObject")

    def replace(self, key: str, body: bytes, *, if_match: str) -> str:
        response = self._write(
            "put_object", Key=_key(key), Body=body, IfMatch=if_match, ContentType="application/json"
        )
        return _etag(response, "PutObject")

    def delete(self, key: str, *, if_match: str) -> None:
        self._write("delete_object", Key=_key(key), IfMatch=if_match)

    def read(self, key: str) -> tuple[bytes, str] | None:
        try:
            response = call(
                self.client,
                "get_object",
                Bucket=self.bucket,
                Key=_key(key),
                ExpectedBucketOwner=self.owner,
            )
        except AwsRequestRejected as error:
            # Only an explicit not-found means absent. A 403 (for example without
            # list permission) is a refusal, never proof that nothing exists.
            if error.code in MISSING_CODES:
                return None
            raise
        etag = _etag(response, "GetObject")
        length = response.get("ContentLength")
        body = response.get("Body")
        if type(length) is not int or not 0 <= length <= MAX_OBJECT_BYTES or body is None:
            raise AmbiguousResponse("GetObject: unexpected object size")
        try:
            data = body.read(MAX_OBJECT_BYTES + 1)
        except BotoCoreError as error:
            raise classify("get_object", error) from None
        finally:
            body.close()
        if len(data) != length:
            raise AmbiguousResponse("GetObject: incomplete body")
        return data, etag
