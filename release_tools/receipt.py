"""The controller's fixed receipt envelope and allowlisted, bounded log events.

Receipts go to stdout behind a marker; JSON log events go to stderr. Neither ever
carries driver text, SQL, credentials or verifiers.
"""

import http.client
import json
import re
import socket
import sys
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from typing import Any

RECEIPT_MARKER = "SENTRY_RELEASE_RECEIPT"
RECEIPT_SCHEMA = "sentry.release-tools.job.v1"
LOG_FIELDS = frozenset(
    {
        "reason",
        "job_id",
        "release_id",
        "kind",
        "database",
        "sql_outcome",
        "outcome",
        "exit_code",
        "pid",
        "backend_start",
        "principal",
        "application_name",
        "state",
    }
)
_KEY = re.compile(r"[a-z][a-z_]{0,31}")
_EVENT = re.compile(r"[a-z][a-z_]{0,39}")
_VALUE = re.compile(r"[A-Za-z0-9_.:,/-]{1,256}")
_STATUSES = frozenset({"succeeded", "failed"})
ENVELOPE_FIELDS = frozenset({"schema", "release_id", "job_id", "task_arn", "status", "result"})
# Cloudflare jobs post a separately versioned envelope to their JobRunner's
# intake; the AWS v1 envelope and its stdout path above are unchanged.
CLOUDFLARE_RECEIPT_SCHEMA = "sentry.release-tools.job.cloudflare.v1"
CLOUDFLARE_ENVELOPE_FIELDS = frozenset(
    {"schema", "release_id", "job_id", "durable_object_id", "launch_nonce", "status", "result"}
)
EVIDENCE_HOST = "evidence.internal"
JOB_RECEIPT_PATH = "/v1/job-receipt"
MAX_POST_BYTES = 2048
POST_DEADLINE_SECONDS = 10.0
POST_ATTEMPTS = 4
POST_PAUSE_SECONDS = 1.0
_OBJECT_ID = re.compile(r"[0-9a-f]{64}")
_NONCE = re.compile(r"[0-9a-f]{32}")


class ReceiptAmbiguous(ValueError):
    """More than one, malformed or non-envelope receipt: the controller holds."""


def _checked(fields: Mapping[str, object]) -> dict[str, str]:
    checked = {}
    for key, value in fields.items():
        text = str(value)
        if not _KEY.fullmatch(key) or not _VALUE.fullmatch(text):
            raise ValueError("value outside the receipt/log allowlist")
        checked[key] = text
    return checked


def emit_receipt(
    *, release_id: str, job_id: str, task_arn: str, status: str, result: dict[str, str]
) -> None:
    if status not in _STATUSES:
        raise ValueError("receipt status")
    envelope = {
        "schema": RECEIPT_SCHEMA,
        **_checked({"release_id": release_id, "job_id": job_id, "task_arn": task_arn}),
        "status": status,
        "result": _checked(result),
    }
    line = json.dumps(envelope, separators=(",", ":"), sort_keys=True)
    sys.stdout.write(f"{RECEIPT_MARKER} {line}\n")
    sys.stdout.flush()


def cloudflare_envelope(
    *,
    release_id: str,
    job_id: str,
    durable_object_id: str,
    launch_nonce: str,
    status: str,
    result: dict[str, str],
) -> dict[str, Any]:
    if status not in _STATUSES:
        raise ValueError("receipt status")
    if not _OBJECT_ID.fullmatch(durable_object_id) or not _NONCE.fullmatch(launch_nonce):
        raise ValueError("receipt identity")
    return {
        "schema": CLOUDFLARE_RECEIPT_SCHEMA,
        **_checked({"release_id": release_id, "job_id": job_id}),
        "durable_object_id": durable_object_id,
        "launch_nonce": launch_nonce,
        "status": status,
        "result": _checked(result),
    }


def post_cloudflare_receipt(
    envelope: Mapping[str, Any],
    *,
    deadline_seconds: float = POST_DEADLINE_SECONDS,
    attempts: int = POST_ATTEMPTS,
    connection: Callable[..., http.client.HTTPConnection] = http.client.HTTPConnection,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> bool:
    """Post the receipt to the JobRunner's intake within one whole deadline.

    The deadline covers name resolution, connecting, sending and the reply: each
    attempt runs in a worker thread that is abandoned (its socket shut down) when
    the remaining time is spent. A refusal (4xx) is final; a lost or failed
    exchange is retried with the identical body, which the intake stores
    idempotently. Returns whether the intake accepted it. Never raises for the
    network: a lost receipt is missing evidence, which holds the release.
    """
    if set(envelope) != CLOUDFLARE_ENVELOPE_FIELDS:
        raise ValueError("receipt envelope")
    body = json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode()
    if len(body) > MAX_POST_BYTES:
        raise ValueError("receipt size")
    deadline = monotonic() + deadline_seconds
    for attempt in range(attempts):
        remaining = deadline - monotonic()
        if remaining <= 0:
            return False
        status = _post_once(body, remaining, connection)
        if status == 204:
            return True
        if status is not None and 400 <= status < 500:
            return False
        if attempt + 1 < attempts:
            sleep(max(0.0, min(POST_PAUSE_SECONDS, deadline - monotonic())))
    return False


def _post_once(
    body: bytes, timeout: float, connection: Callable[..., http.client.HTTPConnection]
) -> int | None:
    holder: dict[str, Any] = {}

    def exchange() -> None:
        try:
            client = connection(EVIDENCE_HOST, 80, timeout=timeout)
        except (OSError, http.client.HTTPException):
            holder["status"] = None
            return
        holder["client"] = client
        try:
            client.request(
                "POST", JOB_RECEIPT_PATH, body=body, headers={"Content-Type": "application/json"}
            )
            response = client.getresponse()
            response.read(1024)
            holder["status"] = response.status
        except (OSError, http.client.HTTPException):
            holder["status"] = None
        finally:
            client.close()

    worker = threading.Thread(target=exchange, name="job-receipt-post", daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        # Shut the socket down so a blocked read returns; a thread still resolving
        # the name is abandoned (daemon) and its late result is ignored.
        sock = getattr(holder.get("client"), "sock", None)
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        return None
    return holder.get("status")


def log(event: str, **fields: object) -> None:
    if not _EVENT.fullmatch(event) or set(fields) - LOG_FIELDS:
        raise ValueError("log event outside the allowlist")
    line = json.dumps({"event": event, **_checked(fields)}, separators=(",", ":"))
    sys.stderr.write(line + "\n")
    sys.stderr.flush()


def extract_receipt(lines: Iterable[str]) -> dict[str, Any] | None:
    """The single receipt in one task's log stream, None if absent.

    The log reader passes only the stream of the observed task. Absence is a
    missing receipt; duplicates or a malformed envelope are ambiguous. Both hold.
    """
    found = [line for line in lines if line.startswith(RECEIPT_MARKER)]
    if not found:
        return None
    if len(found) != 1 or not found[0].startswith(RECEIPT_MARKER + " "):
        raise ReceiptAmbiguous("receipt count or marker")
    try:
        document = json.loads(found[0][len(RECEIPT_MARKER) + 1 :])
    except ValueError as error:
        raise ReceiptAmbiguous("receipt is not JSON") from error
    if (
        not isinstance(document, dict)
        or set(document) != ENVELOPE_FIELDS
        or not isinstance(document["result"], dict)
    ):
        raise ReceiptAmbiguous("receipt envelope")
    return document
