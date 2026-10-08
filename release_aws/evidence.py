"""EvidencePort: receipts from the observed task's own log stream, nothing else.

Only the single marked receipt line is returned, parsed strictly by
``release_tools.receipt.parse_receipt`` for its kind: migration jobs write the
``migration`` envelope, release-tools jobs the ``tools`` one and observers the
``operational`` one, each read from the stream of the task the controller
observed. Ordinary application output is read but never returned, logged or
carried into an exception. A receipt that is still missing stays unproven: none
is returned, never a fabricated one.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from release.manifest import OBSERVER_CONTAINER, Job, Manifest, ObserverCheck
from release.ports import AmbiguousResponse, LogPort
from release_aws.logs import LogStreamMissing
from release_tools.receipt import ReceiptAmbiguous, parse_receipt

# A job stream holds one receipt and allowlisted, bounded log events. Anything
# larger than this is not a stream these jobs write; it is incomplete evidence.
MAX_PAGES = 20
MAX_BYTES = 262_144
PAGE_LIMIT = 100
_TASK_ID = re.compile(r"[0-9a-f]{32}")


def job_stream(environment_name: str, job: Job, task_arn: str) -> tuple[str, str]:
    """The log group and stream Terraform configures for this job's receipt container.

    deploy/aws-platform-fit: migrations log under ``<database>-release`` from the
    ``migration`` container; grant/proof jobs under ``<database>-<phase>`` from a
    container named for the phase. Both write to ``/<prefix>/<database>-release``.
    """
    task_id = task_arn.rsplit("/", 1)[-1]
    if not _TASK_ID.fullmatch(task_id):
        raise ValueError("unexpected task identifier")
    if job.phase == "migrate":
        prefix, container = f"{job.database}-release", "migration"
    else:
        prefix, container = f"{job.database}-{job.phase}", job.phase
    if container not in {item.name for item in job.task.containers}:
        raise ValueError("job task has no receipt container")
    return f"/{environment_name}/{job.database}-release", f"{prefix}/{container}/{task_id}"


def observer_stream(environment_name: str, check: ObserverCheck, task_arn: str) -> tuple[str, str]:
    """The observe log group and the observer container's stream for this task.

    Terraform gives each observer task definition the stream prefix ``<check id>``
    in ``/<prefix>/observe``, so a receipt can only come from the observed task.
    """
    task_id = task_arn.rsplit("/", 1)[-1]
    if not _TASK_ID.fullmatch(task_id):
        raise ValueError("unexpected task identifier")
    return f"/{environment_name}/observe", f"{check.id}/{OBSERVER_CONTAINER}/{task_id}"


def _millis(moment: datetime) -> int:
    return int(moment.timestamp() * 1000)


class LogEvidence:
    """Receipts for one approved manifest, read within its fixed release window.

    Receipts name the release whose revisions ran: this one, or for a rollback
    the retained prior release (``Manifest.evidence_release_id``).
    """

    def __init__(self, logs: LogPort, manifest: Manifest) -> None:
        self.logs = logs
        self.manifest = manifest
        self.jobs = {job.id: job for job in manifest.jobs}
        self.observers = {
            check.id: check
            for check in manifest.operational_checks
            if isinstance(check, ObserverCheck)
        }
        # Fixed bounds for every read: receipts are written inside the window.
        self.start_ms = _millis(manifest.window.not_before)
        self.end_ms = _millis(manifest.window.expires_at)

    def _messages(self, group: str, stream: str) -> list[str] | None:
        """Every message from the head to the stream end, or None if no stream exists."""
        messages: list[str] = []
        size = 0
        token: str | None = None
        for _ in range(MAX_PAGES):
            try:
                page = self.logs.get_log_events(
                    group,
                    stream,
                    start_time_ms=self.start_ms,
                    end_time_ms=self.end_ms,
                    next_token=token,
                    limit=PAGE_LIMIT,
                )
            except LogStreamMissing:
                return None
            for event in page["events"]:
                # Count bytes without ever raising on (and carrying) a malformed line.
                size += len(event["message"].encode("utf-8", "surrogatepass"))
                if size > MAX_BYTES:
                    raise AmbiguousResponse("job receipt stream exceeds its read bound")
                messages.append(event["message"])
            following = page["nextForwardToken"]
            if following == token:
                return messages
            token = following
        raise AmbiguousResponse("job receipt stream exceeds its read bound")

    def _receipt(self, group: str, stream: str, kind: str) -> dict[str, Any] | None:
        messages = self._messages(group, stream)
        if messages is None:
            # Not yet visible: the controller keeps waiting until the task deadline.
            return None
        try:
            return parse_receipt(messages, kind)
        except ReceiptAmbiguous:
            pass
        # Raised outside the handler: the parser's error chain quotes the raw line.
        raise AmbiguousResponse("receipt stream is ambiguous")

    def job_receipt(self, release_id: str, job_id: str, task_arn: str) -> dict[str, Any] | None:
        if release_id != self.manifest.evidence_release_id or job_id not in self.jobs:
            raise ValueError("receipt requested outside the approved manifest")
        group, stream = job_stream(self.manifest.environment.name, self.jobs[job_id], task_arn)
        kind = "migration" if self.jobs[job_id].phase == "migrate" else "tools"
        return self._receipt(group, stream, kind)

    def operational_receipt(
        self, release_id: str, check_id: str, task_arn: str
    ) -> dict[str, Any] | None:
        if release_id != self.manifest.evidence_release_id or check_id not in self.observers:
            raise ValueError("receipt requested outside the approved manifest")
        group, stream = observer_stream(
            self.manifest.environment.name, self.observers[check_id], task_arn
        )
        return self._receipt(group, stream, "operational")
