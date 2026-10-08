"""The report artifact operations every storage backend provides.

``ArtifactStore`` is the call surface the report service, API and worker
already use. Keys are content addressed: the same bytes for the same report map
to the same key, and different bytes never overwrite a published key.
"""

from __future__ import annotations

import hashlib
from typing import Any, Protocol

# The presign ceiling shared by S3 SigV4 and R2: one second to seven days.
MAX_PRESIGN_SECONDS = 7 * 24 * 60 * 60


class ArtifactStore(Protocol):
    def require_available(self) -> None:
        """Fail if the backend cannot be used; performs no object access."""
        ...

    def upload_markdown_report(self, report_id: str, markdown_content: str) -> str: ...

    def upload_trace_data(self, report_id: str, trace_data: dict[Any, Any]) -> str: ...

    def download_content(self, s3_key: str) -> str: ...

    def get_presigned_url(self, s3_key: str, expiration: int = 3600) -> str: ...

    def delete_report_files(self, report_id: str) -> None: ...

    def list_report_files(self, report_id: str) -> list: ...


def report_prefix(report_id: str) -> str:
    return f"reports/{report_id}/"


def artifact_key(report_id: str, content: bytes, extension: str) -> str:
    """``reports/<id>/artifacts/<sha256>.<extension>`` for the exact bytes."""
    return f"{report_prefix(report_id)}artifacts/{hashlib.sha256(content).hexdigest()}.{extension}"
