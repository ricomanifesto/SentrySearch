"""Import the API and worker paths as the Cloudflare entrypoint would, offline.

Executed by tests/test_artifact_r2_offline.py with a poisoned environment and
``SENTRYSEARCH_PLATFORM=cloudflare``. Sockets are denied before any import.
The selected R2 store is driven through the offline R2 model; the shared S3
manager must never initialize. Prints one JSON receipt.
"""

from __future__ import annotations

import json
from pathlib import Path
import socket
import sys

ATTEMPTS: list[str] = []


def deny(name):
    def blocked(*_args, **_kwargs):
        ATTEMPTS.append(name)
        raise OSError(f"network access denied by offline artifact test: {name}")

    return blocked


socket.socket.connect = deny("connect")  # type: ignore[method-assign]
socket.socket.connect_ex = deny("connect_ex")  # type: ignore[method-assign]
socket.create_connection = deny("create_connection")  # type: ignore[assignment]
socket.getaddrinfo = deny("getaddrinfo")  # type: ignore[assignment]
socket.gethostbyname = deny("gethostbyname")  # type: ignore[assignment]
socket.gethostbyname_ex = deny("gethostbyname_ex")  # type: ignore[assignment]

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import dev.run_runtime_worker as worker  # noqa: E402
import src.api.main as api  # noqa: E402
from src.storage.r2_artifacts import R2ArtifactStore  # noqa: E402
from src.storage.report_service import report_service  # noqa: E402
from src.storage.s3_manager import s3_manager  # noqa: E402
from tests.r2_fakes import R2Backend  # noqa: E402

store = report_service.artifacts
assert api.report_service is report_service
# The API and worker reach the store through the service's established name.
assert report_service.s3_manager is store
# The worker's job loader checks persistence; the database is not under test.
setattr(report_service.db_manager, "require_schema", lambda: None)
worker.load_jobs()
assert isinstance(store, R2ArtifactStore)
client = store._client
backend = R2Backend(target=store.target)
client.meta.events.register("before-send.s3", backend.handle)
key = store.upload_markdown_report("report-1", "offline body")
round_trip = store.download_content(key)
url = store.get_presigned_url(key)
store.delete_report_files("report-1")
print(
    json.dumps(
        {
            "socket_attempts": ATTEMPTS,
            "artifacts": type(store).__name__,
            "endpoint": client.meta.endpoint_url,
            "credential_method": client._get_credentials().method,
            "proxies": client._endpoint.http_session._proxy_config._proxies,
            "round_trip": round_trip,
            "presign_host": url.split("/")[2],
            "remaining": backend.keys(),
            "s3_initialized": s3_manager._initialized,
            "requests": [(entry.method, entry.status) for entry in backend.log],
        }
    )
)
