"""Run the operator CLI in a poisoned environment; print a JSON receipt.

Executed by tests/test_release_cli_offline.py in a separate interpreter. An
audit hook records any file opened under the poisoned paths or the poisoned
HOME, any process started and any socket use, before anything is imported.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import sys

POISON = os.environ["SENTRY_CLI_POISON_ROOT"]
EVENTS: list[str] = []


def audit(event: str, args: tuple) -> None:
    if event == "open" and args and isinstance(args[0], (str, bytes, os.PathLike)):
        path = os.fsdecode(args[0])
        if path.startswith(POISON):
            EVENTS.append("open:" + os.path.relpath(path, POISON))
    elif event in {"subprocess.Popen", "os.exec", "os.posix_spawn", "os.system", "os.spawn"}:
        EVENTS.append(event)
    elif event in {"socket.connect", "socket.getaddrinfo", "socket.gethostbyname"}:
        EVENTS.append(event)


sys.addaudithook(audit)


def deny(name):
    def blocked(*_args, **_kwargs):
        EVENTS.append("denied:" + name)
        raise OSError(f"network access denied by CLI process test: {name}")

    return blocked


socket.socket.connect = deny("connect")  # type: ignore[method-assign]
socket.socket.connect_ex = deny("connect_ex")  # type: ignore[method-assign]
socket.create_connection = deny("create_connection")  # type: ignore[assignment]
socket.getaddrinfo = deny("getaddrinfo")  # type: ignore[assignment]
socket.gethostbyname = deny("gethostbyname")  # type: ignore[assignment]

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from release_cli.clients import AwsClients  # noqa: E402
from tests.test_release_cli import cli_rig, fixture_credentials  # noqa: E402

clients = AwsClients(fixture_credentials(), "us-east-1")
built = {}
for service in ("ecs", "logs", "s3", "sts"):
    client = clients.client(service)
    endpoint = client._endpoint
    session = endpoint.http_session
    credentials = client._request_signer._credentials
    built[service] = {
        "endpoint": client.meta.endpoint_url,
        "region": client.meta.region_name,
        "retries": client.meta.config.retries,
        "proxies": session._proxy_config._proxies,
        # True: botocore resolves its locked default bundle per request, no override path.
        "verify_default": session._verify is True,
        "credential_method": credentials.method,
        "explicit_key": credentials.access_key == fixture_credentials().access_key_id,
    }

work = Path(os.environ["SENTRY_CLI_WORK"])
r = cli_rig(work)
code, report = r.main(*r.args("run"))
print(
    json.dumps(
        {
            "clients": built,
            "run": {"code": code, "state": report.get("state"), "reason": report.get("reason")},
            "events": EVENTS,
            "bridge_services": sorted({service for service, _o, _p in r.aws.bridge.calls}),
        }
    )
)
