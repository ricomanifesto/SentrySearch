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


class Captured(Exception):
    pass


def request_headers(client) -> dict:
    """Prepare one real request and stop it before anything is sent."""
    seen = {}

    def capture(request, **_):
        seen.update(
            {
                key: value.decode() if isinstance(value, bytes) else str(value)
                for key, value in request.headers.items()
            }
        )
        raise Captured()

    client.meta.events.register("before-send", capture)
    try:
        client.get_caller_identity()
    except Captured:
        pass
    return seen


built = {}
headers = {}
if os.environ.get("SENTRY_CLI_MODE") != "refusal":
    clients = AwsClients(fixture_credentials(), "us-east-1")
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
            "s3": client.meta.config.s3,
            "user_agent": client.meta.config.user_agent,
        }
    sts = clients.client("sts")
    headers = request_headers(sts)

work = Path(os.environ["SENTRY_CLI_WORK"])
r = cli_rig(work)
code, report = r.main(*r.args("run"), environ=dict(os.environ))
print(
    json.dumps(
        {
            "clients": built,
            "headers": {
                key: value
                for key, value in headers.items()
                if key in {"User-Agent", "X-Amzn-Trace-Id"}
            },
            "run": {
                "code": code,
                "state": report.get("state"),
                "reason": report.get("reason"),
                "error": report.get("error"),
                "detail": report.get("detail"),
            },
            "events": EVENTS,
            "bridge_services": sorted({service for service, _o, _p in r.aws.bridge.calls}),
        }
    )
)
