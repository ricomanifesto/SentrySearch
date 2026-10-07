"""Run releases through the AWS adapters with network access denied; print a JSON receipt.

Executed by tests/test_release_aws_offline.py in a separate interpreter with a
poisoned AWS environment, so socket guards and imports cannot leak into, or be
satisfied by, the test runner.
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
        raise OSError(f"network access denied by adapter process test: {name}")

    return blocked


socket.socket.connect = deny("connect")  # type: ignore[method-assign]
socket.socket.connect_ex = deny("connect_ex")  # type: ignore[method-assign]
socket.create_connection = deny("create_connection")  # type: ignore[assignment]
socket.getaddrinfo = deny("getaddrinfo")  # type: ignore[assignment]
socket.gethostbyname = deny("gethostbyname")  # type: ignore[assignment]

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests.test_release_aws import adapted, aws_rig  # noqa: E402

results = []
endpoints = set()
for checks in ("worker", "all"):
    r, aws = aws_rig(checks=checks)
    outcome = adapted(r, aws).run()
    results.append({"state": outcome.state, "reason": outcome.reason})
    endpoints |= {
        client.meta.endpoint_url
        for client in (aws.client("ecs"), aws.client("logs"), aws.client("s3"))
    }
print(
    json.dumps(
        {
            "results": results,
            "socket_attempts": ATTEMPTS,
            "endpoints": sorted(endpoints),
            "sdk_calls": len(aws.bridge.calls),
        }
    )
)
