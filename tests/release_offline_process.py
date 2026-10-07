"""Run one fake release with network access denied; print a JSON receipt.

Executed by tests/test_release_offline.py in a separate interpreter so module
imports and socket guards cannot leak into, or be satisfied by, the test runner.
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
        raise OSError(f"network access denied by offline release test: {name}")

    return blocked


socket.socket.connect = deny("connect")  # type: ignore[method-assign]
socket.socket.connect_ex = deny("connect_ex")  # type: ignore[method-assign]
socket.create_connection = deny("create_connection")  # type: ignore[assignment]
socket.getaddrinfo = deny("getaddrinfo")  # type: ignore[assignment]
socket.gethostbyname = deny("gethostbyname")  # type: ignore[assignment]

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from release.controller import ReleaseController  # noqa: E402
from release.manifest import load_approval, load_manifest  # noqa: E402
from tests.release_fakes import (  # noqa: E402
    FakeClock,
    FakeEcs,
    FakeEvidence,
    FakeLogs,
    FakeStore,
    JobPlan,
    Tokens,
    approval_document,
    encode,
    manifest_document,
)


def release(fail_job: int | None) -> dict:
    document = manifest_document()
    loaded = load_manifest(encode(document))
    clock = FakeClock()
    ecs = FakeEcs(clock)
    ecs.configure(document)
    if fail_job is not None:
        ecs.plans[document["jobs"][fail_job]["task"]["task_definition"]] = JobPlan(
            exits={"init": 1}
        )
    outcome = ReleaseController(
        loaded,
        load_approval(encode(approval_document(loaded.sha256))),
        store=FakeStore(),
        ecs=ecs,
        evidence=FakeEvidence(ecs, document),
        logs=FakeLogs(ecs, document),
        clock=clock,
        tokens=Tokens(),
        session_id="offline-session",
    ).run()
    return {"state": outcome.state, "reason": outcome.reason}


results = [release(None), release(2)]
print(
    json.dumps(
        {
            "results": results,
            "socket_attempts": ATTEMPTS,
            "loaded_sdk_or_http_modules": sorted(
                name
                for name in sys.modules
                if name.split(".")[0]
                in {
                    "boto3",
                    "botocore",
                    "aiobotocore",
                    "s3transfer",
                    "httpx",
                    "requests",
                    "urllib3",
                }
            ),
        }
    )
)
