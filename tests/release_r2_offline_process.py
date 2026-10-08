"""Run fake releases over the R2 control store with the network denied.

Executed by tests/test_release_r2_offline.py in a separate interpreter whose
environment poisons every credential, endpoint and telemetry fallback, so
imports and socket guards cannot leak into, or be satisfied by, the test runner.
Prints one JSON receipt.
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
        raise OSError(f"network access denied by offline R2 release test: {name}")

    return blocked


socket.socket.connect = deny("connect")  # type: ignore[method-assign]
socket.socket.connect_ex = deny("connect_ex")  # type: ignore[method-assign]
socket.create_connection = deny("create_connection")  # type: ignore[assignment]
socket.getaddrinfo = deny("getaddrinfo")  # type: ignore[assignment]
socket.gethostbyname = deny("gethostbyname")  # type: ignore[assignment]
socket.gethostbyname_ex = deny("gethostbyname_ex")  # type: ignore[assignment]

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from release.controller import ReleaseController  # noqa: E402
from release.manifest import load_approval, load_manifest  # noqa: E402
from release_cloudflare.r2_client import endpoint_for  # noqa: E402
from release_cloudflare.r2_store import R2ObjectStore, parse_envelope  # noqa: E402
from tests.r2_fakes import CONTROL, R2Backend, make_client  # noqa: E402
from tests.release_fakes import (  # noqa: E402
    FakeClock,
    FakeEcs,
    FakeEvidence,
    FakeLogs,
    JobPlan,
    Tokens,
    approval_document,
    encode,
    manifest_document,
)

LOCK = "locks/staging.json"


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
    backend = R2Backend()
    client = make_client(backend)
    outcome = ReleaseController(
        loaded,
        load_approval(encode(approval_document(loaded.sha256))),
        store=R2ObjectStore(client, CONTROL),
        ecs=ecs,
        evidence=FakeEvidence(ecs, document),
        logs=FakeLogs(ecs, document),
        clock=clock,
        tokens=Tokens(),
        session_id="offline-session",
    ).run()
    lock_state = parse_envelope(backend.raw(LOCK))[0]
    return {
        "state": outcome.state,
        "reason": outcome.reason,
        "lock_state": lock_state,
        "requests": len(backend.log),
        "deleting_requests": len(backend.deleting_requests()),
        "endpoint": client.meta.endpoint_url,
        "credential_method": client._get_credentials().method,
    }


results = [release(None), release(2)]
print(
    json.dumps(
        {
            "results": results,
            "expected_endpoint": endpoint_for(CONTROL),
            "socket_attempts": ATTEMPTS,
            "loaded_http_modules": sorted(
                name
                for name in sys.modules
                if name.split(".")[0] in {"boto3", "requests", "httpx", "aiohttp", "dotenv"}
            ),
        }
    )
)
