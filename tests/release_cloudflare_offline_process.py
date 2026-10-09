"""Run whole Cloudflare releases with the network denied.

Executed by tests/test_release_cloudflare_offline.py in a separate interpreter
whose environment poisons every Cloudflare, Wrangler, AWS, proxy and dotenv
channel. Each release uses the real signed control client and the R2 control
store against offline fakes:
- a first release;
- one where the objects refuse migrations as the real JobRunner does, with no
  test-supplied migration receipts;
- one with no operational observers.

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
        raise OSError(f"network access denied by offline Cloudflare release test: {name}")

    return blocked


socket.socket.connect = deny("connect")  # type: ignore[method-assign]
socket.socket.connect_ex = deny("connect_ex")  # type: ignore[method-assign]
socket.create_connection = deny("create_connection")  # type: ignore[assignment]
socket.getaddrinfo = deny("getaddrinfo")  # type: ignore[assignment]
socket.gethostbyname = deny("gethostbyname")  # type: ignore[assignment]
socket.gethostbyname_ex = deny("gethostbyname_ex")  # type: ignore[assignment]

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from release.controller import ReleaseController  # noqa: E402
from release_cloudflare.control_client import ControlClient, Ed25519Signer  # noqa: E402
from release_cloudflare.manifest import load_approval, load_manifest  # noqa: E402
from release_cloudflare.platform import CloudflarePlatform  # noqa: E402
from release_cloudflare.r2_store import R2ObjectStore, parse_envelope  # noqa: E402
from tests.cloudflare_control_vectors import private_key  # noqa: E402
from tests.cloudflare_fakes import (  # noqa: E402
    FakeDOControl,
    FakeReceipts,
    FakeVersions,
    approval_document,
    manifest_document,
)
from tests.r2_fakes import CONTROL, R2Backend, make_client  # noqa: E402
from tests.release_fakes import FakeClock, Tokens, encode  # noqa: E402

LOCK = "locks/staging.json"


def public_key() -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return private_key().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def release(scenario: str) -> dict:
    document = manifest_document()
    loaded = load_manifest(encode(document))
    clock = FakeClock()
    versions = FakeVersions(clock, document)
    control = FakeDOControl(clock, versions, document, public_key())
    receipts = FakeReceipts(control, document)
    # Only the no-producer scenario runs the JobRunner as it is: migrate refused.
    control.wire_migrations = scenario != "migrations_unwired"
    if scenario == "no_observers":
        receipts.missing_checks.update({"runtime-protected-readiness", "api-operational"})
    client = ControlClient(
        control, Ed25519Signer(private_key()), clock, release_id=document["release_id"]
    )
    platform = CloudflarePlatform(
        loaded, control=client, versions=versions, receipts=receipts, clock=clock
    )
    backend = R2Backend()
    outcome = ReleaseController(
        loaded,
        load_approval(encode(approval_document(loaded.sha256))),
        store=R2ObjectStore(make_client(backend), CONTROL),
        platform=platform,
        clock=clock,
        tokens=Tokens(),
        session_id="offline-session",
    ).run()
    return {
        "scenario": scenario,
        "state": outcome.state,
        "reason": outcome.reason,
        "lock_state": parse_envelope(backend.raw(LOCK))[0],
        "control_requests": len(control.requests),
        "unsigned_or_refused": sorted(
            {q["result"] for q in control.requests if q.get("result") not in (200, None)}
        ),
        "deployments": len(versions.mutations),
    }


results = [release(name) for name in ("first_release", "migrations_unwired", "no_observers")]
print(
    json.dumps(
        {
            "results": results,
            "socket_attempts": ATTEMPTS,
            "loaded_http_modules": sorted(
                name
                for name in sys.modules
                if name.split(".")[0] in {"boto3", "requests", "httpx", "aiohttp", "dotenv"}
            ),
        }
    )
)
