"""The shared object rule table, run against FakeDOControl.

deploy/cloudflare/worker/test/fixtures/object-rules.json is also run against
the real objects (deploy/cloudflare/worker/test/lifecycle.test.ts). Both must
pass, so the fake the controller matrix uses cannot drift from the objects'
authority rules (CF05-R17).
"""

from __future__ import annotations

from datetime import timedelta
import itertools
import json
from pathlib import Path

import pytest

from release_cloudflare.control_client import ControlClient, Ed25519Signer
from tests.cloudflare_control_vectors import private_key
from tests.cloudflare_fakes import FakeDOControl, FakeVersions, manifest_document
from tests.release_fakes import FakeClock

RULES = json.loads(
    (
        Path(__file__).resolve().parents[1]
        / "deploy/cloudflare/worker/test/fixtures/object-rules.json"
    ).read_text()
)["cases"]
OTHER_RELEASE = "11111111-2222-4333-8444-555555555555"


class Capture:
    def __init__(self):
        self.requests = []

    def send(self, request, *, timeout):
        self.requests.append(request)
        return 200, b"{}"


def public_key() -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return private_key().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


@pytest.mark.parametrize("rule", RULES, ids=[rule["name"] for rule in RULES])
def test_the_fake_objects_follow_the_shared_rule_table(rule):
    document = manifest_document()
    release = document["release_id"]
    clock = FakeClock()
    versions = FakeVersions(clock, document)
    for worker in ("worker", "jobs"):
        versions.set_deployment(worker, (document["versions"][worker], 100))
    control = FakeDOControl(clock, versions, document, public_key())
    service, name = (
        ("worker", "worker-0")
        if rule["object"] == "worker"
        else ("jobs", f"job-{release}-runtime-grant")
    )
    ids = (f"rule-{n}" for n in itertools.count(1))
    current = {"nonce": ""}
    run = {"job_id": "runtime-grant", "phase": "grant", "database": "runtime",
           "image": "release_tools", "deadline_seconds": 60}  # fmt: skip
    resolved = {
        "$START": {"release_id": release, "version_id": document["versions"]["worker"]},
        "$START_OTHER_VERSION": {"release_id": release, "version_id": "other"},
        "$RUN": run,
        "$RUN_MIGRATE": {**run, "phase": "migrate"},
        "$RUN_OTHER_IMAGE": {**run, "image": "runtime"},
    }

    def send(command):
        capture = Capture()
        client = ControlClient(
            capture,
            Ed25519Signer(private_key()),
            clock,
            release_id=release if command["release"] == "same" else OTHER_RELEASE,
        )
        client.bind(command["session"], 1)
        body = command["body"]
        if body == "$STOP_CURRENT":
            body = {"start_nonce": current["nonce"]}
        body = resolved.get(body, body) if isinstance(body, str) else body
        lifetime = max(command["expires_in"], 1)
        # The table's fence is sent verbatim, even a malformed one bind() refuses.
        client._fence = command["fence"]  # type: ignore[assignment]
        client.send(
            method=command["method"],
            service=service,
            name=name,
            action=command["action"],
            body=body,
            command_id=command.get("command_id") or next(ids),
            expires_at=clock.now() + timedelta(seconds=lifetime),
        )
        if command["expires_in"] == 0:
            clock.advance(seconds=lifetime)
        status, reply = control._deliver(capture.requests[0])
        if isinstance(reply.get("start_nonce"), str):
            current["nonce"] = reply["start_nonce"]
        return status, reply

    for step in rule["setup"]:
        send(step)
    status, reply = send(rule["command"])
    expect = rule["expect"]
    assert status == expect["status"], reply
    if "code" in expect:
        assert reply.get("code") == expect["code"]
    for key, value in expect.get("body", {}).items():
        assert reply.get(key) == value, key
