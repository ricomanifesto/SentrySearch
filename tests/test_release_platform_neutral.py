"""Provider-neutral regression cases for the release controller's platform strategy.

The AWS suites run unchanged against ``EcsPlatform``. These cases pin what the
extraction added: the constructor's two forms, the core's import boundary, the
session authority derived from the journal, and how platform holds and a lost
session authority end a run.
"""

from __future__ import annotations

import ast
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from release.controller import (
    EcsPlatform,
    RecoveryAuthorization,
    ReleaseController,
    ReleaseHalted,
)
from release.machine import plan_rollback
from release.manifest import load_approval, load_manifest
from release.ports import PlatformHold, SessionSuperseded
from tests.release_fakes import SimulatedCrash, encode, iso, sha
from tests.test_release_controller import JOURNAL, LOCK, Rig, rig

RELEASE = Path(__file__).resolve().parents[1] / "release"
FORBIDDEN_IMPORTS = (
    "release_cloudflare",
    "boto3",
    "botocore",
    "httpx",
    "requests",
    "urllib",
    "http",
    "socket",
    "ssl",
    "cryptography",
    "subprocess",
)


class Recording:
    """Delegates to the ECS strategy; records authority and can inject behavior."""

    def __init__(self, inner: EcsPlatform, clock, *, expiry_seconds: int | None = None) -> None:
        self.inner = inner
        self.clock = clock
        self.expiry_seconds = expiry_seconds
        self.authorities = []
        self.sends: list[tuple[str, datetime]] = []
        self.services_error: Exception | None = None

    def __getattr__(self, name):
        return getattr(self.inner, name)

    def bind(self, authority) -> None:
        self.authorities.append(authority)

    def command_fields(self) -> dict:
        if self.expiry_seconds is None:
            return {}
        expires = self.clock.now() + timedelta(seconds=self.expiry_seconds)
        return {"command_expires_at": iso(expires)}

    def services(self):
        if self.services_error is not None:
            raise self.services_error
        return self.inner.services()

    def launch(self, job, request, intent):
        self.sends.append(("launch", self.clock.now()))
        return self.inner.launch(job, request, intent)

    def send_update(self, request, intent):
        self.sends.append(("update", self.clock.now()))
        return self.inner.send_update(request, intent)

    def send_stop(self, request, intent):
        self.sends.append(("stop", self.clock.now()))
        return self.inner.send_stop(request, intent)


def controller(r: Rig, platform, session: str = "session-a") -> ReleaseController:
    return ReleaseController(
        load_manifest(encode(r.document)),
        load_approval(r.approval_raw),
        store=r.store,
        platform=platform,
        clock=r.clock,
        tokens=r.tokens,
        session_id=session,
    )


def recording(r: Rig, **options) -> Recording:
    loaded = load_manifest(encode(r.document))
    return Recording(EcsPlatform(loaded.manifest, r.ecs, r.evidence, r.logs), r.clock, **options)


def test_the_constructor_takes_the_aws_ports_or_one_platform():
    r = rig()
    loaded, approval = load_manifest(encode(r.document)), load_approval(r.approval_raw)
    common = dict(store=r.store, clock=r.clock, tokens=r.tokens, session_id="session-a")
    aws = dict(ecs=r.ecs, evidence=r.evidence, logs=r.logs)
    assert isinstance(ReleaseController(loaded, approval, **common, **aws).platform, EcsPlatform)
    platform = recording(r)
    assert ReleaseController(loaded, approval, **common, platform=platform).platform is platform
    for ports in ({}, {"ecs": r.ecs}, {"ecs": r.ecs, "evidence": r.evidence}):
        with pytest.raises(TypeError):
            ReleaseController(loaded, approval, **common, **ports)
    with pytest.raises(TypeError):
        ReleaseController(loaded, approval, **common, **aws, platform=platform)
    with pytest.raises(TypeError):
        ReleaseController(loaded, approval, **common, logs=r.logs, platform=platform)


def test_the_release_core_imports_no_cloud_sdk_network_or_cloudflare_module():
    found = []
    for path in sorted(RELEASE.glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(), filename=str(path))):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            for name in names:
                if name.split(".")[0] in FORBIDDEN_IMPORTS:
                    found.append((path.name, name))
    assert found == []


def test_a_rollback_plan_depends_on_the_rollback_kind_not_its_class():
    r = rig(rollback="compatible_release")
    manifest = load_manifest(encode(r.document)).manifest
    outcomes = {job.id: "succeeded" for job in manifest.jobs}
    expected = plan_rollback(manifest, outcomes, services_touched=True)
    rollback = SimpleNamespace(**dict(manifest.rollback))
    duck = SimpleNamespace(jobs=manifest.jobs, rollback=rollback)
    assert plan_rollback(duck, outcomes, services_touched=True) == expected
    empty = SimpleNamespace(jobs=manifest.jobs, rollback=SimpleNamespace(kind="empty_hold"))
    assert plan_rollback(empty, outcomes, services_touched=True)["kind"] == "empty_hold"


def test_the_first_session_has_fence_one_and_no_quiet_period():
    r = rig()
    platform = recording(r, expiry_seconds=120)
    outcome = controller(r, platform).run()
    assert outcome.state == "held_paused"
    assert [(a.fence, a.quiet_until) for a in platform.authorities] == [(1, None)]
    authority = platform.authorities[0]
    assert (authority.release_id, authority.session_id) == (r.document["release_id"], "session-a")
    intents = [e for e in r.journal()["events"] if e["kind"] == "intent"]
    assert all("command_expires_at" in e for e in intents if e["action"] != "release_lock")
    assert all("command_expires_at" not in e for e in intents if e["action"] == "release_lock")


def test_a_recovered_session_waits_until_every_earlier_command_expired():
    r = rig()
    r.ecs.crash[("run_task", "after")] = 1
    first = recording(r, expiry_seconds=120)
    with pytest.raises(SimulatedCrash):
        controller(r, first).run()
    expiries = [
        datetime.fromisoformat(e["command_expires_at"])
        for e in r.journal()["events"]
        if e["kind"] == "intent" and "command_expires_at" in e
    ]
    r.clock.advance(seconds=5)
    second = recording(r, expiry_seconds=120)
    recover = controller(r, second, "session-b")
    recover.recover(
        RecoveryAuthorization(
            prior_session_id="session-a",
            lock_etag=r.lock_etag(),
            fence_evidence_sha256=sha("prior session process confirmed terminated"),
            authorized_by="fixture-operator",
        )
    )
    outcome = recover.run()
    assert outcome.state == "held_paused", outcome
    quiet = max(expiries) + timedelta(seconds=30)
    assert [(a.fence, a.quiet_until) for a in second.authorities] == [(2, quiet)]
    assert second.sends and min(at for _, at in second.sends) >= quiet


def test_a_platform_hold_holds_with_its_code_and_keeps_the_lock():
    r = rig()
    platform = recording(r)
    platform.services_error = PlatformHold("instance_listing_incomplete")
    outcome = controller(r, platform).run()
    assert (outcome.state, outcome.reason) == ("hold", "instance_listing_incomplete")
    assert LOCK in r.store.objects


def test_a_superseded_session_halts_without_writing_again():
    r = rig()
    platform = recording(r)
    platform.services_error = SessionSuperseded()
    with pytest.raises(ReleaseHalted) as error:
        controller(r, platform).run()
    assert error.value.code == "session_superseded"
    events = r.journal()["events"]
    assert [e.get("to") for e in events if e["kind"] == "transition"] == ["prepared", "locked"]
    assert JOURNAL in r.store.objects and LOCK in r.store.objects
