"""The rollback kit against the in-memory fakes: a failed upgrade, then the prior pair back.

The prior release is a first deployment the AWS-07b kit ran against its fakes.
A failed upgrade's manifest names that release as its fallback and still holds
the environment lock. The rollback kit fixes the record, re-plans the releases
root (a canned plan document), renders and validates the rollback manifest, runs
``release_cli run`` in process through the offline AWS fakes under the failed
release's handoff, and checks the outcome. No socket opens.
"""

from __future__ import annotations

import copy
from datetime import UTC, datetime
import hashlib
import io
import json
from pathlib import Path
import subprocess
from typing import Any
import uuid

import pytest

from release.journal import Journal, journal_key
from release.manifest import load_manifest
from release_cli import main as cli
from release_cli.clients import AwsClients
from release_cli.clock import MonotonicUtcClock
from release_kits import render, rollback
from release_kits.terraform import UnexpectedPlan
from tests import release_kit_fixtures as fx
from tests.aws_offline import FakeAws
from tests.release_fakes import FakeClock, FakeEcs, FakeEvidence, FakeLogs, FakeStore, Trace
from tests.test_aws_07b_kit import (  # noqa: F401
    OPERATOR,
    FakeIam,
    canary_approval,
    initialized,
    initialized_with,
    no_sockets,
    provider_key_file,
    run_through,
    setup,
    terraform_version,
)
from tests.test_release_cli import ASSUMED, ROLE_ID


def revised(spec: dict, revision: int) -> dict:
    spec = copy.deepcopy(spec)
    family = spec["task_definition"].rsplit(":", 1)[0]
    spec["task_definition"] = f"{family}:{revision}"
    return spec


def failed_upgrade(prior: dict) -> dict:
    """An upgrade from the prior release, at revision 2, whose fallback is the prior pair."""
    document = copy.deepcopy(prior)
    document["release_id"] = str(uuid.uuid4())
    document["jobs"] = [{**job, "task": revised(job["task"], 2)}
                        for job in document["jobs"] if job["phase"] != "bootstrap"]  # fmt: skip
    for check in document["operational_checks"]:
        if "task" in check:
            check["task"] = revised(check["task"], 2)
    document["services"] = {name: revised(spec, 2) for name, spec in prior["services"].items()}
    schemas = {job["database"]: job["expect"]["schema"] for job in prior["jobs"]
               if job["phase"] == "migrate"}  # fmt: skip
    document["rollback"] = {
        "kind": "compatible_release", "release_id": prior["release_id"],
        "images": {name: {"repository": prior["images"][name]["repository"],
                          "arm64_digest": prior["images"][name]["arm64_digest"]}
                   for name in ("runtime", "search")},
        "services": copy.deepcopy(prior["services"]),
        "trust_sha256": fx.sha("prior-trust"),
        "compatible_schemas": {name: [value] for name, value in schemas.items()},
        "backups": {name: f"arn:aws:rds:us-east-1:111122223333:snapshot:pre-upgrade-{name}"
                    for name in ("runtime", "product")},
    }  # fmt: skip
    load_manifest(json.dumps(document).encode())
    return document


class Rig:
    """The offline AWS behind the rollback: store, ECS, logs and evidence fakes."""

    def __init__(self, clock: FakeClock) -> None:
        self.clock = clock
        self.trace = Trace()
        self.store = FakeStore(self.trace)
        self.aws: FakeAws | None = None

    def hold_failed(self, failed: dict, environment: str) -> str:
        journal = Journal(self.store, journal_key(failed["release_id"]))
        journal.create(
            {"schema_version": 1, "release_id": failed["release_id"], "environment": environment,
             "manifest_sha256": fx.sha("failed manifest"), "session_id": "failed-session"},
            {"at": render.iso(self.clock.now()), "kind": "transition", "to": "prepared"},
        )  # fmt: skip
        journal.append({"at": render.iso(self.clock.now()), "kind": "transition", "to": "hold"})
        lock = f"locks/{environment}.json"
        self.store.create(lock, json.dumps({"release_id": failed["release_id"],
                                            "session_id": "failed-session"}).encode())  # fmt: skip
        return self.store.objects[lock][1]

    def configure(self, document: dict) -> None:
        ecs = FakeEcs(self.clock, self.trace)
        ecs.configure(document)
        self.aws = FakeAws(ecs, FakeLogs(ecs, document), FakeEvidence(ecs, document), self.store,
                           document)  # fmt: skip
        self.aws.bridge.handlers[("sts", "GetCallerIdentity")] = self.identity

    def identity(self, _params: dict) -> dict:
        from email.utils import format_datetime

        return {"UserId": f"{ROLE_ID}:{OPERATOR}", "Account": "111122223333", "Arn": ASSUMED,
                "ResponseMetadata": {"HTTPHeaders": {
                    "date": format_datetime(self.clock.now(), usegmt=True)}}}  # fmt: skip

    def clients(self, credentials, region):
        rig = self

        class Bridged:
            def client(self, service: str):
                assert rig.aws is not None
                return rig.aws.bridge.attach(AwsClients(credentials, region).client(service))

        return Bridged()

    def clock_factory(self) -> MonotonicUtcClock:
        seconds = lambda: self.clock.now().timestamp()  # noqa: E731
        return MonotonicUtcClock(wall=seconds, monotonic=seconds, wait=self.clock.sleep)


class FakeRollbackKit(rollback.RollbackKit):
    def __init__(self, *args: Any, world: dict[str, Any], **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.world = world

    def caller(self, session):
        return {"account": "111122223333", "arn": self.world["arn"]}

    def terraform_binary(self):
        return "/fixture/terraform"

    def terraform(self, run, args, session):
        if args[0] == "show":
            variables: dict[str, Any] = {}
            for path in run.var_files:
                variables.update(json.loads(Path(path).read_text()))
            document = {"terraform_version": "1.16.5",
                        "variables": {k: {"value": v} for k, v in variables.items()},
                        "resource_changes": self.world["changes"]}  # fmt: skip
            return subprocess.CompletedProcess(args, 0, json.dumps(document), "")
        if args[0] == "plan":
            Path(run.plan_file).write_bytes(b"replan")
        if args[0] == "output":
            outputs = self.world["replanned"]
            return subprocess.CompletedProcess(
                args, 0, json.dumps({k: {"value": v} for k, v in outputs.items()}), ""
            )
        return subprocess.CompletedProcess(args, 0, "", "")

    def clients(self, session, service):
        if service == "iam":
            return self.world["iam"]
        rig: Rig = self.world["rig"]
        return rig.clients(session.credentials, "us-east-1").client(service)

    def release_cli(self, args):
        self.world.setdefault("cli", []).append(list(args))
        out = io.StringIO()
        rig: Rig = self.world["rig"]
        if args[0] == "validate":
            code = cli.main(args, out=out, environ={})
        else:
            code = cli.main(args, clients=rig.clients, clock_factory=rig.clock_factory,
                            tokens=lambda: "rbtok" + uuid.uuid4().hex[:27],
                            session_ids=lambda: "rollback-session", out=out, environ={})  # fmt: skip
        return code, json.loads(out.getvalue())


REPLAN_CHANGES = [
    {"address": 'module.release["r00000000"].aws_iam_role.task["runtime"]',
     "change": {"actions": ["no-op"]}},
    {"address": 'aws_iam_policy.release_launcher["jobs"]',
     "change": {"actions": ["update"],
                "after": {"policy": '{"Statement": [{"Resource": ["the prior release only"]}]}'}}},
]  # fmt: skip


def rollback_world(setup, canary_now=None,
                   provider: bool = False) -> tuple[dict[str, Any], dict, dict, Path, Path, Path]:  # fmt: skip
    if provider:
        kit = initialized_with(setup, canary_approval(setup, now=canary_now))
        provider_key_file(setup)
    else:
        kit = initialized(setup)
    run_through(setup, kit, "detach")
    done = kit.receipts()
    prior = json.loads(Path(done["validate"]["outputs"]["manifest"]).read_text())
    failed = failed_upgrade(prior)
    tmp = setup["tmp"]
    (tmp / "failed-manifest.json").write_text(json.dumps(failed, indent=2))
    prior_rendered = done["releases"]["outputs"]["rendered"]["releases"]
    ((prior_key, prior_release),) = prior_rendered.items()
    failed_key = render.release_key(failed["release_id"])
    (tmp / "failed-release.json").write_text(json.dumps(
        {failed_key: {**prior_release, "release_id": failed["release_id"], "slot": "current",
                      "bootstrap": None}}))  # fmt: skip
    clock = FakeClock(datetime.now(UTC).replace(microsecond=0))
    rig = Rig(clock)
    etag = rig.hold_failed(failed, prior["environment"]["name"])
    decision = {"schema": rollback.DECISION_SCHEMA, "failed_release_id": failed["release_id"],
                "failed_session": "failed-session", "failed_lock_etag": etag,
                "fence_evidence_sha256": hashlib.sha256(b"failed session fenced").hexdigest(),
                "actual_schemas": {name: values[0] for name, values in
                                   failed["rollback"]["compatible_schemas"].items()},
                "authorized_by": "fixture-release-owner", "decided_at": render.iso(clock.now())}  # fmt: skip
    (tmp / "decision.json").write_text(json.dumps(decision))
    replanned = copy.deepcopy(done["releases"]["outputs"]["terraform"])
    replanned["current_release"] = prior_key
    # With two releases retained the root renders no bootstrap launcher.
    replanned["release_launcher_bootstrap_policy"] = None
    changes = copy.deepcopy(REPLAN_CHANGES)
    changes[0]["address"] = str(changes[0]["address"]).replace("r00000000", prior_key)
    world = {"rig": rig, "replanned": replanned, "changes": changes, "iam": FakeIam(),
             "arn": f"arn:aws:sts::111122223333:assumed-role/admin/{OPERATOR}"}  # fmt: skip
    return (
        world,
        prior,
        failed,
        tmp / "failed-manifest.json",
        tmp / "failed-release.json",
        (tmp / "decision.json"),
    )


def prior_head(setup) -> str | None:
    from release_kits.ledger import Ledger

    return Ledger(setup["tmp"] / "work" / "receipts", kit="aws-07b",
                  plan_sha256=setup["hash"]).head()[1]  # fmt: skip


def rollback_kit(setup, world, **options: Any) -> FakeRollbackKit:
    return FakeRollbackKit(setup["plan"], setup["tmp"] / "rollback-work", world=world,
                           out=io.StringIO(), prompt=lambda _text: setup["typed"].pop(0),
                           **options)  # fmt: skip


def test_the_rollback_kit_restores_the_prior_pair_and_proves_no_failed_writer_runs(setup):
    world, prior, failed, failed_path, failed_input, decision = rollback_world(setup)
    kit = rollback_kit(setup, world)
    setup["typed"].append("init")
    assert kit.begin(prior_work=setup["tmp"] / "work", failed_manifest=failed_path,
                    failed_release_input=failed_input, decision=decision,
                     prior_chain_head=prior_head(setup)) == 0  # fmt: skip
    deployer, operator = str(setup["deployer"]), str(setup["operator"])
    setup["typed"].extend(["replan", "replan"])
    assert (
        kit.run_step("replan", session_path=deployer, chain_head=kit.ledger.head()[1]) == 0
    ), kit.out.getvalue()  # ty: ignore[unresolved-attribute]
    setup["typed"].append("attach")
    assert kit.run_step("attach", session_path=deployer, chain_head=kit.ledger.head()[1]) == 0
    assert len(world["iam"].attached["sentry-staging-operator"]) == 6
    for step in ("render", "validate"):
        setup["typed"].append(step)
        assert (
            kit.run_step(step, chain_head=kit.ledger.head()[1]) == 0
        ), kit.out.getvalue()  # ty: ignore[unresolved-attribute]
    document = json.loads(Path(kit.receipts()["render"]["outputs"]["manifest"]).read_text())
    world["rig"].configure(document)
    world["arn"] = f"arn:aws:sts::111122223333:assumed-role/sentry-staging-operator/{OPERATOR}"
    for step in ("run", "check"):
        setup["typed"].append(step)
        assert (
            kit.run_step(step, session_path=operator, chain_head=kit.ledger.head()[1]) == 0
        ), kit.out.getvalue()  # ty: ignore[unresolved-attribute]
    world["arn"] = f"arn:aws:sts::111122223333:assumed-role/admin/{OPERATOR}"
    setup["typed"].append("detach")
    assert kit.run_step("detach", session_path=deployer, chain_head=kit.ledger.head()[1]) == 0
    assert world["iam"].attached["sentry-staging-operator"] == []
    done = kit.receipts()
    assert done["run"]["outputs"]["run"]["state"] == "held_paused"
    assert done["check"]["outputs"]["status"]["lock"] is None
    assert document["purpose"]["failed_release_id"] == failed["release_id"]
    assert document["services"] == prior["services"]
    assert sorted(job["id"] for job in document["jobs"]) == [
        "product-proof",
        "product-reconcile",
        "runtime-proof",
        "runtime-reconcile",
    ]
    launched = [task.tags.get("sentry:job-id") for task in world["rig"].aws.ecs.tasks.values()
                if task.tags]  # fmt: skip
    assert not any(job and job.endswith(("-migrate", "-grant", "-bootstrap")) for job in launched)
    revisions = done["check"]["outputs"]["service_revisions"]
    assert set(revisions.values()) == {
        spec["task_definition"] for spec in prior["services"].values()
    }
    live = set(done["check"]["outputs"]["live_revisions"])
    # The prior pair's services are seen running, and nothing of the failed release is.
    assert {spec["task_definition"] for spec in prior["services"].values()} <= live
    assert not live & set(document["purpose"]["failed_services"].values())


def test_a_replan_that_would_change_a_retained_release_is_never_applied():
    for actions in (["update"], ["delete", "create"], ["delete"]):
        with pytest.raises(UnexpectedPlan, match="retained release"):
            rollback.check_replan({"terraform_version": "1.16.5", "variables": {}, "resource_changes": [
                {"address": 'module.release["r1"].aws_ecs_task_definition.service["api"]',
                 "change": {"actions": actions}}]}, {})  # fmt: skip
    with pytest.raises(UnexpectedPlan, match="only updated"):
        rollback.check_replan({"terraform_version": "1.16.5", "variables": {}, "resource_changes": [
            {"address": 'aws_iam_policy.release_launcher["jobs"]',
             "change": {"actions": ["delete", "create"]}}]}, {})  # fmt: skip


def test_a_replan_removes_an_interrupted_verification_and_touches_nothing_else_of_it():
    addresses = ['aws_iam_role.restore_execution["runtime-rv-recon"]',
                 'aws_iam_role_policy.restore_execution["runtime-rv-proof"]',
                 'aws_ecs_task_definition.restore["runtime-rv-recon"]',
                 'aws_iam_policy.release_launcher["restore"]']  # fmt: skip
    removed = rollback.check_replan({"terraform_version": "1.16.5", "variables": {},
                                     "resource_changes": [{"address": address,
                                                           "change": {"actions": ["delete"]}}
                                                          for address in addresses]}, {})  # fmt: skip
    assert removed == {"actions": {"delete": 4}}
    for address in addresses:
        for actions in (["create"], ["update"], ["delete", "create"]):
            with pytest.raises(UnexpectedPlan, match="only ever removed"):
                rollback.check_replan({"terraform_version": "1.16.5", "variables": {},
                                       "resource_changes": [{"address": address, "change": {
                                           "actions": actions}}]}, {})  # fmt: skip
    # Another launcher document is still only updated.
    with pytest.raises(UnexpectedPlan, match="only updated"):
        rollback.check_replan({"terraform_version": "1.16.5", "variables": {}, "resource_changes": [
            {"address": 'aws_iam_policy.release_launcher["jobs"]',
             "change": {"actions": ["delete"]}}]}, {})  # fmt: skip


def test_a_decision_with_an_incompatible_schema_or_another_release_is_refused(setup):
    world, _prior, failed, failed_path, failed_input, decision = rollback_world(setup)
    stated = json.loads(decision.read_text())
    for change, message in (
        ({"actual_schemas": {**stated["actual_schemas"], "runtime": "goose:1"}}, "not compatible"),
        ({"failed_release_id": str(uuid.uuid4())}, "another failed release"),
    ):
        decision.write_text(json.dumps({**stated, **change}))
        setup["typed"].append("init")
        kit = rollback_kit(setup, world)
        with pytest.raises(rollback.Refused, match=message):
            kit.begin(prior_work=setup["tmp"] / "work", failed_manifest=failed_path,
                      failed_release_input=failed_input, decision=decision,
                      prior_chain_head=prior_head(setup))  # fmt: skip
        setup["typed"].clear()


def test_every_rollback_step_is_tied_to_section_9():
    text = (Path(__file__).resolve().parents[1] / "deploy" / "aws-staging" / "rollback"
            / "README.md").read_text()  # fmt: skip
    import re

    rows = re.findall(r"^\| `([a-z-]+)` \| (\d+(?:\.\d+)?) \|", text, re.M)
    assert rows == [(step.id, step.section) for step in rollback.STEPS]
    assert "## Proven on the platform only" in text


def test_a_replan_whose_receipts_policy_still_reads_the_failed_worker_or_is_unknown_is_refused():
    release_id = "1234abcd-0000-4000-8000-000000000000"
    for after, message in (({"policy": f'{{"Resource": ["worker/{release_id}/app/*"]}}'},
                            "failed release"), ({}, "not known before apply")):  # fmt: skip
        change = {"address": 'aws_iam_policy.release_launcher["receipts"]',
                  "change": {"actions": ["update"], "after": after}}  # fmt: skip
        with pytest.raises(UnexpectedPlan, match=message):
            rollback.check_replan({"terraform_version": "1.16.5", "variables": {},
                                   "resource_changes": [change]}, {}, "r1234abcd", release_id)  # fmt: skip


def test_a_replan_whose_current_only_policy_still_names_the_failed_release_is_refused():
    change = {"address": 'aws_iam_policy.release_launcher["jobs"]',
              "change": {"actions": ["update"],
                         "after": {"policy": '{"Resource": ["...sentry-staging-r1234abcd-x"]}'}}}  # fmt: skip
    with pytest.raises(UnexpectedPlan, match="failed release"):
        rollback.check_replan({"terraform_version": "1.16.5", "variables": {},
                               "resource_changes": [change]}, {}, "r1234abcd")  # fmt: skip
    change["address"] = 'aws_iam_policy.release_launcher["services"]'
    rollback.check_replan({"terraform_version": "1.16.5", "variables": {},
                           "resource_changes": [change]}, {}, "r1234abcd")  # fmt: skip


def test_the_check_holds_while_a_failed_revision_still_runs(setup):
    world, prior, failed, failed_path, failed_input, decision = rollback_world(setup)
    kit = rollback_kit(setup, world)
    setup["typed"].append("init")
    assert kit.begin(prior_work=setup["tmp"] / "work", failed_manifest=failed_path,
                     failed_release_input=failed_input, decision=decision,
                     prior_chain_head=prior_head(setup)) == 0  # fmt: skip
    deployer, operator = str(setup["deployer"]), str(setup["operator"])
    setup["typed"].extend(["replan", "replan", "attach", "render", "validate", "run", "check"])
    assert kit.run_step("replan", session_path=deployer, chain_head=kit.ledger.head()[1]) == 0
    assert kit.run_step("attach", session_path=deployer, chain_head=kit.ledger.head()[1]) == 0
    for step in ("render", "validate"):
        assert kit.run_step(step, chain_head=kit.ledger.head()[1]) == 0
    document = json.loads(Path(kit.receipts()["render"]["outputs"]["manifest"]).read_text())
    world["rig"].configure(document)
    world["arn"] = f"arn:aws:sts::111122223333:assumed-role/sentry-staging-operator/{OPERATOR}"
    assert kit.run_step("run", session_path=operator, chain_head=kit.ledger.head()[1]) == 0
    # A failed release's job task that nobody stopped is still running.
    ecs = world["rig"].aws.ecs
    stray = failed["jobs"][0]["task"]["task_definition"]
    ecs._task(stray, "stray-token", "family:stray", [("app", "sha256:" + "0" * 64)])
    assert kit.run_step("check", session_path=operator, chain_head=kit.ledger.head()[1]) == 3
    held, _ = kit.ledger.head()
    assert held is not None and held["result"] == "held" and stray in held["detail"]


def begun(setup):
    world, prior, failed, failed_path, failed_input, decision = rollback_world(setup)
    kit = rollback_kit(setup, world)
    setup["typed"].append("init")
    assert kit.begin(prior_work=setup["tmp"] / "work", failed_manifest=failed_path,
                     failed_release_input=failed_input, decision=decision,
                     prior_chain_head=prior_head(setup)) == 0  # fmt: skip
    return world, kit, failed


def test_a_rollback_attach_refuses_a_role_left_holding_policies(setup):
    world, kit, _failed = begun(setup)
    deployer = str(setup["deployer"])
    setup["typed"].extend(["replan", "replan", "attach", "detach"])
    assert kit.run_step("replan", session_path=deployer, chain_head=kit.ledger.head()[1]) == 0
    world["iam"].attached["sentry-staging-operator"] = ["arn:aws:iam::aws:left-over"]
    assert kit.run_step("attach", session_path=deployer, chain_head=kit.ledger.head()[1]) == 3
    assert world["iam"].attached["sentry-staging-operator"] == ["arn:aws:iam::aws:left-over"]
    assert kit.run_step("detach", session_path=deployer, chain_head=kit.ledger.head()[1]) == 3
    with pytest.raises(rollback.Refused, match="runs only after attach"):
        setup["typed"].append("render")
        kit.run_step("render", chain_head=kit.ledger.head()[1])


def test_a_rollback_never_attaches_a_bootstrap_launcher(setup):
    world, kit, _failed = begun(setup)
    world["replanned"][
        "release_launcher_bootstrap_policy"
    ] = "sentry-staging-release-launcher-bootstrap"
    deployer = str(setup["deployer"])
    setup["typed"].extend(["replan", "replan", "attach"])
    assert kit.run_step("replan", session_path=deployer, chain_head=kit.ledger.head()[1]) == 0
    with pytest.raises(rollback.Refused, match="bootstrap launcher"):
        kit.run_step("attach", session_path=deployer, chain_head=kit.ledger.head()[1])
    assert world["iam"].attached.get("sentry-staging-operator", []) == []


def through_run(setup):
    world, kit, failed = begun(setup)
    deployer, operator = str(setup["deployer"]), str(setup["operator"])
    setup["typed"].extend(["replan", "replan", "attach", "render", "validate", "run"])
    assert kit.run_step("replan", session_path=deployer, chain_head=kit.ledger.head()[1]) == 0
    assert kit.run_step("attach", session_path=deployer, chain_head=kit.ledger.head()[1]) == 0
    for step in ("render", "validate"):
        assert kit.run_step(step, chain_head=kit.ledger.head()[1]) == 0
    document = json.loads(Path(kit.receipts()["render"]["outputs"]["manifest"]).read_text())
    world["rig"].configure(document)
    world["arn"] = f"arn:aws:sts::111122223333:assumed-role/sentry-staging-operator/{OPERATOR}"
    assert kit.run_step("run", session_path=operator, chain_head=kit.ledger.head()[1]) == 0
    return world, kit, operator


def test_the_check_refuses_a_manifest_edited_after_it_was_rendered(setup):
    world, kit, operator = through_run(setup)
    path = Path(kit.receipts()["render"]["outputs"]["manifest"])
    path.chmod(0o600)
    path.write_text(path.read_text().replace("}", " }", 1))
    setup["typed"].append("check")
    with pytest.raises(rollback.Refused, match="changed after it was rendered"):
        kit.run_step("check", session_path=operator, chain_head=kit.ledger.head()[1])


def test_the_check_fails_when_ecs_cannot_describe_a_listed_task(setup, monkeypatch):
    world, kit, operator = through_run(setup)
    real = kit.clients

    class Partial:
        """The kit's ECS client, with one listed task ECS cannot describe."""

        def __init__(self, inner):
            self.inner = inner

        def __getattr__(self, name):
            return getattr(self.inner, name)

        def describe_tasks(self, **kwargs):
            answer = self.inner.describe_tasks(**kwargs)
            return {**answer, "failures": [{"arn": kwargs["tasks"][0], "reason": "MISSING"}]}

    monkeypatch.setattr(kit, "clients", lambda session, service: Partial(real(session, service))
                        if service == "ecs" else real(session, service))  # fmt: skip
    setup["typed"].append("check")
    assert kit.run_step("check", session_path=operator, chain_head=kit.ledger.head()[1]) == 3
    failed, _ = kit.ledger.head()
    assert failed is not None and "could not describe" in failed["detail"]


# The prior release's provider canary through a rollback (R1-C2) -------------------------


def rollback_until(setup, world, failed_path, failed_input, decision, last: str,
                   **options: Any) -> FakeRollbackKit:  # fmt: skip
    """A rollback begun and run through ``last``; the fake records each CLI call."""
    kit = rollback_kit(setup, world, **options)
    setup["typed"].append("init")
    assert kit.begin(prior_work=setup["tmp"] / "work", failed_manifest=failed_path,
                     failed_release_input=failed_input, decision=decision,
                     prior_chain_head=prior_head(setup)) == 0  # fmt: skip
    deployer, operator = str(setup["deployer"]), str(setup["operator"])
    for step, session, typed in (("replan", deployer, 2), ("attach", deployer, 1),
                                 ("render", None, 1), ("validate", None, 1),
                                 ("run", operator, 1)):  # fmt: skip
        if step == "run":
            document = json.loads(Path(kit.receipts()["render"]["outputs"]["manifest"]).read_text())
            world["rig"].configure(document)
            world["arn"] = (
                f"arn:aws:sts::111122223333:assumed-role/sentry-staging-operator/{OPERATOR}"
            )
        setup["typed"].extend([step] * typed)
        assert (
            kit.run_step(step, session_path=session, chain_head=kit.ledger.head()[1]) == 0
        ), kit.out.getvalue()  # ty: ignore[unresolved-attribute]
        if step == last:
            return kit
    return kit


def prior_binding(setup) -> dict[str, str]:
    from release_kits.ledger import Ledger

    chain = Ledger(setup["tmp"] / "work" / "receipts", kit="aws-07b", plan_sha256=setup["hash"])
    done = {document["step"]: document for _, document, _ in chain.receipts()}
    return done["validate"]["outputs"]["provider_canary"]


def test_a_rollback_keeps_the_prior_releases_canary_key_and_registered_worker(setup):
    world, prior, _failed, failed_path, failed_input, decision = rollback_world(
        setup, provider=True
    )
    kit = rollback_until(setup, world, failed_path, failed_input, decision, "run")
    expected = prior_binding(setup)
    assert expected is not None and expected["canary_id"] == "local-provider-stub"
    done = kit.receipts()
    for step in ("render", "validate", "run"):
        assert done[step]["outputs"]["provider_canary"] == expected, step
        assert render.describe_provider(expected) in done[step]["commands"], step
    document = json.loads(Path(done["render"]["outputs"]["manifest"]).read_text())
    worker = document["services"]["worker"]
    assert worker["task_definition"] == prior["services"]["worker"]["task_definition"]
    assert worker["secrets"][-1]["version_id"] == expected["key_version_id"]
    assert worker["secrets"] == prior["services"]["worker"]["secrets"]
    assert kit.record()["prior_provider_canary"] == {
        key: expected[key] for key in ("canary_id", "canary_manifest_sha256", "approval_sha256")
    }
    # The retained release itself is unchanged: its registered definitions are the prior's.
    prior_key = render.release_key(kit.record()["prior_release_id"])
    replanned = done["replan"]["outputs"]["terraform"]["releases"][prior_key]
    assert (
        replanned["definitions_sha256"]
        == world["replanned"]["releases"][prior_key]["definitions_sha256"]
        == kit.prior()["releases"]["outputs"]["terraform"]["releases"][prior_key][
            "definitions_sha256"
        ]
    )


def test_a_rollback_of_a_release_without_a_canary_records_no_provider(setup):
    world, _prior, _failed, failed_path, failed_input, decision = rollback_world(setup)
    kit = rollback_until(setup, world, failed_path, failed_input, decision, "run")
    done = kit.receipts()
    assert kit.record()["prior_provider_canary"] is None
    for step in ("render", "validate", "run"):
        assert done[step]["outputs"]["provider_canary"] is None
        assert "worker: no provider" in done[step]["commands"]
    for name in ("manifest", "approval"):
        assert "provider-key" not in Path(done["render"]["outputs"][name]).read_text()


def refused_at_render(setup, kit: FakeRollbackKit, reason: str) -> None:
    written = sorted((kit.work / "rendered").glob("*-manifest.json"))
    setup["typed"].append("render")
    with pytest.raises(rollback.Refused, match=reason):
        kit.run_step("render", chain_head=kit.ledger.head()[1])
    assert sorted((kit.work / "rendered").glob("*-manifest.json")) == written, "a file was written"
    assert "render" not in kit.receipts() and kit.world.get("cli", []) == []


def test_a_prior_canary_ending_before_the_rollback_window_is_refused_at_render(setup):
    # The prior canary stops five hours from now; a rollback rendered two hours from now
    # would run until about six.
    now = aws_07b_now()
    world, _prior, _failed, failed_path, failed_input, decision = rollback_world(
        setup, canary_now=now - rollback.aws_07b.timedelta(hours=7), provider=True)  # fmt: skip
    begun_kit = rollback_until(setup, world, failed_path, failed_input, decision, "attach")
    later = rollback_kit(setup, world, now=lambda: now + rollback.aws_07b.timedelta(hours=2))
    assert later.ledger.head() == begun_kit.ledger.head()
    refused_at_render(setup, later, "ends at or before the release window")


def forged_prior(monkeypatch, kit: FakeRollbackKit, change) -> None:
    prior = kit.prior

    def altered() -> dict[str, dict[str, Any]]:
        done = copy.deepcopy(prior())
        change(done)
        return done

    monkeypatch.setattr(kit, "prior", altered)


def test_a_prior_releases_input_naming_another_manifest_is_refused_at_render(setup, monkeypatch):
    world, _prior, _failed, failed_path, failed_input, decision = rollback_world(
        setup, provider=True
    )
    kit = rollback_until(setup, world, failed_path, failed_input, decision, "attach")

    def change(done):
        for release in done["releases"]["outputs"]["rendered"]["releases"].values():
            release["model_provider"]["canary_manifest_sha256"] = "0" * 64

    forged_prior(monkeypatch, kit, change)
    refused_at_render(setup, kit, "releases input's provider is not the release record's")


def test_a_prior_custody_without_the_canarys_key_is_refused_at_render(setup, monkeypatch):
    world, _prior, _failed, failed_path, failed_input, decision = rollback_world(
        setup, provider=True
    )
    kit = rollback_until(setup, world, failed_path, failed_input, decision, "attach")
    forged_prior(monkeypatch, kit,
                 lambda done: done["custodian"]["outputs"]["bundles"].pop("provider-key/worker"))  # fmt: skip
    refused_at_render(setup, kit, "custody holds no provider key")


def forged_render(monkeypatch, kit: FakeRollbackKit) -> None:
    receipts = kit.receipts

    def altered() -> dict[str, dict[str, Any]]:
        done = copy.deepcopy(receipts())
        done["render"]["outputs"]["provider_canary"]["key_version_id"] = "another-version"
        return done

    monkeypatch.setattr(kit, "receipts", altered)


def test_a_forged_render_receipt_is_refused_at_validate_before_release_cli(setup, monkeypatch):
    world, _prior, _failed, failed_path, failed_input, decision = rollback_world(
        setup, provider=True
    )
    kit = rollback_until(setup, world, failed_path, failed_input, decision, "render")
    forged_render(monkeypatch, kit)
    setup["typed"].append("validate")
    with pytest.raises(rollback.Refused, match="render receipt's provider canary"):
        kit.run_step("validate", chain_head=kit.ledger.head()[1])
    assert world.get("cli", []) == [] and "validate" not in kit.receipts()


def test_a_forged_render_receipt_is_refused_at_run_before_release_cli(setup, monkeypatch):
    world, _prior, _failed, failed_path, failed_input, decision = rollback_world(
        setup, provider=True
    )
    kit = rollback_until(setup, world, failed_path, failed_input, decision, "validate")
    assert [call[0] for call in world["cli"]] == ["validate"]
    forged_render(monkeypatch, kit)
    world["arn"] = f"arn:aws:sts::111122223333:assumed-role/sentry-staging-operator/{OPERATOR}"
    setup["typed"].append("run")
    with pytest.raises(rollback.Refused, match="render receipt's provider canary"):
        kit.run_step("run", session_path=str(setup["operator"]), chain_head=kit.ledger.head()[1])
    assert [call[0] for call in world["cli"]] == ["validate"], "release_cli run was invoked"
    assert not [document for _, document, _ in kit.ledger.receipts() if document["step"] == "run"]


def aws_07b_now():
    return rollback.aws_07b._now()


def test_a_replan_receipt_naming_other_prior_definitions_is_refused_at_render(setup, monkeypatch):
    world, _prior, _failed, failed_path, failed_input, decision = rollback_world(
        setup, provider=True
    )
    kit = rollback_until(setup, world, failed_path, failed_input, decision, "attach")
    receipts = kit.receipts

    def altered() -> dict[str, dict[str, Any]]:
        done = copy.deepcopy(receipts())
        for release in done["replan"]["outputs"]["terraform"]["releases"].values():
            release["definitions_sha256"] = "0" * 64
        return done

    monkeypatch.setattr(kit, "receipts", altered)
    refused_at_render(setup, kit, "changed the prior release's registered definitions")


def test_a_rollback_without_a_canary_writes_exactly_what_the_unchanged_builders_render(setup):
    # At a fixed clock the rendered files are the rollback manifest builder's and the
    # approval renderer's output, byte for byte: the provider checks add nothing to them.
    fixed = aws_07b_now()
    world, _prior, failed, failed_path, failed_input, decision = rollback_world(setup)
    kit = rollback_until(setup, world, failed_path, failed_input, decision, "render",
                         now=lambda: fixed)  # fmt: skip
    done = kit.receipts()
    prior = kit.prior()
    replan = done["replan"]["outputs"]
    release = replan["terraform"]["releases"][render.release_key(kit.record()["prior_release_id"])]
    prior_manifest = json.loads(Path(prior["validate"]["outputs"]["manifest"]).read_text())
    document = rollback.rollback_manifest(
        setup["plan"], kit.record(), prior, prior_manifest, failed, release,
        plan_sha256=replan["plan_file_sha256"],
        not_before=fixed - rollback.aws_07b.timedelta(minutes=1),
    )  # fmt: skip
    rendered = done["render"]["outputs"]
    assert Path(rendered["manifest"]).read_text() == json.dumps(document, indent=2) + "\n"
    approval = render.approval(setup["plan"], document)
    assert Path(rendered["approval"]).read_text() == json.dumps(approval, indent=2) + "\n"
    assert rendered["provider_canary"] is None


@pytest.mark.parametrize("seconds, refused", [(0, True), (1, False)])
def test_a_prior_canary_must_end_strictly_after_the_rollback_window(setup, seconds, refused):
    # Render at a fixed clock two hours on: its window ends at fixed - 1 min + 4 h.
    fixed = aws_07b_now() + rollback.aws_07b.timedelta(hours=2)
    window_end = fixed - rollback.aws_07b.timedelta(minutes=1) + render.WINDOW_LENGTH
    ends = window_end + rollback.aws_07b.timedelta(seconds=seconds)
    world, _prior, _failed, failed_path, failed_input, decision = rollback_world(
        setup, canary_now=ends - rollback.aws_07b.timedelta(hours=12), provider=True)  # fmt: skip
    rollback_until(setup, world, failed_path, failed_input, decision, "attach")
    later = rollback_kit(setup, world, now=lambda: fixed)
    if refused:
        refused_at_render(setup, later, "ends at or before the release window")
        return
    setup["typed"].append("render")
    assert later.run_step("render", chain_head=later.ledger.head()[1]) == 0
    assert later.receipts()["render"]["outputs"]["provider_canary"]["canary_id"] == (
        "local-provider-stub"
    )
