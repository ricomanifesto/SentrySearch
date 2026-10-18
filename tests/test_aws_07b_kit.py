"""The AWS-07b kit offline: plan checks, the receipt chain, typed steps and rendering.

Every account-facing seam is a fake here: Terraform answers from canned plan
documents, SDK clients are in-memory objects, and no socket may open. Nothing
resolves a credential: the only session is a fixture file the test writes.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tarfile
from typing import Any

from botocore.exceptions import ClientError
import pytest

from release.manifest import RUNTIME_GRANT_PIN, load_approval, load_manifest
from release_cli import main as release_cli
from release_kits import aws_07b, images, render
from release_kits import session as sessions
from release_kits.ledger import ChainBroken, Ledger
from release_kits.plan import AccountPlan, PlanRefused, load_plan
from release_kits.terraform import UnexpectedPlan, check_plan
from tests import release_kit_fixtures as fx
from tests.provider_stand_in import stand_in_canary
from tests.test_release_cli import write_credentials

REPO = Path(__file__).resolve().parents[1]
OPERATOR = "fixture-operator"
SQL_PINS = {
    "sql/bootstrap.sql": fx.sha("bootstrap"), "sql/runtime/service.sql": RUNTIME_GRANT_PIN["sha256"],
    "sql/runtime/proof.sql": fx.sha("runtime-proof"), "sql/product/grants.sql": fx.sha("grants"),
    "sql/product/proof.sql": fx.sha("product-proof"), "sql/reconcile.sql": fx.sha("reconcile"),
}  # fmt: skip


@pytest.fixture(autouse=True)
def no_sockets(monkeypatch):
    def refused(*_args, **_kwargs):
        raise AssertionError("the kit must not open a socket in these tests")

    monkeypatch.setattr(socket, "socket", refused)
    monkeypatch.setattr(socket, "create_connection", refused)
    monkeypatch.setattr(socket, "getaddrinfo", refused)


# Fixtures ---------------------------------------------------------------------------


def oci_archive(path: Path, label: str) -> tuple[str, str]:
    """A tiny OCI layout with one platform manifest; returns (archive sha, manifest digest)."""
    config = json.dumps({"architecture": "arm64", "os": "linux", "label": label}).encode()
    layer = (label * 64).encode()
    blobs = {images.digest_of(config): config, images.digest_of(layer): layer}
    manifest = json.dumps({
        "schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                   "digest": images.digest_of(config), "size": len(config)},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": images.digest_of(layer), "size": len(layer)}],
    }).encode()  # fmt: skip
    blobs[images.digest_of(manifest)] = manifest
    with tarfile.open(path, "w") as archive:
        for digest, data in blobs.items():
            info = tarfile.TarInfo(f"blobs/sha256/{digest.split(':')[1]}")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return hashlib.sha256(path.read_bytes()).hexdigest(), images.digest_of(manifest)


def bindings(directory: Path) -> Path:
    found = {}
    for name in ("runtime", "search", "release-tools"):
        archive = directory / f"{name}-arm64.tar"
        archive_sha, manifest = oci_archive(archive, name)
        found[name] = {
            "index": "sha256:" + fx.sha(f"{name}-index"), "platform_manifest": manifest,
            "archive_sha256": archive_sha, "scan_artifact": str(archive),
            "provenance_sha256": fx.sha(f"{name}-provenance"), "sbom_sha256": fx.sha(f"{name}-sbom"),
            "scan_sha256": fx.sha(f"{name}-scan"),
            "source_revision": ("c" * 40 if name == "runtime" else "9" * 40),
        }  # fmt: skip
    path = directory / "bindings.json"
    path.write_text(json.dumps(found, indent=2))
    return path


class FakeEcr:
    def __init__(self, change_digest: bool = False) -> None:
        self.blobs: dict[str, bytes] = {}
        self.parts: dict[str, bytes] = {}
        self.images: dict[tuple[str, str], str] = {}
        self.change_digest = change_digest

    def batch_check_layer_availability(self, *, registryId, repositoryName, layerDigests):
        return {"layers": [{"layerDigest": d, "layerAvailability": "AVAILABLE"}
                           for d in layerDigests if d in self.blobs],
                "failures": [{"layerDigest": d, "failureCode": "MissingLayerDigest"}
                             for d in layerDigests if d not in self.blobs]}  # fmt: skip

    def initiate_layer_upload(self, *, registryId, repositoryName):
        upload = f"upload-{len(self.parts)}"
        self.parts[upload] = b""
        return {"uploadId": upload, "partSize": images.PART_BYTES}

    def upload_layer_part(self, *, registryId, repositoryName, uploadId, partFirstByte,
                          partLastByte, layerPartBlob):  # fmt: skip
        assert partFirstByte == len(self.parts[uploadId])
        self.parts[uploadId] += layerPartBlob
        return {}

    def complete_layer_upload(self, *, registryId, repositoryName, uploadId, layerDigests):
        data = self.parts.pop(uploadId)
        assert images.digest_of(data) == layerDigests[0], "ECR verifies the uploaded digest"
        self.blobs[layerDigests[0]] = data
        return {"layerDigest": layerDigests[0]}

    fail_on: str | None = None

    def put_image(self, *, registryId, repositoryName, imageManifest, imageManifestMediaType,
                  imageDigest):  # fmt: skip
        if repositoryName == self.fail_on:
            raise ClientError({"Error": {"Code": "ThrottlingException"}}, "PutImage")
        stored = imageManifest + (" " if self.change_digest else "")
        digest = images.digest_of(stored.encode())
        if (repositoryName, digest) in self.images:
            raise ClientError({"Error": {"Code": "ImageAlreadyExistsException"}}, "PutImage")
        self.images[(repositoryName, digest)] = stored
        return {"image": {"imageId": {"imageDigest": digest}}}

    def batch_get_image(self, *, registryId, repositoryName, imageIds, acceptedMediaTypes):
        wanted = imageIds[0]["imageDigest"]
        stored = self.images.get((repositoryName, wanted))
        return {"images": [] if stored is None else [{"imageManifest": stored}]}


class Paginator:
    def __init__(self, iam: "FakeIam") -> None:
        self.iam = iam

    def paginate(self, *, RoleName):
        attached = self.iam.attached.get(RoleName, [])
        yield {"AttachedPolicies": [{"PolicyArn": arn} for arn in attached]}


class FakeIam:
    def __init__(self) -> None:
        self.attached: dict[str, list[str]] = {}

    def get_paginator(self, _name):
        return Paginator(self)

    fail_after: int | None = None

    def attach_role_policy(self, *, RoleName, PolicyArn):
        if self.fail_after is not None and len(self.attached.get(RoleName, [])) >= self.fail_after:
            raise ClientError({"Error": {"Code": "ServiceFailure"}}, "AttachRolePolicy")
        self.attached.setdefault(RoleName, []).append(PolicyArn)

    def detach_role_policy(self, *, RoleName, PolicyArn):
        self.attached[RoleName].remove(PolicyArn)


class FakeSecrets:
    def __init__(self, admin: dict[str, str]) -> None:
        self.created: dict[str, tuple[str, str]] = {}
        self.admin = admin

    fail_at: int | None = None

    def create_secret(self, *, Name, SecretString, ClientRequestToken):
        if self.fail_at is not None and len(self.created) == self.fail_at:
            raise ClientError(
                {"Error": {"Code": "ThrottlingException", "Message": "slow down: " + SecretString}},
                "CreateSecret",
            )
        if Name in self.created:
            raise ClientError({"Error": {"Code": "ResourceExistsException"}}, "CreateSecret")
        arn = f"arn:aws:secretsmanager:us-east-1:111122223333:secret:{Name}-AbC123"
        self.created[Name] = (SecretString, ClientRequestToken)
        return {"ARN": arn, "Name": Name, "VersionId": ClientRequestToken}

    def describe_secret(self, *, SecretId):
        if SecretId in self.created:
            return {
                "ARN": f"arn:aws:secretsmanager:us-east-1:111122223333:secret:{SecretId}-AbC123",
                "VersionIdsToStages": {self.created[SecretId][1]: ["AWSCURRENT"]},
            }
        version = "0b9f7c1e-4d2a-4f6b-9a3e-" + fx.sha(SecretId)[:12]
        return {"ARN": SecretId, "VersionIdsToStages": {version: ["AWSCURRENT"],
                                                        "11111111-2222-4333-8444-555555555555":
                                                        ["AWSPREVIOUS"]}}  # fmt: skip


class FakeSts:
    def __init__(self, arn: str) -> None:
        self.arn = arn

    def get_caller_identity(self):
        return {"Account": "111122223333", "Arn": self.arn}


class FakeKit(aws_07b.Kit):
    """The kit with every account-facing seam answered in memory."""

    def __init__(self, *args: Any, world: dict[str, Any], **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.world = world

    def clients(self, session, service):
        return self.world["clients"][service]

    def caller(self, session):
        return {"account": "111122223333", "arn": self.world["arn"]}

    def schemas(self, sources, runtime_checkout):
        return {"runtime": "goose:1,2,3", "product": "sentrysearch:1:" + fx.sha("product")[:16]}

    def docker(self, args):
        self.world.setdefault("docker", []).append(args)
        return json.dumps({"tools_sha256": fx.sha("tools"), "sql": SQL_PINS})

    def terraform_binary(self):
        return "/fixture/terraform"

    def terraform(self, run, args, session):
        calls = self.world.setdefault("terraform", [])
        calls.append((run.root, args[0]))
        if args[0] == "show":
            variables = {}
            for path in run.var_files:
                variables.update(json.loads(Path(path).read_text()))
            address = "aws_thing.this"
            if run.root == "releases":
                (key,) = variables["releases"]
                address = f'module.release["{key}"].aws_ecs_task_definition.service["runtime"]'
            changes = self.world.get("changes", {}).get(run.root) or [
                {"address": address, "change": {"actions": ["create"]}}
            ]
            document = {"terraform_version": "1.16.5",
                        "variables": {k: {"value": v} for k, v in variables.items()},
                        "resource_changes": changes}  # fmt: skip
            return subprocess.CompletedProcess(args, 0, json.dumps(document), "")
        if args[0] == "plan":
            Path(run.plan_file).write_bytes(b"plan-" + run.root.encode())
        if args[0] == "output":
            outputs = self.world["outputs"](run.root, run)
            return subprocess.CompletedProcess(
                args, 0, json.dumps({k: {"value": v} for k, v in outputs.items()}), ""
            )
        return subprocess.CompletedProcess(args, 0, "", "")

    def release_cli(self, args):
        self.world.setdefault("cli", []).append(args)
        if args[0] == "validate":
            out = io.StringIO()
            code = release_cli.main(args, out=out, environ={})
            return code, json.loads(out.getvalue())
        if args[0] == "run":
            return self.world.get("run_result", (0, {"state": "held_paused", "reason": None}))
        if "status_result" in self.world:
            return self.world["status_result"]
        release_id = json.loads(Path(args[args.index("--manifest") + 1]).read_text())["release_id"]
        return 0, {"command": "status", "release_id": release_id, "lock": self.world.get("lock"),
                   "journal": {"state": "held_paused", "outstanding": [], "reason": None}}  # fmt: skip


@pytest.fixture
def setup(tmp_path):
    plan_dir, plan_hash = fx.account_plan(tmp_path)
    plan = load_plan(plan_dir, plan_hash)
    bound = bindings(tmp_path)
    found = json.loads(bound.read_text())
    risk = fx.risk_decision(tmp_path / "risk.json", {
        "runtime": found["runtime"]["platform_manifest"],
        "search": found["search"]["platform_manifest"],
        "release_tools": found["release-tools"]["platform_manifest"],
    })  # fmt: skip
    custody = tmp_path / "custody"
    custody.mkdir(mode=0o700)
    fx.custodian_files(custody, render.BUNDLES)
    deployer = custody / "deployer.json"
    operator = custody / "operator.json"
    for path in (deployer, operator):
        write_credentials(path, expires_at=(render.iso(aws_07b._now()
                                                       + aws_07b.timedelta(hours=6))))  # fmt: skip
    foundation = fx.foundation_outputs(plan)
    rendered: dict[str, Any] = {}

    def outputs(root, run):
        if root == "bootstrap":
            return fx.bootstrap_outputs(plan)
        if root == "foundation":
            return foundation
        if root == "releases":
            values = json.loads(Path(run.var_files[-1]).read_text())
            rendered["releases"] = values
            return fx.releases_outputs(plan, values)
        return fx.services_outputs(plan)

    world: dict[str, Any] = {
        "clients": {"ecr": FakeEcr(), "iam": FakeIam(),
                    "secretsmanager": FakeSecrets(foundation["database_admin_secret_arns"])},
        "arn": f"arn:aws:sts::111122223333:assumed-role/admin/{OPERATOR}",
        "outputs": outputs,
    }  # fmt: skip
    typed: list[str] = []

    def kit(**changes: Any) -> FakeKit:
        return FakeKit(plan, tmp_path / "work", world=world, out=io.StringIO(),
                       prompt=lambda _text: typed.pop(0), **changes)  # fmt: skip

    return {"plan": plan, "plan_dir": plan_dir, "hash": plan_hash, "bindings": bound,
            "risk": risk, "custody": custody, "deployer": deployer, "operator": operator,
            "world": world, "typed": typed, "kit": kit, "tmp": tmp_path}  # fmt: skip


def initialized(setup) -> FakeKit:
    setup["typed"].append("init")
    kit = setup["kit"]()
    assert kit.init(bindings_path=setup["bindings"], risk_path=setup["risk"],
                    runtime_checkout=setup["tmp"], terraform=Path("/fixture/terraform")
                    ) == aws_07b.EXIT_OK  # fmt: skip
    return kit


@pytest.fixture(autouse=True)
def terraform_version(monkeypatch):
    real = subprocess.run

    def fake(args, *rest, **kwargs):
        if args[:1] == ["/fixture/terraform"]:
            return subprocess.CompletedProcess(args, 0, '{"terraform_version": "1.16.5"}', "")
        return real(args, *rest, **kwargs)

    monkeypatch.setattr(aws_07b.subprocess, "run", fake)
    monkeypatch.setattr(aws_07b, "_hash_file", lambda path: (
        fx.sha("terraform") if str(path) == "/fixture/terraform"
        else hashlib.sha256(Path(path).read_bytes()).hexdigest()))  # fmt: skip


def head(kit) -> str | None:
    """The hash the last step printed, which the next command must be given."""
    return kit.ledger.head()[1]


def step(setup, kit: FakeKit, identifier: str, *typed: str, **options: Any) -> int:
    setup["typed"].extend(typed or (identifier,))
    return kit.run_step(identifier, chain_head=head(kit), **options)


def run_through(setup, kit: FakeKit, last: str) -> None:
    sessions_for = {"deployer": str(setup["deployer"]), "operator": str(setup["operator"])}
    for item in aws_07b.STEPS:
        options: dict[str, Any] = {}
        if item.session:
            options["session_path"] = sessions_for[item.session]
            setup["world"]["arn"] = (
                f"arn:aws:sts::111122223333:assumed-role/sentry-staging-operator/{OPERATOR}"
                if item.session == "operator"
                else f"arn:aws:sts::111122223333:assumed-role/admin/{OPERATOR}")  # fmt: skip
        if item.id == "custodian":
            options["custodian"] = setup["custody"]
        typed = (item.id, item.id) if item.root else (item.id,)
        assert (
            step(setup, kit, item.id, *typed, **options) == aws_07b.EXIT_OK
        ), kit.out.getvalue()  # ty: ignore[unresolved-attribute]
        if item.id == last:
            return


# The plan ----------------------------------------------------------------------------


def test_a_plan_loads_only_with_the_hash_the_assembler_printed(setup):
    assert load_plan(setup["plan_dir"], setup["hash"]).plan_sha256 == setup["hash"]
    with pytest.raises(PlanRefused, match="printed"):
        load_plan(setup["plan_dir"], "0" * 64)
    with pytest.raises(PlanRefused, match="plan hash"):
        load_plan(setup["plan_dir"], None)


@pytest.mark.parametrize("tamper, message", [
    (lambda root: (root / "foundation/account.auto.tfvars.json").write_text('{"vpc_cidr": "x"}'),
     "plan's own copy"),
    (lambda root: (root / "manifest.skeleton.json").write_text("{}"), "plan's own copy"),
    (lambda root: (root / "account-plan.json").write_text(
        (root / "account-plan.json").read_text().replace('"16.10"', '"16.11"')), "own plan_sha256"),
    (lambda root: (root / "account-plan.json").write_text(json.dumps(
        {**json.loads((root / "account-plan.json").read_text()), "checklist": [
            {**item, "status": "met"} for item in json.loads(
                (root / "account-plan.json").read_text())["checklist"]] + [
            {"id": "extra", "status": "met"}]})), "own plan_sha256"),
])  # fmt: skip
def test_a_plan_edited_after_assembly_is_refused(setup, tamper, message):
    tamper(setup["plan_dir"])
    with pytest.raises(PlanRefused, match=message):
        load_plan(setup["plan_dir"], setup["hash"])


def test_a_plan_with_an_unconfirmed_account_or_no_operator_trust_is_refused(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    plan_dir, digest = fx.account_plan(tmp_path / "a", account_confirmed_by=None)
    with pytest.raises(PlanRefused, match="identity"):
        load_plan(plan_dir, digest)
    plan_dir, digest = fx.account_plan(tmp_path / "b", operator_trust=None)
    with pytest.raises(PlanRefused, match="operator trust"):
        load_plan(plan_dir, digest)


# The receipt chain -------------------------------------------------------------------


def test_receipts_chain_and_any_later_edit_breaks_the_chain(tmp_path):
    ledger = Ledger(tmp_path / "receipts", kit="aws-07b", plan_sha256="a" * 64)
    first = ledger.write("init", {"result": "ok"})
    second = ledger.write("bootstrap", {"result": "ok"})
    chain = ledger.receipts()
    assert [entry[2] for entry in chain] == [first, second]
    assert chain[1][1]["previous_sha256"] == first
    path = chain[0][0]
    path.chmod(0o644)
    path.write_text(path.read_text().replace('"ok"', '"failed"'))
    with pytest.raises(ChainBroken, match="does not name the receipt before it"):
        ledger.receipts()


def test_a_receipt_that_would_hold_a_secret_value_is_never_written(tmp_path):
    ledger = Ledger(tmp_path / "receipts", kit="aws-07b", plan_sha256="a" * 64)
    with pytest.raises(ValueError, match="secret"):
        ledger.write("custodian", {"outputs": {"x": "the-secret-value"}},
                     keep_out=["the-secret-value"])  # fmt: skip
    assert not (tmp_path / "receipts").exists() or not list((tmp_path / "receipts").iterdir())


KEPT_OUT = "fixture-value-kept-out"
CUSTODIAN = aws_07b.Step("custodian", "7.3", "fixture custodian", None)


def finish(tmp_path: Path, outputs: dict[str, Any]) -> tuple[int, list[str], Ledger]:
    out = io.StringIO()
    kit = aws_07b.Kit(AccountPlan(tmp_path, {"plan_sha256": "a" * 64}), tmp_path / "work",
                      out=out)  # fmt: skip
    code = kit._finish(CUSTODIAN, [], "custodian", lambda: dict(outputs), None, (KEPT_OUT,))
    return code, out.getvalue().splitlines(), kit.ledger


@pytest.mark.parametrize("held", [None, "a fixture hold"])
def test_a_withheld_receipt_fails_the_step_in_its_output_and_exit_status(tmp_path, held):
    code, lines, ledger = finish(tmp_path, {"value": KEPT_OUT, **({"_held": held} if held else {})})
    ((path, record, digest),) = ledger.receipts()
    withheld = "receipt withheld: it would hold a secret value"
    assert (record["result"], record["detail"]) == ("failed", withheld)
    assert code == aws_07b.EXIT_FAILED
    # The step reports what its receipt records: no "done" or hold, no next chain head.
    assert lines == [f"Step custodian FAILED: {withheld}. Receipt {digest}"]
    assert KEPT_OUT not in path.read_text() and KEPT_OUT not in "\n".join(lines)
    assert ledger.completed() == {}


@pytest.mark.parametrize("held", [None, "a fixture hold"])
def test_a_safe_receipt_reports_its_own_outcome_and_the_next_chain_head(tmp_path, held):
    code, lines, ledger = finish(tmp_path,
                                 {"value": "safe-reference", **({"_held": held} if held else {})})  # fmt: skip
    ((_, record, digest),) = ledger.receipts()
    assert record["result"] == ("held" if held else "ok")
    assert code == (aws_07b.EXIT_FAILED if held else aws_07b.EXIT_OK)
    assert lines == [f"Step custodian {'HELD: ' + held if held else 'done'}. Receipt {digest}",
                     f"Give the next command --chain-head {digest}"]  # fmt: skip
    assert set(ledger.completed()) == (set() if held else {"custodian"})


def test_a_failed_step_whose_receipt_is_withheld_keeps_its_failure_and_exit_status(tmp_path):
    out = io.StringIO()
    kit = aws_07b.Kit(AccountPlan(tmp_path, {"plan_sha256": "a" * 64}), tmp_path / "work",
                      out=out)  # fmt: skip

    def action() -> dict[str, Any]:
        kit.partial["value"] = KEPT_OUT  # something ran, and what it returned is kept out
        raise aws_07b.StepFailed("fixture failure")

    code = kit._finish(CUSTODIAN, [], "custodian", action, None, (KEPT_OUT,))
    ((path, record, digest),) = kit.ledger.receipts()
    withheld = "receipt withheld: it would hold a secret value"
    assert (record["result"], record["detail"]) == ("failed", withheld)
    assert code == aws_07b.EXIT_FAILED
    lines = out.getvalue().splitlines()
    assert lines == [f"Step custodian FAILED: fixture failure. Receipt {digest}"]
    assert KEPT_OUT not in path.read_text() and KEPT_OUT not in out.getvalue()
    assert kit.ledger.completed() == {}


# Sessions and the environment Terraform gets ----------------------------------------


def test_a_step_without_an_explicit_session_file_is_refused(setup):
    kit = initialized(setup)
    setup["typed"].append("bootstrap")
    with pytest.raises(aws_07b.Refused, match="explicit --session"):
        kit.run_step("bootstrap", chain_head=head(kit))


def test_terraform_gets_only_the_session_and_switches_that_disable_every_other_source(
    setup, monkeypatch
):
    monkeypatch.setenv("AWS_PROFILE", "ambient")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAAMBIENTAMBIENT00")
    loaded = sessions.load(str(setup["deployer"]), operator=OPERATOR)
    environment = sessions.terraform_environment(loaded, region="us-east-1",
                                                 home=Path("/h"), data_dir=Path("/d"))  # fmt: skip
    assert environment["AWS_ACCESS_KEY_ID"] == loaded.credentials.access_key_id
    assert "AWS_PROFILE" not in environment and environment["AWS_EC2_METADATA_DISABLED"] == "true"
    assert environment["AWS_CONFIG_FILE"].startswith("/nonexistent/")
    assert set(environment) == {
        "PATH", "HOME", "LANG", "TF_IN_AUTOMATION", "CHECKPOINT_DISABLE", "TF_INPUT",
        "TF_DATA_DIR", "TF_CLI_CONFIG_FILE", "AWS_REGION", "AWS_CONFIG_FILE",
        "AWS_SHARED_CREDENTIALS_FILE", "AWS_EC2_METADATA_DISABLED", "AWS_SDK_LOAD_CONFIG",
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    }  # fmt: skip


def test_a_stand_in_endpoint_must_be_loopback(setup):
    with pytest.raises(sessions.SessionRefused, match="loopback"):
        sessions.load(str(setup["deployer"]), operator=OPERATOR,
                      endpoint="http://moto.example.com:5000")  # fmt: skip


# The diff check ----------------------------------------------------------------------


def plan_document(*changes: tuple[str, list[str]], version="1.16.5", variables=None):
    return {"terraform_version": version,
            "variables": {k: {"value": v} for k, v in (variables or {"a": 1}).items()},
            "resource_changes": [{"address": a, "change": {"actions": x}} for a, x in changes]}  # fmt: skip


def test_a_first_deployment_plan_of_creates_passes_and_anything_else_stops():
    ok = plan_document(("aws_vpc.this", ["create"]), ("data.aws_x.y", ["read"]))
    assert check_plan(ok, root="foundation", variables={"a": 1})["actions"] == {
        "create": 1,
        "read": 1,
    }
    for actions in (["update"], ["delete"], ["delete", "create"], ["create", "delete"]):
        with pytest.raises(UnexpectedPlan):
            check_plan(plan_document(("aws_vpc.this", actions)), root="foundation",
                       variables={"a": 1})  # fmt: skip
    with pytest.raises(UnexpectedPlan, match="Terraform 1.9.8"):
        check_plan(plan_document(("x.y", ["create"]), version="1.9.8"), root="foundation",
                   variables={"a": 1})  # fmt: skip
    with pytest.raises(UnexpectedPlan, match="rendered value"):
        check_plan(ok, root="foundation", variables={"a": 2})


def test_the_releases_plan_creates_nothing_outside_the_current_release():
    inside = ('module.release["r0b9f7c1e"].aws_iam_role.task["runtime"]', ["create"])
    policy = ('aws_iam_policy.release_launcher["jobs"]', ["create"])
    check_plan(plan_document(inside, policy), root="releases", variables={"a": 1},
               current_key="r0b9f7c1e")  # fmt: skip
    with pytest.raises(UnexpectedPlan, match="outside the current release"):
        check_plan(plan_document(('module.release["r11111111"].aws_iam_role.x', ["create"])),
                   root="releases", variables={"a": 1}, current_key="r0b9f7c1e")  # fmt: skip


# Images ------------------------------------------------------------------------------


def test_an_image_is_pushed_by_digest_unchanged_and_verified_on_read_back(tmp_path):
    archive_sha, digest = oci_archive(tmp_path / "a.tar", "runtime")
    image = images.read_archive(tmp_path / "a.tar", archive_sha256=archive_sha,
                                platform_manifest=digest)  # fmt: skip
    ecr = FakeEcr()
    result = images.push(ecr, image, repository="sentry-staging/runtime", registry_id="1" * 12)
    assert result["registry_digest"] == digest and len(result["uploaded_blobs"]) == 2
    again = images.push(ecr, image, repository="sentry-staging/runtime", registry_id="1" * 12)
    assert again["uploaded_blobs"] == [] and len(again["already_present"]) == 2
    with pytest.raises(images.PushRefused, match="changed the manifest digest"):
        images.push(FakeEcr(change_digest=True), image, repository="r", registry_id="1" * 12)


def test_an_archive_or_blob_that_is_not_the_bound_one_is_refused(tmp_path):
    archive_sha, digest = oci_archive(tmp_path / "a.tar", "runtime")
    with pytest.raises(images.PushRefused, match="not the archive"):
        images.read_archive(tmp_path / "a.tar", archive_sha256="0" * 64, platform_manifest=digest)
    with pytest.raises(images.PushRefused, match="lacks blob"):
        images.read_archive(tmp_path / "a.tar", archive_sha256=archive_sha,
                            platform_manifest="sha256:" + "0" * 64)  # fmt: skip


# The sequence ------------------------------------------------------------------------


def test_steps_run_in_order_after_typed_confirmation_and_the_run_ends_held_paused(setup):
    kit = initialized(setup)
    with pytest.raises(aws_07b.Refused, match="only after bootstrap"):
        kit.run_step("foundation", chain_head=head(kit), session_path=str(setup["deployer"]))
    run_through(setup, kit, "detach")
    receipts = kit.ledger.receipts()
    assert [doc["step"] for _, doc, _ in receipts] == ["init", *(s.id for s in aws_07b.STEPS)]
    assert all(doc["result"] == "ok" and doc["plan_sha256"] == setup["hash"]
               for _, doc, _ in receipts)  # fmt: skip
    done = kit.receipts()
    manifest_path = Path(done["validate"]["outputs"]["manifest"])
    manifest = load_manifest(manifest_path.read_bytes())
    assert manifest.sha256 == done["validate"]["outputs"]["manifest_sha256"]
    assert manifest.manifest.images.runtime.arm64_digest == (
        done["images"]["outputs"]["registry_digests"]["runtime"]
    )
    assert (
        manifest.manifest.risk.decision_sha256
        == hashlib.sha256(setup["risk"].read_bytes()).hexdigest()
    )
    assert done["run"]["outputs"]["run"]["state"] == "held_paused"
    assert done["detach"]["outputs"]["remaining"] == []
    attached = done["attach"]["outputs"]["attached"]
    assert [arn.rsplit("/", 1)[1] for arn in attached] == sorted(
        [
            f"sentry-staging-release-launcher-{n}"
            for n in ("jobs", "observe", "receipts", "services", "tasks")
        ]
        + ["sentry-staging-release-evidence", "sentry-staging-release-launcher-bootstrap"]
    )
    # Every value was rendered: the operator typed only step identifiers.
    assert all(doc["typed"] == doc["step"] for _, doc, _ in receipts)
    custody_values = [v for path in setup["custody"].rglob("*.json")
                      if path.name not in ("deployer.json", "operator.json")
                      for v in json.loads(path.read_text()).values()]  # fmt: skip
    text = "".join(path.read_text() for path, _, _ in receipts)
    assert not any(value in text for value in custody_values), "a secret value reached a receipt"


def test_a_mistyped_identifier_runs_nothing_and_writes_nothing(setup):
    kit = initialized(setup)
    setup["typed"].append("bootstrap-please")
    with pytest.raises(aws_07b.Refused, match="not confirmed"):
        kit.run_step("bootstrap", chain_head=head(kit), session_path=str(setup["deployer"]))
    assert "terraform" not in setup["world"] and len(kit.ledger.receipts()) == 1


def test_an_unexpected_plan_is_never_applied_and_its_receipt_says_why(setup):
    kit = initialized(setup)
    setup["world"]["changes"] = {
        "bootstrap": [
            {"address": "aws_s3_bucket.control", "change": {"actions": ["delete", "create"]}}
        ]
    }
    assert step(setup, kit, "bootstrap", session_path=str(setup["deployer"])) == (
        aws_07b.EXIT_FAILED
    )
    assert ("bootstrap", "apply") not in setup["world"]["terraform"]
    head, _ = kit.ledger.head()
    assert head is not None and head["result"] == "failed" and "first deployment" in head["detail"]


def test_a_release_that_holds_is_recorded_held_and_detach_still_runs(setup):
    kit = initialized(setup)
    run_through(setup, kit, "validate")
    setup["world"]["run_result"] = (3, {"state": "held", "reason": "worker_not_ready"})
    setup["world"][
        "arn"
    ] = f"arn:aws:sts::111122223333:assumed-role/sentry-staging-operator/{OPERATOR}"
    assert step(setup, kit, "run", session_path=str(setup["operator"])) == aws_07b.EXIT_FAILED
    head, _ = kit.ledger.head()
    assert head is not None and head["result"] == "held" and "worker_not_ready" in head["detail"]
    setup["world"]["arn"] = f"arn:aws:sts::111122223333:assumed-role/admin/{OPERATOR}"
    assert step(setup, kit, "detach", session_path=str(setup["deployer"])) == aws_07b.EXIT_OK


def status_like(kit, **changes):
    document = json.loads(Path(kit.receipts()["validate"]["outputs"]["manifest"]).read_text())
    found = {"command": "status", "release_id": document["release_id"], "lock": None,
             "journal": {"state": "held_paused", "outstanding": [], "reason": None}}  # fmt: skip
    found.update(changes)
    return found


@pytest.mark.parametrize("label", ["aws_unconfirmed", "session_expires_too_soon", "unparsed",
                                   "no lock field", "another release", "still open",
                                   "lock held"])  # fmt: skip
def test_the_run_step_holds_unless_status_proves_the_release_paused_and_unlocked(setup, label):
    kit = initialized(setup)
    run_through(setup, kit, "validate")
    rid = status_like(kit)["release_id"]
    responses = {
        "aws_unconfirmed": (4, {"error": "aws_unconfirmed"}),
        "session_expires_too_soon": (2, {"error": "session_expires_too_soon"}),
        "unparsed": (0, {"unparsed_output_sha256": "0" * 64}),
        "no lock field": (0, {k: v for k, v in status_like(kit).items() if k != "lock"}),
        "another release": (0, status_like(kit, release_id="0" * 8 + rid[8:])),
        "still open": (0, status_like(kit, journal={"state": "held_paused", "outstanding": [
            {"action": "RunTask", "subject": "job:x", "sequence": 9}]})),
        "lock held": (0, status_like(kit, lock={"release_id": rid, "session_id": "s",
                                                "etag": "e"})),
    }  # fmt: skip
    setup["world"]["status_result"] = responses[label]
    setup["world"][
        "arn"
    ] = f"arn:aws:sts::111122223333:assumed-role/sentry-staging-operator/{OPERATOR}"
    assert step(setup, kit, "run", session_path=str(setup["operator"])) == aws_07b.EXIT_FAILED
    held, _ = kit.ledger.head()
    assert held is not None and held["result"] == "held"
    setup["world"]["arn"] = f"arn:aws:sts::111122223333:assumed-role/admin/{OPERATOR}"
    assert step(setup, kit, "detach", session_path=str(setup["deployer"])) == aws_07b.EXIT_OK


def test_the_operator_steps_need_the_operator_roles_own_session(setup):
    kit = initialized(setup)
    run_through(setup, kit, "attach")
    setup["world"]["arn"] = f"arn:aws:sts::111122223333:assumed-role/admin/{OPERATOR}"
    setup["typed"].append("session")
    with pytest.raises(aws_07b.Refused, match="operator role's session"):
        kit.run_step("session", chain_head=head(kit), session_path=str(setup["operator"]))


def test_attach_refuses_a_role_that_already_has_policies(setup):
    kit = initialized(setup)
    run_through(setup, kit, "services")
    setup["world"]["clients"]["iam"].attached["sentry-staging-operator"] = ["arn:aws:iam::aws:x"]
    assert step(setup, kit, "attach", session_path=str(setup["deployer"])) == aws_07b.EXIT_FAILED


def test_detach_fails_naming_a_policy_no_step_attached_and_leaves_it(setup):
    kit = initialized(setup)
    run_through(setup, kit, "services")
    iam = setup["world"]["clients"]["iam"]
    iam.attached["sentry-staging-operator"] = ["arn:aws:iam::aws:stray"]
    options = {"session_path": str(setup["deployer"])}
    assert step(setup, kit, "attach", **options) == aws_07b.EXIT_FAILED
    assert step(setup, kit, "detach", **options) == aws_07b.EXIT_FAILED
    assert iam.attached["sentry-staging-operator"] == ["arn:aws:iam::aws:stray"]
    failed, _ = kit.ledger.head()
    assert failed is not None and "arn:aws:iam::aws:stray" in failed["detail"]


def test_an_anchor_given_against_missing_history_is_refused(setup):
    kit = initialized(setup)
    run_through(setup, kit, "foundation")
    anchor = head(kit)
    for path in (setup["tmp"] / "work" / "receipts").iterdir():
        path.rename(setup["tmp"] / f"kept-{path.name}")
    setup["typed"].append("custodian")
    with pytest.raises(aws_07b.Refused, match="history"):
        kit.run_step("custodian", chain_head=anchor, session_path=str(setup["deployer"]),
                     custodian=setup["custody"])  # fmt: skip
    assert setup["typed"] == ["custodian"], "the step asked before refusing"
    assert kit.ledger.receipts() == []


def test_custodian_inputs_must_be_owner_only_and_hold_exactly_the_bundle_keys(setup):
    kit = initialized(setup)
    run_through(setup, kit, "foundation")
    path = setup["custody"] / "environment" / "runtime.json"
    path.chmod(0o644)
    setup["typed"].append("custodian")
    with pytest.raises(aws_07b.Refused, match="readable by others"):
        kit.run_step(
            "custodian",
            chain_head=head(kit),
            session_path=str(setup["deployer"]),
            custodian=setup["custody"],
        )
    path.chmod(0o600)
    path.write_text(json.dumps({"DATABASE_URL": "x"}))
    with pytest.raises(aws_07b.Refused, match="exactly the keys"):
        kit.run_step(
            "custodian",
            chain_head=head(kit),
            session_path=str(setup["deployer"]),
            custodian=setup["custody"],
        )


def test_init_refuses_bindings_whose_archives_do_not_verify(setup):
    found = json.loads(setup["bindings"].read_text())
    found["search"]["archive_sha256"] = "0" * 64
    setup["bindings"].write_text(json.dumps(found))
    setup["typed"].append("init")
    with pytest.raises(images.PushRefused, match="not the archive"):
        setup["kit"]().init(
            bindings_path=setup["bindings"],
            risk_path=setup["risk"],
            runtime_checkout=setup["tmp"],
            terraform=Path("/fixture/terraform"),
        )


def test_a_risk_decision_about_other_images_stops_init(setup):
    fx.risk_decision(setup["risk"], {"runtime": "sha256:" + "1" * 64, "search": "x",
                                     "release_tools": "y"})  # fmt: skip
    kit = initialized_or_failed(setup)
    head, _ = kit.ledger.head()
    assert head is not None and head["result"] == "failed" and "other images" in head["detail"]


def initialized_or_failed(setup) -> FakeKit:
    setup["typed"].append("init")
    kit = setup["kit"]()
    kit.init(bindings_path=setup["bindings"], risk_path=setup["risk"],
             runtime_checkout=setup["tmp"], terraform=Path("/fixture/terraform"))  # fmt: skip
    return kit


# Rendering ---------------------------------------------------------------------------


def test_the_rendered_releases_input_has_seventeen_distinct_bundles_and_digest_pins(setup):
    kit = initialized(setup)
    run_through(setup, kit, "releases")
    rendered = kit.receipts()["releases"]["outputs"]["rendered"]
    ((key, release),) = rendered["releases"].items()
    assert key == render.release_key(release["release_id"])
    arns = re.findall(r'"arn": "(arn:aws:secretsmanager:[^"]+)"', json.dumps(release))
    managed = [arn for arn in arns if ":secret:rds!db-" in arn]
    assert len(set(arns) - set(managed)) == 17 and len(managed) == 2
    pattern = r"111122223333\.dkr\.ecr\.us-east-1\.amazonaws\.com/sentry-staging/(runtime|search|release-tools)@sha256:[0-9a-f]{64}"  # noqa: E501
    for image in (*release["images"].values(), release["release_tools"]["image"]):
        assert re.fullmatch(pattern, image)
    assert release["release_tools"]["sql_sha256"]["runtime_grant"] == RUNTIME_GRANT_PIN["sha256"]


# A release that names a provider canary ----------------------------------------------
#
# Only an approved capped canary names a provider: init fixes its approval into the
# release record, the custodian then accepts a provider key for that release alone,
# and the releases step gives it to the worker. No key here is real.

CANARY_HOST = "provider.example.test"


def canary_approval(setup, *, now=None, **changes: Any) -> Path:
    manifest = stand_in_canary(CANARY_HOST, now or aws_07b._now())
    decided = (aws_07b._now() - aws_07b.timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    document = {"schema": aws_07b.PROVIDER_SCHEMA, "plan_sha256": setup["plan"].plan_sha256,
                "image_bindings_sha256": hashlib.sha256(setup["bindings"].read_bytes()).hexdigest(),
                "decided_by": "michael", "decided_at": decided,
                "canary_id": "local-provider-stub", "canary_manifest": manifest,
                "canary_manifest_sha256": hashlib.sha256(manifest.encode()).hexdigest(),
                "base_url": f"https://{CANARY_HOST}/api/v1", **changes}  # fmt: skip
    path = setup["tmp"] / "provider-approval.json"
    path.write_text(
        json.dumps({key: value for key, value in document.items() if value is not None})
    )
    return path


def initialized_with(setup, approval: Path) -> FakeKit:
    setup["typed"].append("init")
    kit = setup["kit"]()
    assert kit.init(bindings_path=setup["bindings"], risk_path=setup["risk"],
                    runtime_checkout=setup["tmp"], terraform=Path("/fixture/terraform"),
                    provider_path=approval) == aws_07b.EXIT_OK  # fmt: skip
    return kit


def provider_key_file(setup, value: str = "placeholder-provider-key") -> Path:
    path = setup["custody"] / "provider-key" / "worker.json"
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps({"OPENROUTER_API_KEY": value}))
    path.chmod(0o400)
    return path


def custodian_step(setup, kit: FakeKit) -> int:
    setup["typed"].append("custodian")
    return kit.run_step("custodian", chain_head=head(kit), session_path=str(setup["deployer"]),
                        custodian=setup["custody"])  # fmt: skip


def test_without_a_provider_approval_the_record_and_release_name_no_provider(setup):
    kit = initialized(setup)
    assert not {"provider", "provider_approval"} & set(kit.record())
    run_through(setup, kit, "releases")
    assert set(kit.receipts()["custodian"]["outputs"]["bundles"]) == set(render.BUNDLES)
    ((_, release),) = kit.receipts()["releases"]["outputs"]["rendered"]["releases"].items()
    assert "model_provider" not in release
    created = setup["world"]["clients"]["secretsmanager"].created
    assert not [name for name in created if "provider-key" in name]


def test_init_fixes_the_provider_approval_into_the_release_record(setup):
    approval = canary_approval(setup)
    document = json.loads(approval.read_text())
    kit = initialized_with(setup, approval)
    record = kit.record()
    assert record["provider"] == {field: document[field] for field in render.PROVIDER_FIELDS}
    assert record["provider_approval"] == {
        "sha256": hashlib.sha256(approval.read_bytes()).hexdigest(),
        "decided_by": "michael", "decided_at": document["decided_at"],
    }  # fmt: skip
    # The operator confirms the whole canary, not its name alone.
    said = kit.out.getvalue()  # ty: ignore[unresolved-attribute]
    for shown in ("provider canary local-provider-stub", document["canary_manifest_sha256"],
                  document["base_url"], json.loads(document["canary_manifest"])["not_after"],
                  "approved by michael", f"openrouter: at most 1000 requests to {CANARY_HOST}",
                  "stops after 20 consecutive failures"):  # fmt: skip
        assert shown in said
    # The record is the init receipt: what later steps read is what was fixed here.
    (receipt,) = (kit.work / "receipts").iterdir()
    assert json.loads(receipt.read_text())["outputs"]["provider"] == record["provider"]


def unusable_approvals() -> list[tuple[str, Any, str]]:
    now = aws_07b._now()
    other = stand_in_canary(CANARY_HOST, now).replace("local-provider-stub", "another-canary")
    expired = stand_in_canary(CANARY_HOST, now - aws_07b.timedelta(hours=13))
    malformed = json.dumps({"schema": "sentry.provider-canary.v1"})

    def manifest(text: str) -> dict[str, str]:
        return {"canary_manifest": text,
                "canary_manifest_sha256": hashlib.sha256(text.encode()).hexdigest()}  # fmt: skip

    return [
        ("another plan", {"plan_sha256": "0" * 64}, "for another plan"),
        ("other images", {"image_bindings_sha256": "0" * 64}, "other images than the bindings"),
        ("no approver", {"decided_by": " "}, "names who decided"),
        ("decided later", {"decided_at": "2999-01-01T00:00:00Z"}, "decided_at is in the future"),
        ("no decision time", {"decided_at": "yesterday"}, "decided_at is not a UTC time"),
        (
            "unnamed model host",
            {"base_url": "https://other.example.test/api/v1"},
            "does not name the base_url's host",
        ),
        ("another schema", {"schema": "sentry.risk-decision.v1"}, "not a sentry.provider-canary"),
        ("an extra field", {"key": "x"}, "not a sentry.provider-canary"),
        ("another hash", {"canary_manifest_sha256": "0" * 64}, "not the one the release names"),
        ("another canary", manifest(other), "not the one the release names"),
        ("malformed", manifest(malformed), "not a usable canary manifest"),
        ("expired", manifest(expired), "has expired"),
        ("plain http", {"base_url": f"http://{CANARY_HOST}/api/v1"}, "https address"),
        ("an empty field", {"base_url": ""}, "provider names base_url, canary_id"),
    ]


@pytest.mark.parametrize("label, changes, reason", unusable_approvals(),
                         ids=[case[0] for case in unusable_approvals()])  # fmt: skip
def test_init_refuses_a_provider_approval_the_worker_would_refuse(setup, label, changes, reason):
    approval = canary_approval(setup, **changes)
    setup["typed"].append("init")
    kit = setup["kit"]()
    with pytest.raises(aws_07b.Refused, match=reason):
        kit.init(bindings_path=setup["bindings"], risk_path=setup["risk"],
                 runtime_checkout=setup["tmp"], terraform=Path("/fixture/terraform"),
                 provider_path=approval)  # fmt: skip
    assert kit.ledger.receipts() == [] and setup["typed"] == ["init"], "init asked or wrote"


def test_init_refuses_a_provider_approval_that_is_not_json(setup):
    approval = setup["tmp"] / "provider-approval.json"
    approval.write_text("canary: yes")
    setup["typed"].append("init")
    kit = setup["kit"]()
    with pytest.raises(aws_07b.Refused, match="not JSON"):
        kit.init(bindings_path=setup["bindings"], risk_path=setup["risk"],
                 runtime_checkout=setup["tmp"], terraform=Path("/fixture/terraform"),
                 provider_path=approval)  # fmt: skip
    assert kit.ledger.receipts() == []


def test_the_cli_passes_a_provider_approval_to_init_only_when_given(setup):
    seen: list[dict[str, Any]] = []

    class Recording(aws_07b.Kit):
        def init(self, **kwargs: Any) -> int:
            seen.append(kwargs)
            return aws_07b.EXIT_OK

    base = ["init", "--plan", str(setup["plan_dir"]), "--plan-sha256", setup["hash"],
            "--work", str(setup["tmp"] / "cli"), "--image-bindings", "b.json",
            "--risk-decision", "r.json", "--runtime-checkout", "rt", "--terraform", "tf"]  # fmt: skip
    assert aws_07b.main(base, kit_class=Recording) == aws_07b.EXIT_OK
    assert aws_07b.main([*base, "--provider-canary", "p.json"], kit_class=Recording) == 0
    assert [call["provider_path"] for call in seen] == [None, Path("p.json")]


def test_a_provider_key_file_without_a_named_canary_is_refused_before_any_secret(setup):
    kit = initialized(setup)
    run_through(setup, kit, "foundation")
    provider_key_file(setup)
    with pytest.raises(aws_07b.Refused, match="names no provider canary"):
        custodian_step(setup, kit)
    assert setup["world"]["clients"]["secretsmanager"].created == {}
    assert "custodian" not in kit.receipts()


def test_a_named_canary_needs_its_provider_key_file(setup):
    kit = initialized_with(setup, canary_approval(setup))
    run_through(setup, kit, "foundation")
    with pytest.raises(aws_07b.Refused, match="give provider-key/worker.json"):
        custodian_step(setup, kit)
    assert setup["world"]["clients"]["secretsmanager"].created == {}


def test_a_canary_that_expires_before_the_custodian_step_is_refused(setup):
    # The manifest stops two minutes after init; the custodian runs five minutes later.
    now = aws_07b._now()
    approval = canary_approval(setup, now=now - aws_07b.timedelta(hours=12, minutes=-2))
    kit = initialized_with(setup, approval)
    run_through(setup, kit, "foundation")
    provider_key_file(setup)
    later = setup["kit"](now=lambda: aws_07b._now() + aws_07b.timedelta(minutes=5))
    with pytest.raises(aws_07b.Refused, match="has expired"):
        custodian_step(setup, later)
    assert setup["world"]["clients"]["secretsmanager"].created == {}


@pytest.mark.parametrize("value, reason", [("disabled-local-platform-fit", "disabled placeholder"),
                                           (" disabled-local-platform-fit\n", "disabled placeholder"),
                                           ("   ", "an empty key")])  # fmt: skip
def test_a_provider_key_file_holding_no_key_is_refused(setup, value, reason):
    kit = initialized_with(setup, canary_approval(setup))
    run_through(setup, kit, "foundation")
    provider_key_file(setup, value=value)
    with pytest.raises(aws_07b.Refused, match=reason):
        custodian_step(setup, kit)
    assert setup["world"]["clients"]["secretsmanager"].created == {}


def test_a_canary_that_expires_before_the_releases_step_is_refused_there(setup):
    now = aws_07b._now()
    approval = canary_approval(setup, now=now - aws_07b.timedelta(hours=12, minutes=-2))
    kit = initialized_with(setup, approval)
    provider_key_file(setup)
    run_through(setup, kit, "images")
    later = setup["kit"](now=lambda: aws_07b._now() + aws_07b.timedelta(minutes=5))
    setup["typed"].append("releases")
    with pytest.raises(aws_07b.Refused, match="has expired"):
        later.run_step("releases", chain_head=head(later), session_path=str(setup["deployer"]))
    assert "releases" not in later.receipts()


def test_the_validated_manifest_lists_the_workers_provider_key(setup):
    kit = initialized_with(setup, canary_approval(setup))
    provider_key_file(setup)
    run_through(setup, kit, "validate")
    done = kit.receipts()["validate"]["outputs"]
    manifest = load_manifest(Path(done["manifest"]).read_bytes()).manifest
    key = kit.receipts()["custodian"]["outputs"]["bundles"]["provider-key/worker"]
    assert [item.arn for item in manifest.services.worker.secrets][-1] == key["arn"]
    for name in ("runtime", "api"):
        assert key["arn"] not in {item.arn for item in getattr(manifest.services, name).secrets}


def test_a_named_canary_gives_only_the_worker_its_key_at_the_created_version(setup):
    approval = canary_approval(setup)
    canary = json.loads(approval.read_text())
    kit = initialized_with(setup, approval)
    provider_key_file(setup)
    run_through(setup, kit, "releases")
    created = setup["world"]["clients"]["secretsmanager"].created
    name = render.secret_name(setup["plan"], "provider-key/worker")
    assert json.loads(created[name][0]) == {"OPENROUTER_API_KEY": "placeholder-provider-key"}
    bundles = kit.receipts()["custodian"]["outputs"]["bundles"]
    assert set(bundles) == {*render.BUNDLES, "provider-key/worker"}
    ((_, release),) = kit.receipts()["releases"]["outputs"]["rendered"]["releases"].items()
    assert release["model_provider"] == {
        "base_url": canary["base_url"], "canary_manifest": canary["canary_manifest"],
        "canary_manifest_sha256": canary["canary_manifest_sha256"],
        "key_bundle": bundles["provider-key/worker"],
    }  # fmt: skip
    arns = re.findall(r'"arn": "(arn:aws:secretsmanager:[^"]+)"', json.dumps(release))
    assert len({arn for arn in arns if ":secret:rds!db-" not in arn}) == 18
    # The key reaches the secret alone: no receipt, rendered file or transcript holds it.
    assert "placeholder-provider-key" not in kit.out.getvalue()  # ty: ignore[unresolved-attribute]
    for path in (*(kit.work / "receipts").iterdir(), *(kit.work / "rendered").iterdir()):
        assert "placeholder-provider-key" not in path.read_text()


def test_the_rendered_approval_binds_the_manifest_inside_its_window(setup):
    kit = initialized(setup)
    run_through(setup, kit, "validate")
    done = kit.receipts()["validate"]["outputs"]
    manifest = load_manifest(Path(done["manifest"]).read_bytes())
    approval = load_approval(Path(done["approval"]).read_bytes())
    assert approval.approval.manifest_sha256 == manifest.sha256
    window = manifest.manifest.window
    assert window.not_before <= approval.approval.not_before < approval.approval.not_after
    assert approval.approval.not_after <= window.expires_at


# Section 8 ---------------------------------------------------------------------------


def section_8_approval(setup, kit, schema, **fields) -> Path:
    _, head = kit.ledger.head()
    path = setup["tmp"] / f"{schema}.json"
    path.write_text(json.dumps({"schema": schema, "plan_sha256": setup["hash"],
                                "chain_head_sha256": head, "approved_by": OPERATOR,
                                "not_after": "2099-01-01T00:00:00Z", **fields}))  # fmt: skip
    return path


def test_restore_and_teardown_refuse_an_empty_or_uninitialized_chain(setup):
    """An approval prepared against an empty directory must not start a fresh chain."""
    kit = setup["kit"]()  # no init: the work directory has no receipts
    restore = section_8_approval(setup, kit, aws_07b.RESTORE_SCHEMA, database="runtime",
                                 target_identifier="sentry-staging-runtime-db-restore-x",
                                 restore_time="2026-10-17T00:00:00Z")  # fmt: skip
    teardown = section_8_approval(setup, kit, aws_07b.TEARDOWN_SCHEMA, remove=[])
    for command, approval in ((kit.restore, restore), (kit.teardown, teardown)):
        with pytest.raises(aws_07b.Refused, match="no receipts"):
            command(session_path=str(setup["deployer"]), approval_path=approval)
    assert kit.ledger.receipts() == [] and not (setup["tmp"] / "work" / "terraform").exists()


def test_restore_and_teardown_refuse_without_their_own_bound_approval(setup):
    kit = initialized(setup)
    run_through(setup, kit, "detach")
    wrong = section_8_approval(setup, kit, aws_07b.TEARDOWN_SCHEMA, database="runtime")
    with pytest.raises(aws_07b.Refused, match="restore-approval"):
        kit.restore(chain_head=head(kit), session_path=str(setup["deployer"]), approval_path=wrong)
    stale = section_8_approval(setup, kit, aws_07b.RESTORE_SCHEMA, database="runtime",
                               target_identifier="sentry-staging-runtime-db-restore-a",
                               restore_time="latest", chain_head_sha256="0" * 64)  # fmt: skip
    with pytest.raises(aws_07b.Refused, match="receipt chain head"):
        kit.restore(chain_head=head(kit), session_path=str(setup["deployer"]), approval_path=stale)
    over = section_8_approval(setup, kit, aws_07b.RESTORE_SCHEMA, database="runtime",
                              target_identifier="sentry-staging-runtime-db",
                              restore_time="latest")  # fmt: skip
    with pytest.raises(aws_07b.Refused, match="new instance"):
        kit.restore(chain_head=head(kit), session_path=str(setup["deployer"]), approval_path=over)
    partial = section_8_approval(setup, kit, aws_07b.TEARDOWN_SCHEMA,
                                 remove=['aws_ecs_service.this["runtime"]'])  # fmt: skip
    with pytest.raises(aws_07b.Refused, match="exactly the services"):
        kit.teardown(
            chain_head=head(kit), session_path=str(setup["deployer"]), approval_path=partial
        )


class FakeRds:
    def __init__(self) -> None:
        self.instances = {"sentry-staging-runtime-db": {
            "DBInstanceIdentifier": "sentry-staging-runtime-db", "DBInstanceStatus": "available",
            "DBSubnetGroup": {"DBSubnetGroupName": "sentry-staging-db"},
            "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-0aaaaaaaaaaaaaaa1"}]}}  # fmt: skip
        self.restored: list[dict] = []

    def describe_db_instances(self):
        return {"DBInstances": list(self.instances.values())}

    def restore_db_instance_to_point_in_time(self, **arguments):
        self.restored.append(arguments)
        created = {"DBInstanceIdentifier": arguments["TargetDBInstanceIdentifier"],
                   "DBInstanceStatus": "creating"}  # fmt: skip
        self.instances[created["DBInstanceIdentifier"]] = created
        return {"DBInstance": created}


def test_restore_goes_into_a_new_instance_and_leaves_the_original(setup):
    kit = initialized(setup)
    run_through(setup, kit, "detach")
    rds = FakeRds()
    setup["world"]["clients"]["rds"] = rds
    approval = section_8_approval(setup, kit, aws_07b.RESTORE_SCHEMA, database="runtime",
                                  target_identifier="sentry-staging-runtime-db-restore-a",
                                  restore_time="latest")  # fmt: skip
    setup["typed"].append("restore")
    assert (
        kit.restore(
            chain_head=head(kit), session_path=str(setup["deployer"]), approval_path=approval
        )
        == 0
    )
    (call,) = rds.restored
    assert call["SourceDBInstanceIdentifier"] == "sentry-staging-runtime-db"
    assert call["TargetDBInstanceIdentifier"] == "sentry-staging-runtime-db-restore-a"
    assert call["DeletionProtection"] is True and call["UseLatestRestorableTime"] is True
    assert rds.instances["sentry-staging-runtime-db"]["DBInstanceStatus"] == "available"


# The runbook -------------------------------------------------------------------------

RUNBOOK = REPO / "deploy" / "aws-staging" / "aws-07b" / "README.md"


def test_every_kit_step_is_tied_to_the_proposal_section_it_implements():
    text = RUNBOOK.read_text()
    rows = re.findall(r"^\| `([a-z-]+)` \| (\d+(?:\.\d+)?) \|", text, re.M)
    assert rows == [(item.id, item.section) for item in aws_07b.STEPS] + [
        ("restore", "8"),
        ("teardown", "8"),
    ]
    assert [item.section for item in aws_07b.STEPS] == [f"7.{n}" for n in range(1, 12)]
    assert "## Proven on the platform only" in text


def test_the_kit_reads_no_ambient_credential_source(monkeypatch):
    import importlib

    # Modules that may read the environment, and what for: aws_07b passes HOME to the
    # local Docker CLI; aws_08a and cutover pass an allowlist of tool settings to
    # local suites. None forwards a credential or provider setting.
    allowed = {"aws_07b.py": None, "aws_08a.py": "environment", "cutover.py": "production_today"}
    for path in sorted((REPO / "release_kits").glob("*.py")):
        source = path.read_text()
        assert "getenv(" not in source and "boto3" not in source, path.name
        assert "~/.aws" not in source and "AWS_PROFILE" not in source, path.name
        if "os.environ" in source:
            assert path.name in allowed, f"{path.name} reads the environment"
    ambient = ("AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SESSION_TOKEN", "OPENROUTER_API_KEY")
    for name in ambient:
        monkeypatch.setenv(name, "ambient")
    for module, function in allowed.items():
        if function and (REPO / "release_kits" / module).exists():
            loaded = importlib.import_module(f"release_kits.{module[:-3]}")
            assert not set(ambient) & set(getattr(loaded, function)()), module


# Review regressions -------------------------------------------------------------------


def test_the_real_release_cli_subprocess_validates_the_rendered_manifest(setup):
    kit = initialized(setup)
    run_through(setup, kit, "validate")
    done = kit.receipts()["validate"]["outputs"]
    code, report = aws_07b.Kit.release_cli(
        kit, ["validate", "--manifest", done["manifest"], "--approval", done["approval"]]
    )
    assert code == 0, report
    assert report["manifest_sha256"] == done["manifest_sha256"]


def test_an_edited_or_removed_newest_receipt_is_refused(setup):
    kit = initialized(setup)
    run_through(setup, kit, "attach")
    printed = head(kit)
    newest = kit.ledger.receipts()[-1][0]
    document = json.loads(newest.read_text())
    document["outputs"]["attached"] = []
    newest.chmod(0o644)
    newest.write_bytes((json.dumps(document, indent=2, sort_keys=True) + "\n").encode())
    setup["typed"].append("session")
    with pytest.raises(aws_07b.Refused, match="chain-head"):
        kit.run_step("session", chain_head=printed, session_path=str(setup["operator"]))
    newest.unlink()
    with pytest.raises(aws_07b.Refused, match="chain-head"):
        kit.run_step("attach", chain_head=printed, session_path=str(setup["deployer"]))


def test_a_custodian_step_that_fails_midway_keeps_what_it_made_and_its_retry_completes(setup):
    kit = initialized(setup)
    run_through(setup, kit, "foundation")
    secrets = setup["world"]["clients"]["secretsmanager"]
    secrets.fail_at = 9
    options = {"session_path": str(setup["deployer"]), "custodian": setup["custody"]}
    assert step(setup, kit, "custodian", **options) == aws_07b.EXIT_FAILED
    failed, _ = kit.ledger.head()
    assert failed is not None and failed["detail"] == "ClientError (message withheld)"
    made = failed["partial"]["bundles"]
    assert len(made) == 9
    secrets.fail_at = None
    assert step(setup, kit, "custodian", **options) == aws_07b.EXIT_OK
    bundles = kit.receipts()["custodian"]["outputs"]["bundles"]
    assert len(bundles) == 17 and {k: bundles[k] for k in made} == made


def test_a_partial_image_push_is_retried_to_the_same_digests(setup):
    kit = initialized(setup)
    run_through(setup, kit, "custodian")
    ecr = setup["world"]["clients"]["ecr"]
    ecr.fail_on = "sentry-staging/search"
    options = {"session_path": str(setup["deployer"])}
    assert step(setup, kit, "images", **options) == aws_07b.EXIT_FAILED
    failed, _ = kit.ledger.head()
    assert failed is not None and set(failed["partial"]["registry_digests"]) == {"runtime"}
    ecr.fail_on = None
    assert step(setup, kit, "images", **options) == aws_07b.EXIT_OK
    pushed = kit.receipts()["images"]["outputs"]["registry_digests"]
    assert pushed["runtime"] == failed["partial"]["registry_digests"]["runtime"]


def test_a_failed_attach_is_still_undone_by_detach(setup):
    kit = initialized(setup)
    run_through(setup, kit, "services")
    iam = setup["world"]["clients"]["iam"]
    iam.fail_after = 3
    options = {"session_path": str(setup["deployer"])}
    assert step(setup, kit, "attach", **options) == aws_07b.EXIT_FAILED
    assert len(iam.attached["sentry-staging-operator"]) == 3
    assert step(setup, kit, "detach", **options) == aws_07b.EXIT_OK
    assert iam.attached["sentry-staging-operator"] == []
    assert len(kit.receipts()["detach"]["outputs"]["detached"]) == 3


def test_an_unexpected_error_leaves_a_receipt_naming_only_its_class(setup, monkeypatch):
    kit = initialized(setup)
    run_through(setup, kit, "foundation")
    secrets = setup["world"]["clients"]["secretsmanager"]

    def broken(**_kwargs):
        raise KeyError("something the provider said")

    monkeypatch.setattr(secrets, "describe_secret", broken)
    options = {"session_path": str(setup["deployer"]), "custodian": setup["custody"]}
    assert step(setup, kit, "custodian", **options) == aws_07b.EXIT_FAILED
    failed, _ = kit.ledger.head()
    assert failed is not None and failed["detail"] == "KeyError (message withheld)"
    assert "provider said" not in kit.ledger.receipts()[-1][0].read_text()


def test_a_variable_file_terraform_would_load_from_the_root_is_refused(
    setup, tmp_path, monkeypatch
):
    kit = initialized(setup)
    root = tmp_path / "roots" / "bootstrap"
    root.mkdir(parents=True)
    (root / "override.auto.tfvars.json").write_text("{}")
    monkeypatch.setattr(kit, "terraform_directory", lambda name: tmp_path / "roots" / name)
    setup["typed"].append("bootstrap")
    with pytest.raises(aws_07b.Refused, match="would load"):
        kit.run_step("bootstrap", chain_head=head(kit), session_path=str(setup["deployer"]))


def test_terraform_reads_the_verified_plan_not_files_edited_after_it_loaded(setup):
    kit = initialized(setup)
    (setup["plan_dir"] / "bootstrap" / "account.auto.tfvars.json").write_text(
        json.dumps({"account_id": "999999999999", "region": "us-east-1",
                    "name_prefix": "sentry-staging"}))  # fmt: skip
    assert step(setup, kit, "bootstrap", "bootstrap", "bootstrap",
                session_path=str(setup["deployer"])) == aws_07b.EXIT_OK  # fmt: skip
    written = sorted((kit.work / "rendered").glob("*-bootstrap.account.tfvars.json"))[-1]
    assert json.loads(written.read_text()) == setup["plan"].inputs["bootstrap"]


def test_a_plan_file_changed_after_its_check_is_never_applied(setup):
    kit = initialized(setup)
    answers = iter(["bootstrap", "bootstrap"])

    def prompt(text: str) -> str:
        if "apply exactly" in text:
            for path in (kit.work / "plans").glob("*.tfplan"):
                path.write_bytes(b"swapped")
        return next(answers)

    kit.prompt = prompt
    assert kit.run_step("bootstrap", chain_head=head(kit),
                        session_path=str(setup["deployer"])) == aws_07b.EXIT_FAILED  # fmt: skip
    failed, _ = kit.ledger.head()
    assert failed is not None and "changed after it was checked" in failed["detail"]
    assert ("bootstrap", "apply") not in setup["world"]["terraform"]


class FakeServices:
    def __init__(self) -> None:
        self.desired: dict[str, int] = {}

    def update_service(self, *, cluster, service, desiredCount):
        self.desired[service] = desiredCount

    def describe_services(self, *, cluster, services):
        return {"services": [{"serviceArn": arn, "desiredCount": self.desired.get(arn, 1)}
                             for arn in services]}  # fmt: skip


def teardown_ready(setup) -> tuple[FakeKit, Path]:
    kit = initialized(setup)
    run_through(setup, kit, "detach")
    setup["world"]["clients"]["ecs"] = FakeServices()
    names = ("runtime", "api", "worker")
    setup["world"]["changes"]["services"] = [
        {"address": f'aws_ecs_service.this["{n}"]', "change": {"actions": ["delete"]}}
        for n in names]  # fmt: skip
    approval = section_8_approval(setup, kit, aws_07b.TEARDOWN_SCHEMA,
                                  remove=[f'aws_ecs_service.this["{n}"]' for n in names])  # fmt: skip
    return kit, approval


def test_teardown_scales_to_zero_detaches_then_removes_exactly_the_approved_services(setup):
    setup["world"]["changes"] = {}
    kit, approval = teardown_ready(setup)
    setup["typed"].extend(["teardown", "teardown"])
    assert kit.teardown(chain_head=head(kit), session_path=str(setup["deployer"]),
                        approval_path=approval) == aws_07b.EXIT_OK  # fmt: skip
    done = kit.receipts()["teardown"]["outputs"]
    services = setup["world"]["clients"]["ecs"].desired
    assert set(services.values()) == {0} and len(services) == 3
    assert len(done["removed"]) == 3 and ("services", "apply") in setup["world"]["terraform"]


def test_teardown_never_applies_a_destroy_plan_beyond_the_approved_list(setup):
    setup["world"]["changes"] = {}
    kit, approval = teardown_ready(setup)
    setup["world"]["changes"]["services"].append(
        {"address": "aws_s3_bucket.reports", "change": {"actions": ["delete"]}}
    )
    setup["typed"].extend(["teardown", "teardown"])
    applied = len([c for c in setup["world"]["terraform"] if c == ("services", "apply")])
    assert kit.teardown(chain_head=head(kit), session_path=str(setup["deployer"]),
                        approval_path=approval) == aws_07b.EXIT_FAILED  # fmt: skip
    failed, _ = kit.ledger.head()
    assert failed is not None and "not exactly the approved list" in failed["detail"]
    assert len([c for c in setup["world"]["terraform"] if c == ("services", "apply")]) == applied


def test_the_role_and_revision_keys_the_kit_reads_are_the_modules_own():
    source = (REPO / "deploy" / "aws-platform-fit" / "main.tf").read_text()
    for template in ('"${name}-task"', '"${name}-execution"', '"${name}-release-task"',
                     '"${name}-release-execution"', '"runtime-observe-task"', '"${key}-execution"',
                     '"${key}-task"', '"${name}-release" => task.arn'):  # fmt: skip
        assert template in source, template
    assert "${local.tools_jobs[key].database}-${local.tools_jobs[key].role}-execution" in source
    tools = (REPO / "deploy" / "aws-platform-fit" / "tools.tf").read_text()
    assert 'role = "recon"' in tools and 'role = "grant"' in tools and 'role = "proof"' in tools
