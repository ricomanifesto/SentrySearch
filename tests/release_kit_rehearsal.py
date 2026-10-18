"""Explicit AWS-07b rehearsal; run it with dev/rehearse_aws_07b.py.

The kit itself runs every step: ``init``, the four Terraform roots, the custodian's
secrets, the image push, attach, the operator session, validate, run and detach.
Only the account behind it is replaced:

- moto 5.2.3 in server mode on loopback (started by the operator, account
  111122223333) answers ECR, S3, Secrets Manager, STS and IAM. moto does not
  implement ECR's layer upload, so ``LayerShim`` answers those four operations in
  front of it, verifying each blob's digest as ECR does, and refuses a manifest
  whose layers it has not received or whose digest is not its bytes' hash.
- The plan half of each Terraform step is the pinned binary with
  ``-backend=false`` and the mocked provider (``terraform test``, ``command =
  plan``) over the kit's rendered variables, in a copy of ``deploy/``; its plan
  rendering becomes the plan document the kit checks. Apply is not rehearsed:
  each root's outputs are stand-ins from ``tests.release_kit_fixtures``, and the
  resources later steps call are created in moto here.
- ``release_cli run`` and ``status`` run in process through the container-backed
  ECS and Logs fakes of the release canary, with the journal and lock in moto S3
  and the operator's identity from a moto STS session of the operator role.

The restore-verify leg continues the same chain (section 8): ``restore`` asks moto
RDS for a point-in-time restore of the runtime instance, a second PostgreSQL 16
container holding a copy of the source's cluster answers at the restored endpoint
under the source's authority, and ``restore-verify`` runs its reconcile and proof
jobs there through the same fakes. As for every job, the canary builds their
connection itself (the restored endpoint, the stand-in's own logins); the restore
bundles' endpoint, logins and database are what the kit checks and stores in moto,
not what the jobs read. The releases root's restore plans are the same
mocked plans over the state the earlier applies left: a resource the applied plan
rendered identically is unchanged, one it did not render is created and one it
rendered that is gone is destroyed.

No AWS request is made: every connection the kit or the CLI opens is to loopback.
"""

from __future__ import annotations

import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import threading
from typing import Any
from urllib.parse import urlparse

import pytest

from release_cli import main as cli
from release_cli.clients import client_config, isolated_session
from release_cli.clock import MonotonicUtcClock
from release_kits import aws_07b, aws_08a, render
from release_kits.images import digest_of
from release_kits.terraform import VERSION, restore_address
from release_tools.receipt import RECEIPT_MARKER
from tests import release_kit_fixtures as fx
from tests.release_canary import _images, loopback_only, normalized, save, stored
from tests.release_canary_stack import CanaryAws, CanaryEcs, CanaryEnvironment, TaskDefinitions

MOTO = os.environ.get("KIT_MOTO_ENDPOINT", "")
TERRAFORM = os.environ.get("KIT_TERRAFORM", "")
PLUGINS = os.environ.get("KIT_TERRAFORM_PLUGIN_DIR", "")
RUNTIME_CHECKOUT = os.environ.get("KIT_RUNTIME_CHECKOUT", "")
ARTIFACTS = os.environ.get("CANARY_ARTIFACTS", "")
REPO = Path(__file__).resolve().parents[1]
OPERATOR = "fixture-operator"
ISSUER = "arn:aws:iam::111122223333:role/release-issuer"
TARGETS = {"InitiateLayerUpload", "UploadLayerPart", "CompleteLayerUpload",
           "BatchCheckLayerAvailability", "PutImage"}  # fmt: skip
CHANGE = re.compile(r"^\s*# (\S+) (will be created|will be read during apply|will be updated "
                    r"in-place|will be destroyed|must be replaced)", re.M)  # fmt: skip
ACTIONS = {"will be created": ["create"], "will be read during apply": ["read"],
           "will be updated in-place": ["update"], "will be destroyed": ["delete"],
           "must be replaced": ["delete", "create"]}  # fmt: skip
SUMMARY = re.compile(r"^\s*(?:Plan: |No changes\.|Changes to Outputs:)", re.M)


def planned(text: str) -> dict[str, tuple[list[str], str]]:
    """Each resource a plan rendering names: its actions and its rendered block."""
    marks = list(CHANGE.finditer(text))
    found = {}
    for index, mark in enumerate(marks):
        end = marks[index + 1].start() if index + 1 < len(marks) else len(text)
        block = SUMMARY.split(text[mark.end() : end], maxsplit=1)[0]
        found[mark.group(1)] = (ACTIONS[mark.group(2)], block.strip())
    return found


def admin(service: str) -> Any:
    """The rehearsal's own moto client: the stand-in for applies, never the kit's."""
    config = client_config()
    if service == "s3":
        from botocore.config import Config

        config = config.merge(
            Config(s3={**(getattr(config, "s3", None) or {}), "addressing_style": "path"})
        )
    return isolated_session().create_client(
        service, region_name="us-east-1", endpoint_url=MOTO, aws_access_key_id="rehearsal",
        aws_secret_access_key="rehearsal", aws_session_token="rehearsal", config=config)  # fmt: skip


# The ECR layer shim ---------------------------------------------------------------------


class LayerShim:
    """ECR's layer upload in front of moto; every other request goes to moto unchanged."""

    def __init__(self, upstream: str) -> None:
        parsed = urlparse(upstream)
        self.upstream = (str(parsed.hostname), int(parsed.port or 80))
        self.blobs: dict[tuple[str, str], bytes] = {}
        self.uploads: dict[str, tuple[str, bytearray]] = {}
        self.calls: list[str] = []
        shim = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                target = (self.headers.get("X-Amz-Target") or "").rsplit(".", 1)[-1]
                shim.calls.append(target)
                if target in TARGETS:
                    status, answer = shim.answer(target, json.loads(body or b"{}"))
                    if answer is not None:
                        self.reply(status, json.dumps(answer).encode(),
                                   "application/x-amz-json-1.1")  # fmt: skip
                        return
                self.forward(body)

            def forward(self, body: bytes) -> None:
                connection = http.client.HTTPConnection(*shim.upstream, timeout=30)
                headers = {k: v for k, v in self.headers.items() if k.lower() != "host"}
                connection.request(self.command, self.path, body=body, headers=headers)
                response = connection.getresponse()
                self.reply(response.status, response.read(),
                           response.getheader("Content-Type") or "application/json")  # fmt: skip

            def reply(self, status: int, data: bytes, kind: str) -> None:
                self.send_response(status)
                self.send_header("Content-Type", kind)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, format: str, *args: Any) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.endpoint = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def answer(self, target: str, request: dict[str, Any]) -> tuple[int, Any]:
        repository = request.get("repositoryName", "")
        if target == "BatchCheckLayerAvailability":
            found = [d for d in request["layerDigests"] if (repository, d) in self.blobs]
            return 200, {
                "layers": [{"layerDigest": d, "layerAvailability": "AVAILABLE",
                            "layerSize": len(self.blobs[(repository, d)])} for d in found],
                "failures": [{"layerDigest": d, "failureCode": "MissingLayerDigest",
                              "failureReason": "not found"}
                             for d in request["layerDigests"] if d not in found],
            }  # fmt: skip
        if target == "InitiateLayerUpload":
            upload = hashlib.sha256(os.urandom(16)).hexdigest()
            self.uploads[upload] = (repository, bytearray())
            return 200, {"uploadId": upload, "partSize": 20 * 1024 * 1024}
        if target == "UploadLayerPart":
            owner, data = self.uploads[request["uploadId"]]
            import base64

            part = base64.b64decode(request["layerPartBlob"])
            if owner != repository or request["partFirstByte"] != len(data):
                return 400, {"__type": "InvalidLayerPartException", "message": "out of order"}
            data.extend(part)
            return 200, {"uploadId": request["uploadId"], "lastByteReceived": len(data) - 1,
                         "registryId": request.get("registryId"),
                         "repositoryName": repository}  # fmt: skip
        if target == "CompleteLayerUpload":
            owner, data = self.uploads.pop(request["uploadId"])
            (wanted,) = request["layerDigests"]
            if digest_of(bytes(data)) != wanted:
                return 400, {"__type": "LayerDigestMismatchException", "message": "digest"}
            self.blobs[(repository, wanted)] = bytes(data)
            return 200, {"uploadId": request["uploadId"], "layerDigest": wanted,
                         "registryId": request.get("registryId"),
                         "repositoryName": repository}  # fmt: skip
        # PutImage: ECR's own checks, then moto stores the image.
        manifest = request["imageManifest"]
        if request.get("imageDigest") != digest_of(manifest.encode()):
            return 400, {"__type": "ImageDigestDoesNotMatchException", "message": "digest"}
        document = json.loads(manifest)
        needed = [document["config"]["digest"], *(item["digest"] for item in document["layers"])]
        if any((repository, name) not in self.blobs for name in needed):
            return 400, {"__type": "LayersNotFoundException", "message": "missing layers"}
        return 200, None

    def close(self) -> None:
        self.server.shutdown()


# Terraform's plan half ------------------------------------------------------------------


class MockedTerraform:
    """Each root's plan with the mocked provider, in a copy of deploy/ with no tests."""

    def __init__(self, root: Path) -> None:
        self.copy = root / "deploy"
        shutil.copytree(REPO / "deploy", self.copy,
                        ignore=shutil.ignore_patterns(".terraform", "tests", "aws-07b"))  # fmt: skip
        self.runs: list[dict[str, Any]] = []

    def directory(self, root: str) -> Path:
        return self.copy / "aws-staging" / root

    def call(self, root: str, args: list[str], data: Path) -> subprocess.CompletedProcess:
        environment = {"HOME": str(data.parent), "PATH": "/usr/bin:/bin", "TF_IN_AUTOMATION": "1",
                       "CHECKPOINT_DISABLE": "1", "TF_DATA_DIR": str(data)}  # fmt: skip
        result = subprocess.run([TERRAFORM, *args], cwd=self.directory(root), env=environment,
                                text=True, capture_output=True, timeout=900)  # fmt: skip
        self.runs.append({"root": root, "args": args, "exit": result.returncode})
        return result


class RehearsalKit(aws_07b.Kit):
    rehearsal = True

    def __init__(self, *args: Any, world: dict[str, Any], **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.world = world

    # Clients: moto, with ECR through the layer shim.
    def endpoint(self) -> str | None:
        return MOTO

    def clients(self, session, service):
        from release_kits import session as sessions

        endpoint = self.world["shim"].endpoint if service == "ecr" else MOTO
        moved = sessions.Session(session.credentials, session.path, endpoint)
        return sessions.client(moved, service, self.plan.region)

    def schemas(self, sources, runtime_checkout):
        return super().schemas(sources, Path(RUNTIME_CHECKOUT))

    # Terraform: the mocked plan; the apply is a stand-in.
    def terraform_directory(self, root):
        return self.world["terraform"].directory(root)

    def terraform(self, run, args, session):
        mocked: MockedTerraform = self.world["terraform"]
        data = self.work / "terraform" / run.root
        data.mkdir(parents=True, exist_ok=True, mode=0o700)
        verb = args[0]
        if verb == "init":
            result = mocked.call(run.root, ["init", "-backend=false", "-input=false",
                                            "-lockfile=readonly", f"-plugin-dir={PLUGINS}",
                                            "-no-color"], data)  # fmt: skip
        elif verb == "plan":
            tests = mocked.directory(run.root) / "kit-rehearsal"
            tests.mkdir(exist_ok=True)
            (tests / "plan.tftest.hcl").write_text(
                'mock_provider "aws" {}\nrun "kit_plan" {\n  command = plan\n}\n'
            )
            result = mocked.call(run.root, ["test", "-no-color", "-verbose",
                                            "-test-directory=kit-rehearsal",
                                            *(f"-var-file={path}" for path in run.var_files)],
                                 data)  # fmt: skip
            if result.returncode == 0:
                Path(run.plan_file).write_text(result.stdout)
        elif verb == "show":
            text = Path(run.plan_file).read_text()
            variables: dict[str, Any] = {}
            for path in run.var_files:
                variables.update(json.loads(Path(path).read_text()))
            changes = [{"address": address, "change": {"actions": actions}}
                       for address, actions in self.changes(run.root, text)]  # fmt: skip
            document = {"terraform_version": VERSION, "rehearsal": "mocked provider",
                        "variables": {k: {"value": v} for k, v in variables.items()},
                        "resource_changes": changes}  # fmt: skip
            return subprocess.CompletedProcess(args, 0, json.dumps(document), "")
        else:
            raise AssertionError(f"terraform {verb} is never run in the rehearsal")
        return result

    def changes(self, root: str, text: str) -> list[tuple[str, list[str]]]:
        """The plan's changes against the state the root's last applied plan left.

        The mocked plan has no state, so it renders every resource as created. Once a
        plan of the root was applied, a resource it rendered with the same block is
        unchanged, a differently rendered one is updated, a new one is created and
        one it rendered that this plan does not is destroyed.
        """
        found = planned(text)
        state = self.world.setdefault("state", {}).get(root)
        if state is None:
            return [(address, actions) for address, (actions, _) in found.items()]
        changes = []
        for address, (actions, block) in found.items():
            if actions != ["read"] and address in state:
                actions = ["no-op"] if state[address] == block else ["update"]
            changes.append((address, actions))
        return changes + [(address, ["delete"]) for address in state if address not in found]

    def terraform_binary(self):
        return TERRAFORM

    def extra_outputs(self, step):
        return {**super().extra_outputs(step), "apply": "not rehearsed: stand-in outputs",
                "plan_document": "synthesized from the mocked provider's plan rendering"}  # fmt: skip

    def terraform_apply(self, step, run, session):
        """Not rehearsed: the stand-in outputs, and moto gets what later steps call."""
        outputs = self.world["apply"](run.root, run)
        self.world.setdefault("applied", []).append(run.root)
        # The state an apply of this plan leaves: every resource it rendered.
        self.world.setdefault("state", {})[run.root] = {
            address: block for address, (actions, block) in planned(
                Path(run.plan_file).read_text()).items() if actions != ["read"]}  # fmt: skip
        return outputs

    # The release CLI: in process, through the canary fakes.
    def release_cli(self, args):
        out = io.StringIO()
        if args[0] == "validate":
            code = cli.main(args, out=out, environ={})
            return code, json.loads(out.getvalue())
        canary = self.world["canary"](args)
        with loopback_only() as attempts:
            code = cli.main(args, clients=canary["clients"], clock_factory=MonotonicUtcClock,
                            tokens=canary["tokens"], session_ids=lambda: "rehearsal-session",
                            out=out, environ={})  # fmt: skip
        assert not attempts, f"the CLI reached beyond loopback: {attempts}"
        report = json.loads(out.getvalue())
        canary["outputs"].append(report)
        return code, report


# The rehearsal --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def rehearsal(request):
    if not (MOTO and TERRAFORM and PLUGINS and RUNTIME_CHECKOUT):
        pytest.fail("KIT_MOTO_ENDPOINT, KIT_TERRAFORM, KIT_TERRAFORM_PLUGIN_DIR and "
                    "KIT_RUNTIME_CHECKOUT are required")  # fmt: skip
    images, bindings = _images()
    with tempfile.TemporaryDirectory(prefix="aws-07b-rehearsal-") as directory:
        root = Path(directory).resolve()
        root.chmod(0o755)
        env = CanaryEnvironment(root / "canary", images, label="kit")
        (root / "canary").mkdir()
        shim = LayerShim(MOTO)
        try:
            env.start()
            yield root, env, bindings, shim
        finally:
            shim.close()
            env.stop()


@dataclass
class Chain:
    """The rehearsed chain the module's tests continue: init and every step, once."""

    root: Path
    env: CanaryEnvironment
    bound: dict[str, Any]
    shim: LayerShim
    plan: Any
    kit: RehearsalKit
    world: dict[str, Any]
    canary: dict[str, Any]
    issuer: Any
    custody: Path
    deployer: Path
    typed: list[str]
    out: io.StringIO
    # The roots applied by the chain's own steps, before any later test applies more.
    applied: list[str]
    # Each restore outcome's AWS-08a pitr-restore verdict, kept with the evidence.
    verdicts: list[dict[str, Any]] = field(default_factory=list)


@pytest.fixture(scope="module")
def chain(rehearsal) -> Chain:
    root, env, bound, shim = rehearsal
    (root / "account").mkdir()
    plan_dir, plan_hash = fx.account_plan(root / "account")
    from release_kits.plan import load_plan

    plan = load_plan(plan_dir, plan_hash)
    bindings_path = Path(os.environ["CANARY_IMAGE_BINDINGS"])
    risk = fx.risk_decision(root / "risk.json", {
        "runtime": bound["runtime"]["platform_manifest"],
        "search": bound["search"]["platform_manifest"],
        "release_tools": bound["release-tools"]["platform_manifest"],
    }, decision_id="rehearsal-only-not-a-decision")  # fmt: skip
    custody = root / "custody"
    custody.mkdir(mode=0o700)
    fx.custodian_files(custody, render.BUNDLES)
    issuer = admin("sts")
    iam = admin("iam")
    deployer_role = iam.create_role(RoleName="rehearsal-deployer", AssumeRolePolicyDocument="{}")
    deployer = write_session(
        custody / "deployer.json",
        issuer.assume_role(
            RoleArn=deployer_role["Role"]["Arn"], RoleSessionName=OPERATOR, DurationSeconds=21600
        ),
    )
    world: dict[str, Any] = {"shim": shim, "terraform": MockedTerraform(root / "terraform")}
    rendered: dict[str, Any] = {}

    def apply(name: str, run) -> dict[str, Any]:
        if name == "bootstrap":
            s3 = admin("s3")
            bucket = render.control_bucket(plan)
            s3.create_bucket(Bucket=bucket)
            s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
            for policy in (
                "release-evidence",
                *(f"state-{r}" for r in ("bootstrap", "foundation", "releases", "services")),
            ):
                iam.create_policy(PolicyName=f"{plan.name_prefix}-{policy}",
                                  PolicyDocument=STAND_IN_POLICY)  # fmt: skip
            iam.create_role(RoleName=f"{plan.name_prefix}-operator",
                            AssumeRolePolicyDocument=json.dumps({"Statement": [
                                {"Effect": "Allow", "Principal": {"AWS": ISSUER},
                                 "Action": "sts:AssumeRole"}]}))  # fmt: skip
            return fx.bootstrap_outputs(plan)
        if name == "foundation":
            ecr = admin("ecr")
            for repository in render.repositories(plan).values():
                ecr.create_repository(repositoryName=repository, imageTagMutability="IMMUTABLE")
            secrets = admin("secretsmanager")
            arns = {}
            for database in render.DATABASES:
                made = secrets.create_secret(
                    Name=f"rds!db-{fx.sha(database)[:8]}-{fx.sha(database)[8:12]}-"
                         f"4{fx.sha(database)[13:16]}-8{fx.sha(database)[17:20]}-"
                         f"{fx.sha(database)[20:32]}",
                    SecretString=json.dumps({"username": f"{database}_admin",
                                             "password": "rehearsal-placeholder"}))  # fmt: skip
                arns[database] = made["ARN"]
            return fx.foundation_outputs(plan, arns)
        if name == "releases":
            values = json.loads(Path(run.var_files[-1]).read_text())
            label = Path(run.plan_file).name
            if label.endswith(("-restore-add.tfplan", "-restore-remove.tfplan")):
                return restore_apply(values, adding=label.endswith("-restore-add.tfplan"))
            rendered.update(values)
            for policy in ("jobs", "services", "receipts", "tasks", "observe", "bootstrap"):
                iam.create_policy(PolicyName=f"{plan.name_prefix}-release-launcher-{policy}",
                                  PolicyDocument=STAND_IN_POLICY)  # fmt: skip
            return fx.releases_outputs(plan, values)
        return fx.services_outputs(plan)

    added = {"entries": 0}

    def restore_apply(values: dict[str, Any], *, adding: bool) -> dict[str, Any]:
        """A verification's entry added (its launcher document, new revisions) or removed."""
        launcher = render.policy_arn(plan, f"{plan.name_prefix}-release-launcher-restore")
        if not adding:
            if iam.get_policy(PolicyArn=launcher)["Policy"].get("AttachmentCount"):
                raise AssertionError("IAM refuses to delete a policy that is still attached")
            iam.delete_policy(PolicyArn=launcher)
            return fx.releases_outputs(plan, values)
        added["entries"] += 1
        iam.create_policy(PolicyName=launcher.rsplit("/", 1)[1], PolicyDocument=STAND_IN_POLICY)
        outputs = fx.releases_outputs(plan, values)
        for entry in outputs["restore_verifications"].values():
            for job in entry["jobs"].values():
                # Each entry registers the two restore families' next revisions.
                family = job["task_definition"].rsplit(":", 1)[0]
                job["task_definition"] = f"{family}:{added['entries']}"
        return outputs

    world["apply"] = apply
    canary_state: dict[str, Any] = {}

    def canary(args: list[str]) -> dict[str, Any]:
        manifest = json.loads(Path(args[args.index("--manifest") + 1]).read_text())
        if not canary_state:
            tools = rendered["releases"][render.release_key(manifest["release_id"])]
            not_after = moment(tools["release_tools"]["not_after"])
            definitions = TaskDefinitions(env)
            definitions.register(manifest, not_after=not_after,
                                 budget_seconds=render.TOOLS_BUDGET_SECONDS)  # fmt: skip
            ecs = CanaryEcs(env, definitions)
            ecs.configure(manifest)
            aws = CanaryAws(ecs, manifest)
            counter = {"n": 0}

            def tokens() -> str:
                counter["n"] += 1
                return f"kit{manifest['release_id'][:8]}{counter['n']:04d}" + "0" * 21

            class Clients:
                def __init__(self, credentials, region) -> None:
                    from release_kits import session as sessions

                    self.session = sessions.Session(credentials, Path("/unused"), MOTO)

                def client(self, service: str):
                    from release_kits import session as sessions
                    from release_cli.clients import AwsClients

                    if service in ("s3", "sts"):
                        return sessions.client(self.session, service, "us-east-1")
                    real = AwsClients(self.session.credentials, "us-east-1").client(service)
                    return aws.bridge.attach(real)

            canary_state.update(manifest=manifest, ecs=ecs, aws=aws, clients=Clients,
                                tokens=tokens, outputs=[], learned=set())  # fmt: skip
        purpose = manifest.get("purpose") or {}
        if (purpose.get("kind") == "restore_verify"
                and purpose["verification_id"] not in canary_state["learned"]):  # fmt: skip
            # A verification's two new revisions under its own deadline, in the same
            # environment: the release's tasks, streams and receipts carry on.
            ecs = canary_state["ecs"]
            ecs.definitions.register_restore(manifest, not_after=moment(purpose["not_after"]),
                                             budget_seconds=render.TOOLS_BUDGET_SECONDS)  # fmt: skip
            ecs.learn(manifest)
            canary_state["aws"].documents.append(manifest)
            canary_state["learned"].add(purpose["verification_id"])
        return canary_state

    world["canary"] = canary
    typed: list[str] = []
    out = io.StringIO()
    kit = RehearsalKit(plan, root / "work", world=world, out=out,
                       prompt=lambda _text: typed.pop(0))  # fmt: skip
    typed.append("init")
    assert kit.init(bindings_path=bindings_path, risk_path=risk,
                    runtime_checkout=Path(RUNTIME_CHECKOUT), terraform=Path(TERRAFORM)) == 0, (
        out.getvalue())  # fmt: skip
    operator_path = custody / "operator.json"
    for item in aws_07b.STEPS:
        options: dict[str, Any] = {}
        if item.session == "deployer":
            options["session_path"] = str(deployer)
        if item.id == "session":
            # The custodian's step: a moto STS session of the operator role.
            write_session(operator_path, issuer.assume_role(
                RoleArn=plan.skeleton["operator_role"], RoleSessionName=OPERATOR,
                SourceIdentity=OPERATOR, DurationSeconds=14400))  # fmt: skip
        if item.session == "operator":
            options["session_path"] = str(operator_path)
        if item.id == "custodian":
            options["custodian"] = custody
        typed.extend([item.id, item.id] if item.root else [item.id])
        code = kit.run_step(item.id, chain_head=kit.ledger.head()[1], **options)
        assert code == 0, out.getvalue()[-6000:]
    return Chain(root=root, env=env, bound=bound, shim=shim, plan=plan, kit=kit, world=world,
                 canary=canary_state, issuer=issuer, custody=custody, deployer=deployer,
                 typed=typed, out=out, applied=list(world["applied"]))  # fmt: skip


def test_the_aws_07b_kit_rehearses_every_step_to_held_paused(chain):
    kit, world, shim, bound = chain.kit, chain.world, chain.shim, chain.bound
    done = kit.receipts()
    assert done["run"]["outputs"]["run"]["state"] == "held_paused"
    assert done["run"]["outputs"]["status"]["lock"] is None, "the lock is released"
    assert chain.applied == ["bootstrap", "foundation", "releases", "services"]
    assert {"InitiateLayerUpload", "CompleteLayerUpload", "PutImage"} <= set(shim.calls)
    pushed = done["images"]["outputs"]["registry_digests"]
    assert pushed == {key: bound[name]["platform_manifest"]
                      for key, name in aws_07b.IMAGE_NAMES.items()}  # fmt: skip
    assert done["detach"]["outputs"]["remaining"] == []
    record(chain.root, kit, world, chain.canary, chain.out)


STAND_IN_POLICY = json.dumps({"Version": "2012-10-17", "Statement": [
    {"Effect": "Deny", "Action": "*", "Resource": "*"}]})  # fmt: skip


def write_session(path: Path, answer: dict[str, Any]) -> Path:
    credentials = answer["Credentials"]
    if path.exists():
        path.chmod(0o600)
        path.unlink()
    path.write_text(json.dumps({
        "schema": "sentry.operator-session.v1",
        "access_key_id": credentials["AccessKeyId"],
        "secret_access_key": credentials["SecretAccessKey"],
        "session_token": credentials["SessionToken"],
        "expires_at": credentials["Expiration"].strftime("%Y-%m-%dT%H:%M:%SZ"),
        "session_name": OPERATOR,
    }))  # fmt: skip
    path.chmod(0o400)
    return path


def record(root: Path, kit: RehearsalKit, world: dict[str, Any], canary: dict[str, Any],
           out: io.StringIO) -> None:  # fmt: skip
    """Keep the rehearsal's receipts, logs and the release's evidence beside the canary's."""
    if not ARTIFACTS:
        return
    target = Path(ARTIFACTS) / "aws-07b-rehearsal"
    target.mkdir(parents=True, exist_ok=True)
    shutil.copytree(kit.work / "receipts", target / "receipts")
    shutil.copytree(kit.work / "rendered", target / "rendered")
    (target / "terraform-runs.json").write_text(json.dumps(world["terraform"].runs, indent=1))
    (target / "shim-calls.json").write_text(json.dumps(world["shim"].calls, indent=1))
    (target / "kit-output.txt").write_text(out.getvalue())

    class Saved:
        document = canary["manifest"]
        ecs = canary["ecs"]
        outputs = canary["outputs"]
        root = Path(kit.receipts()["validate"]["outputs"]["manifest"]).parent

    for name in ("manifest", "approval"):
        source = Path(kit.receipts()["validate"]["outputs"][name])
        (Saved.root / f"{name}.json").write_bytes(source.read_bytes())
    save(Saved, "aws-07b-rehearsal")  # ty: ignore[invalid-argument-type]


def moment(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=aws_07b.UTC)


# The restore-verify leg (section 8) ------------------------------------------------------

# A migration the release never applied, recorded in the restored database only.
SEEDED_VERSION = 99999999999999


def test_the_aws_07b_kit_verifies_a_restored_database_with_its_own_jobs(chain, request):
    """restore, then restore-verify's outcomes against the restored stand-in.

    A verified run passes the AWS-08a pitr-restore case. A bundle naming the source
    host and an expired approval are refused before any write. A proof receipt that
    never reaches its stream, another recorded migration and an extra grant to the
    service login each end restore_unverified, and the 08a case fails on each.
    """
    kit, plan, env, world = chain.kit, chain.plan, chain.env, chain.world
    database = env.databases["runtime"]
    source = source_instance(plan)
    target = f"{plan.name_prefix}-runtime-db-restore-rehearsal"
    chain.typed.append("restore")
    restore = approval(chain, aws_07b.RESTORE_SCHEMA, database="runtime",
                       target_identifier=target, restore_time="latest")  # fmt: skip
    assert kit.restore(chain_head=kit.ledger.head()[1], session_path=str(chain.deployer),
                       approval_path=restore) == 0, chain.out.getvalue()[-6000:]  # fmt: skip
    instances = {item["DBInstanceIdentifier"]: item
                 for item in admin("rds").describe_db_instances()["DBInstances"]}  # fmt: skip
    endpoint = instances[target]["Endpoint"]["Address"]
    assert endpoint.startswith(f"{target}.") and endpoint != source
    container = env.restored_database("runtime", endpoint)
    # The evidence is kept whether the leg passes or fails.
    request.addfinalizer(lambda: record_restore(
        chain, container, instances=(f"{plan.name_prefix}-runtime-db", target)))  # fmt: skip
    alone = judged(chain)
    chain.verdicts.append({"outcome": "restore without a verification", **alone})
    assert alone["ok"] is False and alone["observed"]["verification"] == "missing"
    operator = write_session(chain.custody / "restore-operator.json", chain.issuer.assume_role(
        RoleArn=plan.skeleton["operator_role"], RoleSessionName=OPERATOR,
        SourceIdentity=OPERATOR, DurationSeconds=14400))  # fmt: skip
    custody = restore_custody(chain.root / "restore-custody", endpoint, database)

    # Refused before any write: a bundle naming the source host, an expired approval.
    before = writes(chain)
    with pytest.raises(aws_07b.Refused, match="another host than the restored endpoint"):
        verify(chain, verify_approval(chain, target),
               restore_custody(chain.root / "source-custody", source, database), operator,
               typed=0)  # fmt: skip
    expired = render.iso(datetime.now(aws_07b.UTC) - timedelta(minutes=1))
    with pytest.raises(aws_07b.Refused, match="expired"):
        verify(chain, verify_approval(chain, target, not_after=expired), custody, operator,
               typed=0)  # fmt: skip
    assert writes(chain) == before and chain.typed == []

    # Verified: both jobs ran on the restored instance; the entry was removed again.
    assert (
        verify(chain, verify_approval(chain, target), custody, operator) == 0
    ), chain.out.getvalue()[-6000:]
    receipt = kit.receipts()["restore-verify"]["outputs"]
    assert receipt["kind"] == "restore_verified" and receipt["run_state"] == "restore_verified"
    assert receipt["hosts"] == {"runtime-rv-recon": endpoint, "runtime-rv-proof": endpoint}
    assert receipt["foreign_sessions"] == "0"
    jobs = job_receipts(chain, receipt)
    assert {job: body["status"] for job, body in jobs.items()} == {
        "runtime-rv-recon": "succeeded", "runtime-rv-proof": "succeeded"}  # fmt: skip
    assert {body["result"]["host"] for body in jobs.values()} == {endpoint}
    assert jobs["runtime-rv-recon"]["result"]["foreign_sessions"] == "0"
    assert jobs["runtime-rv-proof"]["result"]["sql_digest"] == receipt["sql_digest"]
    sessions = [f"release:{jobs[job]['release_id']}:{job}" for job in jobs]
    restored_log, source_log = env.logs(container), env.logs(env.database_container("runtime"))
    assert all(name in restored_log and name not in source_log for name in sessions)
    assert receipt["status"]["lock"] is None
    removed(chain)
    assert latest_verdict(chain, "verified") is True

    # The proof's receipt never reaches its stream: held at the job's deadline.
    aws = chain.canary["aws"]
    aws.suppressed.add("runtime-rv-proof")
    try:
        held = unverified(chain, target, custody, operator)
    finally:
        aws.suppressed.clear()
    assert held["run_reason"] == "job_deadline_exceeded"
    assert (
        job_receipts(chain, held)["runtime-rv-proof"]["status"] == "succeeded"
    ), "the job proved; only its receipt was lost"
    assert latest_verdict(chain, "proof receipt lost") is False

    # Another migration recorded in the restored database: the proof reads another schema.
    env.sql(container, database.name, "INSERT INTO public.goose_db_version "
            f"(version_id, is_applied) VALUES ({SEEDED_VERSION}, true)")  # fmt: skip
    held = unverified(chain, target, custody, operator)
    env.sql(container, database.name,
            f"DELETE FROM public.goose_db_version WHERE version_id = {SEEDED_VERSION}")  # fmt: skip
    assert held["run_reason"] == "job_receipt_mismatch"
    jobs = job_receipts(chain, held)
    # The reconcile reads the schema first; the hold stops the run before the proof.
    assert jobs["runtime-rv-recon"]["result"]["schema"] == f"{held['schema']},{SEEDED_VERSION}"
    assert "runtime-rv-proof" not in jobs
    assert latest_verdict(chain, "another recorded migration") is False

    # An extra grant to the service login: the proof fails its privilege inventory.
    errors = server_errors(env, container)
    env.sql(container, database.name, f"GRANT INSERT ON public.runtime_runs TO {database.service}")
    held = unverified(chain, target, custody, operator)
    env.sql(container, database.name,
            f"REVOKE INSERT ON public.runtime_runs FROM {database.service}")  # fmt: skip
    proof = job_receipts(chain, held)["runtime-rv-proof"]
    assert proof["status"] == "failed"
    assert proof["result"]["reason"] == "privilege_inventory_mismatch"
    # RT101-RT109 share that reason: the server's own log names RT105's check, and
    # never RT104's (database or schema privileges), which the cluster copy preserves.
    raised = [line for line in server_errors(env, container)[len(errors) :]
              if "runtime-rv-proof" in line]  # fmt: skip
    assert raised and all("table privileges differ" in line for line in raised)
    assert not any("database or schema privileges differ" in line
                   for line in server_errors(env, container))  # fmt: skip
    assert latest_verdict(chain, "extra grant to the service login") is False


def source_instance(plan) -> str:
    """The runtime database as the account holds it: a moto RDS instance in a VPC."""
    ec2, rds = admin("ec2"), admin("rds")
    vpc = ec2.create_vpc(CidrBlock="10.40.0.0/16")["Vpc"]["VpcId"]
    subnets = [ec2.create_subnet(VpcId=vpc, CidrBlock=f"10.40.{index}.0/24",
                                 AvailabilityZone=f"{plan.region}{zone}")["Subnet"]["SubnetId"]
               for index, zone in ((1, "a"), (2, "b"))]  # fmt: skip
    group = ec2.create_security_group(GroupName=f"{plan.name_prefix}-runtime-db", VpcId=vpc,
                                      Description="rehearsal stand-in")["GroupId"]  # fmt: skip
    rds.create_db_subnet_group(DBSubnetGroupName=f"{plan.name_prefix}-db", SubnetIds=subnets,
                               DBSubnetGroupDescription="rehearsal stand-in")  # fmt: skip
    created = rds.create_db_instance(
        DBInstanceIdentifier=f"{plan.name_prefix}-runtime-db", Engine="postgres",
        EngineVersion="16.4", DBInstanceClass="db.t4g.micro", AllocatedStorage=20,
        MasterUsername="runtime_admin", MasterUserPassword="rehearsal-placeholder",
        DBSubnetGroupName=f"{plan.name_prefix}-db", VpcSecurityGroupIds=[group],
        BackupRetentionPeriod=7, DeletionProtection=True,
    )  # fmt: skip
    return created["DBInstance"]["Endpoint"]["Address"]


def approval(chain: Chain, schema: str, **fields: Any) -> Path:
    """A section 8 approval of the operator's, for this plan and the chain's head."""
    directory = chain.root / "approvals"
    directory.mkdir(exist_ok=True)
    path = directory / f"{len(list(directory.iterdir())):03d}-{schema}.json"
    not_after = render.iso(datetime.now(aws_07b.UTC) + timedelta(hours=6))
    path.write_text(json.dumps({"schema": schema, "plan_sha256": chain.plan.plan_sha256,
                                "chain_head_sha256": chain.kit.ledger.head()[1],
                                "approved_by": chain.plan.operator, "not_after": not_after,
                                **fields}))  # fmt: skip
    return path


def verify_approval(chain: Chain, target: str, **changes: Any) -> Path:
    return approval(chain, aws_07b.RESTORE_VERIFY_SCHEMA, database="runtime",
                    target_identifier=target, **changes)  # fmt: skip


def restore_custody(directory: Path, host: str, database: Any) -> Path:
    """The custodian's two restore bundles for the runtime database at ``host``.

    The jobs connect with the stand-in's own logins; the kit checks each bundle's
    endpoint, login and database and stores it in moto.
    """
    for purpose, login in zip(render.RESTORE_BUNDLES, (database.owner, database.service)):
        path = directory / purpose / "runtime.json"
        path.parent.mkdir(parents=True)
        url = (f"postgresql://{login}:placeholder-{fx.sha(purpose)[:16]}@{host}:5432/"
               f"{database.name}?sslmode=verify-full&sslrootcert=/run/material/postgres-ca.pem")  # fmt: skip
        path.write_text(json.dumps({"DATABASE_URL": url}))
        path.chmod(0o400)
    directory.chmod(0o700)
    return directory


def verify(chain: Chain, approval_path: Path, custody: Path, operator: Path, *,
           typed: int = 3) -> int:  # fmt: skip
    """restore-verify as the operator runs it, typing the step for each confirmation."""
    chain.typed.extend(["restore-verify"] * typed)
    code = chain.kit.restore_verify(chain_head=chain.kit.ledger.head()[1],
                                    session_path=str(chain.deployer),
                                    operator_session_path=str(operator),
                                    approval_path=approval_path, custodian=custody)  # fmt: skip
    assert chain.typed == [], "every confirmation was asked"
    return code


def unverified(chain: Chain, target: str, custody: Path, operator: Path) -> dict[str, Any]:
    """A verification that ends held as restore_unverified, detached and removed."""
    code = verify(chain, verify_approval(chain, target), custody, operator)
    _, document, _ = chain.kit.ledger.receipts()[-1]
    assert (code, document["step"], document["result"]) == (
        aws_07b.EXIT_FAILED, "restore-verify", "held"), chain.out.getvalue()[-6000:]  # fmt: skip
    outputs = document["outputs"]
    assert outputs["kind"] == "restore_unverified" and outputs["verified"] is False
    assert outputs["status"]["lock"] is None, "a held verification releases its lock"
    removed(chain)
    return outputs


def removed(chain: Chain) -> None:
    """The attended set is detached and the entry is gone from the releases state."""
    role = f"{chain.plan.name_prefix}-operator"
    assert admin("iam").list_attached_role_policies(RoleName=role)["AttachedPolicies"] == []
    assert not [address for address in chain.world["state"]["releases"]
                if restore_address(address)]  # fmt: skip


def writes(chain: Chain) -> tuple[Any, ...]:
    """What a refused verification leaves exactly as it was."""
    secrets = admin("secretsmanager").list_secrets()["SecretList"]
    role = f"{chain.plan.name_prefix}-operator"
    attached = admin("iam").list_attached_role_policies(RoleName=role)["AttachedPolicies"]
    return (sorted((item["Name"], sorted(item.get("SecretVersionsToStages") or {}))
                   for item in secrets),
            sorted(item["PolicyArn"] for item in attached),
            len(chain.world["terraform"].runs), len(chain.kit.ledger.receipts()),
            len(chain.canary["outputs"]))  # fmt: skip


def job_receipts(chain: Chain, outputs: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """The receipt each of a verification's jobs printed, from its task's own output."""
    manifest = json.loads(Path(outputs["manifest"]).read_text())
    definitions = {job["task"]["task_definition"]: job["id"] for job in manifest["jobs"]}
    ecs = chain.canary["ecs"]
    found: dict[str, dict[str, Any]] = {}
    for task in ecs.tasks.values():
        job = definitions.get(task.task_definition)
        if job is None:
            continue
        for _, line in ecs.lines(task):
            if line.startswith(RECEIPT_MARKER + " "):
                found[job] = json.loads(line[len(RECEIPT_MARKER) + 1 :])
    return found


def latest_verdict(chain: Chain, outcome: str) -> bool:
    """The 08a case's verdict, judged on the chain's latest receipt (a verification)."""
    verdict = judged(chain)
    chain.verdicts.append({"outcome": outcome, **verdict})
    _, latest, _ = chain.kit.ledger.receipts()[-1]
    assert verdict["observed"]["verification_sequence"] == latest["sequence"]
    return verdict["ok"]


def server_errors(env: CanaryEnvironment, container: str) -> list[str]:
    """The ERROR lines of a database container's server log, in order."""
    return [line for line in env.logs(container).splitlines() if " ERROR: " in line]


def judged(chain: Chain) -> dict[str, Any]:
    """The AWS-08a pitr-restore case over this chain, as a platform run reads it."""
    document = {"plan_sha256": chain.plan.plan_sha256,
                "aws_07b_chain_head": chain.kit.ledger.head()[1]}  # fmt: skip
    target = aws_08a.Target(chain.root / "aws-08a-target.json", document, "0" * 64)
    platform = aws_08a.Platform(target, http=None, clients=lambda _service: None,
                                prompt=lambda _text: "", aws_07b=chain.kit.work)  # fmt: skip
    return platform.run(next(case for case in aws_08a.CASES if case.id == "pitr-restore"))


def record_restore(chain: Chain, container: str, *, instances: tuple[str, ...]) -> None:
    """Keep the leg's receipts, plans, journals, task output and server logs, moto's
    view of both instances and each outcome's 08a verdict beside the rehearsal's."""
    if not ARTIFACTS:
        return
    out = Path(ARTIFACTS) / "aws-07b-rehearsal-restore"
    out.mkdir(parents=True)
    kit, env, ecs = chain.kit, chain.env, chain.canary["ecs"]
    shutil.copytree(kit.work / "receipts", out / "receipts")
    shutil.copytree(kit.work / "rendered", out / "rendered")
    (out / "terraform-runs.json").write_text(json.dumps(chain.world["terraform"].runs, indent=1))
    (out / "kit-output.txt").write_text(chain.out.getvalue())
    (out / "verdicts.json").write_text(json.dumps(chain.verdicts, indent=1))
    described = [item for item in admin("rds").describe_db_instances()["DBInstances"]
                 if item["DBInstanceIdentifier"] in instances]  # fmt: skip
    (out / "rds-instances.json").write_text(json.dumps(described, indent=1, default=str))
    logs = {"restored-server.log": env.logs(container),
            "source-server.log": env.logs(env.database_container("runtime"))}  # fmt: skip
    withheld = {}
    for file, text in logs.items():
        # A server logs a failing statement in full: never keep one that names a secret.
        leaked = [key for key, value in env.secrets.items() if value in text]
        if leaked or "SCRAM-SHA-256$" in text:
            withheld[file] = leaked or ["a password verifier"]
            continue
        (out / file).write_text(text)
    for _, document, _ in kit.ledger.receipts():
        if document["step"] != "restore-verify":
            continue
        # A failed attempt has only its partial outputs, and may have no manifest yet.
        outputs = document.get("outputs") or document.get("partial") or {}
        if "verification_id" not in outputs:
            continue
        directory = out / f"verification-{outputs['verification_id'][:8]}-{document['sequence']}"
        directory.mkdir()
        (directory / "receipt.json").write_text(json.dumps(document, indent=1))
        # The rendered manifest is in rendered/ even when a failed attempt's partial
        # outputs do not name it; its tasks are found by its jobs' definitions.
        if "manifest" in outputs:
            manifest = json.loads(Path(outputs["manifest"]).read_text())
            (directory / "manifest.json").write_text(json.dumps(manifest, indent=1))
            definitions = {job["task"]["task_definition"] for job in manifest["jobs"]}
            (directory / "task-output.json").write_text(json.dumps({
                arn.rsplit("/", 1)[1]: {"job": task.tags.get("sentry:job-id"),
                                        "definition": task.task_definition,
                                        "lines": [line for _, line in ecs.lines(task)]}
                for arn, task in ecs.tasks.items() if task.task_definition in definitions},
                indent=1))  # fmt: skip
        found = stored(f"releases/{outputs['verification_id']}/journal.json")
        if found is not None:
            raw = json.loads(found[0])
            (directory / "journal.json").write_text(json.dumps(raw, indent=1, sort_keys=True))
            (directory / "journal-normalized.json").write_text(
                json.dumps(normalized(raw), indent=1, sort_keys=True))  # fmt: skip
    # Everything else is kept first; a withheld log still fails the run.
    assert not withheld, f"server logs withheld for naming secrets: {withheld}"
