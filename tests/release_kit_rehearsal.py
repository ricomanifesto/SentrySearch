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

No AWS request is made: every connection the kit or the CLI opens is to loopback.
"""

from __future__ import annotations

import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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
from release_kits import aws_07b, render
from release_kits.images import digest_of
from release_kits.terraform import VERSION
from tests import release_kit_fixtures as fx
from tests.release_canary import _images, loopback_only, save
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
            changes = [{"address": address, "change": {"actions": ACTIONS[kind]}}
                       for address, kind in CHANGE.findall(text)]  # fmt: skip
            document = {"terraform_version": VERSION, "rehearsal": "mocked provider",
                        "variables": {k: {"value": v} for k, v in variables.items()},
                        "resource_changes": changes}  # fmt: skip
            return subprocess.CompletedProcess(args, 0, json.dumps(document), "")
        else:
            raise AssertionError(f"terraform {verb} is never run in the rehearsal")
        return result

    def terraform_binary(self):
        return TERRAFORM

    def extra_outputs(self, step):
        return {**super().extra_outputs(step), "apply": "not rehearsed: stand-in outputs",
                "plan_document": "synthesized from the mocked provider's plan rendering"}  # fmt: skip

    def terraform_apply(self, step, run, session):
        """Not rehearsed: the stand-in outputs, and moto gets what later steps call."""
        outputs = self.world["apply"](run.root, run)
        self.world.setdefault("applied", []).append(run.root)
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


@pytest.fixture
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


def test_the_aws_07b_kit_rehearses_every_step_to_held_paused(rehearsal):
    root, env, bound, shim = rehearsal
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
            rendered.update(values)
            for policy in ("jobs", "services", "receipts", "tasks", "observe", "bootstrap"):
                iam.create_policy(PolicyName=f"{plan.name_prefix}-release-launcher-{policy}",
                                  PolicyDocument=STAND_IN_POLICY)  # fmt: skip
            return fx.releases_outputs(plan, values)
        return fx.services_outputs(plan)

    world["apply"] = apply
    canary_state: dict[str, Any] = {}

    def canary(args: list[str]) -> dict[str, Any]:
        if not canary_state:
            manifest = json.loads(Path(args[args.index("--manifest") + 1]).read_text())
            tools = rendered["releases"][render.release_key(manifest["release_id"])]
            from datetime import datetime

            not_after = datetime.strptime(tools["release_tools"]["not_after"],
                                          "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=aws_07b.UTC)  # fmt: skip
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
                                tokens=tokens, outputs=[])  # fmt: skip
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
    done = kit.receipts()
    assert done["run"]["outputs"]["run"]["state"] == "held_paused"
    assert done["run"]["outputs"]["status"]["lock"] is None, "the lock is released"
    assert world["applied"] == ["bootstrap", "foundation", "releases", "services"]
    assert {"InitiateLayerUpload", "CompleteLayerUpload", "PutImage"} <= set(shim.calls)
    pushed = done["images"]["outputs"]["registry_digests"]
    assert pushed == {key: bound[name]["platform_manifest"]
                      for key, name in aws_07b.IMAGE_NAMES.items()}  # fmt: skip
    assert done["detach"]["outputs"]["remaining"] == []
    record(root, kit, world, canary_state, out)


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
