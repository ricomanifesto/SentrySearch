"""AWS-07b: publication, apply and the first attended release, one typed step at a time.

    python -m release_kits.aws_07b init     --plan DIR --plan-sha256 HASH --work DIR \\
        --image-bindings FILE --risk-decision FILE --runtime-checkout DIR --terraform BINARY \\
        [--provider-canary FILE]
    python -m release_kits.aws_07b status   --plan DIR --plan-sha256 HASH --work DIR
    python -m release_kits.aws_07b step ID  --plan DIR --plan-sha256 HASH --work DIR \\
        [--session FILE] [--custodian DIR]
    python -m release_kits.aws_07b restore  --plan DIR --plan-sha256 HASH --work DIR \\
        --session FILE --approval FILE
    python -m release_kits.aws_07b teardown --plan DIR --plan-sha256 HASH --work DIR \\
        --session FILE --approval FILE

The steps are the operational proposal's section 7, in order (``STEPS``). Each
step prints its exact commands and the plan hash, waits for the operator to type
its identifier, runs, and writes a receipt chained to the previous one; a step
runs only after the step before it has a successful receipt. Terraform steps type
the identifier a second time, after the plan file is checked, to apply exactly
that file. Restore and teardown (section 8) are separate commands that refuse
without their own approval document bound to this plan and this receipt chain.
Exit codes: 0 done, 2 refused before anything ran, 3 the step ran and failed or
held (its receipt says why).
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import time
from typing import Any, Callable, TextIO
import uuid

from dev.assemble_account_plan import canonical
from botocore.exceptions import ClientError

from release.manifest import RUNTIME_GRANT_PIN, ReleaseRejected
from release_kits import images as oci
from release_kits import render
from release_kits import session as sessions
from release_kits.ledger import ChainBroken, Ledger
from release_kits.plan import AccountPlan, PlanRefused, load_plan, sha256
from release_kits.terraform import VERSION as TERRAFORM_VERSION
from release_kits.terraform import (
    RootRun,
    UnexpectedPlan,
    check_plan,
    printable,
)
from src.execution import provider_canary

KIT = "aws-07b"
REPO = Path(__file__).resolve().parents[1]
STAGING = REPO / "deploy" / "aws-staging"
EXIT_OK, EXIT_REFUSED, EXIT_FAILED = 0, 2, 3


@dataclass(frozen=True)
class Step:
    id: str
    section: str  # aws-operational-proposal.md
    title: str
    session: str | None  # "deployer", "operator" or None
    root: str | None = None


STEPS = (
    Step("bootstrap", "7.1", "bootstrap/: plan and apply with local state", "deployer", "bootstrap"),
    Step("foundation", "7.2", "foundation/: init, plan, review, apply", "deployer", "foundation"),
    Step("custodian", "7.3", "custodian: create and version the section 4 secrets", "deployer"),
    Step("images", "7.4", "images: push the three platform manifests by digest", "deployer"),
    Step("releases", "7.5", "releases/: plan and apply one current release", "deployer", "releases"),
    Step("services", "7.6", "services/: plan and apply three services at zero", "deployer",
         "services"),
    Step("attach", "7.7", "attach the attended set, release-evidence and the bootstrap launcher",
         "deployer"),
    Step("session", "7.8", "check the custodian's operator session file", "operator"),
    Step("validate", "7.9", "render, then validate the manifest and approval locally", None),
    Step("run", "7.10", "python -m release_cli run, then status", "operator"),
    Step("detach", "7.11", "detach the bootstrap launcher and the attended set", "deployer"),
)  # fmt: skip
SUBCOMMANDS = {"restore": "8", "teardown": "8", "init": None}
RISK_SCHEMA = "sentry.risk-decision.v1"
RESTORE_SCHEMA = "sentry.restore-approval.v1"
TEARDOWN_SCHEMA = "sentry.teardown-approval.v1"
PROVIDER_SCHEMA = "sentry.provider-canary-approval.v1"
IMAGE_NAMES = {"runtime": "runtime", "search": "search", "release_tools": "release-tools"}


class Refused(Exception):
    """Refused before anything ran; nothing is written."""


class StepFailed(Exception):
    """The step ran and failed; its receipt records why."""


_UNCHECKED = object()


def _now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _hash_file(path: Path) -> str:
    return sha256(path.read_bytes())


def _private_file(path: Path) -> bytes:
    """An owner-only regular file outside any repository: a custodian input."""
    try:
        info = os.lstat(path)
    except OSError:
        raise Refused(f"{path} is missing") from None
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
        raise Refused(f"{path} is not a regular file of yours")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise Refused(f"{path} is readable by others; use mode 0400 or 0600")
    for parent in path.resolve().parents:
        if (parent / ".git").exists():
            raise Refused(f"{path} is inside a repository")
    return path.read_bytes()


class Kit:
    """One work directory's sequence. The rehearsal subclasses the account-facing seams."""

    rehearsal = False
    kit_name = KIT
    steps: tuple[Step, ...] = STEPS

    def __init__(self, plan: AccountPlan, work: Path, *, out: TextIO = sys.stdout,
                 prompt: Callable[[str], str] = input, now: Callable[[], datetime] = _now
                 ) -> None:  # fmt: skip
        self.plan = plan
        self.work = work.resolve()
        self.out = out
        self.prompt = prompt
        self.now = now
        self.sleep: Callable[[float], None] = time.sleep
        self.partial: dict[str, Any] = {}
        self.expected: dict[str, Any] = {}
        self.started_head: Any = _UNCHECKED
        self.ledger = Ledger(
            self.work / "receipts", kit=self.kit_name, plan_sha256=plan.plan_sha256
        )

    # Seams the rehearsal replaces ----------------------------------------------------

    def endpoint(self) -> str | None:
        return None

    def terraform_binary(self) -> str:
        """The pinned binary init recorded, unchanged since."""
        pinned = self.record()["terraform"]
        if _hash_file(Path(pinned["path"])) != pinned["sha256"]:
            raise Refused("the Terraform binary changed since init")
        return pinned["path"]

    def terraform_directory(self, root: str) -> Path:
        return STAGING / root

    def plugin_dir(self) -> Path | None:
        return None

    def terraform(self, run: RootRun, args: list[str], session: sessions.Session | None
                  ) -> subprocess.CompletedProcess:  # fmt: skip
        data = self.work / "terraform" / run.root
        data.mkdir(parents=True, exist_ok=True, mode=0o700)
        environment = sessions.terraform_environment(
            session, region=self.plan.region, home=self.home(), data_dir=data
        )
        return subprocess.run([self.terraform_binary(), f"-chdir={run.directory}", *args],
                              env=environment, text=True, capture_output=True, check=False)  # fmt: skip

    def terraform_apply(self, step: Step, run: RootRun, session: sessions.Session
                        ) -> dict[str, Any]:  # fmt: skip
        """Apply the checked plan file and return the root's outputs."""
        for args in (run.apply(), run.output()):
            result = self.terraform(run, args, session)
            self.log(step.id, args, result)
            if result.returncode:
                raise StepFailed(f"terraform {args[0]} exited {result.returncode}")
        return {name: value["value"] for name, value in json.loads(result.stdout).items()}

    def docker(self, args: list[str]) -> str:
        result = subprocess.run(["docker", *args], text=True, capture_output=True, check=False,
                                env={"PATH": "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin",
                                     "HOME": os.environ.get("HOME", "/nonexistent")})  # fmt: skip
        if result.returncode:
            raise Refused(f"docker {args[0]} exited {result.returncode}")
        return result.stdout

    def release_cli(self, args: list[str]) -> tuple[int, dict[str, Any]]:
        environment = {"PATH": "/usr/bin:/bin", "HOME": str(self.home()),
                       "PYTHON_DOTENV_DISABLED": "1", "PYTHONDONTWRITEBYTECODE": "1"}  # fmt: skip
        # -E and -s, not -I: -I would also drop the checkout from sys.path (-P), and the
        # CLI runs from this checkout. The environment is built here from nothing.
        result = subprocess.run([sys.executable, "-E", "-s", "-B", "-m", "release_cli", *args],
                                cwd=REPO, env=environment, text=True, capture_output=True,
                                check=False)  # fmt: skip
        try:
            report = json.loads(result.stdout)
        except ValueError:
            report = {"unparsed_output_sha256": sha256(result.stdout.encode())}
        return result.returncode, report

    def clients(self, session: sessions.Session, service: str) -> Any:
        return sessions.client(session, service, self.plan.region)

    def caller(self, session: sessions.Session) -> dict[str, str]:
        answer = self.clients(session, "sts").get_caller_identity()
        return {"account": answer["Account"], "arn": answer["Arn"]}

    def schemas(self, sources: dict[str, str], runtime_checkout: Path) -> dict[str, str]:
        return {"runtime": runtime_schema(runtime_checkout, sources["runtime"]),
                "product": product_schema(sources["search"])}  # fmt: skip

    # Shared mechanics -----------------------------------------------------------------

    def home(self) -> Path:
        path = self.work / "home"
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        return path

    def log(self, step: str, args: list[str], result: subprocess.CompletedProcess) -> None:
        directory = self.work / "logs"
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        path = directory / f"{step}-{args[0]}-{stamp}.log"
        with path.open("x") as stream:
            stream.write(f"$ {shlex.join(args)}\nexit {result.returncode}\n")
            stream.write(result.stdout or "")
            stream.write(result.stderr or "")

    def say(self, text: str = "") -> None:
        print(text, file=self.out, flush=True)

    def confirm(self, identifier: str, what: str) -> str:
        typed = self.prompt(f"Type {identifier} to {what} (anything else stops): ").strip()
        if typed != identifier:
            raise Refused(f"not confirmed: expected {identifier!r}")
        return typed

    def record(self) -> dict[str, Any]:
        init = self.ledger.completed().get("init")
        if init is None:
            raise Refused("run init first")
        return init["outputs"]

    def receipts(self) -> dict[str, dict[str, Any]]:
        return self.ledger.completed()

    def session(self, step: Step, path: str | None) -> sessions.Session:
        try:
            loaded = sessions.load(path, operator=self.plan.operator, now=self.now(),
                                   endpoint=self.endpoint())  # fmt: skip
        except sessions.SessionRefused as error:
            raise Refused(str(error)) from None
        identity = self.caller(loaded) if step.session else None
        if identity is not None and identity["account"] != self.plan.account_id:
            raise Refused("the session belongs to another account than the plan")
        if step.session == "operator":
            role = f"{self.plan.name_prefix}-operator"
            wanted = (f"arn:aws:sts::{self.plan.account_id}:assumed-role/{role}/"
                      f"{self.plan.operator}")  # fmt: skip
            if identity is None or identity["arn"] != wanted:
                raise Refused("the session is not the operator role's session for this operator")
        return loaded

    def require_previous(self, step: Step) -> None:
        done = self.receipts()
        index = self.steps.index(step)
        if step.id == "detach":
            # After any attach attempt, ok or failed: a partial attach must be undoable.
            if not any(document["step"] == "attach" for _, document, _ in self.ledger.receipts()):
                raise Refused("nothing was attached")
            return
        previous = "init" if index == 0 else self.steps[index - 1].id
        if previous not in done:
            raise Refused(f"step {step.id} runs only after {previous} succeeded")
        if step.id in done:
            raise Refused(f"step {step.id} already succeeded")

    # Steps --------------------------------------------------------------------------

    def run_step(self, identifier: str, *, session_path: str | None = None,
                 custodian: Path | None = None, chain_head: str | None = None) -> int:  # fmt: skip
        step = {item.id: item for item in self.steps}.get(identifier)
        if step is None:
            raise Refused(f"no step {identifier}; the steps are {[s.id for s in self.steps]}")
        self.check_head(chain_head)
        self.require_previous(step)
        session = self.session(step, session_path) if step.session else None
        self.say(f"{self.kit_name} step {step.id} (operational proposal section {step.section}):"
                 f" {step.title}")  # fmt: skip
        self.say(f"Plan {self.plan.plan_sha256}; account {self.plan.account_id}, region "
                 f"{self.plan.region}, prefix {self.plan.name_prefix}")  # fmt: skip
        if session is not None:
            described = session.describe()
            self.say(f"Session: {described['session_name']} from {described['session_file']}, "
                     f"expires {described['expires_at']}")  # fmt: skip
        if step.root is not None:
            return self._terraform_step(step, session)
        prepare = getattr(self, f"_prepare_{step.id}")
        commands, action, keep_out = prepare(session, custodian)
        for command in commands:
            self.say(f"  {command}")
        typed = self.confirm(step.id, "run this step")
        return self._finish(step, commands, typed, action, session, keep_out)

    def _finish(self, step: Step, commands: list[str], typed: str,
                action: Callable[[], dict[str, Any]], session: sessions.Session | None,
                keep_out: tuple[str, ...] = ()) -> int:  # fmt: skip
        started = render.iso(self.now())
        body: dict[str, Any] = {"section": step.section, "title": step.title, "typed": typed,
                                "started_at": started, "commands": commands,
                                "mode": "rehearsal" if self.rehearsal else "account"}  # fmt: skip
        if session is not None:
            body["session"] = session.describe()
        secrets = (*keep_out, *(session.secrets if session else ()))
        self.partial = {}
        try:
            outputs = action()
        except KeyboardInterrupt:
            body.update(result="failed", detail="interrupted", partial=self.partial,
                        finished_at=render.iso(self.now()))  # fmt: skip
            self._write(step, body, secrets)
            raise
        except Exception as error:
            # Something may already have run (a plan, a push, a call): the receipt keeps
            # what is known. Only the kit's own messages are recorded; any other error
            # by its class, since a provider message can quote a request.
            known = isinstance(error, (StepFailed, UnexpectedPlan, oci.PushRefused, Refused))
            detail = str(error) if known else f"{type(error).__name__} (message withheld)"
            body.update(result="failed", detail=detail, partial=self.partial,
                        finished_at=render.iso(self.now()))  # fmt: skip
            digest, _ = self._write(step, body, secrets)
            self.say(f"Step {step.id} FAILED: {detail}. Receipt {digest}")
            return EXIT_FAILED
        held = outputs.pop("_held", None)
        body.update(result="held" if held else "ok", outputs=outputs,
                    finished_at=render.iso(self.now()))  # fmt: skip
        if held:
            body["detail"] = held
        digest, written = self._write(step, body, secrets)
        if written["result"] == "failed":
            # The receipt was withheld and records a failure; the step reports that failure.
            self.say(f"Step {step.id} FAILED: {written['detail']}. Receipt {digest}")
            return EXIT_FAILED
        self.say(f"Step {step.id} {'HELD: ' + held if held else 'done'}. Receipt {digest}")
        self.say(f"Give the next command --chain-head {digest}")
        return EXIT_FAILED if held else EXIT_OK

    def _write(self, step: Step, body: dict[str, Any],
               secrets: tuple[str, ...]) -> tuple[str, dict[str, Any]]:  # fmt: skip
        """Write the step's receipt; return its hash and the body it actually records."""
        if self.started_head is not _UNCHECKED and self.ledger.head()[1] != self.started_head:
            # Never chain onto a receipt that changed while this step ran.
            self.say(f"Step {step.id} finished {body.get('result')} but the receipts changed "
                     "while it ran; no receipt is written. Its outcome is in the logs.")  # fmt: skip
            raise ChainBroken("the receipts changed while the step ran")
        try:
            return self.ledger.write(step.id, body, keep_out=secrets), body
        except ValueError:
            # The outputs would have held a secret value: keep only that it happened.
            kept = {key: body[key] for key in ("section", "title", "typed", "started_at",
                                               "commands", "mode", "finished_at") if key in body}  # fmt: skip
            kept.update(result="failed", detail="receipt withheld: it would hold a secret value")
            return self.ledger.write(step.id, kept, keep_out=secrets), kept

    def check_head(self, given: str | None) -> None:
        """The newest receipt is the one whose hash the operator was last shown."""
        _, head = self.ledger.head()
        self.started_head = head
        if head is None and given is not None:
            raise Refused(
                "--chain-head names a receipt, but this work directory has none: its history "
                "is missing or this is the wrong directory"
            )
        if head is not None and given != head:
            raise Refused("give --chain-head with the hash the last step printed; the newest "
                          "receipt is not the one it names")  # fmt: skip

    def init(self, *, bindings_path: Path, risk_path: Path, runtime_checkout: Path,
             terraform: Path, provider_path: Path | None = None) -> int:  # fmt: skip
        if self.ledger.receipts():
            raise Refused("this work directory already has receipts; use a new one")
        for parent in (self.work, *self.work.parents):
            if (parent / ".git").exists():
                raise Refused("the work directory is inside a repository; use one outside")
        self.work.mkdir(parents=True, exist_ok=True, mode=0o700)
        if stat.S_IMODE(os.stat(self.work).st_mode) & 0o077:
            raise Refused("the work directory is readable by others; use mode 0700")
        version = subprocess.run([str(terraform), "version", "-json"], text=True,
                                 capture_output=True, check=False,
                                 env={"PATH": "/usr/bin:/bin", "CHECKPOINT_DISABLE": "1"})  # fmt: skip
        try:
            reported = json.loads(version.stdout).get("terraform_version")
        except ValueError:
            reported = None
        if reported != TERRAFORM_VERSION:
            raise Refused(f"{terraform} is not Terraform {TERRAFORM_VERSION}")
        bindings_raw = bindings_path.read_bytes()
        bindings = json.loads(bindings_raw)
        record: dict[str, Any] = {
            "release_id": str(uuid.uuid4()), "image_bindings_sha256": sha256(bindings_raw),
            "terraform": {"path": str(terraform.resolve()), "version": reported,
                          "sha256": _hash_file(terraform.resolve())},
        }  # fmt: skip
        record["images"] = {}
        for key, name in IMAGE_NAMES.items():
            binding = bindings[name]
            archive = Path(binding["scan_artifact"])
            oci.read_archive(archive, archive_sha256=binding["archive_sha256"],
                             platform_manifest=binding["platform_manifest"])  # fmt: skip
            record["images"][key] = {
                "index": binding["index"], "platform_manifest": binding["platform_manifest"],
                "archive": str(archive), "archive_sha256": binding["archive_sha256"],
                **{field: binding[field]
                   for field in ("provenance_sha256", "sbom_sha256", "scan_sha256")},
            }  # fmt: skip
        record["sources"] = {key: bindings[name]["source_revision"]
                             for key, name in IMAGE_NAMES.items()}  # fmt: skip
        if record["sources"]["search"] != record["sources"]["release_tools"]:
            # The product grant script is pinned to one commit both images carry.
            raise Refused("the Search and release-tools images were built from other commits")
        if provider_path is not None:
            # Only an approved capped canary names a provider; the record fixes it, and
            # the custodian accepts a provider key for this release alone.
            record["provider"], record["provider_approval"] = provider_approval(
                provider_path, self.plan, record, self.now()
            )
            canary = json.loads(record["provider"]["canary_manifest"])
            self.say(f"  this release names provider canary {canary['canary_id']} "
                     f"(manifest {record['provider']['canary_manifest_sha256']}) at "
                     f"{record['provider']['base_url']}, until {canary['not_after']}, "
                     f"reviewed against {canary['budget_usd']} USD; approved by "
                     f"{record['provider_approval']['decided_by']}")  # fmt: skip
            for name, spec in sorted(canary["providers"].items()):
                self.say(f"    {name}: at most {spec['max_requests']} requests to "
                         f"{', '.join(spec['hosts'])}")  # fmt: skip
            self.say(f"    stops after {canary['stop']['max_consecutive_failures']} "
                     "consecutive failures")  # fmt: skip
        commands = [
            f"docker run --rm --pull never --network none {record['images']['release_tools']['index']} digest",
            f"git -C {REPO} show {record['sources']['search']}:src/storage/schema.py",
            f"git -C {runtime_checkout} ls-tree --name-only "
            f"{record['sources']['runtime']} db/migrations/",
        ]  # fmt: skip
        for command in commands:
            self.say(f"  {command}")
        typed = self.confirm("init", "fix this release's record")

        def action() -> dict[str, Any]:
            pins = json.loads(
                self.docker(
                    [
                        "run",
                        "--rm",
                        "--pull",
                        "never",
                        "--network",
                        "none",
                        record["images"]["release_tools"]["index"],
                        "digest",
                    ]
                )
            )
            if pins["sql"].get("sql/runtime/service.sql") != RUNTIME_GRANT_PIN["sha256"]:
                raise StepFailed("the release-tools image lacks the reviewed Runtime grant pin")
            record["pins"] = pins
            record["schemas"] = self.schemas(record["sources"], runtime_checkout)
            record["risk"] = risk_decision(risk_path, record, self.now())
            record["fixed"] = {"tools_budget_seconds": render.TOOLS_BUDGET_SECONDS,
                               "observer_budget_seconds": render.OBSERVER_BUDGET_SECONDS,
                               "tools_deadline_hours": render.TOOLS_DEADLINE // timedelta(hours=1),
                               "identities": render.IDENTITIES, "window": render.WINDOW}  # fmt: skip
            return record

        return self._finish(Step("init", "7", "fix the release record", None), commands, typed,
                            action, None)  # fmt: skip

    # Terraform roots ------------------------------------------------------------------

    def _root_run(self, step: Step) -> tuple[RootRun, dict[str, Any]]:
        root = str(step.root)
        rendered: dict[str, Any] | None = None
        done = self.receipts()
        record = self.record()
        if root == "releases":
            try:
                render.model_provider(record, self.now())
            except ValueError as error:
                raise Refused(str(error)) from None
            foundation = done["foundation"]["outputs"]["terraform"]
            rendered = render.releases_input(
                self.plan,
                record,
                foundation,
                done["custodian"]["outputs"]["bundles"],
                done["custodian"]["outputs"]["administrator_secrets"],
                done["images"]["outputs"]["registry_digests"],
                self.now(),
            )
        elif root == "services":
            rendered = render.services_input(done["foundation"]["outputs"]["terraform"],
                                             done["releases"]["outputs"]["terraform"])  # fmt: skip
        directory = self.work / "rendered"
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        sequence = len(self.ledger.receipts())
        # The plan's own inputs, written from the verified plan in memory: a file edited
        # in the plan directory after it was loaded is never what Terraform reads.
        account = directory / f"{sequence:03d}-{root}.account.tfvars.json"
        account.write_text(json.dumps(self.plan.inputs[root], indent=2, sort_keys=True) + "\n")
        var_files = [account]
        self.expected = dict(self.plan.inputs[root])
        if rendered is not None:
            path = directory / f"{sequence:03d}-{root}.tfvars.json"
            path.write_text(json.dumps(rendered, indent=2, sort_keys=True) + "\n")
            var_files.append(path)
            self.expected.update(rendered)
        self.refuse_auto_tfvars(root)
        state = self.work / "state"
        state.mkdir(parents=True, exist_ok=True, mode=0o700)
        backend = render.backend(self.plan, root, str(state / "bootstrap.tfstate"))
        if (
            root != "bootstrap"
            and backend["bucket"] != done["bootstrap"]["outputs"]["terraform"]["control_bucket"]
        ):
            raise Refused("the bootstrap receipt names another control bucket")
        plans = self.work / "plans"
        plans.mkdir(parents=True, exist_ok=True, mode=0o700)
        run = RootRun(root, self.terraform_directory(root), backend, tuple(var_files),
                      plans / f"{sequence:03d}-{root}.tfplan", self.plugin_dir())  # fmt: skip
        return run, rendered or {}

    def refuse_auto_tfvars(self, root: str) -> None:
        """Terraform would also read these from the root directory; none may exist there."""
        directory = self.terraform_directory(root)
        found = sorted(path.name for pattern in ("terraform.tfvars", "terraform.tfvars.json",
                                                 "*.auto.tfvars", "*.auto.tfvars.json")
                       for path in directory.glob(pattern))  # fmt: skip
        if found:
            raise Refused(f"{directory} holds variable files Terraform would load: {found}")

    def _terraform_step(self, step: Step, session: sessions.Session | None) -> int:
        assert session is not None
        run, rendered = self._root_run(step)
        binary = self.terraform_binary()
        commands = [printable(binary, run.directory, args)
                    for args in (run.init(), run.plan(), run.show())]  # fmt: skip
        commands.append("(the kit checks the plan file before anything is applied)")
        commands += [printable(binary, run.directory, args) for args in (run.apply(), run.output())]
        for command in commands:
            self.say(f"  {command}")
        typed = self.confirm(step.id, "initialize and plan")

        def action() -> dict[str, Any]:
            for args in (run.init(), run.plan(), run.show()):
                result = self.terraform(run, args, session)
                self.log(step.id, args, result)
                if result.returncode:
                    raise StepFailed(f"terraform {args[0]} exited {result.returncode}")
            summary = self.plan_check(json.loads(result.stdout), step, run)
            checked = _hash_file(run.plan_file)
            self.partial["plan_file_sha256"] = checked
            self.say(f"Plan file checked: {summary['actions']} (SHA-256 {checked})")
            again = self.confirm(step.id, "apply exactly this plan file")
            if _hash_file(run.plan_file) != checked:
                raise StepFailed("the plan file changed after it was checked")
            outputs = self.terraform_apply(step, run, session)
            self.partial["terraform"] = outputs
            self.check_outputs(step, outputs, rendered)
            return {"plan_file": str(run.plan_file), "plan_file_sha256": checked,
                    "plan_summary": summary, "typed_apply": again, "rendered": rendered,
                    "terraform": outputs, **self.extra_outputs(step)}  # fmt: skip

        return self._finish(step, commands, typed, action, session)

    def plan_check(self, document: dict[str, Any], step: Step, run: RootRun) -> dict[str, Any]:
        """A first deployment's plan: creates only, nothing outside the current release."""
        key = render.release_key(self.record()["release_id"])
        return check_plan(document, root=str(step.root), variables=self.expected,
                          current_key=key)  # fmt: skip

    def check_outputs(self, step: Step, outputs: dict[str, Any], rendered: dict[str, Any]) -> None:
        plan = self.plan
        if step.root == "bootstrap":
            if outputs.get("control_bucket") != render.control_bucket(plan):
                raise StepFailed("bootstrap reports another control bucket")
            if outputs.get("operator_role_arn") != plan.skeleton["operator_role"]:
                raise StepFailed("bootstrap reports another operator role")
        if step.root == "releases":
            key = render.release_key(self.record()["release_id"])
            if outputs.get("current_release") != key or key not in outputs.get("releases", {}):
                raise StepFailed("the releases root reports another current release")
            if outputs.get("release_launcher_bootstrap_policy") is None:
                raise StepFailed("a first deployment has a bootstrap launcher; none was rendered")
        if step.root == "services":
            if outputs.get("service_arns") != plan.skeleton["environment"]["services"]:
                raise StepFailed("the services root reports other service ARNs")

    def extra_outputs(self, step: Step) -> dict[str, Any]:
        if step.root != "services":
            return {}
        done = self.receipts()
        files = {root: done[root]["outputs"]["plan_file_sha256"]
                 for root in ("bootstrap", "foundation", "releases")}  # fmt: skip
        files["services"] = _hash_file(sorted((self.work / "plans").glob("*-services.tfplan"))[-1])
        return {"plan_files": files, "plan_files_sha256": sha256(canonical(files))}

    # Account steps --------------------------------------------------------------------

    def _prepare_custodian(self, session, custodian):
        if custodian is None:
            raise Refused("the custodian step needs --custodian DIR with one JSON file per bundle")
        try:
            provider = render.model_provider(self.record(), self.now())
        except ValueError as error:
            raise Refused(str(error)) from None
        # A provider key is given only for a release that names its canary.
        expected = dict(render.BUNDLES)
        key_file = custodian / f"{render.PROVIDER_BUNDLE}.json"
        if provider is not None:
            if not os.path.lexists(key_file):
                raise Refused(f"this release names provider canary {provider['canary_id']}; "
                              f"give {render.PROVIDER_BUNDLE}.json")  # fmt: skip
            expected[render.PROVIDER_BUNDLE] = render.PROVIDER_KEYS
        elif os.path.lexists(key_file):
            raise Refused(f"{render.PROVIDER_BUNDLE}.json is given, but this release names no "
                          "provider canary")  # fmt: skip
        files, values = {}, []
        for purpose, keys in expected.items():
            path = custodian / f"{purpose}.json"
            raw = _private_file(path)
            try:
                document = json.loads(raw)
            except ValueError:
                raise Refused(f"{purpose}.json is not JSON") from None
            if (
                not isinstance(document, dict)
                or set(document) != set(keys)
                or not all(isinstance(value, str) and value for value in document.values())
            ):
                raise Refused(f"{purpose}.json must hold exactly the keys {sorted(keys)}")
            if purpose == render.PROVIDER_BUNDLE:
                # The worker strips its key: a blank key or the placeholder is no key.
                held = {value.strip() for value in document.values()}
                if "" in held:
                    raise Refused(f"{purpose}.json holds an empty key")
                if provider_canary.SENTINEL_KEY in held:
                    raise Refused(f"{purpose}.json holds the disabled placeholder, not a key")
            files[purpose] = raw
            values += [value for value in document.values() if len(value) >= 8]
        foundation = self.receipts()["foundation"]["outputs"]["terraform"]
        admin = foundation.get("database_admin_secret_arns") or {}
        if any(not admin.get(database) for database in render.DATABASES):
            raise Refused("the foundation reports no RDS-managed administrator secret")
        # One token per secret, fixed by plan, release and purpose: a retry after a
        # partial failure sends the same version again and never makes a second one.
        release = self.record()["release_id"]
        # The content is part of the name: a file changed between attempts makes a new
        # token, which an existing secret does not hold, so the retry fails loudly.
        tokens = {purpose: str(uuid.uuid5(uuid.NAMESPACE_URL, f"sentry-kit:{self.plan.plan_sha256}"
                                          f"/{release}/{purpose}/{sha256(files[purpose])}"))
                  for purpose in files}  # fmt: skip
        commands = [f"secretsmanager CreateSecret --name {render.secret_name(self.plan, purpose)} "
                    f"--secret-string <{purpose}.json> --client-request-token {tokens[purpose]}"
                    for purpose in files]  # fmt: skip
        commands += [f"secretsmanager DescribeSecret --secret-id {admin[database]}"
                     for database in render.DATABASES]  # fmt: skip
        client = self.clients(session, "secretsmanager")

        def action() -> dict[str, Any]:
            bundles: dict[str, dict[str, str]] = {}
            self.partial["bundles"] = bundles
            for purpose, raw in files.items():
                name = render.secret_name(self.plan, purpose)
                try:
                    answer = client.create_secret(Name=name, SecretString=raw.decode(),
                                                  ClientRequestToken=tokens[purpose])  # fmt: skip
                except ClientError as error:
                    if error.response.get("Error", {}).get("Code") != "ResourceExistsException":
                        raise
                    # A retry: the secret is ours only if it holds this step's version.
                    described = client.describe_secret(SecretId=name)
                    if tokens[purpose] not in (described.get("VersionIdsToStages") or {}):
                        raise StepFailed(f"{name} already exists with other versions") from None
                    answer = {"ARN": described["ARN"], "VersionId": tokens[purpose]}
                if answer.get("VersionId") != tokens[purpose]:
                    raise StepFailed(f"{purpose}: the version is not the requested one")
                bundles[purpose] = {"arn": answer["ARN"], "version_id": answer["VersionId"]}
            administrators = {}
            for database in render.DATABASES:
                described = client.describe_secret(SecretId=admin[database])
                current = [version for version, stages in described["VersionIdsToStages"].items()
                           if "AWSCURRENT" in stages]  # fmt: skip
                if len(current) != 1 or described["ARN"] != admin[database]:
                    raise StepFailed(f"{database}: no single current administrator secret version")
                administrators[database] = {"arn": admin[database], "version_id": current[0]}
            return {"bundles": bundles, "administrator_secrets": administrators}

        return commands, action, tuple(values)

    def _prepare_images(self, session, _custodian):
        record = self.record()
        foundation = self.receipts()["foundation"]["outputs"]["terraform"]
        names = render.repositories(self.plan)
        expected = {key: f"{render.registry(self.plan)}/{name}" for key, name in names.items()}
        if {key: foundation["repository_urls"][key] for key in expected} != expected:
            raise Refused("the foundation's repositories are not this plan's")
        commands = [f"ecr PutImage --repository-name {names[key]} --image-digest "
                    f"{record['images'][key]['platform_manifest']} (manifest and blobs from "
                    f"{record['images'][key]['archive']})" for key in names]  # fmt: skip
        client = self.clients(session, "ecr")

        def action() -> dict[str, Any]:
            pushed: dict[str, str] = {}
            details: dict[str, Any] = {}
            self.partial["registry_digests"] = pushed
            for key, repository in names.items():
                image = record["images"][key]
                platform = oci.read_archive(Path(image["archive"]),
                                            archive_sha256=image["archive_sha256"],
                                            platform_manifest=image["platform_manifest"])  # fmt: skip
                details[key] = oci.push(client, platform, repository=repository,
                                        registry_id=self.plan.account_id)  # fmt: skip
                if details[key]["registry_digest"] != image["platform_manifest"]:
                    raise StepFailed(f"{key}: the registry digest differs from the local manifest")
                pushed[key] = details[key]["registry_digest"]
            return {"registry_digests": pushed, "pushes": details}

        return commands, action, ()

    def _policies(self) -> dict[str, list[str]]:
        releases = self.receipts()["releases"]["outputs"]["terraform"]
        return render.attended_policies(self.plan, releases)

    def _prepare_attach(self, session, _custodian):
        role = f"{self.plan.name_prefix}-operator"
        groups = self._policies()
        names = groups["attended"] + groups["evidence"] + groups["bootstrap"]
        arns = [render.policy_arn(self.plan, name) for name in names]
        commands = [f"iam AttachRolePolicy --role-name {role} --policy-arn {arn}" for arn in arns]
        commands.append(f"iam ListAttachedRolePolicies --role-name {role}")
        iam = self.clients(session, "iam")

        def action() -> dict[str, Any]:
            before = attached(iam, role)
            if before:
                raise StepFailed(f"the operator role already has policies attached: {before}")
            done: list[str] = []
            self.partial["attached"] = done
            for arn in arns:
                iam.attach_role_policy(RoleName=role, PolicyArn=arn)
                done.append(arn)
            after = attached(iam, role)
            for _ in range(5):  # IAM's listing can lag an attach briefly
                if sorted(after) == sorted(arns):
                    break
                self.sleep(2)
                after = attached(iam, role)
            if sorted(after) != sorted(arns):
                raise StepFailed(f"the operator role's policies are not exactly the set: {after}")
            return {"role": role, "attached": sorted(after)}

        return commands, action, ()

    def _prepare_session(self, session, _custodian):
        def action() -> dict[str, Any]:
            return {"session": session.describe(),
                    "caller": self.caller(session)["arn"]}  # fmt: skip

        return ["sts GetCallerIdentity (the operator's session)"], action, ()

    def _prepare_validate(self, _session, _custodian):
        done = self.receipts()
        record = self.record()
        expires = datetime.strptime(done["session"]["outputs"]["session"]["expires_at"],
                                    "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)  # fmt: skip
        document = render.manifest(self.plan, record, done, not_before=self.now()
                                   - timedelta(minutes=1), session_expires=expires)  # fmt: skip
        approval = render.approval(self.plan, document)
        # Refused before anything is written unless every link names the same canary,
        # or none does, and a named canary outlasts the window.
        binding = self._provider_binding(record, done, document)
        directory = self.work / "rendered"
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        sequence = len(self.ledger.receipts())
        manifest_path = directory / f"{sequence:03d}-manifest.json"
        approval_path = directory / f"{sequence:03d}-approval.json"
        args = ["validate", "--manifest", str(manifest_path), "--approval", str(approval_path)]
        commands = [f"write {manifest_path} (release {document['release_id']}, manifest "
                    f"{approval['manifest_sha256']})", f"write {approval_path}",
                    render.describe_provider(binding),
                    "python -m release_cli " + shlex.join(args)]  # fmt: skip

        def action() -> dict[str, Any]:
            for path, content in ((manifest_path, document), (approval_path, approval)):
                with path.open("x") as stream:
                    stream.write(json.dumps(content, indent=2) + "\n")
            code, report = self.release_cli(args)
            if code or report.get("manifest_sha256") != approval["manifest_sha256"]:
                raise StepFailed(f"release_cli validate exited {code}")
            return {"manifest": str(manifest_path), "approval": str(approval_path),
                    "manifest_sha256": approval["manifest_sha256"],
                    "manifest_file_sha256": _hash_file(manifest_path),
                    "approval_file_sha256": _hash_file(approval_path), "report": report,
                    "provider_canary": binding}  # fmt: skip

        return commands, action, ()

    def _provider_binding(self, record: dict[str, Any], done: dict[str, dict[str, Any]],
                          document: dict[str, Any]) -> dict[str, str] | None:  # fmt: skip
        """The worker's provider canary as the record, the releases input, custody and the
        manifest all name it, or None when none does; refused otherwise."""
        rendered = done["releases"]["outputs"]["rendered"]["releases"]
        try:
            return render.provider_binding(
                self.plan, record, done["custodian"]["outputs"]["bundles"],
                rendered[render.release_key(record["release_id"])], document, self.now(),
            )  # fmt: skip
        except ValueError as error:
            raise Refused(str(error)) from None
        except (KeyError, TypeError):
            raise Refused("the receipts do not carry the release's provider links") from None

    def _prepare_run(self, session, _custodian):
        receipts = self.receipts()
        done = receipts["validate"]["outputs"]
        if session.describe() != receipts["session"]["outputs"]["session"]:
            raise Refused("this is not the session the session step checked")
        try:
            raw = Path(done["manifest"]).read_bytes()
        except OSError:
            raise Refused("the validated manifest is missing") from None
        if sha256(raw) != done["manifest_file_sha256"]:
            raise Refused("the manifest changed after validation")
        # The canary is checked again at run time, against the validated manifest's window.
        binding = self._provider_binding(self.record(), receipts, json.loads(raw))
        if binding != done.get("provider_canary"):
            raise Refused("the worker's provider canary is not the one validation recorded")
        common = ["--manifest", done["manifest"]]
        run = ["run", *common, "--approval", done["approval"], "--credentials", str(session.path)]
        status = ["status", *common, "--credentials", str(session.path)]
        commands = [render.describe_provider(binding),
                    "python -m release_cli " + shlex.join(run),
                    "python -m release_cli " + shlex.join(status)]  # fmt: skip

        def action() -> dict[str, Any]:
            for name in ("manifest", "approval"):
                if _hash_file(Path(done[name])) != done[f"{name}_file_sha256"]:
                    raise StepFailed(f"the {name} changed after validation")
            release_id = json.loads(Path(done["manifest"]).read_bytes())["release_id"]
            code, report = self.release_cli(run)
            status_code, summary = self.release_cli(status)
            outputs: dict[str, Any] = {"run_exit": code, "run": report,
                                       "status_exit": status_code, "status": summary,
                                       "provider_canary": binding}  # fmt: skip
            if code != 0 or report.get("state") != "held_paused":
                outputs["_held"] = f"release_cli run exited {code}: {report.get('reason')}"
            elif problem := status_problem(status_code, summary, release_id):
                outputs["_held"] = problem
            return outputs

        return commands, action, ()

    def _prepare_detach(self, session, _custodian):
        role = f"{self.plan.name_prefix}-operator"
        named = sorted(render.policy_arn(self.plan, name)
                       for names in self._policies().values() for name in names)  # fmt: skip
        commands = [f"iam DetachRolePolicy --role-name {role} --policy-arn {arn}" for arn in named]
        commands.append(f"iam ListAttachedRolePolicies --role-name {role}")
        iam = self.clients(session, "iam")

        def action() -> dict[str, Any]:
            detached: list[str] = []
            self.partial["detached"] = detached
            for arn in named:
                if arn in attached(iam, role):
                    iam.detach_role_policy(RoleName=role, PolicyArn=arn)
                    detached.append(arn)
            remaining = attached(iam, role)
            if set(remaining) & set(named):
                raise StepFailed(f"still attached: {sorted(set(remaining) & set(named))}")
            if remaining:
                # Not this kit's to remove; attach refuses until the role is empty again.
                raise StepFailed(f"detached the named set; the operator role still has policies no "
                                 f"step here attached: {sorted(remaining)}. Removing them is a "
                                 "separate, reviewed action; attach refuses until then")  # fmt: skip
            return {"role": role, "detached": detached, "remaining": remaining}

        return commands, action, ()

    # Section 8 ------------------------------------------------------------------------

    def _approval(self, path: Path, schema: str) -> tuple[dict[str, Any], str]:
        raw = path.read_bytes()
        document = json.loads(raw)
        _, head = self.ledger.head()
        if head is None or "init" not in self.receipts():
            # Never an approved account write tied to no release history.
            raise Refused("this work directory has no receipts of an initialized AWS-07b "
                          "chain; restore and teardown run only on one")  # fmt: skip
        if not isinstance(document, dict) or document.get("schema") != schema:
            raise Refused(f"the approval is not a {schema} document")
        if document.get("plan_sha256") != self.plan.plan_sha256:
            raise Refused("the approval is for another plan")
        named = document.get("chain_head_sha256")
        if not isinstance(named, str) or not re.fullmatch(r"[0-9a-f]{64}", named) or named != head:
            raise Refused("the approval names another receipt chain head")
        if document.get("approved_by") != self.plan.operator:
            raise Refused("the approval is not the operator's")
        not_after = datetime.strptime(str(document.get("not_after")), "%Y-%m-%dT%H:%M:%SZ")
        if not_after.replace(tzinfo=UTC) < self.now():
            raise Refused("the approval has expired")
        return document, sha256(raw)

    def restore(self, *, session_path: str | None, approval_path: Path,
                chain_head: str | None = None) -> int:  # fmt: skip
        """Section 8: restore one database into a new instance, never over the original."""
        step = Step("restore", "8", "restore a database by point in time into a new instance",
                    "deployer")  # fmt: skip
        self.check_head(chain_head)
        approval, approval_sha256 = self._approval(approval_path, RESTORE_SCHEMA)
        database = approval.get("database")
        if database not in render.DATABASES:
            raise Refused("the approval names no database of this environment")
        source = f"{self.plan.name_prefix}-{database}-db"
        target = str(approval.get("target_identifier"))
        if not re.fullmatch(rf"{re.escape(source)}-restore-[a-z0-9-]{{1,20}}", target):
            raise Refused(f"the target must be a new instance named {source}-restore-<label>")
        restore_time = approval.get("restore_time")
        session = self.session(step, session_path)
        rds = self.clients(session, "rds")
        when = ("--use-latest-restorable-time" if restore_time == "latest"
                else f"--restore-time {restore_time}")  # fmt: skip
        commands = [f"rds RestoreDBInstanceToPointInTime --source-db-instance-identifier {source} "
                    f"--target-db-instance-identifier {target} {when} --deletion-protection",
                    f"rds DescribeDBInstances --db-instance-identifier {target}"]  # fmt: skip
        for command in commands:
            self.say(f"  {command}")
        typed = self.confirm("restore", f"restore {database} into {target}")

        def action() -> dict[str, Any]:
            existing = rds.describe_db_instances()["DBInstances"]
            names = {item["DBInstanceIdentifier"]: item for item in existing}
            if target in names:
                raise StepFailed(f"{target} already exists; a restore never reuses an instance")
            original = names.get(source)
            if original is None:
                raise StepFailed(f"{source} is not in the account")
            arguments: dict[str, Any] = {
                "SourceDBInstanceIdentifier": source, "TargetDBInstanceIdentifier": target,
                "DBSubnetGroupName": original["DBSubnetGroup"]["DBSubnetGroupName"],
                "VpcSecurityGroupIds": [group["VpcSecurityGroupId"]
                                        for group in original["VpcSecurityGroups"]],
                "DeletionProtection": True, "PubliclyAccessible": False,
                "CopyTagsToSnapshot": True,
            }  # fmt: skip
            if restore_time == "latest":
                arguments["UseLatestRestorableTime"] = True
            else:
                arguments["RestoreTime"] = datetime.strptime(
                    str(restore_time), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)  # fmt: skip
            self.partial["restore_requested"] = target
            created = rds.restore_db_instance_to_point_in_time(**arguments)["DBInstance"]
            after = {item["DBInstanceIdentifier"]: item
                     for item in rds.describe_db_instances()["DBInstances"]}  # fmt: skip
            if after.get(source, {}).get("DBInstanceStatus") in (None, "deleting"):
                raise StepFailed("the original instance is no longer available")
            return {"approval_sha256": approval_sha256, "database": database, "source": source,
                    "target": created["DBInstanceIdentifier"],
                    "target_status": created.get("DBInstanceStatus"),
                    # Nothing here runs the reconcile and proof jobs against the new
                    # instance: that needs bundles naming it, which no kit builds yet.
                    "schema_verification": "not run: needs a release whose bundles name the "
                                           "restored instance (not built)"}  # fmt: skip

        return self._finish(step, commands, typed, action, session)

    def teardown(self, *, session_path: str | None, approval_path: Path,
                 chain_head: str | None = None) -> int:  # fmt: skip
        """Section 8 teardown review: zero, detach, then only the approved, exact list."""
        step = Step("teardown", "8", "teardown review: scale to zero, detach, remove services",
                    "deployer")  # fmt: skip
        self.check_head(chain_head)
        approval, approval_sha256 = self._approval(approval_path, TEARDOWN_SCHEMA)
        done = self.receipts()
        services = self.plan.skeleton["environment"]["services"]
        expected = sorted(f'aws_ecs_service.this["{name}"]' for name in services)
        if sorted(approval.get("remove", [])) != expected:
            raise Refused(f"the approval must list exactly the services to remove: {expected}")
        session = self.session(step, session_path)
        ecs = self.clients(session, "ecs")
        iam = self.clients(session, "iam")
        role = f"{self.plan.name_prefix}-operator"
        launchers = ([render.policy_arn(self.plan, name) for names in self._policies().values()
                      for name in names] if "releases" in done else [])  # fmt: skip
        cluster = self.plan.skeleton["environment"]["cluster_arn"]
        run, _ = self._services_destroy_run()
        binary = self.terraform_binary()
        commands = [f"ecs UpdateService --cluster {cluster} --service {arn} --desired-count 0"
                    for arn in services.values()]  # fmt: skip
        commands += [f"iam DetachRolePolicy --role-name {role} --policy-arn {arn}"
                     for arn in launchers]  # fmt: skip
        commands += [
            printable(binary, run.directory, args)
            for args in (run.init(), [*run.plan()[:1], "-destroy", *run.plan()[1:]], run.show())
        ]
        commands.append("(the kit checks the destroy plan removes exactly the approved list)")
        commands.append(printable(binary, run.directory, run.apply()))
        commands.append("NOT done here: releases are retired by `terraform state rm` and "
                        "deregistration, and the foundation needs a reviewed change lifting "
                        "prevent_destroy; snapshots and images are kept")  # fmt: skip
        for command in commands:
            self.say(f"  {command}")
        typed = self.confirm("teardown", "scale to zero, detach and remove the services")

        def action() -> dict[str, Any]:
            scaled: list[str] = []
            self.partial["scaled_to_zero"] = scaled
            for arn in services.values():
                ecs.update_service(cluster=cluster, service=arn, desiredCount=0)
                scaled.append(arn)
            described = ecs.describe_services(cluster=cluster, services=list(services.values()))
            if any(item["desiredCount"] for item in described["services"]):
                raise StepFailed("a service still has a desired count")
            detached: list[str] = []
            self.partial["detached"] = detached
            for arn in launchers:
                if arn in attached(iam, role):
                    iam.detach_role_policy(RoleName=role, PolicyArn=arn)
                    detached.append(arn)
            destroy = [*run.plan()[:1], "-destroy", *run.plan()[1:]]
            for args in (run.init(), destroy, run.show()):
                result = self.terraform(run, args, session)
                self.log(step.id, args, result)
                if result.returncode:
                    raise StepFailed(f"terraform {args[0]} exited {result.returncode}")
            changes = json.loads(result.stdout).get("resource_changes") or []
            removed = sorted(change["address"] for change in changes
                             if change["change"]["actions"] == ["delete"])  # fmt: skip
            others = [change["address"] for change in changes
                      if change["change"]["actions"] not in (["delete"], ["no-op"])]  # fmt: skip
            if removed != expected or others:
                raise StepFailed(f"the destroy plan is not exactly the approved list: {removed}")
            checked = _hash_file(run.plan_file)
            self.partial["destroy_plan_sha256"] = checked
            again = self.confirm("teardown", "apply exactly this destroy plan")
            if _hash_file(run.plan_file) != checked:
                raise StepFailed("the destroy plan file changed after it was checked")
            outputs = self.terraform_apply(step, run, session)
            return {"approval_sha256": approval_sha256, "scaled_to_zero": sorted(services),
                    "detached": detached, "removed": removed, "typed_apply": again,
                    "destroy_plan_sha256": checked, "remaining_outputs": outputs, "kept": ["releases", "foundation",
                                                           "snapshots", "images"]}  # fmt: skip

        return self._finish(step, commands, typed, action, session)

    def _services_destroy_run(self) -> tuple[RootRun, dict[str, Any]]:
        state = self.work / "state"
        backend = render.backend(self.plan, "services", str(state / "bootstrap.tfstate"))
        done = self.receipts()
        directory = self.work / "rendered"
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        sequence = len(self.ledger.receipts())
        account = directory / f"{sequence:03d}-services-destroy.account.tfvars.json"
        account.write_text(json.dumps(self.plan.inputs["services"], indent=2, sort_keys=True))
        var_files = [account]
        if "services" in done:
            rendered = directory / f"{sequence:03d}-services-destroy.tfvars.json"
            rendered.write_text(json.dumps(done["services"]["outputs"]["rendered"], indent=2,
                                           sort_keys=True))  # fmt: skip
            var_files.append(rendered)
        self.refuse_auto_tfvars("services")
        plans = self.work / "plans"
        plans.mkdir(parents=True, exist_ok=True, mode=0o700)
        sequence = len(self.ledger.receipts())
        run = RootRun("services", self.terraform_directory("services"), backend,
                      tuple(var_files), plans / f"{sequence:03d}-services-destroy.tfplan",
                      self.plugin_dir())  # fmt: skip
        return run, {}

    def status(self) -> int:
        done = self.receipts()
        self.say(f"Plan {self.plan.plan_sha256}")
        for _, document, digest in self.ledger.receipts():
            self.say(f"  {document['sequence']:03d} {document['step']:<10} {document['result']:<6}"
                     f" {digest}")  # fmt: skip
        pending = [step.id for step in self.steps if step.id not in done]
        self.say(f"Next: {pending[0] if pending else 'nothing; section 8 commands only'}")
        return EXIT_OK


def status_problem(code: int, summary: dict[str, Any], release_id: str) -> str | None:
    """Why a ``release_cli status`` answer does not prove this release ended held_paused
    with nothing outstanding and the environment lock released; None when it does.

    A refusal, an unparseable answer or a missing field is never read as an absent
    lock or a finished run.
    """
    if code != 0:
        reason = summary.get("error") or "unparsed output"
        return f"release_cli status exited {code} ({reason}): nothing about the lock is known"
    if summary.get("command") != "status" or summary.get("release_id") != release_id:
        return "release_cli status did not answer for this release"
    journal = summary.get("journal")
    if not isinstance(journal, dict) or journal.get("state") != "held_paused":
        return "the journal does not show held_paused"
    if journal.get("outstanding") != []:
        return "the journal still has outstanding intents"
    if "lock" not in summary:
        return "release_cli status did not report the lock"
    if summary["lock"] is not None:
        return "the environment lock is still held"
    return None


def attached(iam: Any, role: str) -> list[str]:
    found = []
    for page in iam.get_paginator("list_attached_role_policies").paginate(RoleName=role):
        found += [policy["PolicyArn"] for policy in page["AttachedPolicies"]]
    return found


def runtime_schema(checkout: Path, revision: str) -> str:
    """The schema the Runtime's release migration reports: its goose versions."""
    listed = subprocess.run(["git", "-C", str(checkout), "ls-tree", "--name-only", revision,
                             "db/migrations/"], text=True, capture_output=True, check=False)  # fmt: skip
    if listed.returncode:
        raise StepFailed("the Runtime checkout does not have the image's source revision")
    versions = sorted(int(Path(name).name.split("_", 1)[0]) for name in listed.stdout.split()
                      if name.endswith(".sql"))  # fmt: skip
    if not versions:
        raise StepFailed("no Runtime migrations at the image's source revision")
    return "goose:" + ",".join(str(version) for version in versions)


def product_schema(revision: str) -> str:
    """The product schema revision at the Search image's source: version and checksum."""

    def show(path: str) -> bytes:
        result = subprocess.run(["git", "-C", str(REPO), "show", f"{revision}:{path}"],
                                capture_output=True, check=False)  # fmt: skip
        if result.returncode:
            raise StepFailed("this checkout does not have the Search image's source revision")
        return result.stdout

    version = re.search(rb"^SCHEMA_VERSION = (\d+)$", show("src/storage/schema.py"), re.M)
    if version is None:
        raise StepFailed("no SCHEMA_VERSION at the Search image's source revision")
    checksum = hashlib.sha256(show("src/storage/migrations/001_release.sql")).hexdigest()
    return f"sentrysearch:{int(version.group(1))}:{checksum[:16]}"


def risk_decision(path: Path, record: dict[str, Any], now: datetime) -> dict[str, Any]:
    """Michael's recorded decision on the images' retained findings; the kit makes none."""
    raw = path.read_bytes()
    document = json.loads(raw)
    fields = {"schema", "decision_id", "decided_by", "decided_at", "expires_at",
              "retained_findings", "images"}  # fmt: skip
    if (
        not isinstance(document, dict)
        or set(document) != fields
        or document["schema"] != RISK_SCHEMA
    ):
        raise StepFailed(f"the risk decision is not a {RISK_SCHEMA} document")
    bound = {key: record["images"][key]["platform_manifest"] for key in IMAGE_NAMES}
    if document["images"] != bound:
        raise StepFailed("the risk decision is about other images than the bindings name")
    if not isinstance(document["decision_id"], str) or not re.fullmatch(
        r"[a-z0-9][a-z0-9-]{0,62}", document["decision_id"]
    ):
        raise StepFailed("the risk decision_id is not a lowercase name the manifest accepts")
    try:
        expires = datetime.strptime(str(document["expires_at"]), "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise StepFailed("the risk decision's expires_at is not a UTC time") from None
    # The release must run inside the decision: through the tools deadline and its window.
    if expires.replace(tzinfo=UTC) < now + render.TOOLS_DEADLINE:
        raise StepFailed("the risk decision expires before this release could run")
    return {"decision_id": document["decision_id"], "decision_sha256": sha256(raw),
            "decided_by": document["decided_by"], "expires_at": document["expires_at"],
            "retained_findings": document["retained_findings"]}  # fmt: skip


def provider_approval(path: Path, plan: AccountPlan, record: dict[str, Any], now: datetime
                      ) -> tuple[dict[str, str], dict[str, str]]:  # fmt: skip
    """Michael's approval naming this release's provider canary (its id, manifest,
    manifest hash and base URL) for this plan and these images. Without one a release
    has no provider."""
    raw = path.read_bytes()
    try:
        document = json.loads(raw)
    except ValueError:
        raise Refused("the provider approval is not JSON") from None
    fields = {"schema", "plan_sha256", "image_bindings_sha256", "decided_by", "decided_at",
              *render.PROVIDER_FIELDS}  # fmt: skip
    if (
        not isinstance(document, dict)
        or set(document) != fields
        or document["schema"] != PROVIDER_SCHEMA
    ):
        raise Refused(f"the provider approval is not a {PROVIDER_SCHEMA} document")
    if document["plan_sha256"] != plan.plan_sha256:
        raise Refused("the provider approval is for another plan")
    # The images carry the worker's provider guard; a canary approved for other images
    # could give a key to a worker without it.
    if document["image_bindings_sha256"] != record["image_bindings_sha256"]:
        raise Refused("the provider approval is about other images than the bindings name")
    if not isinstance(document["decided_by"], str) or not document["decided_by"].strip():
        raise Refused("the provider approval names who decided it")
    try:
        decided = datetime.strptime(str(document["decided_at"]), "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise Refused("the provider approval's decided_at is not a UTC time") from None
    if decided.replace(tzinfo=UTC) > now:
        raise Refused("the provider approval's decided_at is in the future")
    try:
        named = render.check_provider({field: document[field] for field in render.PROVIDER_FIELDS},
                                      now)  # fmt: skip
    except ValueError as error:
        raise Refused(str(error)) from None
    return named, {"sha256": sha256(raw), "decided_by": document["decided_by"],
                   "decided_at": document["decided_at"]}  # fmt: skip


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m release_kits.aws_07b", allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("init", "status", "step", "restore", "teardown"):
        command = commands.add_parser(name, allow_abbrev=False)
        command.add_argument("--plan", type=Path, required=True)
        command.add_argument("--plan-sha256", required=True)
        command.add_argument("--work", type=Path, required=True)
        if name == "init":
            command.add_argument("--image-bindings", type=Path, required=True)
            command.add_argument("--risk-decision", type=Path, required=True)
            command.add_argument("--runtime-checkout", type=Path, required=True)
            command.add_argument(
                "--terraform", type=Path, required=True, help="the pinned Terraform 1.16.5 binary"
            )
            command.add_argument(
                "--provider-canary", type=Path,
                help="only for a capped provider canary: the approval that names it",
            )  # fmt: skip
        if name == "step":
            command.add_argument("id", choices=[step.id for step in STEPS])
            command.add_argument("--session")
            command.add_argument("--custodian", type=Path)
        if name in ("restore", "teardown"):
            command.add_argument("--session", required=True)
            command.add_argument("--approval", type=Path, required=True)
        if name in ("step", "restore", "teardown"):
            command.add_argument("--chain-head", help="the receipt hash the last step printed")
    return parser


def main(argv: list[str] | None = None, *, kit_class: type[Kit] = Kit, **options: Any) -> int:
    args = build_parser().parse_args(argv)
    try:
        plan = load_plan(args.plan, args.plan_sha256)
        kit = kit_class(plan, args.work, **options)
        if args.command == "init":
            return kit.init(bindings_path=args.image_bindings, risk_path=args.risk_decision,
                            runtime_checkout=args.runtime_checkout, terraform=args.terraform,
                            provider_path=args.provider_canary)  # fmt: skip
        if args.command == "status":
            return kit.status()
        if args.command == "step":
            return kit.run_step(args.id, session_path=args.session, custodian=args.custodian,
                                chain_head=args.chain_head)  # fmt: skip
        if args.command == "restore":
            return kit.restore(session_path=args.session, approval_path=args.approval,
                               chain_head=args.chain_head)  # fmt: skip
        return kit.teardown(session_path=args.session, approval_path=args.approval,
                            chain_head=args.chain_head)  # fmt: skip
    except (PlanRefused, ChainBroken, Refused, oci.PushRefused, ReleaseRejected) as error:
        print(f"aws_07b: refused: {error}", file=options.get("out", sys.stderr))
        return EXIT_REFUSED


if __name__ == "__main__":
    raise SystemExit(main())
