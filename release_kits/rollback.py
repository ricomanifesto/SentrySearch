"""Rollback rehearsal and run kit: restore the retained prior pair after a failed release.

    python -m release_kits.rollback init     --plan DIR --plan-sha256 HASH --work DIR \\
        --prior-work AWS07B_WORK --failed-manifest FILE --failed-release-input FILE \\
        --decision FILE
    python -m release_kits.rollback step ID  --plan DIR --plan-sha256 HASH --work DIR \\
        [--session FILE]

The steps follow the operational proposal's section 9 and the controller's
rollback runs (``docs/release-controller.md``): re-plan the releases root with
the prior release as ``current`` (``replan``), attach the re-planned attended set
and ``release-evidence`` to the operator role (``attach``), write the rollback
manifest and approval (``render``), validate them (``validate``), run them under
the failed release's fenced handoff (``run``), check the outcome (``check``), and
detach what ``attach`` names (``detach``, after any attach attempt or run
outcome). The run
itself quiesces the services (pause and drain), sweeps and reconciles every
launch the failed release journaled, runs the prior release's reconcile and
proof jobs against the stated schemas, starts the prior pair and proves it
operational, then releases the lock at ``held_paused``. ``check`` confirms that:
the journal ended ``held_paused`` with nothing outstanding and the lock is free,
and every service runs the prior release's revision with no task of a failed
revision still running.

Inputs are explicit files: the prior release's AWS-07b work directory (its
receipts give the prior manifest, bundles, groups and revisions), the failed
release's manifest and its ``releases`` input as applied, and the rollback
decision (``sentry.rollback-decision.v1``): the failed release's session and
lock ETag, the fence evidence hash, both databases' actual schemas and who
decided. The kit decides none of these.
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import shlex
import sys
from typing import Any
import uuid

from release.manifest import load_manifest
from release_kits import aws_07b, render
from release_kits.aws_07b import Kit, Refused, Step, StepFailed
from release_kits.ledger import ChainBroken, Ledger
from release_kits.plan import PlanRefused, load_plan, sha256
from release_kits.terraform import RootRun, UnexpectedPlan

KIT = "rollback"
DECISION_SCHEMA = "sentry.rollback-decision.v1"
STEPS = (
    Step("replan", "9.1", "releases/: re-plan with the prior release current", "deployer",
         "releases"),
    Step("attach", "7.7", "attach the attended set and release-evidence for the rollback window",
         "deployer"),
    Step("render", "9.2", "write the rollback manifest and approval", None),
    Step("validate", "9.2", "python -m release_cli validate", None),
    Step("run", "9.3", "python -m release_cli run with the failed release's handoff", "operator"),
    Step("check", "9.4", "held_paused on the prior pair, lock free, no failed revision running",
         "operator"),
    Step("detach", "7.11", "detach every policy attach names, wherever it is attached", "deployer"),
)  # fmt: skip


# Launcher policies scoped to the current release only: after the re-plan they may name
# nothing of the failed release. Jobs and observers name it by its release key (role
# names); the receipts policy names its worker stream by its release id. Services may
# use either retained release's revisions; tasks names no release.
CURRENT_ONLY = {"jobs": "key", "observe": "key", "receipts": "release_id"}


def check_replan(document: dict[str, Any], variables: dict[str, Any],
                 failed_key: str | None = None, failed_release_id: str | None = None
                 ) -> dict[str, Any]:  # fmt: skip
    """A re-plan that swaps slots: retained releases unchanged, launcher policies updated."""
    if document.get("terraform_version") != "1.16.5":
        raise UnexpectedPlan(f"planned by Terraform {document.get('terraform_version')}")
    planned = {
        name: entry.get("value") for name, entry in (document.get("variables") or {}).items()
    }
    for name, value in variables.items():
        if planned.get(name) != value:
            raise UnexpectedPlan(f"variable {name} is not the rendered value")
    counts: dict[str, int] = {}
    for change in document.get("resource_changes") or []:
        actions = sorted(change.get("change", {}).get("actions") or [])
        address = str(change.get("address"))
        if address.startswith("module.release["):
            if actions not in (["no-op"], ["read"]):
                raise UnexpectedPlan(f"{address}: {actions} would change a retained release")
        elif address.startswith("aws_iam_policy.release_launcher["):
            if actions not in (["no-op"], ["update"]):
                raise UnexpectedPlan(f"{address}: {actions}; a launcher policy is only updated")
            name = address.split('["', 1)[1].rstrip('"]')
            if name in CURRENT_ONLY and actions == ["update"] and failed_key:
                after = (change.get("change", {}).get("after") or {}).get("policy")
                if not isinstance(after, str) or not after:
                    raise UnexpectedPlan(f"{address}: the planned policy is not known before apply")
                marker = failed_key if CURRENT_ONLY[name] == "key" else failed_release_id
                if marker and marker in after:
                    raise UnexpectedPlan(f"{address} would still name the failed release")
        elif actions not in (["no-op"], ["read"]):
            raise UnexpectedPlan(f"{address}: {actions} in a rollback re-plan")
        counts["/".join(actions)] = counts.get("/".join(actions), 0) + 1
    return {"actions": counts}


class RollbackKit(Kit):
    kit_name = KIT
    steps = STEPS

    def record(self) -> dict[str, Any]:
        init = self.ledger.completed().get("init")
        if init is None:
            raise Refused("run init first")
        return init["outputs"]

    def prior(self) -> dict[str, dict[str, Any]]:
        """The prior release's AWS-07b receipts, re-verified against this plan."""
        record = self.record()
        chain = Ledger(Path(record["prior_work"]) / "receipts", kit=aws_07b.KIT,
                       plan_sha256=self.plan.plan_sha256)  # fmt: skip
        if chain.head()[1] != record["prior_chain_head"]:
            raise Refused("the prior release's receipts changed since this rollback's init")
        done = {document["step"]: document for _, document, _ in chain.receipts()
                if document["result"] in ("ok", "held")}  # fmt: skip
        if done.get("run", {}).get("result") != "ok":
            raise Refused("the prior release never reached held_paused under this plan")
        return done

    def begin(self, *, prior_work: Path, failed_manifest: Path, failed_release_input: Path,
             decision: Path, prior_chain_head: str | None = None) -> int:  # fmt: skip
        if self.ledger.receipts():
            raise Refused("this work directory already has receipts; use a new one")
        self.ledger.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        record: dict[str, Any] = {"prior_work": str(prior_work.resolve())}
        chain = Ledger(prior_work / "receipts", kit=aws_07b.KIT, plan_sha256=self.plan.plan_sha256)
        prior = {document["step"]: document for _, document, _ in chain.receipts()
                 if document["result"] == "ok"}  # fmt: skip
        if "run" not in prior:
            raise Refused("the prior release never reached held_paused under this plan")
        head = chain.head()[1]
        if prior_chain_head != head:
            raise Refused("give --prior-chain-head: the prior release's last receipt hash")
        record["prior_chain_head"] = head
        prior_manifest = json.loads(Path(prior["validate"]["outputs"]["manifest"]).read_text())
        failed_raw = failed_manifest.read_bytes()
        failed = load_manifest(failed_raw).manifest
        failed_document = json.loads(failed_raw)
        fallback = failed_document.get("rollback") or {}
        if fallback.get("kind") != "compatible_release" or (
            fallback.get("release_id") != prior_manifest["release_id"]
        ):
            raise Refused("the failed release's fallback is not this prior release")
        if fallback["services"] != prior_manifest["services"]:
            raise Refused("the failed release's fallback names other services than the prior's")
        decided = json.loads(decision.read_bytes())
        fields = {"schema", "failed_release_id", "failed_session", "failed_lock_etag",
                  "fence_evidence_sha256", "actual_schemas", "authorized_by", "decided_at"}  # fmt: skip
        if (
            not isinstance(decided, dict)
            or set(decided) != fields
            or (decided["schema"] != DECISION_SCHEMA)
        ):
            raise Refused(f"the decision is not a {DECISION_SCHEMA} document")
        if decided["failed_release_id"] != failed.release_id:
            raise Refused("the decision names another failed release")
        for database in render.DATABASES:
            if (
                decided["actual_schemas"].get(database)
                not in fallback["compatible_schemas"][database]
            ):
                raise Refused(f"the stated {database} schema is not compatible with the prior pair")
        failed_input = json.loads(failed_release_input.read_bytes())
        if set(failed_input) != {render.release_key(failed.release_id)}:
            raise Refused("the failed release input is not exactly the failed release's entry")
        # The prior release's worker canary as its own init record names it; render,
        # validate and run hold every later link to it.
        prior_provider = prior_canary(prior["init"]["outputs"])
        record.update(
            prior_provider_canary=prior_provider,
            release_id=str(uuid.uuid4()), prior_release_id=prior_manifest["release_id"],
            prior_manifest_sha256=load_manifest(json.dumps(prior_manifest).encode()).sha256,
            failed_manifest=str(failed_manifest.resolve()), failed_manifest_sha256=sha256(failed_raw),
            failed_release_input=failed_input, decision=decided,
            decision_sha256=sha256(decision.read_bytes()),
        )  # fmt: skip
        commands = [f"read {prior_work}/receipts (AWS-07b chain for plan {self.plan.plan_sha256})",
                    f"read {failed_manifest} (release {failed.release_id})",
                    f"read {decision} (decided by {decided['authorized_by']})",
                    "prior release's " + (
                        "worker: no provider" if prior_provider is None else
                        f"worker provider canary {prior_provider['canary_id']}, manifest "
                        f"{prior_provider['canary_manifest_sha256']}")]  # fmt: skip
        for command in commands:
            self.say(f"  {command}")
        typed = self.confirm("init", "fix this rollback's record")
        return self._finish(Step("init", "9", "fix the rollback record", None), commands, typed,
                            lambda: record, None)  # fmt: skip

    # 9.1: the re-plan ---------------------------------------------------------------

    def _root_run(self, step: Step) -> tuple[RootRun, dict[str, Any]]:
        prior = self.prior()
        record = self.record()
        rendered = copy.deepcopy(prior["releases"]["outputs"]["rendered"])
        self.refuse_auto_tfvars("releases")
        (prior_key,) = rendered["releases"]
        rendered["releases"][prior_key]["slot"] = "current"
        for key, release in record["failed_release_input"].items():
            rendered["releases"][key] = {**release, "slot": "rollback"}
        directory = self.work / "rendered"
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        sequence = len(self.ledger.receipts())
        account = directory / f"{sequence:03d}-releases.account.tfvars.json"
        account.write_text(json.dumps(self.plan.inputs["releases"], indent=2, sort_keys=True))
        path = directory / f"{sequence:03d}-releases.tfvars.json"
        path.write_text(json.dumps(rendered, indent=2, sort_keys=True) + "\n")
        self.expected = {**self.plan.inputs["releases"], **rendered}
        plans = self.work / "plans"
        plans.mkdir(parents=True, exist_ok=True, mode=0o700)
        backend = render.backend(self.plan, "releases")
        run = RootRun("releases", self.terraform_directory("releases"), backend,
                      (account, path),
                      plans / f"{sequence:03d}-releases.tfplan", self.plugin_dir())  # fmt: skip
        return run, rendered

    def terraform_binary(self) -> str:
        """The pinned binary the prior release's init recorded, unchanged since."""
        pinned = self.prior()["init"]["outputs"]["terraform"]
        if aws_07b._hash_file(Path(pinned["path"])) != pinned["sha256"]:
            raise Refused("the Terraform binary changed since the prior release's init")
        return pinned["path"]

    def plan_check(self, document: dict[str, Any], step: Step, run: RootRun) -> dict[str, Any]:
        ((failed_key, failed),) = self.record()["failed_release_input"].items()
        return check_replan(document, self.expected, failed_key, failed.get("release_id"))

    def check_outputs(self, step: Step, outputs: dict[str, Any], rendered: dict[str, Any]) -> None:
        prior_key = render.release_key(self.record()["prior_release_id"])
        if outputs.get("current_release") != prior_key:
            raise StepFailed("the releases root does not report the prior release as current")
        before = self.prior()["releases"]["outputs"]["terraform"]["releases"][prior_key]
        if outputs["releases"][prior_key]["definitions_sha256"] != before["definitions_sha256"]:
            raise StepFailed("the prior release's registered definitions changed")

    def extra_outputs(self, step: Step) -> dict[str, Any]:
        return {}

    def _policies(self) -> dict[str, list[str]]:
        """The launcher set the re-plan rendered for the prior release, now current."""
        releases = self.receipts()["replan"]["outputs"]["terraform"]
        if releases.get("release_launcher_bootstrap_policy") is not None:
            raise Refused("the re-planned catalog still has a bootstrap launcher; a rollback "
                          "never attaches one")  # fmt: skip
        return render.attended_policies(self.plan, releases)

    # 9.2 to 9.4 ---------------------------------------------------------------------

    def _prepare_render(self, _session, _custodian):
        record = self.record()
        prior = self.prior()
        validated = prior["validate"]["outputs"]
        prior_raw = Path(validated["manifest"]).read_bytes()
        if sha256(prior_raw) != validated["manifest_file_sha256"]:
            raise Refused("the prior manifest changed since its release validated it")
        prior_manifest = json.loads(prior_raw)
        failed_raw = Path(record["failed_manifest"]).read_bytes()
        if sha256(failed_raw) != record["failed_manifest_sha256"]:
            raise Refused("the failed manifest changed since this rollback's init")
        failed = json.loads(failed_raw)
        replan = self.receipts()["replan"]["outputs"]
        release = replan["terraform"]["releases"][render.release_key(record["prior_release_id"])]
        document = rollback_manifest(self.plan, record, prior, prior_manifest, failed, release,
                                     plan_sha256=replan["plan_file_sha256"],
                                     not_before=self.now() - aws_07b.timedelta(minutes=1))  # fmt: skip
        approval = render.approval(self.plan, document)
        # The retained release is never changed to make a rollback pass: its registered
        # definitions, and its worker's canary and key version, are the prior's own.
        prior_key = render.release_key(record["prior_release_id"])
        before = prior["releases"]["outputs"]["terraform"]["releases"][prior_key]
        if release["definitions_sha256"] != before["definitions_sha256"]:
            raise Refused("the re-plan changed the prior release's registered definitions")
        binding = self._prior_binding(prior, document)
        directory = self.work / "rendered"
        sequence = len(self.ledger.receipts())
        paths = {
            name: directory / f"{sequence:03d}-{name}.json" for name in ("manifest", "approval")
        }
        commands = [f"write {paths['manifest']} (rollback {document['release_id']} of "
                    f"{record['decision']['failed_release_id']}, manifest "
                    f"{approval['manifest_sha256']})", f"write {paths['approval']}",
                    render.describe_provider(binding)]  # fmt: skip

        def action() -> dict[str, Any]:
            for name, content in (("manifest", document), ("approval", approval)):
                with paths[name].open("x") as stream:
                    stream.write(json.dumps(content, indent=2) + "\n")
            return {name: str(path) for name, path in paths.items()} | {
                "manifest_sha256": approval["manifest_sha256"],
                **{f"{name}_file_sha256": aws_07b._hash_file(path) for name, path in paths.items()},
                "provider_canary": binding,
            }

        return commands, action, ()

    def _prior_binding(self, prior: dict[str, dict[str, Any]],
                       document: dict[str, Any]) -> dict[str, str] | None:  # fmt: skip
        """The prior release's worker canary as its record, releases input, custody and
        this rollback's manifest all name it, unchanged since this rollback's init, and
        outlasting this rollback's window; or None when none names one."""
        record = prior["init"]["outputs"]
        rendered = prior["releases"]["outputs"]["rendered"]["releases"]
        try:
            binding = render.provider_binding(
                self.plan, record, prior["custodian"]["outputs"]["bundles"],
                rendered[render.release_key(record["release_id"])], document, self.now(),
            )  # fmt: skip
        except ValueError as error:
            raise Refused(f"the prior release's provider: {error}") from None
        except (KeyError, TypeError):
            raise Refused("the prior release's receipts do not carry its provider links") from None
        named = None if binding is None else prior_canary(record)
        if named != self.record().get("prior_provider_canary"):
            raise Refused("the prior release's provider canary is not the one this rollback's "
                          "init recorded")  # fmt: skip
        return binding

    def _rendered_binding(self) -> tuple[dict[str, Any], dict[str, str] | None]:
        """The render receipt's files and canary, checked again against the prior release
        before release_cli is given them."""
        done = self.receipts()["render"]["outputs"]
        try:
            raw = Path(done["manifest"]).read_bytes()
        except OSError:
            raise Refused("the rendered rollback manifest is missing") from None
        if sha256(raw) != done["manifest_file_sha256"]:
            raise Refused("the rollback manifest changed after it was rendered")
        binding = self._prior_binding(self.prior(), json.loads(raw))
        if binding != done.get("provider_canary"):
            raise Refused("the render receipt's provider canary is not the prior release's")
        return done, binding

    def _prepare_validate(self, _session, _custodian):
        done, binding = self._rendered_binding()
        args = ["validate", "--manifest", done["manifest"], "--approval", done["approval"]]

        def action() -> dict[str, Any]:
            code, report = self.release_cli(args)
            if (
                code
                or report.get("execution") != "rollback"
                or (report.get("manifest_sha256") != done["manifest_sha256"])
            ):
                raise StepFailed(f"release_cli validate exited {code}")
            return {"report": report, "provider_canary": binding}

        return (
            [render.describe_provider(binding), "python -m release_cli " + shlex.join(args)],
            action,
            (),
        )

    def _prepare_run(self, session, _custodian):
        done, binding = self._rendered_binding()
        decision = self.record()["decision"]
        args = ["run", "--manifest", done["manifest"], "--approval", done["approval"],
                "--credentials", str(session.path), "--failed-session", decision["failed_session"],
                "--failed-lock-etag", decision["failed_lock_etag"],
                "--fence-evidence-sha256", decision["fence_evidence_sha256"],
                "--authorized-by", decision["authorized_by"]]  # fmt: skip

        def action() -> dict[str, Any]:
            for name in ("manifest", "approval"):
                if aws_07b._hash_file(Path(done[name])) != done[f"{name}_file_sha256"]:
                    raise StepFailed(f"the {name} changed after it was rendered")
            code, report = self.release_cli(args)
            outputs: dict[str, Any] = {"run_exit": code, "run": report, "provider_canary": binding}
            if code != 0 or report.get("state") != "held_paused":
                outputs["_held"] = f"release_cli run exited {code}: {report.get('reason')}"
            return outputs

        return (
            [render.describe_provider(binding), "python -m release_cli " + shlex.join(args)],
            action,
            (),
        )

    def _prepare_check(self, session, _custodian):
        done = self.receipts()["render"]["outputs"]
        raw = Path(done["manifest"]).read_bytes()
        if sha256(raw) != done["manifest_file_sha256"]:
            raise Refused("the rollback manifest changed after it was rendered")
        document = json.loads(raw)
        environment = document["environment"]
        cluster = environment["cluster_arn"]
        # The only revisions that may run now: the prior pair's services and the jobs and
        # observers this rollback launched. Anything else still running is a writer the
        # rollback did not fence, whichever release it came from.
        allowed = {spec["task_definition"] for spec in document["services"].values()}
        allowed |= {job["task"]["task_definition"] for job in document["jobs"]}
        allowed |= {check["task"]["task_definition"] for check in document["operational_checks"]
                    if "task" in check}  # fmt: skip
        status = ["status", "--manifest", done["manifest"], "--credentials", str(session.path)]
        commands = ["python -m release_cli " + shlex.join(status),
                    f"ecs DescribeServices --cluster {cluster}",
                    f"ecs ListTasks --cluster {cluster} (running, and stopping but not stopped)",
                    "ecs DescribeTasks for every task listed"]  # fmt: skip
        ecs = self.clients(session, "ecs")

        def action() -> dict[str, Any]:
            code, summary = self.release_cli(status)
            problems = []
            if problem := aws_07b.status_problem(code, summary, document["release_id"]):
                problems.append(problem)
            services = list(environment["services"].values())
            described = ecs.describe_services(cluster=cluster, services=services)["services"]
            revisions = {item["serviceArn"]: item["taskDefinition"] for item in described}
            for name, arn in environment["services"].items():
                if revisions.get(arn) != document["services"][name]["task_definition"]:
                    problems.append(f"{name} does not run the prior release's revision")
            live = cluster_tasks(ecs, cluster)
            unfenced = sorted({task["taskDefinitionArn"] for task in live}
                              - allowed)  # fmt: skip
            if unfenced:
                problems.append(f"revisions other than the prior pair's still run: {unfenced}")
            outputs: dict[str, Any] = {
                "status": summary, "service_revisions": revisions,
                "live_tasks": len(live),
                "live_revisions": sorted({task["taskDefinitionArn"] for task in live}),
            }  # fmt: skip
            for name, spec in document["services"].items():
                if not any(task["taskDefinitionArn"] == spec["task_definition"] for task in live):
                    problems.append(f"no {name} task runs the prior release's revision")
            if problems:
                outputs["_held"] = "; ".join(problems)
            return outputs

        return commands, action, ()


def prior_canary(record: dict[str, Any]) -> dict[str, str] | None:
    """A release record's named canary and its approval, as fixed at its init."""
    named = record.get("provider")
    if named is None:
        return None
    return {"canary_id": named["canary_id"],
            "canary_manifest_sha256": named["canary_manifest_sha256"],
            "approval_sha256": record["provider_approval"]["sha256"]}  # fmt: skip


def cluster_tasks(ecs: Any, cluster: str) -> list[dict[str, Any]]:
    """Every task in the cluster that has not stopped: running ones and ones still draining."""
    arns: list[str] = []
    for desired in ("RUNNING", "STOPPED"):
        token = None
        while True:
            page = ecs.list_tasks(cluster=cluster, desiredStatus=desired,
                                  **({"nextToken": token} if token else {}))  # fmt: skip
            arns += page.get("taskArns", [])
            token = page.get("nextToken")
            if not token:
                break
    tasks: list[dict[str, Any]] = []
    for start in range(0, len(arns), 100):
        answer = ecs.describe_tasks(cluster=cluster, tasks=arns[start : start + 100])
        if answer.get("failures"):
            # A listed task ECS cannot describe is not known to be stopped.
            raise StepFailed(f"ECS could not describe {len(answer['failures'])} listed tasks")
        tasks += answer["tasks"]
    return [task for task in tasks if task.get("lastStatus") != "STOPPED"]


def rollback_manifest(plan, record: dict[str, Any], prior: dict[str, dict[str, Any]],
                      prior_manifest: dict[str, Any], failed: dict[str, Any],
                      release: dict[str, Any], *, plan_sha256: str, not_before) -> dict[str, Any]:  # fmt: skip
    """The rollback run: the prior pair's own revisions over the decided actual schemas."""
    decision = record["decision"]
    schemas = decision["actual_schemas"]
    bundles = prior["custodian"]["outputs"]["bundles"]
    groups = prior["foundation"]["outputs"]["terraform"]["security_group_ids"]
    window_end = min(not_before + render.WINDOW_LENGTH,
                     aws_07b.datetime.strptime(prior_manifest["risk"]["expires_at"],
                                               "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=aws_07b.UTC))  # fmt: skip
    if window_end <= not_before + aws_07b.timedelta(minutes=30):
        raise Refused("the prior release's risk decision expires before a rollback window")
    jobs = []
    for database in render.DATABASES:
        identity = render.IDENTITIES[database]
        expect = {"database": identity["database"], "principal": identity["owner"],
                  "schema": schemas[database], "release_sessions": "0", "owner_sessions": "0"}  # fmt: skip
        jobs.append(render._job(plan, release, f"{database}-reconcile", "reconcile", database,
                                expect, [bundles[f"owner-environment/{database}"],
                                         bundles[f"owner-material/{database}"]],
                                [groups[f"{database}_db_jobs"]], "release_tools"))  # fmt: skip
    for job in prior_manifest["jobs"]:
        if job["phase"] == "proof":
            proof = copy.deepcopy(job)
            proof["expect"]["schema"] = schemas[job["database"]]
            jobs.append(proof)
    document = {
        "schema_version": 2,
        "purpose": {"kind": "rollback", "failed_release_id": decision["failed_release_id"],
                    "failed_services": {name: spec["task_definition"]
                                        for name, spec in failed["services"].items()},
                    "actual_schemas": schemas},
        "release_id": record["release_id"],
        "milestone": "operational-paused",
        "environment": copy.deepcopy(failed["environment"]),
        "operator": failed["operator"],
        "operator_role": failed["operator_role"],
        "window": {"not_before": render.iso(not_before), "expires_at": render.iso(window_end),
                   **render.WINDOW},
        "sources": copy.deepcopy(prior_manifest["sources"]),
        "images": copy.deepcopy(prior_manifest["images"]),
        "risk": copy.deepcopy(prior_manifest["risk"]),
        "plan_sha256": plan_sha256,
        "network": copy.deepcopy(prior_manifest["network"]),
        "services": copy.deepcopy(prior_manifest["services"]),
        "jobs": jobs,
        "operational_checks": copy.deepcopy(prior_manifest["operational_checks"]),
        "rollback": copy.deepcopy(failed["rollback"]),
    }  # fmt: skip
    load_manifest(json.dumps(document).encode())  # the controller's own refusal, first
    return document


def main(argv: list[str] | None = None, *, kit_class: type[RollbackKit] = RollbackKit,
         **options: Any) -> int:  # fmt: skip
    parser = argparse.ArgumentParser(prog="python -m release_kits.rollback", allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("init", "status", "step"):
        command = commands.add_parser(name, allow_abbrev=False)
        command.add_argument("--plan", type=Path, required=True)
        command.add_argument("--plan-sha256", required=True)
        command.add_argument("--work", type=Path, required=True)
        if name == "init":
            for flag in ("--prior-work", "--failed-manifest", "--failed-release-input",
                         "--decision"):  # fmt: skip
                command.add_argument(flag, type=Path, required=True)
            command.add_argument("--prior-chain-head", required=True,
                                 help="the prior release's last AWS-07b receipt hash")  # fmt: skip
        if name == "step":
            command.add_argument("id", choices=[step.id for step in STEPS])
            command.add_argument("--session")
            command.add_argument("--chain-head", help="the receipt hash the last step printed")
    args = parser.parse_args(argv)
    try:
        plan = load_plan(args.plan, args.plan_sha256)
        kit = kit_class(plan, args.work, **options)
        if args.command == "init":
            return kit.begin(prior_work=args.prior_work, failed_manifest=args.failed_manifest,
                            failed_release_input=args.failed_release_input,
                            decision=args.decision,
                            prior_chain_head=args.prior_chain_head)  # fmt: skip
        if args.command == "status":
            return kit.status()
        return kit.run_step(args.id, session_path=args.session, chain_head=args.chain_head)
    except (PlanRefused, ChainBroken, Refused) as error:
        print(f"rollback: refused: {error}", file=options.get("out", sys.stderr))
        return aws_07b.EXIT_REFUSED


if __name__ == "__main__":
    raise SystemExit(main())
