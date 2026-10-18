"""Terraform for the kit's root steps: pinned binary, rendered inputs, plan file, diff check.

Every step initializes its root with ``-backend-config`` values rendered from the
plan (the control bucket, the root's fixed state key and the region; the bootstrap
root keeps local state in the work directory), writes a plan file, reads it back
with ``terraform show -json`` and refuses to apply when the plan is not the one
the kit expects. Only that plan file is ever applied.

What the kit expects of a first deployment: Terraform 1.16.5; exactly the
variables it rendered; no resource change other than create, read or no-op; and,
for the releases root, nothing created outside the current release's module and
the launcher policies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
import shlex
from typing import Any

VERSION = "1.16.5"
ALLOWED_ACTIONS = ({"create"}, {"read"}, {"no-op"})
ROOT_TOP_LEVEL = {
    "bootstrap": None,
    "foundation": None,
    "services": None,
    # Everything else in the releases root lives in a release module.
    "releases": ("aws_iam_policy.release_launcher[", "aws_iam_policy.release_launcher_bootstrap["),
}


# A restore verification's own resources at the releases root (releases/restore.tf). They
# exist only while one verification runs and belong to no release module.
RESTORE_ADDRESSES = (
    "aws_iam_role.restore_execution[",
    "aws_iam_role_policy.restore_execution[",
    "aws_ecs_task_definition.restore[",
    'aws_iam_policy.release_launcher["restore"]',
)


def restore_address(address: str) -> bool:
    return address.startswith(RESTORE_ADDRESSES)


class UnexpectedPlan(Exception):
    """The plan differs from what this step expects; nothing is applied."""


@dataclass(frozen=True)
class RootRun:
    """One root's commands for a step, all from the plan and earlier receipts."""

    root: str
    directory: Path
    backend: dict[str, str]
    var_files: tuple[Path, ...]
    plan_file: Path
    plugin_dir: Path | None = None
    extra_init: tuple[str, ...] = field(default=())

    def init(self) -> list[str]:
        args = ["init", "-input=false", "-lockfile=readonly", "-no-color"]
        args += [f"-backend-config={key}={value}" for key, value in sorted(self.backend.items())]
        if self.plugin_dir is not None:
            args.append(f"-plugin-dir={self.plugin_dir}")
        return args + list(self.extra_init)

    def plan(self) -> list[str]:
        return (["plan", "-input=false", "-no-color", "-lock=true", f"-out={self.plan_file}"]
                + [f"-var-file={path}" for path in self.var_files])  # fmt: skip

    def show(self) -> list[str]:
        return ["show", "-json", "-no-color", str(self.plan_file)]

    def apply(self) -> list[str]:
        return ["apply", "-input=false", "-no-color", "-auto-approve", str(self.plan_file)]

    def output(self) -> list[str]:
        return ["output", "-json", "-no-color"]


def printable(binary: str, directory: Path, args: list[str]) -> str:
    return shlex.join([binary, f"-chdir={directory}", *args])


def expected_variables(var_files: tuple[Path, ...]) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for path in var_files:
        values.update(json.loads(path.read_text()))
    return values


def check_plan(document: dict[str, Any], *, root: str, variables: dict[str, Any],
               current_key: str | None = None) -> dict[str, Any]:  # fmt: skip
    """The plan's change summary, or UnexpectedPlan naming the first surprise."""
    if document.get("terraform_version") != VERSION:
        raise UnexpectedPlan(f"planned by Terraform {document.get('terraform_version')}")
    if document.get("errored"):
        raise UnexpectedPlan("the plan errored")
    planned = {
        name: entry.get("value") for name, entry in (document.get("variables") or {}).items()
    }
    for name, value in variables.items():
        if planned.get(name) != value:
            raise UnexpectedPlan(f"variable {name} is not the rendered value")
    counts: dict[str, int] = {}
    allowed_top = ROOT_TOP_LEVEL[root]
    for change in document.get("resource_changes") or []:
        actions = set(change.get("change", {}).get("actions") or [])
        address = str(change.get("address"))
        if actions not in ALLOWED_ACTIONS:
            raise UnexpectedPlan(f"{address}: {sorted(actions)} in a first deployment")
        if root == "releases" and "create" in actions:
            inside = current_key is not None and address.startswith(
                f'module.release["{current_key}"].'
            )
            if not inside and not address.startswith(allowed_top or ()):
                raise UnexpectedPlan(f"{address} is outside the current release")
        name = "/".join(sorted(actions))
        counts[name] = counts.get(name, 0) + 1
    if not counts.get("create") and not counts.get("no-op"):
        raise UnexpectedPlan("the plan changes nothing a first deployment needs")
    return {"actions": counts}


def check_restore_plan(document: dict[str, Any], *, variables: dict[str, Any],
                       adding: bool) -> dict[str, Any]:  # fmt: skip
    """A restore verification's own plan of the releases root: it adds the one entry's
    resources (``adding``) or removes them, and changes nothing else."""
    if document.get("terraform_version") != VERSION:
        raise UnexpectedPlan(f"planned by Terraform {document.get('terraform_version')}")
    if document.get("errored"):
        raise UnexpectedPlan("the plan errored")
    planned = {
        name: entry.get("value") for name, entry in (document.get("variables") or {}).items()
    }
    for name, value in variables.items():
        if planned.get(name) != value:
            raise UnexpectedPlan(f"variable {name} is not the rendered value")
    wanted = ["create"] if adding else ["delete"]
    counts: dict[str, int] = {}
    for change in document.get("resource_changes") or []:
        actions = sorted(change.get("change", {}).get("actions") or [])
        address = str(change.get("address"))
        if restore_address(address):
            if actions not in (wanted, ["no-op"]):
                raise UnexpectedPlan(f"{address}: {actions}; this plan only "
                                     f"{'adds' if adding else 'removes'} the verification")  # fmt: skip
        elif address.startswith('aws_iam_policy.release_launcher["'):
            # The attended documents other than the restore one stay as they are.
            if actions != ["no-op"]:
                raise UnexpectedPlan(f"{address}: {actions}; a verification changes no other "
                                     "launcher document")  # fmt: skip
        elif actions not in (["no-op"], ["read"]):
            raise UnexpectedPlan(f"{address}: {actions} outside the verification's resources")
        name = "/".join(actions)
        counts[name] = counts.get(name, 0) + 1
    if not counts.get(wanted[0]):
        raise UnexpectedPlan(f"the plan {'adds' if adding else 'removes'} nothing")
    return {"actions": counts}
