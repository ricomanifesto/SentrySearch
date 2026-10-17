"""The account plan a kit runs from: the directory ``dev.assemble_account_plan`` wrote.

A plan is usable only when its hash verifies. ``account-plan.json`` carries the
hash the assembler printed; it is recomputed here from the plan's inputs, manifest
skeleton, bundle manifest hash, decisions hash and checklist (so an edited
checklist status cannot pass the all-met gate), and every file the kits read
(each root's ``account.auto.tfvars.json`` and ``manifest.skeleton.json``) must be
exactly the plan's own copy. The operator also passes the hash the assembler
printed, so a plan rewritten afterwards is refused.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from dev.assemble_account_plan import ROOTS, canonical

SHA256 = re.compile(r"[0-9a-f]{64}")
# Checklist items a first apply may proceed past while still unknown: none. An
# unmet or unknown inspection item is a decision for the operator, not the kit.
REQUIRED_STATUS = "met"


class PlanRefused(Exception):
    """The plan directory cannot be used as it is."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(path: Path) -> Any:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        raise PlanRefused(f"{path.name} is missing or not JSON") from None


@dataclass(frozen=True)
class AccountPlan:
    root: Path
    document: dict[str, Any]

    @property
    def plan_sha256(self) -> str:
        return self.document["plan_sha256"]

    @property
    def inputs(self) -> dict[str, dict[str, Any]]:
        return self.document["inputs"]

    @property
    def skeleton(self) -> dict[str, Any]:
        return self.document["manifest_skeleton"]

    @property
    def account_id(self) -> str:
        return self.inputs["bootstrap"]["account_id"]

    @property
    def region(self) -> str:
        return self.inputs["bootstrap"]["region"]

    @property
    def name_prefix(self) -> str:
        return self.inputs["bootstrap"]["name_prefix"]

    @property
    def operator(self) -> str:
        return self.skeleton["operator"]

    def tfvars(self, root: str) -> Path:
        return self.root / root / "account.auto.tfvars.json"


def load_plan(root: Path, printed: str | None) -> AccountPlan:
    """The verified plan, or PlanRefused naming the first thing that does not hold."""
    if printed is None or SHA256.fullmatch(printed) is None:
        raise PlanRefused("give the plan hash the assembler printed (--plan-sha256)")
    root = root.resolve()
    document = _json(root / "account-plan.json")
    if not isinstance(document, dict):
        raise PlanRefused("account-plan.json is not an object")
    hashed = {
        "inputs": document.get("inputs"),
        "manifest_skeleton": document.get("manifest_skeleton"),
        "bundle_manifest_sha256": (document.get("bundle") or {}).get("manifest_sha256"),
        "decisions_sha256": document.get("decisions_sha256"),
        "checklist": document.get("checklist"),
    }
    if sha256(canonical(hashed)) != document.get("plan_sha256"):
        raise PlanRefused("account-plan.json does not hash to its own plan_sha256")
    if document["plan_sha256"] != printed:
        raise PlanRefused("the plan is not the one whose hash the assembler printed")
    for name in ROOTS:
        if _json(root / name / "account.auto.tfvars.json") != document["inputs"].get(name):
            raise PlanRefused(f"{name}/account.auto.tfvars.json is not the plan's own copy")
    if _json(root / "manifest.skeleton.json") != document["manifest_skeleton"]:
        raise PlanRefused("manifest.skeleton.json is not the plan's own copy")
    unmet = [item["id"] for item in document.get("checklist", [])
             if item.get("status") != REQUIRED_STATUS]  # fmt: skip
    if unmet or not document.get("checklist"):
        raise PlanRefused(f"inspection checklist items not met: {unmet or 'no checklist'}")
    plan = AccountPlan(root, document)
    if plan.operator.startswith("TBD("):
        raise PlanRefused("the plan names no operator")
    if "operator_trust" not in plan.inputs["bootstrap"]:
        raise PlanRefused("the plan has no operator trust: the operator role cannot be created")
    return plan
