"""Shared fixtures for the release kits: an assembled plan and stand-in root outputs.

Stand-in outputs are what each root's apply would report, derived from the
inputs the kit rendered with the names ``deploy/aws-platform-fit`` and the naming
module give. They stand in for an apply nobody ran: every identifier uses the
documentation account and none is a real resource.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import json
from pathlib import Path
from typing import Any

from dev import assemble_account_plan as assembler
from tests.test_assemble_account_plan import decisions, printed, write_bundle

SECURITY_GROUPS = ("runtime", "api", "worker", "runtime_db_jobs", "product_db_jobs",
                   "runtime_transport_proof", "api_proof", "storage_proof", "runtime_db",
                   "product_db", "endpoints")  # fmt: skip
TOOLS_JOBS = {"grant": "grant", "proof": "proof", "reconcile": "recon"}


def sha(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def account_plan(root: Path, **changes: Any) -> tuple[Path, str]:
    """An assembled plan directory from a clean synthetic inspection, and its hash."""
    written = write_bundle(root / "bundle")
    bundle = assembler.Bundle(written, printed(written))
    plan = assembler.assemble(bundle, decisions(**changes))
    assembler.write_outputs(plan, root / "plan")
    return root / "plan", plan["plan_sha256"]


def bootstrap_outputs(plan) -> dict[str, Any]:
    prefix, account = plan.name_prefix, plan.account_id
    return {
        "control_bucket": f"{prefix}-{account}-control",
        "state_keys": {root: f"state/{root}.tfstate"
                       for root in ("bootstrap", "foundation", "releases", "services")},
        "operator_role_arn": f"arn:aws:iam::{account}:role/{prefix}-operator",
    }  # fmt: skip


def foundation_outputs(plan, admin_secret_arns: dict[str, str] | None = None) -> dict[str, Any]:
    prefix, account, region = plan.name_prefix, plan.account_id, plan.region
    namespace = plan.inputs["foundation"]["private_dns_namespace"]
    registry = f"{account}.dkr.ecr.{region}.amazonaws.com"

    def administrator(name: str) -> str:
        h = sha(name)
        return (f"arn:aws:secretsmanager:{region}:{account}:secret:rds!db-"
                f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}-{h[32:38]}")  # fmt: skip

    admin = admin_secret_arns or {name: administrator(name) for name in ("runtime", "product")}
    return {
        "vpc_id": "vpc-0a1b2c3d4e5f60718",
        # The subnets the offline ECS fakes attach task ENIs in.
        "task_subnet_ids": ["subnet-0a1b2c3d4e5f60718", "subnet-0f1e2d3c4b5a69788"],
        "security_group_ids": {name: "sg-0" + sha(name)[:16] for name in SECURITY_GROUPS},
        "cluster_arn": f"arn:aws:ecs:{region}:{account}:cluster/{prefix}",
        "discovery_service_arns": {
            "runtime": f"arn:aws:servicediscovery:{region}:{account}:service/srv-runtime0000000001",
            "api": f"arn:aws:servicediscovery:{region}:{account}:service/srv-api00000000000002",
        },
        "private_dns_namespace": namespace,
        "repository_urls": {"runtime": f"{registry}/{prefix}/runtime",
                            "search": f"{registry}/{prefix}/search",
                            "release_tools": f"{registry}/{prefix}/release-tools"},
        "database_endpoints": {name: f"{name}-db.{namespace}" for name in ("runtime", "product")},
        "database_admin_secret_arns": admin,
    }  # fmt: skip


def releases_outputs(plan, rendered: dict[str, Any], revision: int = 1) -> dict[str, Any]:
    """What the releases root reports for the rendered current release."""
    prefix, account, region = plan.name_prefix, plan.account_id, plan.region
    ((key, release),) = rendered["releases"].items()
    scope = f"{prefix}-{key}"

    def family(name: str) -> str:
        return f"arn:aws:ecs:{region}:{account}:task-definition/{prefix}-{name}:{revision}"

    definitions = {name: family(name) for name in ("runtime", "api", "worker")}
    roles = {}
    for name in ("runtime", "api", "worker"):
        roles[f"{name}-task"] = f"{scope}-{name}-task"
        roles[f"{name}-execution"] = f"{scope}-{name}-execution"
    for database in ("runtime", "product"):
        definitions[f"{database}-release"] = family(f"{database}-release")
        roles[f"{database}-release-task"] = f"{scope}-{database}-release-task"
        roles[f"{database}-release-execution"] = f"{scope}-{database}-release-execution"
        for kind, role in TOOLS_JOBS.items():
            definitions[f"{database}-{kind}"] = family(f"{database}-{kind}")
            roles[f"{database}-{role}-execution"] = f"{scope}-{database}-{role}-execution"
        definitions[f"{database}-bootstrap"] = family(f"{database}-bootstrap")
        # Keys as iam_role_names gives them; names as deploy/aws-platform-fit makes them.
        roles[f"{database}-bootstrap-task"] = f"{scope}-{database}-boot-task"
        roles[f"{database}-bootstrap-execution"] = f"{scope}-{database}-boot-execution"
    for check in ("runtime-observe", "api-observe"):
        definitions[check] = family(check)
        roles[f"{check}-execution"] = f"{scope}-{check}-execution"
    roles["runtime-observe-task"] = f"{scope}-runtime-observe-task"
    tools = release["release_tools"]
    namespace = plan.inputs["releases"]["private_dns_namespace"]
    identities = {database: tools[database] for database in ("runtime", "product")}
    bindings = {
        "release_id": release["release_id"], "not_after": tools["not_after"],
        "budget_seconds": tools["budget_seconds"], "tools_sha256": tools["tools_sha256"],
        "receipt_schema": "sentry.release-tools.job.v1",
        "migration_receipt_schema": "sentry.release-migration.v1",
        "migration_expectations": {
            f"{database}-migrate": {"database": ids["database"], "principal": ids["owner"]}
            for database, ids in identities.items()
        },
        "expectations": {
            **{f"{database}-grant": {"database": ids["database"], "principal": ids["owner"],
                                     "service_role": ids["service"],
                                     "sql_digest": tools["sql_sha256"][f"{database}_grant"]}
               for database, ids in identities.items()},
            **{f"{database}-proof": {"database": ids["database"], "principal": ids["service"]}
               for database, ids in identities.items()},
        },
    }  # fmt: skip
    groups = rendered["observer_security_group_ids"]
    return {
        "releases": {key: {
            "release_id": release["release_id"], "slot": "current",
            "task_definition_arns": definitions, "iam_role_names": roles,
            "tools_bindings": bindings,
            "observer_bindings": {"receipt_schema": "sentry.operational.v1",
                                  "budget_seconds": release["observers"]["budget_seconds"],
                                  "checks": {"runtime-observe": {"target": "runtime",
                                                                 "host": f"runtime.{namespace}",
                                                                 "port": 8443},
                                             "api-observe": {"target": "api",
                                                             "host": f"api.{namespace}",
                                                             "port": 8001}}},
            "bootstrap_bindings": {
                f"{database}-bootstrap": {
                    "database": ids["database"],
                    "principal": release["bootstrap"][database]["administrator"],
                    "owner_role": ids["owner"], "service_role": ids["service"]}
                for database, ids in identities.items()},
            "definitions_sha256": sha(json.dumps(release, sort_keys=True)),
        }},
        "current_release": key,
        "rollback_release": None,
        "current_service_task_definitions": {name: definitions[name]
                                             for name in ("runtime", "api", "worker")},
        "release_launcher_policies": {name: {"Version": "2012-10-17"}
                                      for name in ("jobs", "services", "receipts", "tasks",
                                                   "observe")},
        "release_launcher_bootstrap_policy": {"Version": "2012-10-17"},
        "observer_networks": {"runtime-observe": [groups["runtime"]],
                              "api-observe": [groups["api"]]},
    }  # fmt: skip


def services_outputs(plan) -> dict[str, Any]:
    return {"service_arns": plan.skeleton["environment"]["services"]}


def custodian_files(directory: Path, bundles: dict[str, tuple[str, ...]]) -> None:
    """One owner-only JSON file per bundle, every value a placeholder."""
    for purpose, keys in bundles.items():
        path = directory / f"{purpose}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({key: f"placeholder-{sha(purpose + key)[:16]}" for key in keys}))
        path.chmod(0o400)


def risk_decision(path: Path, images: dict[str, str], **changes: Any) -> Path:
    document = {"schema": "sentry.risk-decision.v1", "decision_id": "fixture-risk-decision",
                "decided_by": "fixture-release-owner", "decided_at": "2026-10-17T00:00:00Z",
                "expires_at": (datetime.now(UTC) + timedelta(days=14)).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"), "retained_findings": 27, "images": images,
                **changes}  # fmt: skip
    path.write_text(json.dumps(document, indent=2))
    return path
