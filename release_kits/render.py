"""Every value a later AWS-07b step needs, rendered from the plan and earlier receipts.

Nothing here is typed by the operator. Names follow ``deploy/aws-staging/modules/
naming`` and ``deploy/aws-platform-fit``; identifiers that only exist after an
apply (subnets, security groups, revisions, role names, secret ARNs and version
IDs, pushed digests) come from the receipt of the step that produced them. The
rendered manifest is loaded by the release controller's own parser before the
kit writes it, so a value the controller would refuse is refused here first.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
import re
from typing import Any

from release.manifest import RUNTIME_GRANT_PIN, load_approval, load_manifest
from release_kits.plan import AccountPlan, sha256
from src.execution import provider_canary

# Secret bundles the custodian creates (operational proposal, section 4). One
# secret per purpose; a later release adds versions to the same secrets.
SERVICE_DB_KEYS = ("DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD")
BUNDLES: dict[str, tuple[str, ...]] = {
    "environment/runtime": ("DATABASE_URL", "SENTRYRUNTIME_AUTH_CREDENTIALS"),
    "environment/api": SERVICE_DB_KEYS,
    "environment/worker": (*SERVICE_DB_KEYS, "SENTRYRUNTIME_PRODUCER_TOKEN",
                           "SENTRYRUNTIME_WORKER_TOKEN"),
    "material/runtime": ("server-cert.pem", "server-key.pem", "runtime-ca.pem",
                         "postgres-ca.pem", "probe-token"),
    "material/api": ("runtime-ca.pem", "postgres-ca.pem"),
    "material/worker": ("runtime-ca.pem", "postgres-ca.pem"),
    "owner-environment/runtime": ("DATABASE_URL",),
    "owner-environment/product": SERVICE_DB_KEYS,
    "owner-material/runtime": ("postgres-ca.pem",),
    "owner-material/product": ("postgres-ca.pem",),
    "proof-environment/runtime": ("DATABASE_URL",),
    "proof-environment/product": SERVICE_DB_KEYS,
    "observer-material/runtime": ("runtime-ca.pem", "probe-token"),
    "bootstrap-credentials/runtime": ("RELEASE_OWNER_PASSWORD", "RELEASE_SERVICE_PASSWORD"),
    "bootstrap-credentials/product": ("RELEASE_OWNER_PASSWORD", "RELEASE_SERVICE_PASSWORD"),
    "bootstrap-ca/runtime": ("postgres-ca.pem",),
    "bootstrap-ca/product": ("postgres-ca.pem",),
}  # fmt: skip
# A release whose record names a provider canary also gives its worker a provider
# key; every other release keeps the disabled scaffold and has no such bundle.
PROVIDER_BUNDLE = "provider-key/worker"
PROVIDER_KEYS = ("OPENROUTER_API_KEY",)
PROVIDER_FIELDS = ("canary_id", "canary_manifest", "canary_manifest_sha256", "base_url")
DATABASES = ("runtime", "product")
# The logins bootstrap creates and every later job and bundle uses.
IDENTITIES = {
    "runtime": {"database": "runtime_db", "owner": "runtime_owner", "service": "runtime_service"},
    "product": {"database": "product_db", "owner": "product_owner", "service": "product_service"},
}
# Fixed for every release this kit renders; recorded in the init receipt.
TOOLS_BUDGET_SECONDS = 900
OBSERVER_BUDGET_SECONDS = 300
JOB_DEADLINE_SECONDS = 900
OBSERVER_DEADLINE_SECONDS = 300
STOP_GRACE_SECONDS = 30
TOOLS_DEADLINE = timedelta(hours=72)
WINDOW = {"total_seconds": 3600, "poll_seconds": 5, "service_start_seconds": 600}
WINDOW_LENGTH = timedelta(hours=4)
SQL = {
    "runtime_grant": "sql/runtime/service.sql", "product_grant": "sql/product/grants.sql",
    "runtime_proof": "sql/runtime/proof.sql", "product_proof": "sql/product/proof.sql",
    "reconcile": "sql/reconcile.sql",
}  # fmt: skip
IMAGE_KEYS = {"runtime": "runtime", "search": "search", "release_tools": "release-tools"}


def iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def release_key(release_id: str) -> str:
    return "r" + release_id[:8]


def registry(plan: AccountPlan) -> str:
    return f"{plan.account_id}.dkr.ecr.{plan.region}.amazonaws.com"


def repositories(plan: AccountPlan) -> dict[str, str]:
    """ECR repository names (naming module), keyed like the manifest's images."""
    return {key: f"{plan.name_prefix}/{name}" for key, name in IMAGE_KEYS.items()}


def secret_name(plan: AccountPlan, purpose: str) -> str:
    return f"{plan.name_prefix}/{purpose}"


def control_bucket(plan: AccountPlan) -> str:
    return f"{plan.name_prefix}-{plan.account_id}-control"


def backend(plan: AccountPlan, root: str, state_path: str | None = None) -> dict[str, str]:
    if root == "bootstrap":
        return {"path": str(state_path)}
    return {"bucket": control_bucket(plan), "key": f"state/{root}.tfstate", "region": plan.region}


def policy_arn(plan: AccountPlan, name: str) -> str:
    return f"arn:aws:iam::{plan.account_id}:policy/{name}"


def role_arn(plan: AccountPlan, name: str) -> str:
    return f"arn:aws:iam::{plan.account_id}:role/{name}"


def attended_policies(plan: AccountPlan, releases: dict[str, Any]) -> dict[str, list[str]]:
    """The policies section 7 step 7 attaches, by name, from the releases root's outputs."""
    prefix = plan.name_prefix
    attended = sorted(f"{prefix}-release-launcher-{key}"
                      for key in releases["release_launcher_policies"])  # fmt: skip
    bootstrap = ([f"{prefix}-release-launcher-bootstrap"]
                 if releases.get("release_launcher_bootstrap_policy") is not None else [])  # fmt: skip
    return {"attended": attended, "evidence": [f"{prefix}-release-evidence"],
            "bootstrap": bootstrap}  # fmt: skip


# The releases root -------------------------------------------------------------------


def model_provider(record: dict[str, Any], now: datetime) -> dict[str, str] | None:
    """The provider canary the release record names, or None: the worker keeps the
    disabled scaffold."""
    named = record.get("provider")
    return None if named is None else check_provider(named, now)


def check_provider(named: Any, now: datetime) -> dict[str, str]:
    """A named provider canary, checked as the worker will check it."""
    if (
        not isinstance(named, dict)
        or set(named) != set(PROVIDER_FIELDS)
        or not all(isinstance(value, str) and value for value in named.values())
    ):
        raise ValueError(f"the release's provider names {', '.join(sorted(PROVIDER_FIELDS))}")
    manifest = named["canary_manifest"]
    if sha256(manifest.encode()) != named["canary_manifest_sha256"]:
        raise ValueError("the canary manifest is not the one the release names")
    try:
        caps = provider_canary.load(json.loads(manifest))
    except (ValueError, TypeError, AttributeError, KeyError):
        raise ValueError("the release's canary is not a usable canary manifest") from None
    if caps.canary_id != named["canary_id"]:
        raise ValueError("the canary manifest is not the one the release names")
    if now >= caps.not_after:
        raise ValueError("the release's canary has expired")
    if not re.fullmatch(r"https://[a-z0-9]([a-z0-9.-]*[a-z0-9])?(/[A-Za-z0-9._~/-]*)?",
                        named["base_url"]):  # fmt: skip
        raise ValueError("the provider's base_url is an https address")
    if not provider_canary.names_model_host(caps, named["base_url"]):
        raise ValueError("the release's canary does not name the base_url's host")
    return {field: named[field] for field in PROVIDER_FIELDS}


def provider_binding(plan: AccountPlan, record: dict[str, Any], bundles: dict[str, dict[str, str]],
                     rendered_release: dict[str, Any], document: dict[str, Any],
                     now: datetime) -> dict[str, str] | None:  # fmt: skip
    """The worker's provider canary as every link of the chain names it, or None when no
    link names one. ValueError when the record, the releases input, custody and the
    manifest disagree, or the canary ends at or before the manifest window's end."""
    canary = model_provider(record, now)
    rendered = rendered_release.get("model_provider")
    held = bundles.get(PROVIDER_BUNDLE)
    worker = document["services"]["worker"]["secrets"]
    key_prefix = f":secret:{secret_name(plan, PROVIDER_BUNDLE)}-"
    if canary is None:
        if rendered is not None:
            raise ValueError("the releases input names a provider the release record does not")
        if held is not None:
            raise ValueError("custody holds a provider key, but the release names no canary")
        if any(key_prefix in secret["arn"] for secret in worker):
            raise ValueError("the worker reads a provider key, but the release names no canary")
        return None
    if rendered is None or {field: rendered.get(field) for field in
                            ("base_url", "canary_manifest", "canary_manifest_sha256")} != {
            field: canary[field] for field in ("base_url", "canary_manifest",
                                               "canary_manifest_sha256")}:  # fmt: skip
        raise ValueError("the releases input's provider is not the release record's canary")
    if held is None:
        raise ValueError("custody holds no provider key for the release's canary")
    if rendered.get("key_bundle") != held:
        raise ValueError("the releases input reads another provider key than custody created")
    if not worker or worker[-1] != held:
        raise ValueError("the manifest's worker secrets do not end with the provider key")
    not_after = provider_canary.load(json.loads(canary["canary_manifest"])).not_after
    window_end = datetime.strptime(document["window"]["expires_at"], "%Y-%m-%dT%H:%M:%SZ")
    if not not_after > window_end.replace(tzinfo=UTC):
        raise ValueError("the canary ends at or before the release window does")
    return {"canary_id": canary["canary_id"],
            "canary_manifest_sha256": canary["canary_manifest_sha256"],
            "key_version_id": held["version_id"],
            "approval_sha256": record["provider_approval"]["sha256"]}  # fmt: skip


def describe_provider(binding: dict[str, str] | None) -> str:
    if binding is None:
        return "worker: no provider"
    return (
        f"worker provider canary {binding['canary_id']}, manifest "
        f"{binding['canary_manifest_sha256']}, key version {binding['key_version_id']}"
    )


def releases_input(plan: AccountPlan, record: dict[str, Any], foundation: dict[str, Any],
                   bundles: dict[str, dict[str, str]], admin: dict[str, dict[str, str]],
                   pushed: dict[str, str], now: datetime) -> dict[str, Any]:  # fmt: skip
    """The releases root's variables for a first deployment: one current release."""
    release_id = record["release_id"]
    urls = foundation["repository_urls"]
    expected = {key: f"{registry(plan)}/{name}" for key, name in repositories(plan).items()}
    if {key: urls[key] for key in expected} != expected:
        raise ValueError("the foundation's repository URLs are not this plan's repositories")
    sql = record["pins"]["sql"]
    tools: dict[str, Any] = {
        "image": f"{urls['release_tools']}@{pushed['release_tools']}",
        "not_after": iso(now + TOOLS_DEADLINE),
        "budget_seconds": TOOLS_BUDGET_SECONDS,
        "tools_sha256": record["pins"]["tools_sha256"],
        "sql_sha256": {name: sql[path] for name, path in SQL.items()},
    }
    for database in DATABASES:
        tools[database] = {**IDENTITIES[database],
                           "proof_bundle": bundles[f"proof-environment/{database}"]}  # fmt: skip
    release = {
        "release_id": release_id,
        "slot": "current",
        "images": {name: f"{urls[name]}@{pushed[name]}" for name in ("runtime", "search")},
        "environment_bundles": {name: bundles[f"environment/{name}"]
                                for name in ("runtime", "api", "worker")},
        "material_bundles": {name: bundles[f"material/{name}"]
                             for name in ("runtime", "api", "worker")},
        "release_jobs": {
            **{database: {"environment_bundle": bundles[f"owner-environment/{database}"],
                          "material_bundle": bundles[f"owner-material/{database}"]}
               for database in DATABASES},
            "runtime_grants": {"source_commit": RUNTIME_GRANT_PIN["source_commit"],
                               "sql_sha256": RUNTIME_GRANT_PIN["sha256"]},
        },
        "release_tools": tools,
        "observers": {"budget_seconds": OBSERVER_BUDGET_SECONDS,
                      "runtime_bundle": bundles["observer-material/runtime"]},
        "bootstrap": {
            "sql_sha256": sql["sql/bootstrap.sql"],
            **{database: {
                "host": foundation["database_endpoints"][database],
                "administrator": f"{database}_admin",
                "admin_secret": admin[database],
                "credentials": bundles[f"bootstrap-credentials/{database}"],
                "ca_bundle": bundles[f"bootstrap-ca/{database}"],
            } for database in DATABASES},
        },
    }  # fmt: skip
    provider = model_provider(record, now)
    if provider is not None:
        release["model_provider"] = {
            **{field: provider[field]
               for field in ("base_url", "canary_manifest", "canary_manifest_sha256")},
            "key_bundle": bundles[PROVIDER_BUNDLE],
        }  # fmt: skip
    groups = foundation["security_group_ids"]
    return {
        "releases": {release_key(release_id): release},
        "observer_security_group_ids": {"runtime": groups["runtime_transport_proof"],
                                        "api": groups["api_proof"]},
    }  # fmt: skip


def services_input(foundation: dict[str, Any], releases: dict[str, Any]) -> dict[str, Any]:
    groups = foundation["security_group_ids"]
    return {
        "task_subnet_ids": foundation["task_subnet_ids"],
        "security_group_ids": {name: groups[name] for name in ("runtime", "api", "worker")},
        "discovery_service_arns": {name: foundation["discovery_service_arns"][name]
                                   for name in ("runtime", "api")},
        "task_definition_arns": releases["current_service_task_definitions"],
    }  # fmt: skip


# The release manifest and approval ---------------------------------------------------


def _task(plan: AccountPlan, release: dict[str, Any], family: str, task_role: str | None,
          execution_role: str, secrets: list[dict[str, str]], groups: list[str],
          containers: list[tuple[str, str]]) -> dict[str, Any]:  # fmt: skip
    names = release["iam_role_names"]
    spec: dict[str, Any] = {
        "task_definition": release["task_definition_arns"][family],
        "execution_role": role_arn(plan, names[execution_role]),
        "secrets": secrets,
        "security_groups": groups,
        "containers": [{"name": name, "image": image} for name, image in containers],
    }
    if task_role is not None:
        spec["task_role"] = role_arn(plan, names[task_role])
    return spec


def manifest(plan: AccountPlan, record: dict[str, Any], receipts: dict[str, dict[str, Any]],
             *, not_before: datetime, session_expires: datetime) -> dict[str, Any]:  # fmt: skip
    """The first deployment's schema-2 manifest, from the skeleton and every receipt."""
    foundation = receipts["foundation"]["outputs"]["terraform"]
    releases_out = receipts["releases"]["outputs"]["terraform"]
    bundles = receipts["custodian"]["outputs"]["bundles"]
    admin = receipts["custodian"]["outputs"]["administrator_secrets"]
    pushed = receipts["images"]["outputs"]["registry_digests"]
    release_id = record["release_id"]
    release = releases_out["releases"][release_key(release_id)]
    groups = foundation["security_group_ids"]
    urls = foundation["repository_urls"]
    document = json.loads(json.dumps(plan.skeleton))
    expires = min(not_before + WINDOW_LENGTH, session_expires - timedelta(minutes=10))
    document.update(
        release_id=release_id,
        window={"not_before": iso(not_before), "expires_at": iso(expires), **WINDOW},
        sources=record["sources"],
        risk=record["risk"],
        plan_sha256=receipts["services"]["outputs"]["plan_files_sha256"],
        network={"subnets": foundation["task_subnet_ids"], "assign_public_ip": "DISABLED",
                 "platform_version": "1.4.0"},
    )  # fmt: skip
    document["images"] = {
        key: {"repository": urls[key], "manifest_digest": record["images"][key]["index"],
              "arm64_digest": pushed[key],
              **{name: record["images"][key][name]
                 for name in ("provenance_sha256", "sbom_sha256", "scan_sha256")}}
        for key in IMAGE_KEYS
    }  # fmt: skip
    app = {"runtime": "runtime", "api": "search", "worker": "search"}
    secrets = {name: [bundles[f"environment/{name}"], bundles[f"material/{name}"]]
               for name in ("runtime", "api", "worker")}  # fmt: skip
    if record.get("provider") is not None and PROVIDER_BUNDLE in bundles:
        # The worker's task definition also reads its provider key; a named canary
        # whose key custody does not hold is refused by provider_binding.
        secrets["worker"].append(bundles[PROVIDER_BUNDLE])
    document["services"] = {
        name: _task(plan, release, name, f"{name}-task", f"{name}-execution", secrets[name],
                    [groups[name]], [("init", "search"), ("app", app[name])])
        for name in ("runtime", "api", "worker")
    }  # fmt: skip
    tools = release["tools_bindings"]
    schemas = record["schemas"]
    jobs = []
    for database in DATABASES:
        expect = release["bootstrap_bindings"][f"{database}-bootstrap"]
        jobs.append(_job(plan, release, f"{database}-bootstrap", "bootstrap", database, expect,
                         [admin[database], bundles[f"bootstrap-credentials/{database}"],
                          bundles[f"bootstrap-ca/{database}"]],
                         [groups[f"{database}_db_jobs"]], "release_tools"))  # fmt: skip
    migration_image = {"runtime": "runtime", "product": "search"}
    for phase in ("migrate", "grant", "proof"):
        for database in DATABASES:
            key = f"{database}-{phase}"
            owner = [
                bundles[f"owner-environment/{database}"],
                bundles[f"owner-material/{database}"],
            ]
            if phase == "migrate":
                expect = {**tools["migration_expectations"][key], "schema": schemas[database]}
                jobs.append(
                    _job(
                        plan,
                        release,
                        key,
                        phase,
                        database,
                        expect,
                        owner,
                        [groups[f"{database}_db_jobs"]],
                        migration_image[database],
                    )
                )
                continue
            expect = dict(tools["expectations"][key])
            secrets = owner
            if phase == "proof":
                expect["schema"] = schemas[database]
                secrets = [bundles[f"proof-environment/{database}"],
                           bundles[f"owner-material/{database}"]]  # fmt: skip
            job = _job(plan, release, key, phase, database, expect, secrets,
                       [groups[f"{database}_db_jobs"]], "release_tools")  # fmt: skip
            if phase == "grant":
                job["sql"] = (dict(RUNTIME_GRANT_PIN) if database == "runtime" else
                              {"path": "release_tools/sql/product/grants.sql",
                               "source_commit": record["sources"]["release_tools"],
                               "sha256": expect["sql_digest"]})  # fmt: skip
            jobs.append(job)
    document["jobs"] = jobs
    networks = releases_out["observer_networks"]
    observers = release["observer_bindings"]["checks"]
    checks: list[dict[str, Any]] = [{"id": "worker-readiness",
                                     "receipt_schema": "sentry.worker-readiness.v1"}]  # fmt: skip
    for key, target in (("runtime-observe", "runtime"), ("api-observe", "api")):
        binding = observers[key]
        if target == "runtime":
            task = _task(plan, release, key, "runtime-observe-task", f"{key}-execution",
                         [bundles["observer-material/runtime"]], networks[key],
                         [("init", "search"), ("observer", "release_tools")])  # fmt: skip
        else:
            task = _task(plan, release, key, None, f"{key}-execution", [], networks[key],
                         [("observer", "release_tools")])  # fmt: skip
        checks.append({"id": key, "receipt_schema": "sentry.operational.v1", "target": target,
                       "host": binding["host"], "port": binding["port"], "task": task,
                       "deadline_seconds": OBSERVER_DEADLINE_SECONDS,
                       "stop_grace_seconds": STOP_GRACE_SECONDS})  # fmt: skip
    document["operational_checks"] = checks
    load_manifest(json.dumps(document).encode())  # the controller's own refusal, first
    return document


def _job(plan: AccountPlan, release: dict[str, Any], key: str, phase: str, database: str,
         expect: dict[str, str], secrets: list[dict[str, str]], groups: list[str],
         image: str) -> dict[str, Any]:  # fmt: skip
    if phase == "migrate":
        family, task_role, execution = (f"{database}-release", f"{database}-release-task",
                                        f"{database}-release-execution")  # fmt: skip
        container = "migration"
    elif phase == "bootstrap":
        family, task_role, execution = key, f"{key}-task", f"{key}-execution"
        container = "bootstrap"
    else:
        role = {"grant": "grant", "proof": "proof", "reconcile": "recon"}[phase]
        family, task_role, execution = (key, f"{database}-release-task",
                                        f"{database}-{role}-execution")  # fmt: skip
        container = phase
    return {
        "id": key, "phase": phase, "database": database,
        "task": _task(plan, release, family, task_role, execution, secrets, groups,
                      [("init", "search"), (container, image)]),
        "deadline_seconds": JOB_DEADLINE_SECONDS, "stop_grace_seconds": STOP_GRACE_SECONDS,
        "receipt_schema": ("sentry.release-migration.v1" if phase == "migrate"
                           else "sentry.release-tools.job.v1"),
        "expect": expect,
    }  # fmt: skip


def approval(plan: AccountPlan, document: dict[str, Any]) -> dict[str, Any]:
    """The release approval bound to this manifest, inside its window."""
    loaded = load_manifest(json.dumps(document).encode())
    rendered = {
        "schema_version": 1, "kind": "release-approval", "release_id": document["release_id"],
        "manifest_sha256": loaded.sha256, "environment": plan.name_prefix,
        "account_id": plan.account_id, "region": plan.region, "milestone": "operational-paused",
        "approved_by": plan.operator, "not_before": document["window"]["not_before"],
        "not_after": document["window"]["expires_at"],
    }  # fmt: skip
    load_approval(json.dumps(rendered).encode())
    return rendered


# Restore verification (deploy/aws-staging/releases/restore.tf, docs/release-controller.md) ---

RESTORE_BUNDLES = ("restore-owner-environment", "restore-proof-environment")


def restore_bundle_keys(database: str) -> tuple[str, ...]:
    """A restore bundle holds the same keys as the database's owner environment."""
    return BUNDLES[f"owner-environment/{database}"]


def restore_pins(record: dict[str, Any], releases: dict[str, Any],
                 database: str) -> dict[str, str]:  # fmt: skip
    """The reconcile and proof program digests a verification pins: the tools image's
    report, which must be the programs the current release's definitions run.

    ValueError (``restore_proof_pin_mismatch``) otherwise: the verification would prove
    another inventory than the release did.
    """
    tools = releases["releases"][release_key(record["release_id"])]["release_tools"]
    sql = record["pins"]["sql"]
    pinned = {"reconcile": sql[SQL["reconcile"]], "proof": sql[SQL[f"{database}_proof"]]}
    current = {"reconcile": tools["sql_sha256"]["reconcile"],
               "proof": tools["sql_sha256"][f"{database}_proof"]}  # fmt: skip
    if pinned != current:
        raise ValueError("restore_proof_pin_mismatch: the tools image's reconcile or proof "
                         "program is not the one the current release runs")  # fmt: skip
    return pinned


def restore_entry(record: dict[str, Any], releases: dict[str, Any], database: str, *,
                  instance: str, not_after: datetime,
                  bundles: dict[str, dict[str, str]]) -> dict[str, Any]:  # fmt: skip
    """The releases root's ``restore_verifications`` entry for one database: the current
    release's release-tools image, its digest report and the two restore bundles."""
    tools = releases["releases"][release_key(record["release_id"])]["release_tools"]
    pinned = restore_pins(record, releases, database)
    return {
        "database": database, "instance_identifier": instance, "not_after": iso(not_after),
        "budget_seconds": TOOLS_BUDGET_SECONDS, "image": tools["image"],
        "tools_sha256": record["pins"]["tools_sha256"], "sql_sha256": pinned,
        "owner_bundle": bundles[f"restore-owner-environment/{database}"],
        "proof_bundle": bundles[f"restore-proof-environment/{database}"],
    }  # fmt: skip


def restore_manifest(current: dict[str, Any], restore: dict[str, Any], *, database: str,
                     instance: str, endpoint: str, verification_id: str,
                     bundles: dict[str, dict[str, str]], plan_sha256: str,
                     not_before: datetime, session_expires: datetime,
                     not_after: datetime) -> dict[str, Any]:  # fmt: skip
    """A restore_verify manifest of the current release's validated manifest.

    The release, services, images, rollback descriptor and checks are the current
    release's, unchanged. Only the window, the purpose, the plan hash and the two jobs
    are new: the restore definitions the releases root reported, the restore bundle
    with the database's owner CA bundle, and the current release's own proof
    expectation and program digest, read on the restored endpoint.
    """
    document = json.loads(json.dumps(current))
    expires = min(not_before + WINDOW_LENGTH, session_expires - timedelta(minutes=10), not_after)
    document["window"] = {"not_before": iso(not_before), "expires_at": iso(expires), **WINDOW}
    document["plan_sha256"] = plan_sha256
    document["purpose"] = {
        "kind": "restore_verify", "database": database, "restored_instance": instance,
        "restored_endpoint": endpoint, "verification_id": verification_id,
        "not_after": iso(not_after),
    }  # fmt: skip
    jobs = {job["id"]: job for job in current["jobs"]}
    proof, migrate = jobs[f"{database}-proof"], jobs[f"{database}-migrate"]
    shared = {"database": proof["expect"]["database"], "schema": proof["expect"]["schema"],
              "host": endpoint}  # fmt: skip
    expectations = {
        "rv-recon": {**shared, "principal": migrate["expect"]["principal"],
                     "release_sessions": "0", "owner_sessions": "0", "foreign_sessions": "0"},
        # The program the releases root fixed into the proof definition.
        "rv-proof": {**shared, "principal": proof["expect"]["principal"],
                     "sql_digest": restore["jobs"][f"{database}-rv-proof"]["expect"]["sql_digest"]},
    }  # fmt: skip
    purposes = {"rv-recon": "restore-owner-environment", "rv-proof": "restore-proof-environment"}
    reported = restore["jobs"]
    document["jobs"] = [{
        "id": f"{database}-{kind}", "phase": kind, "database": database,
        "task": {
            "task_definition": reported[f"{database}-{kind}"]["task_definition"],
            "task_role": reported[f"{database}-{kind}"]["task_role"],
            "execution_role": reported[f"{database}-{kind}"]["execution_role"],
            "secrets": [bundles[f"{purposes[kind]}/{database}"],
                        bundles[f"owner-material/{database}"]],
            "security_groups": proof["task"]["security_groups"],
            "containers": [{"name": "init", "image": "search"},
                           {"name": kind, "image": "release_tools"}],
        },
        "deadline_seconds": JOB_DEADLINE_SECONDS, "stop_grace_seconds": STOP_GRACE_SECONDS,
        "receipt_schema": "sentry.release-tools.job.v1", "expect": expectations[kind],
    } for kind in ("rv-recon", "rv-proof")]  # fmt: skip
    load_manifest(json.dumps(document).encode())  # the controller's own refusal, first
    return document
