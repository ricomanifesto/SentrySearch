"""Deterministic offline fixtures for the Cloudflare release path.

Every identifier is synthetic: the account, zone, namespace, application and
version ids below are derived from labels and name no real resource.
"""

from __future__ import annotations

from datetime import timedelta
import hashlib
from typing import Any

from tests.release_fakes import PRIOR_RELEASE_ID, RELEASE_ID, RUNTIME_GRANT, START, digest, iso, sha

ACCOUNT = hashlib.sha256(b"fixture-account").hexdigest()[:32]
ZONE = hashlib.sha256(b"fixture-zone").hexdigest()[:32]
REGISTRY = f"registry.cloudflare.com/{ACCOUNT}"
WORKERS = ("edge", "api", "worker", "runtime", "jobs")
CONTAINER_WORKERS = ("api", "worker", "runtime", "jobs")


def uuid_of(label: str) -> str:
    """A version-4-shaped UUID derived from a label (synthetic, never a real id)."""
    value = hashlib.sha256(label.encode()).hexdigest()
    return f"{value[:8]}-{value[8:12]}-4{value[13:16]}-8{value[17:20]}-{value[20:32]}"


def hex32(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()[:32]


def versions(label: str) -> dict[str, str]:
    return {worker: uuid_of(f"{label}-{worker}-version") for worker in WORKERS}


def image(name: str, label: str = "candidate") -> dict:
    return {
        "repository": f"{REGISTRY}/sentry-staging-{name}",
        "amd64_digest": digest(f"{name}-{label}-amd64"),
        "provenance_sha256": sha(f"{name}-{label}-provenance"),
        "sbom_sha256": sha(f"{name}-{label}-sbom"),
        "scan_sha256": sha(f"{name}-{label}-scan"),
    }


def application(worker: str, images: tuple[str, ...]) -> dict:
    return {
        "id": uuid_of(f"{worker}-application"),
        "scheduling_policy": "durable_object",
        "instance_type": "lite" if worker in ("runtime", "jobs") else "standard-1",
        "ssh_enabled": False,
        "logs_enabled": False,
        "images": list(images),
    }


def secrets(worker: str, *names: str) -> list[dict]:
    return [{"name": name, "sha256": sha(f"{worker}-{name}-value")} for name in names]


def job(job_id: str, phase: str, database: str, *, image_key: str, expect: dict, sql=None) -> dict:
    result = {
        "id": job_id,
        "phase": phase,
        "database": database,
        "image": image_key,
        "deadline_seconds": 900,
        "stop_grace_seconds": 30,
        "receipt_schema": (
            "sentry.release.migrate.cloudflare.v1"
            if phase == "migrate"
            else "sentry.release-tools.job.cloudflare.v1"
        ),
        "expect": expect,
    }
    if sql is not None:
        result["sql"] = sql
    return result


def manifest_document(*, rollback: str = "empty_hold") -> dict:
    db = {"database": "runtime_db", "principal": "runtime_owner"}
    product = {"database": "product_db", "principal": "product_owner"}
    product_schema = "sentrysearch:1:" + sha("001_release.sql")[:16]
    document: dict[str, Any] = {
        "schema_version": 1,
        "platform": "cloudflare",
        "release_id": RELEASE_ID,
        "milestone": "operational-paused",
        "environment": {
            "name": "staging",
            "account_id": ACCOUNT,
            "zone_id": ZONE,
            "workers": {worker: f"sentry-staging-{worker}" for worker in WORKERS},
            "namespaces": {worker: hex32(f"{worker}-namespace") for worker in CONTAINER_WORKERS},
            "bootstrap_versions": versions("bootstrap"),
        },
        "operator": "fixture-operator",
        "window": {
            "not_before": iso(START - timedelta(hours=1)),
            "expires_at": iso(START + timedelta(hours=6)),
            "total_seconds": 3600,
            "poll_seconds": 5,
            "service_start_seconds": 600,
        },
        "sources": {"runtime": "b" * 40, "search": "c" * 40, "release_tools": "c" * 40},
        "images": {name: image(name) for name in ("runtime", "search", "release_tools")},
        "risk": {
            "decision_id": "fixture-risk-decision",
            "decision_sha256": sha("fixture-risk-decision"),
            "decided_by": "fixture-release-owner",
            "expires_at": iso(START + timedelta(days=7)),
            "retained_findings": 27,
        },
        "plan_sha256": sha("fixture-reviewed-plan"),
        "versions": versions("candidate"),
        "applications": {
            "api": application("api", ("search",)),
            "worker": application("worker", ("search",)),
            "runtime": application("runtime", ("runtime",)),
            "jobs": application("jobs", ("release_tools", "runtime", "search")),
        },
        "storage": {
            "artifacts_bucket": "sentry-staging-artifacts",
            "control_bucket": "sentry-staging-control",
            "jurisdiction": "default",
        },
        "placement": {"regions": ["ENAM"]},
        "secrets": {
            "edge": [],
            "api": secrets("api", "SEARCH_DATABASE_URL", "R2_ACCESS_KEY"),
            "worker": secrets("worker", "SEARCH_DATABASE_URL", "RUNTIME_WORKER_TOKEN"),
            "runtime": secrets("runtime", "RUNTIME_DATABASE_URL", "RUNTIME_TLS_KEY"),
            "jobs": secrets("jobs", "RUNTIME_OWNER_PASSWORD", "PRODUCT_OWNER_PASSWORD"),
        },
        "operator_key_id": sha("fixture-operator-key"),
        "wrangler_min_version": "4.141.0",
        "jobs": [
            job("runtime-migrate", "migrate", "runtime", image_key="runtime",
                expect={**db, "schema": "goose:1,2,3"}),
            job("product-migrate", "migrate", "product", image_key="search",
                expect={**product, "schema": product_schema}),
            job("runtime-grant", "grant", "runtime", image_key="release_tools",
                expect={**db, "service_role": "runtime_service",
                        "sql_digest": RUNTIME_GRANT["sha256"]},
                sql=dict(RUNTIME_GRANT)),
            job("product-grant", "grant", "product", image_key="release_tools",
                expect={**product, "service_role": "product_service",
                        "sql_digest": sha("product-grants")},
                sql={"path": "release_tools/sql/product/grants.sql", "source_commit": "c" * 40,
                     "sha256": sha("product-grants")}),
            job("runtime-proof", "proof", "runtime", image_key="release_tools",
                expect={"database": "runtime_db", "principal": "runtime_service",
                        "schema": "goose:1,2,3"}),
            job("product-proof", "proof", "product", image_key="release_tools",
                expect={"database": "product_db", "principal": "product_service",
                        "schema": product_schema}),
        ],  # fmt: skip
        "operational_checks": [
            {"id": "worker-readiness", "receipt_schema": "sentry.worker-readiness.v1"},
            {
                "id": "runtime-protected-readiness",
                "receipt_schema": "sentry.release.runtime-ready.cloudflare.v1",
            },
            {"id": "api-operational", "receipt_schema": "sentry.release.api-ready.cloudflare.v1"},
        ],
        "rollback": {"kind": "empty_hold"},
    }
    if rollback == "compatible_release":
        document["rollback"] = {
            "kind": "compatible_release",
            "release_id": PRIOR_RELEASE_ID,
            "versions": versions("prior"),
            "images": {
                name: {
                    "repository": f"{REGISTRY}/sentry-staging-{name}",
                    "amd64_digest": digest(f"{name}-prior-amd64"),
                }
                for name in ("runtime", "search")
            },
            "trust_sha256": sha("prior-trust"),
            "compatible_schemas": {"runtime": ["goose:1,2,3"], "product": [product_schema]},
            "backups": {
                "runtime": "vendor:snapshot/runtime-pre-release",
                "product": "vendor:snapshot/product-pre-release",
            },
        }
    return document


def approval_document(manifest_sha256: str, **changes: Any) -> dict:
    document = {
        "schema_version": 1,
        "kind": "cloudflare-release-approval",
        "release_id": RELEASE_ID,
        "manifest_sha256": manifest_sha256,
        "environment": "staging",
        "account_id": ACCOUNT,
        "zone_id": ZONE,
        "milestone": "operational-paused",
        "approved_by": "fixture-approver",
        "not_before": iso(START - timedelta(minutes=30)),
        "not_after": iso(START + timedelta(hours=4)),
    }
    document.update(changes)
    return document
