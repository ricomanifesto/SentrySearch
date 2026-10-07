"""Strict release manifest, canonical hash and approval-binding contracts."""

from __future__ import annotations

import copy
import json
from datetime import timedelta

import pytest

from release.manifest import (
    ReleaseRejected,
    canonical_sha256,
    load_approval,
    load_manifest,
    verify_approval,
)
from tests.release_fakes import (
    ACCOUNT,
    REGION,
    START,
    approval_document,
    encode,
    iso,
    manifest_document,
)


def rejected(raw: bytes, *, loader=load_manifest) -> ReleaseRejected:
    with pytest.raises(ReleaseRejected) as error:
        loader(raw)
    return error.value


def mutate(path: str, value, *, rollback: str = "empty_hold") -> bytes:
    document = manifest_document(rollback=rollback)
    target = document
    keys = path.split(".")
    for key in keys[:-1]:
        target = target[int(key)] if isinstance(target, list) else target[key]
    last = keys[-1]
    if value is _DELETE:
        del target[last]
    elif isinstance(target, list):
        target[int(last)] = value
    else:
        target[last] = value
    return encode(document)


_DELETE = object()


def test_valid_manifest_has_a_canonical_hash_independent_of_formatting():
    document = manifest_document()
    loaded = load_manifest(encode(document))
    compact = json.dumps(document, separators=(",", ":"), sort_keys=False).encode()
    reordered = json.dumps(dict(reversed(list(document.items())))).encode()
    assert load_manifest(compact).sha256 == loaded.sha256 == load_manifest(reordered).sha256
    assert loaded.sha256 == canonical_sha256(document)
    changed = copy.deepcopy(document)
    changed["window"]["poll_seconds"] = 6
    assert load_manifest(encode(changed)).sha256 != loaded.sha256
    assert loaded.manifest.release_id == document["release_id"]


@pytest.mark.parametrize(
    "raw, code",
    [
        (b'{"schema_version": 1, "schema_version": 1}', "duplicate_key"),
        (b'{"schema_version": 1.0}', "non_integer_number"),
        (b'{"schema_version": NaN}', "non_integer_number"),
        (b"[1, 2]", "invalid_json"),
        (b"\xff", "invalid_json"),
    ],
)
def test_ambiguous_json_is_rejected_before_hashing(raw, code):
    assert rejected(raw).code == code


@pytest.mark.parametrize(
    "path, value, code, detail",
    [
        ("approved", True, "unknown_field", "approved"),
        ("environment.region_override", "us-west-2", "override_rejected", ""),
        ("jobs.0.task.overrides", {"command": ["sh"]}, "override_rejected", ""),
        ("services.api.containerOverrides", [], "override_rejected", ""),
        ("risk", _DELETE, "missing_field", "risk"),
        ("rollback", _DELETE, "missing_field", "rollback"),
        ("risk.decided_by", _DELETE, "missing_field", "risk.decided_by"),
        ("milestone", "synthetic-admission", "invalid_field", "milestone"),
        ("schema_version", 2, "invalid_field", "schema_version"),
        ("network.assign_public_ip", "ENABLED", "invalid_field", "network.assign_public_ip"),
        ("rollback", {"kind": "previous"}, "invalid_field", "rollback"),
        ("rollback", {"kind": "empty_hold", "release_id": "x"}, "unknown_field", "rollback"),
    ],
)
def test_schema_rejects_unknown_override_and_missing_fields(path, value, code, detail):
    error = rejected(mutate(path, value))
    assert error.code == code
    assert error.detail.startswith(detail)


@pytest.mark.parametrize(
    "path, value",
    [
        ("images.runtime.manifest_digest", "latest"),
        ("images.search.repository", f"{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/search:latest"),
        ("images.search.repository", f"{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/search@sha256:abc"),
        ("services.api.task_definition", f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/api"),
        ("services.api.task_definition", f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/api:0"),
        ("services.api.secrets.0.version_id", "AWSCURRENT"),
        ("sources.search", "main"),
        ("network.platform_version", "LATEST"),
        ("network.platform_version", "1.3.0"),
    ],
)
def test_mutable_or_floating_references_are_rejected(path, value):
    error = rejected(mutate(path, value))
    assert error.code in {"invalid_field", "mutable_reference"}, error


@pytest.mark.parametrize(
    "path, value",
    [
        ("environment.cluster_arn", "arn:aws:ecs:us-west-2:111122223333:cluster/sentry-staging"),
        ("environment.services.api", "arn:aws:ecs:us-east-1:444455556666:service/sentry-staging/api"),
        ("environment.services.api", "arn:aws:ecs:us-east-1:111122223333:service/other/api"),
        ("services.worker.task_role", "arn:aws:iam::444455556666:role/sentry-staging/worker"),
        ("services.worker.secrets.0.arn",
         "arn:aws:secretsmanager:eu-west-1:111122223333:secret:sentry-staging/w-AbC123"),
        ("images.runtime.repository", "444455556666.dkr.ecr.us-east-1.amazonaws.com/runtime"),
        ("jobs.2.task.task_definition", "arn:aws:ecs:us-west-2:111122223333:task-definition/g:7"),
    ],
)  # fmt: skip
def test_every_resource_must_belong_to_the_manifest_account_and_region(path, value):
    assert rejected(mutate(path, value)).code == "resource_scope_mismatch"


def test_rollback_backups_are_bound_to_account_and_region():
    raw = mutate(
        "rollback.backups.runtime",
        "arn:aws:rds:us-west-2:111122223333:snapshot:runtime",
        rollback="compatible_release",
    )
    assert rejected(raw).code == "resource_scope_mismatch"


def test_risk_decision_must_cover_the_release_window():
    raw = mutate("risk.expires_at", iso(START + timedelta(hours=5)))
    assert rejected(raw).code == "risk_expires_before_release"


def test_runtime_grant_requires_the_reviewed_pinned_source():
    document = manifest_document()
    document["jobs"][2]["sql"]["sha256"] = "0" * 64
    assert rejected(encode(document)).code == "grant_pin_mismatch"
    document = manifest_document()
    del document["jobs"][2]["sql"]
    assert rejected(encode(document)).code == "grant_sql_required"
    document = manifest_document()
    document["jobs"][0]["sql"] = document["jobs"][2]["sql"]
    assert rejected(encode(document)).code == "unexpected_sql"


@pytest.mark.parametrize("drop", [0, 3, 5])
def test_every_database_needs_its_ordered_migrate_grant_and_proof_job(drop):
    document = manifest_document()
    del document["jobs"][drop]
    assert rejected(encode(document)).code == "job_plan_invalid"


def test_jobs_cannot_run_out_of_order():
    document = manifest_document()
    document["jobs"][0], document["jobs"][2] = document["jobs"][2], document["jobs"][0]
    assert rejected(encode(document)).code == "job_plan_invalid"


def test_migrations_must_state_their_exact_schema_and_identity():
    document = manifest_document()
    del document["jobs"][0]["expect"]["schema"]
    assert rejected(encode(document)).code == "job_expectation_incomplete"
    document = manifest_document()
    del document["jobs"][4]["expect"]["principal"]
    assert rejected(encode(document)).code == "job_expectation_incomplete"


def test_service_and_owner_secret_bundles_stay_disjoint():
    document = manifest_document()
    document["services"]["worker"]["secrets"][0] = document["services"]["api"]["secrets"][0]
    assert rejected(encode(document)).code == "shared_secret_bundle"
    document = manifest_document()
    document["jobs"][0]["task"]["secrets"][0] = document["services"]["runtime"]["secrets"][0]
    assert rejected(encode(document)).code == "shared_secret_bundle"


def test_compatible_rollback_needs_a_distinct_complete_prior_release():
    document = manifest_document(rollback="compatible_release")
    assert load_manifest(encode(document)).manifest.rollback.kind == "compatible_release"
    same = copy.deepcopy(document)
    same["rollback"]["release_id"] = same["release_id"]
    assert rejected(encode(same)).code == "rollback_not_prior_release"
    for field in ("services", "backups", "compatible_schemas", "trust_sha256", "images"):
        missing = copy.deepcopy(document)
        del missing["rollback"][field]
        assert rejected(encode(missing)).code == "missing_field"
    empty = copy.deepcopy(document)
    empty["rollback"]["compatible_schemas"]["product"] = []
    assert rejected(encode(empty)).code == "invalid_field"


def test_window_must_be_ordered_and_bounded():
    assert rejected(mutate("window.expires_at", iso(START - timedelta(hours=2)))).code == (
        "window_invalid"
    )
    assert rejected(mutate("window.expires_at", iso(START + timedelta(days=9)))).code == (
        "window_invalid"
    )
    raw = mutate("window.expires_at", "2026-10-07T18:00:00+02:00")
    assert rejected(raw).code == "invalid_field"


# Approval receipts ----------------------------------------------------------


def approved(**changes):
    loaded = load_manifest(encode(manifest_document()))
    document = approval_document(loaded.sha256)
    document.update(changes)
    approval = load_approval(encode(document))
    return loaded, approval


def test_matching_approval_binds_hash_environment_milestone_and_interval():
    loaded, approval = approved()
    verify_approval(loaded, approval, START)
    assert len(approval.sha256) == 64


@pytest.mark.parametrize(
    "changes, now, code",
    [
        ({"manifest_sha256": "0" * 64}, START, "approval_manifest_mismatch"),
        ({"release_id": "11111111-2222-4333-8444-555555555555"}, START, "approval_scope_mismatch"),
        ({"account_id": "444455556666"}, START, "approval_scope_mismatch"),
        ({"region": "us-west-2"}, START, "approval_scope_mismatch"),
        ({"environment": "production"}, START, "approval_scope_mismatch"),
        ({}, START + timedelta(hours=4), "approval_expired"),
        ({}, START - timedelta(hours=1), "approval_not_yet_valid"),
        ({"not_after": iso(START + timedelta(hours=7))}, START, "approval_outlives_manifest"),
        ({"not_before": iso(START + timedelta(hours=1)),
          "not_after": iso(START)}, START, "approval_interval_invalid"),
    ],
)  # fmt: skip
def test_mismatched_or_out_of_window_approval_is_rejected(changes, now, code):
    loaded, approval = approved(**changes)
    with pytest.raises(ReleaseRejected) as error:
        verify_approval(loaded, approval, now)
    assert error.value.code == code


def test_approval_is_a_strict_external_document():
    loaded = load_manifest(encode(manifest_document()))
    document = approval_document(loaded.sha256, scope="all")
    assert rejected(encode(document), loader=load_approval).code == "unknown_field"
    document = approval_document(loaded.sha256, milestone="production")
    assert rejected(encode(document), loader=load_approval).code == "invalid_field"
