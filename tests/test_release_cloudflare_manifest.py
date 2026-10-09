"""Strict Cloudflare release manifest, canonical hash and approval-binding contracts.

Mirrors tests/test_release_manifest.py case by case for the Cloudflare schema,
then adds the Cloudflare-only identities and the cross-platform refusals.
"""

from __future__ import annotations

import copy
import json
from datetime import timedelta

import pytest

from release import manifest as aws
from release.manifest import ReleaseRejected, canonical_sha256
from release.readiness import WORKER_READINESS_CHECK, WORKER_RECEIPT_KIND
from release_cloudflare.manifest import (
    CLOUDFLARE_JOB_RECEIPT_SCHEMA,
    expected_job_receipt,
    load_approval,
    load_manifest,
    verify_approval,
)
from tests import release_fakes
from tests.cloudflare_fakes import ACCOUNT, ZONE, approval_document, hex32, manifest_document
from tests.release_fakes import START, encode, iso

OTHER_ACCOUNT = hex32("other-account")


def rejected(raw: bytes, *, loader=load_manifest) -> ReleaseRejected:
    with pytest.raises(ReleaseRejected) as error:
        loader(raw)
    return error.value


_DELETE = object()


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
    assert load_manifest(encode(manifest_document(rollback="compatible_release")))


def test_loaded_job_expectations_are_immutable_and_do_not_change_the_approval_binding():
    document = manifest_document()
    loaded = load_manifest(encode(document))
    approval = load_approval(encode(approval_document(loaded.sha256)))
    expected = dict(document["jobs"][0]["expect"])
    original = loaded.sha256
    with pytest.raises(TypeError):
        loaded.manifest.jobs[0].expect["schema"] = "unapproved"  # ty: ignore[invalid-assignment]
    document["jobs"][0]["expect"]["schema"] = "changed-input"
    serialized = loaded.manifest.model_dump(mode="json")
    serialized["jobs"][0]["expect"]["schema"] = "changed-output"
    assert dict(loaded.manifest.jobs[0].expect) == expected
    assert loaded.sha256 == original
    verify_approval(loaded, approval, START)


@pytest.mark.parametrize(
    "key",
    [
        "release_id",
        "job_id",
        "durable_object_id",
        "launch_nonce",
        "task_arn",
        "status",
        "result",
        "receipt_schema",
        "schema_version",
    ],
)
def test_expectations_cannot_override_receipt_envelope_identity_or_control_fields(key):
    document = manifest_document()
    document["jobs"][0]["expect"][key] = "forged"
    error = rejected(encode(document))
    assert (error.code, error.detail) == ("job_expectation_reserved", "jobs.runtime-migrate.expect")


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
        ("environment.zone_override", ZONE, "override_rejected", ""),
        ("applications.api.instance_override", "standard-4", "override_rejected", ""),
        ("jobs.0.overrides", {"command": ["sh"]}, "override_rejected", ""),
        ("risk", _DELETE, "missing_field", "risk"),
        ("rollback", _DELETE, "missing_field", "rollback"),
        ("platform", _DELETE, "missing_field", "platform"),
        ("platform", "aws", "invalid_field", "platform"),
        ("milestone", "synthetic-admission", "invalid_field", "milestone"),
        ("schema_version", 2, "invalid_field", "schema_version"),
        ("rollback", {"kind": "previous"}, "invalid_field", "rollback"),
        ("rollback", {"kind": "empty_hold", "release_id": "x"}, "unknown_field", "rollback"),
        ("applications.api.ssh_enabled", True, "invalid_field", "applications.api.ssh_enabled"),
        ("applications.worker.logs_enabled", True, "invalid_field", "applications.worker"),
        ("applications.jobs.scheduling_policy", "default", "invalid_field", "applications.jobs"),
        ("applications.runtime.instance_type", "basic", "invalid_field", "applications.runtime"),
        ("storage.jurisdiction", "moon", "invalid_field", "storage.jurisdiction"),
        ("images.runtime.arm64_digest", release_fakes.digest("x"), "unknown_field", "images"),
        ("jobs.0.task", {"task_definition": "x"}, "unknown_field", "jobs.0.task"),
    ],
)
def test_schema_rejects_unknown_override_and_missing_fields(path, value, code, detail):
    error = rejected(mutate(path, value))
    assert error.code == code
    assert error.detail.startswith(detail)


@pytest.mark.parametrize(
    "path, value",
    [
        ("images.runtime.amd64_digest", "latest"),
        ("images.search.repository", f"registry.cloudflare.com/{ACCOUNT}/search:latest"),
        ("images.search.repository", f"registry.cloudflare.com/{ACCOUNT}/search@sha256:abc"),
        ("versions.api", "latest"),
        ("versions.jobs", "11111111-2222-4333-8444-55555555555"),
        ("sources.search", "main"),
        ("wrangler_min_version", "latest"),
        ("wrangler_min_version", "3.99.0"),
        ("secrets.api.0.sha256", "not-a-digest"),
        ("operator_key_id", "ed25519:abc"),
    ],
)
def test_mutable_or_floating_references_are_rejected(path, value):
    assert rejected(mutate(path, value)).code in {"invalid_field", "mutable_reference"}


@pytest.mark.parametrize(
    "path, value",
    [
        ("images.runtime.repository", f"registry.cloudflare.com/{OTHER_ACCOUNT}/runtime"),
        ("images.search.repository", "docker.io/library/search"),
        ("images.release_tools.repository", f"registry.cloudflare.com/{ACCOUNT}x/tools"),
    ],
)
def test_every_image_must_belong_to_the_manifest_account_registry(path, value):
    assert rejected(mutate(path, value)).code == "resource_scope_mismatch"


def test_rollback_images_are_bound_to_the_account_registry():
    raw = mutate(
        "rollback.images.runtime.repository",
        f"registry.cloudflare.com/{OTHER_ACCOUNT}/runtime",
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


def test_release_tools_jobs_use_the_tools_image_and_the_cloudflare_receipt_schema():
    document = manifest_document()
    document["jobs"][2]["receipt_schema"] = aws.RELEASE_TOOLS_RECEIPT_SCHEMA
    assert rejected(encode(document)).code == "job_receipt_schema_invalid"
    document = manifest_document()
    document["jobs"][4]["image"] = "search"
    assert rejected(encode(document)).code == "job_image_invalid"
    assert CLOUDFLARE_JOB_RECEIPT_SCHEMA == "sentry.release-tools.job.cloudflare.v1"
    assert CLOUDFLARE_JOB_RECEIPT_SCHEMA != aws.RELEASE_TOOLS_RECEIPT_SCHEMA


@pytest.mark.parametrize(("job", "image"), [(0, "search"), (1, "runtime"), (0, "release_tools")])
def test_migrations_run_their_own_databases_image(job, image):
    document = manifest_document()
    document["jobs"][job]["image"] = image
    assert rejected(encode(document)).code == "job_image_invalid"


@pytest.mark.parametrize(
    "change",
    [
        lambda checks: checks.pop(0),
        lambda checks: checks[0].update(receipt_schema="sentry.release.worker-readiness.v1"),
        lambda checks: checks[1].update(receipt_schema=WORKER_RECEIPT_KIND),
    ],
)
def test_worker_readiness_is_proven_only_from_supervisor_receipts(change):
    document = manifest_document()
    assert document["operational_checks"][0] == {
        "id": WORKER_READINESS_CHECK,
        "receipt_schema": WORKER_RECEIPT_KIND,
    }
    change(document["operational_checks"])
    assert rejected(encode(document)).code == "worker_readiness_check_invalid"


def test_release_tools_job_ids_match_the_fixed_job_ids():
    document = manifest_document()
    document["jobs"][3]["id"] = "product-grants"
    assert rejected(encode(document)).code == "job_id_invalid"


def test_grant_receipts_must_echo_the_pinned_sql_digest():
    document = manifest_document()
    document["jobs"][2]["expect"]["sql_digest"] = "0" * 64
    assert rejected(encode(document)).code == "grant_pin_mismatch"
    document = manifest_document()
    document["jobs"][3]["sql"]["sha256"] = "0" * 64
    assert rejected(encode(document)).code == "grant_pin_mismatch"


@pytest.mark.parametrize(
    ("job", "change"),
    [
        (2, {"service_role": None}),
        (3, {"sql_digest": None}),
        (4, {"schema": None}),
        (5, {"extra": "value"}),
        (2, {"schema": "goose:1,2,3"}),
    ],
)
def test_release_tools_expectations_are_exactly_what_the_tools_report(job, change):
    document = manifest_document()
    for key, value in change.items():
        if value is None:
            del document["jobs"][job]["expect"][key]
        else:
            document["jobs"][job]["expect"][key] = value
    assert rejected(encode(document)).code == "job_expectation_invalid"


@pytest.mark.parametrize(
    ("job", "key", "value"),
    [
        (4, "schema", "goose:1,2"),
        (5, "database", "other_db"),
        (2, "principal", "someone_else"),
        (3, "service_role", "someone_else"),
    ],
)
def test_grant_and_proof_must_agree_with_the_migrated_identity_and_schema(job, key, value):
    document = manifest_document()
    document["jobs"][job]["expect"][key] = value
    assert rejected(encode(document)).code == "job_expectation_inconsistent"


def test_proof_principal_cannot_be_the_migration_owner():
    document = manifest_document()
    document["jobs"][2]["expect"]["service_role"] = "runtime_owner"
    document["jobs"][4]["expect"]["principal"] = "runtime_owner"
    assert rejected(encode(document)).code == "job_expectation_inconsistent"


def test_product_grant_is_the_tools_script_from_the_reviewed_search_source():
    document = manifest_document()
    document["sources"]["release_tools"] = "e" * 40
    assert rejected(encode(document)).code == "grant_pin_mismatch"
    document = manifest_document()
    document["jobs"][3]["sql"]["path"] = "deploy/release/product_grants.sql"
    assert rejected(encode(document)).code == "grant_pin_mismatch"


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


def test_secret_values_never_repeat_across_workers_or_into_the_jobs_worker():
    document = manifest_document()
    document["secrets"]["worker"][0] = dict(document["secrets"]["api"][0], name="OTHER")
    assert rejected(encode(document)).code == "shared_secret_bundle"
    document = manifest_document()
    document["secrets"]["jobs"][0] = dict(document["secrets"]["runtime"][0], name="OWNER")
    assert rejected(encode(document)).code == "shared_secret_bundle"
    document = manifest_document()
    document["secrets"]["api"].append(dict(document["secrets"]["api"][0], name="AGAIN"))
    assert rejected(encode(document)).code == "shared_secret_bundle"
    document = manifest_document()
    document["secrets"]["api"].append(dict(document["secrets"]["api"][0], sha256="1" * 64))
    assert rejected(encode(document)).code == "invalid_field"
    document = manifest_document()
    document["secrets"]["jobs"] = []
    assert rejected(encode(document)).code == "invalid_field"


def test_compatible_rollback_needs_a_distinct_complete_prior_release():
    document = manifest_document(rollback="compatible_release")
    assert load_manifest(encode(document)).manifest.rollback.kind == "compatible_release"
    same = copy.deepcopy(document)
    same["rollback"]["release_id"] = same["release_id"]
    assert rejected(encode(same)).code == "rollback_not_prior_release"
    for field in ("versions", "backups", "compatible_schemas", "trust_sha256", "images"):
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


# Cloudflare identities ------------------------------------------------------


@pytest.mark.parametrize(
    "where",
    ["versions", "environment.bootstrap_versions", "rollback.versions"],
)
def test_every_worker_has_its_own_version_id(where):
    document = manifest_document(rollback="compatible_release")
    target = document
    for key in where.split("."):
        target = target[key]
    target["api"] = target["worker"]
    assert rejected(encode(document)).code == "invalid_field"


@pytest.mark.parametrize("source", ["environment.bootstrap_versions", "rollback.versions"])
def test_a_release_never_reuses_a_prior_version(source):
    document = manifest_document(rollback="compatible_release")
    target = document
    for key in source.split("."):
        target = target[key]
    document["versions"]["runtime"] = target["runtime"]
    assert rejected(encode(document)).code == "version_reused"


def test_scripts_namespaces_applications_and_buckets_are_distinct():
    for path, source in (
        ("environment.workers.api", "environment.workers.worker"),
        ("environment.namespaces.api", "environment.namespaces.jobs"),
        ("applications.api.id", "applications.runtime.id"),
        ("storage.control_bucket", "storage.artifacts_bucket"),
    ):
        document = manifest_document()
        value = document
        for key in source.split("."):
            value = value[key]
        assert rejected(mutate(path, value)).code == "invalid_field", path


@pytest.mark.parametrize(
    ("worker", "images"),
    [("api", ["runtime"]), ("runtime", ["search"]), ("jobs", ["release_tools"])],
)
def test_container_applications_carry_exactly_their_scripts_image_map(worker, images):
    assert rejected(mutate(f"applications.{worker}.images", images)).code == (
        "application_images_invalid"
    )


def test_the_job_receipt_is_the_separately_versioned_cloudflare_envelope():
    loaded = load_manifest(encode(manifest_document()))
    job = loaded.manifest.jobs[2]
    receipt = expected_job_receipt(job, loaded.manifest.release_id, "a" * 64, "b" * 32)
    assert set(receipt) == {
        "schema",
        "release_id",
        "job_id",
        "durable_object_id",
        "launch_nonce",
        "status",
        "result",
    }
    assert receipt["schema"] == CLOUDFLARE_JOB_RECEIPT_SCHEMA
    assert "task_arn" not in receipt and receipt["result"] == dict(job.expect)


def test_the_aws_and_cloudflare_loaders_refuse_each_others_documents():
    cloudflare = encode(manifest_document())
    assert rejected(cloudflare, loader=aws.load_manifest).code == "unknown_field"
    assert rejected(encode(release_fakes.manifest_document())).code in {
        "missing_field",
        "unknown_field",
    }
    loaded = load_manifest(cloudflare)
    cloudflare_approval = encode(approval_document(loaded.sha256))
    assert rejected(cloudflare_approval, loader=aws.load_approval).code in {
        "invalid_field",
        "unknown_field",
    }
    aws_approval = encode(release_fakes.approval_document(loaded.sha256))
    assert rejected(aws_approval, loader=load_approval).code in {"invalid_field", "unknown_field"}


def test_a_cloudflare_approval_never_authorizes_an_aws_manifest_and_vice_versa():
    aws_loaded = aws.load_manifest(encode(release_fakes.manifest_document()))
    cloudflare_loaded = load_manifest(encode(manifest_document()))
    cloudflare_approval = load_approval(encode(approval_document(cloudflare_loaded.sha256)))
    with pytest.raises(ReleaseRejected) as error:
        verify_approval(aws_loaded, cloudflare_approval, START)
    assert error.value.code == "approval_platform_mismatch"
    aws_approval = aws.load_approval(
        encode(release_fakes.approval_document(cloudflare_loaded.sha256))
    )
    with pytest.raises(ReleaseRejected) as error:
        verify_approval(cloudflare_loaded, aws_approval, START)
    assert error.value.code == "approval_platform_mismatch"


# Approval receipts ----------------------------------------------------------


def approved(**changes):
    loaded = load_manifest(encode(manifest_document()))
    document = approval_document(loaded.sha256)
    document.update(changes)
    return loaded, load_approval(encode(document))


def test_matching_approval_binds_hash_environment_account_zone_and_interval():
    loaded, approval = approved()
    verify_approval(loaded, approval, START)
    assert len(approval.sha256) == 64


@pytest.mark.parametrize(
    "changes, now, code",
    [
        ({"manifest_sha256": "0" * 64}, START, "approval_manifest_mismatch"),
        ({"release_id": "11111111-2222-4333-8444-555555555555"}, START, "approval_scope_mismatch"),
        ({"account_id": OTHER_ACCOUNT}, START, "approval_scope_mismatch"),
        ({"zone_id": hex32("other-zone")}, START, "approval_scope_mismatch"),
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
    document = approval_document(loaded.sha256, region="us-east-1")
    assert rejected(encode(document), loader=load_approval).code == "unknown_field"


@pytest.mark.parametrize(
    "path",
    ["environment.bootstrap_control_protocol", "rollback.control_protocol"],
)
def test_prior_code_must_implement_the_authority_protocol(path):
    """CF-04 objects refuse a next release's reads; quiescing them would hold."""
    assert rejected(mutate(path, "sentry.control.v1", rollback="compatible_release")).code == (
        "invalid_field"
    )
    assert rejected(mutate(path, _DELETE, rollback="compatible_release")).code == "missing_field"
