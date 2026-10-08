"""Strict release manifest, canonical hash and approval-binding contracts."""

from __future__ import annotations

import copy
import json
from datetime import timedelta

import pytest

from release.manifest import (
    MIGRATION_RECEIPT_SCHEMA,
    OPERATIONAL_RECEIPT_SCHEMA,
    RELEASE_TOOLS_RECEIPT_SCHEMA,
    CompatibleRelease,
    ReleaseRejected,
    canonical_sha256,
    load_approval,
    load_manifest,
    verify_approval,
)
from release.readiness import WORKER_READINESS_CHECK, WORKER_RECEIPT_KIND
from tests.release_fakes import (
    OPERATOR_ROLE,
    ACCOUNT,
    FAILED_RELEASE_ID,
    PRIOR_RELEASE_ID,
    REGION,
    START,
    approval_document,
    encode,
    forward_document,
    iso,
    manifest_document,
    observer_check,
    rollback_run_document,
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


def test_loaded_job_expectations_are_immutable_and_do_not_change_the_approval_binding():
    document = manifest_document()
    loaded = load_manifest(encode(document))
    approval = load_approval(encode(approval_document(loaded.sha256)))
    expected = dict(document["jobs"][0]["expect"])
    original_sha256 = loaded.sha256

    with pytest.raises(TypeError):
        loaded.manifest.jobs[0].expect[
            "schema"
        ] = "unapproved-schema"  # ty: ignore[invalid-assignment]
    with pytest.raises(TypeError):
        del loaded.manifest.jobs[0].expect["principal"]  # ty: ignore[not-subscriptable]
    # Neither the input document nor a serialized copy is an authority to edit
    # the already loaded and approved release candidate.
    document["jobs"][0]["expect"]["schema"] = "changed-input"
    serialized = loaded.manifest.model_dump(mode="json")
    serialized["jobs"][0]["expect"]["schema"] = "changed-output"
    assert dict(loaded.manifest.jobs[0].expect) == expected
    assert loaded.sha256 == original_sha256
    verify_approval(loaded, approval, START)


@pytest.mark.parametrize(
    "key",
    ["release_id", "job_id", "task_arn", "status", "result", "receipt_schema", "schema_version"],
)
def test_expectations_cannot_override_receipt_envelope_identity_or_control_fields(key):
    document = manifest_document()
    document["jobs"][0]["expect"][key] = "forged"
    error = rejected(encode(document))
    assert error.code == "job_expectation_reserved"
    assert error.detail == "jobs.runtime-migrate.expect"


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
        ("schema_version", 3, "invalid_field", "schema_version"),
        # Schema 2 states its purpose; schema 1 cannot.
        ("schema_version", 2, "missing_field", "purpose"),
        ("purpose", {"kind": "forward"}, "unknown_field", "purpose"),
        ("purpose", None, "unknown_field", "purpose"),  # not even an explicit null
        ("operator_role", None, "unknown_field", "operator_role"),
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


def test_release_tools_jobs_use_the_tools_image_and_receipt_schema():
    document = manifest_document()
    document["jobs"][2]["receipt_schema"] = "sentry.release.grant.v1"
    assert rejected(encode(document)).code == "job_receipt_schema_invalid"
    document = manifest_document()
    document["jobs"][4]["task"]["containers"][1]["image"] = "search"
    assert rejected(encode(document)).code == "job_image_invalid"
    assert RELEASE_TOOLS_RECEIPT_SCHEMA == "sentry.release-tools.job.v1"


@pytest.mark.parametrize(
    ("change", "code"),
    [
        (lambda checks: checks.pop(0), "worker_readiness_check_invalid"),
        (lambda checks: checks[0].update(id="worker-ready"), "worker_readiness_check_invalid"),
        (lambda checks: checks.append({"id": "worker-again", "receipt_schema": WORKER_RECEIPT_KIND}),
         "worker_readiness_check_invalid"),
        # The schema selects the check's shape: no other schema is a worker check,
        # and an observer's fields never fit one.
        (lambda checks: checks[0].update(receipt_schema="sentry.release.worker-readiness.v1"),
         "invalid_field"),
        (lambda checks: checks[1].update(receipt_schema=WORKER_RECEIPT_KIND), "unknown_field"),
    ],
)  # fmt: skip
def test_worker_readiness_is_proven_only_from_supervisor_receipts(change, code):
    document = manifest_document()
    assert document["operational_checks"][0] == {
        "id": WORKER_READINESS_CHECK,
        "receipt_schema": WORKER_RECEIPT_KIND,
    }
    change(document["operational_checks"])
    assert rejected(encode(document)).code == code


def _observers(document: dict) -> dict[str, dict]:
    return {c["target"]: c for c in document["operational_checks"] if "target" in c}


@pytest.mark.parametrize(
    ("change", "code"),
    [
        # Exactly one observer for each of the Runtime and the API.
        (lambda d: d["operational_checks"].pop(1), "observer_checks_invalid"),
        (lambda d: d["operational_checks"].append(observer_check("api-again", "api")),
         "observer_checks_invalid"),
        # The check id is the one its task definition fixes (and fits the session name).
        (lambda d: _observers(d)["runtime"].update(id="runtime-protected-readiness"),
         "observer_id_invalid"),
        (lambda d: _observers(d)["api"].update(id="api-operational"), "observer_id_invalid"),
        # The service's own private name and port, in one shared namespace.
        (lambda d: _observers(d)["runtime"].update(host="api.sentry-staging.internal"),
         "observer_target_invalid"),
        (lambda d: _observers(d)["api"].update(host="api.other.internal"),
         "observer_target_invalid"),
        (lambda d: _observers(d)["api"].update(host="api.10.0.0.7"), "observer_target_invalid"),
        (lambda d: _observers(d)["runtime"].update(port=8001), "observer_target_invalid"),
        (lambda d: _observers(d)["api"].update(port=443), "observer_target_invalid"),
        (lambda d: _observers(d)["api"].update(host="api"), "invalid_field"),
        (lambda d: _observers(d)["api"].update(host="API.sentry-staging.internal"),
         "invalid_field"),
        (lambda d: _observers(d)["api"].update(target="worker"), "invalid_field"),
        # Its own release-tools task: an init container and the observer container.
        (lambda d: _observers(d)["api"]["task"]["containers"][1].update(image="search"),
         "observer_task_invalid"),
        (lambda d: _observers(d)["api"]["task"]["containers"][1].update(name="app"),
         "observer_task_invalid"),
        (lambda d: _observers(d)["api"]["task"]["containers"].append(
            {"name": "sidecar", "image": "release_tools"}), "observer_task_invalid"),
        (lambda d: _observers(d)["runtime"]["task"]["containers"].pop(0), "invalid_field"),
        # Bounded, and never sharing an identifier with a job.
        (lambda d: _observers(d)["api"].update(deadline_seconds=59), "invalid_field"),
        (lambda d: _observers(d)["api"].update(deadline_seconds=3601), "invalid_field"),
        (lambda d: _observers(d)["api"].update(stop_grace_seconds=0), "invalid_field"),
        (lambda d: _observers(d)["api"].update(id=d["jobs"][0]["id"]), "invalid_field"),
        (lambda d: _observers(d)["api"].update(id="worker-readiness"), "invalid_field"),
        (lambda d: _observers(d)["api"].update(extra=True), "unknown_field"),
        (lambda d: _observers(d)["api"].pop("host"), "missing_field"),
    ],
)  # fmt: skip
def test_runtime_and_api_are_each_proven_by_one_scoped_observer_task(change, code):
    document = manifest_document()
    assert {key: value["receipt_schema"] for key, value in _observers(document).items()} == {
        "runtime": OPERATIONAL_RECEIPT_SCHEMA, "api": OPERATIONAL_RECEIPT_SCHEMA,
    }  # fmt: skip
    load_manifest(encode(document))
    change(document)
    assert rejected(encode(document)).code == code


@pytest.mark.parametrize(
    "share",
    [
        lambda d: d["jobs"][0]["task"]["secrets"][1],
        lambda d: d["services"]["runtime"]["secrets"][1],
        lambda d: _observers(d)["api"]["task"]["secrets"][1],
    ],
)
def test_an_observers_material_is_its_own(share):
    document = manifest_document()
    _observers(document)["runtime"]["task"]["secrets"][1] = copy.deepcopy(share(document))
    assert rejected(encode(document)).code == "shared_secret_bundle"


@pytest.mark.parametrize(
    "field, value, code",
    [
        ("task_definition", "arn:aws:ecs:us-east-1:444455556666:task-definition/x:1",
         "resource_scope_mismatch"),
        ("task_definition", "arn:aws:ecs:us-east-1:" + ACCOUNT
         + ":task-definition/sentry-staging-api-observe", "mutable_reference"),
        ("task_role", "arn:aws:iam::444455556666:role/observer", "resource_scope_mismatch"),
    ],
)  # fmt: skip
def test_observer_tasks_are_scoped_to_the_environment_account(field, value, code):
    document = manifest_document()
    _observers(document)["api"]["task"][field] = value
    assert rejected(encode(document)).code == code


def test_migration_jobs_report_in_the_shared_migration_envelope():
    document = manifest_document()
    migrations = [job for job in document["jobs"] if job["phase"] == "migrate"]
    assert {job["receipt_schema"] for job in migrations} == {MIGRATION_RECEIPT_SCHEMA}
    assert all(set(job["expect"]) == {"database", "principal", "schema"} for job in migrations)
    for change, code in (
        (lambda job: job.update(receipt_schema=RELEASE_TOOLS_RECEIPT_SCHEMA),
         "job_receipt_schema_invalid"),
        (lambda job: job.update(receipt_schema="sentry.release.migrate.v1"),
         "job_receipt_schema_invalid"),
        (lambda job: job["expect"].pop("principal"), "job_expectation_incomplete"),
        (lambda job: job["expect"].update(owner_role="product_owner"), "job_expectation_invalid"),
    ):  # fmt: skip
        document = manifest_document()
        change(document["jobs"][1])
        assert rejected(encode(document)).code == code


@pytest.mark.parametrize(("name", "image"), [("worker", "search"), ("app", "runtime")])
def test_worker_receipts_come_from_its_search_app_container_stream(name, image):
    document = manifest_document()
    assert document["services"]["worker"]["containers"][1] == {"name": "app", "image": "search"}
    document["services"]["worker"]["containers"][1] = {"name": name, "image": image}
    assert rejected(encode(document)).code == "worker_container_invalid"


def test_release_tools_job_ids_match_the_fixed_task_definition_ids():
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


# Schema 2: explicit execution purpose, bootstrap and rollback runs ---------------


def edited(document: dict, change) -> bytes:
    document = copy.deepcopy(document)
    change(document)
    return encode(document)


def job_named(document: dict, job_id: str) -> dict:
    return next(job for job in document["jobs"] if job["id"] == job_id)


def test_schema_one_keeps_its_meaning_a_forward_run_even_with_a_compatible_fallback():
    for rollback in ("empty_hold", "compatible_release"):
        manifest = load_manifest(encode(manifest_document(rollback=rollback))).manifest
        assert manifest.execution == "forward"
        # The fallback plan never suppresses the candidate's migrations.
        assert [job.phase for job in manifest.jobs][:2] == ["migrate", "migrate"]


def test_schema_two_states_forward_purpose_and_may_bootstrap_first():
    manifest = load_manifest(encode(forward_document())).manifest
    assert manifest.execution == "forward"
    assert [(job.phase, job.database) for job in manifest.jobs[:3]] == [
        ("bootstrap", "runtime"), ("bootstrap", "product"), ("migrate", "runtime")
    ]  # fmt: skip
    assert load_manifest(encode(forward_document(bootstrap=False))).manifest.execution == "forward"


def test_a_forward_upgrade_with_a_compatible_fallback_still_migrates():
    document = manifest_document(rollback="compatible_release")
    document["schema_version"], document["purpose"] = 2, {"kind": "forward"}
    document["operator_role"] = OPERATOR_ROLE
    manifest = load_manifest(encode(document)).manifest
    assert manifest.execution == "forward"
    assert {job.phase for job in manifest.jobs} == {"migrate", "grant", "proof"}


@pytest.mark.parametrize(
    "purpose, code",
    [
        ({"kind": "rollback_maybe"}, "invalid_field"),
        ({"kind": "forward", "failed_release_id": FAILED_RELEASE_ID}, "unknown_field"),
        ({"kind": "rollback", "failed_release_id": FAILED_RELEASE_ID}, "missing_field"),
    ],
)
def test_purpose_is_a_strict_discriminated_union(purpose, code):
    assert rejected(edited(forward_document(), lambda d: d.update(purpose=purpose))).code == code


def test_bootstrap_is_only_for_a_first_deployment():
    def compatible(document: dict) -> None:
        document["rollback"] = manifest_document(rollback="compatible_release")["rollback"]

    assert rejected(edited(forward_document(), compatible)).code == "bootstrap_requires_empty_hold"


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d["jobs"].pop(0),  # one database only
        lambda d: d["jobs"].insert(3, d["jobs"].pop(0)),  # after a migration
        lambda d: (d.update(schema_version=1), d.pop("purpose"), d.pop("operator_role")),
    ],
    ids=["one-database", "out-of-order", "schema-one"],
)
def test_bootstrap_runs_first_for_both_databases_and_only_in_schema_two(change):
    assert rejected(edited(forward_document(), change)).code == "job_plan_invalid"


@pytest.mark.parametrize(
    "key, value",
    [
        ("owner_role", "product_owner"),  # not the runtime migration owner
        ("service_role", "runtime_owner"),  # not the grant's service role
        ("principal", "runtime_owner"),  # the administrator is not the owner
        ("principal", "runtime_service"),  # nor the service login
        ("database", "product_db"),
    ],
)
def test_bootstrap_creates_exactly_the_logins_later_jobs_use(key, value):
    error = rejected(
        edited(forward_document(), lambda d: d["jobs"][0]["expect"].update({key: value}))
    )
    assert error.code == "job_expectation_inconsistent"


@pytest.mark.parametrize(
    "change, code",
    [
        (lambda d: d["jobs"][0]["expect"].pop("owner_role"), "job_expectation_invalid"),
        (lambda d: d["jobs"][0]["expect"].update(schema="x"), "job_expectation_invalid"),
        (lambda d: d["jobs"][0].update(id="runtime-admin"), "job_id_invalid"),
        (lambda d: d["jobs"][0].update(receipt_schema="sentry.other.v1"),
         "job_receipt_schema_invalid"),
        (lambda d: d["jobs"][0]["task"]["containers"][1].update(image="runtime"),
         "job_image_invalid"),
    ],
)  # fmt: skip
def test_bootstrap_is_a_release_tools_job_with_its_exact_receipt(change, code):
    assert rejected(edited(forward_document(), change)).code == code


@pytest.mark.parametrize(
    "share",
    [
        lambda d: d["jobs"][0]["task"]["secrets"].append(d["services"]["runtime"]["secrets"][0]),
        lambda d: d["jobs"][0]["task"]["secrets"].append(d["jobs"][4]["task"]["secrets"][0]),
        lambda d: d["jobs"][6]["task"]["secrets"].append(d["jobs"][0]["task"]["secrets"][0]),
        lambda d: d["jobs"][1]["task"]["secrets"].append(d["jobs"][0]["task"]["secrets"][0]),
    ],
    ids=["service", "grant-job", "proof-job", "other-bootstrap"],
)
def test_the_administrator_bundle_is_exclusive_to_its_bootstrap_job(share):
    assert rejected(edited(forward_document(), share)).code == "shared_secret_bundle"


def test_owner_jobs_including_reconcile_never_reuse_a_service_bundle():
    def share(document: dict) -> None:
        job_named(document, "runtime-reconcile")["task"]["secrets"].append(
            document["services"]["runtime"]["secrets"][0]
        )

    assert rejected(edited(rollback_run_document(), share)).code == "shared_secret_bundle"


def test_a_rollback_run_reconciles_and_proves_only_over_the_prior_pair():
    manifest = load_manifest(encode(rollback_run_document())).manifest
    assert manifest.execution == "rollback"
    assert [job.phase for job in manifest.jobs] == ["reconcile", "reconcile", "proof", "proof"]
    assert isinstance(manifest.rollback, CompatibleRelease)
    assert manifest.services == manifest.rollback.services


@pytest.mark.parametrize("phase", ["migrate", "grant", "bootstrap"])
def test_a_rollback_run_never_migrates_grants_or_bootstraps(phase):
    def add(document: dict) -> None:
        forward = forward_document()
        donor = next(job for job in forward["jobs"] if job["phase"] == phase)
        document["jobs"].insert(0, donor)

    assert rejected(edited(rollback_run_document(), add)).code in {
        "job_plan_invalid", "bootstrap_requires_empty_hold"
    }  # fmt: skip


@pytest.mark.parametrize(
    "change, code",
    [
        (lambda d: d.update(rollback={"kind": "empty_hold"}),
         "rollback_run_requires_prior_release"),
        (lambda d: d["purpose"].update(failed_release_id=d["release_id"]),
         "rollback_failed_release_invalid"),
        (lambda d: d["purpose"].update(failed_release_id=PRIOR_RELEASE_ID),
         "rollback_failed_release_invalid"),
        (lambda d: d["services"]["api"].update(
            task_definition=d["services"]["api"]["task_definition"].replace(":6", ":7")),
         "rollback_services_not_prior"),
        (lambda d: d["images"]["search"].update(
            arm64_digest=manifest_document()["images"]["search"]["arm64_digest"]),
         "rollback_images_not_prior"),
        (lambda d: d["purpose"]["actual_schemas"].update(runtime="goose:1,2"),
         "rollback_schema_incompatible"),
    ],
)  # fmt: skip
def test_a_rollback_run_restores_exactly_the_retained_compatible_pair(change, code):
    assert rejected(edited(rollback_run_document(), change)).code == code


@pytest.mark.parametrize(
    "job_id, key, value",
    [
        ("runtime-reconcile", "schema", "goose:1,2"),
        ("runtime-proof", "schema", "goose:1,2"),
        ("product-reconcile", "release_sessions", "1"),
        ("product-reconcile", "owner_sessions", "2"),
        ("runtime-reconcile", "principal", "runtime_service"),
        ("runtime-reconcile", "database", "product_db"),
    ],
)
def test_rollback_reconciliation_must_observe_the_stated_schemas_and_no_sessions(
    job_id, key, value
):
    error = rejected(
        edited(
            rollback_run_document(), lambda d: job_named(d, job_id)["expect"].update({key: value})
        )
    )
    assert error.code == "job_expectation_inconsistent"


def test_schema_two_hash_and_approval_binding_cover_the_purpose():
    forward = load_manifest(encode(forward_document()))
    rollback = load_manifest(encode(rollback_run_document()))
    approval = load_approval(encode(approval_document(forward.sha256)))
    verify_approval(forward, approval, START)
    with pytest.raises(ReleaseRejected) as error:
        verify_approval(rollback, approval, START)
    assert error.value.code == "approval_manifest_mismatch"


def test_a_rollback_run_cannot_carry_the_forward_job_plan():
    def forward_jobs(document: dict) -> None:
        document["jobs"] = manifest_document(rollback="compatible_release")["jobs"]

    assert rejected(edited(rollback_run_document(), forward_jobs)).code == "job_plan_invalid"


def test_schema_two_names_the_approved_operator_role_in_its_own_account():
    def drop(document: dict) -> None:
        del document["operator_role"]

    assert rejected(edited(forward_document(), drop)).code == "missing_field"
    foreign = "arn:aws:iam::999999999999:role/sentry-staging/sentry-staging-operator"
    error = rejected(edited(forward_document(), lambda d: d.update(operator_role=foreign)))
    assert error.code == "resource_scope_mismatch"
    for bad in ("arn:aws:iam::111122223333:user/fixture-operator",
                "arn:aws:iam::111122223333:role/a b"):  # fmt: skip
        error = rejected(edited(forward_document(), lambda d, bad=bad: d.update(operator_role=bad)))
        assert error.code in {"resource_scope_mismatch", "mutable_reference"}


@pytest.mark.parametrize("index, job_id", [(0, "runtime-migration"), (1, "product-migrate-v2")])
def test_migration_job_ids_are_the_ones_their_task_definitions_fix(index, job_id):
    document = manifest_document()
    assert document["jobs"][index]["phase"] == "migrate"
    document["jobs"][index]["id"] = job_id
    assert rejected(encode(document)).code == "job_id_invalid"
