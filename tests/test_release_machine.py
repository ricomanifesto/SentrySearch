"""Pure release state-machine and observation evaluation contracts."""

from __future__ import annotations

import copy
from datetime import timedelta

import pytest

from release.machine import (
    FORWARD_STATES,
    State,
    check_transition,
    evaluate_job,
    evaluate_service,
    migration_schemas,
    token_expires_at,
)
from release.manifest import ReleaseRejected, load_manifest
from tests.release_fakes import START, encode, manifest_document

DOCUMENT = manifest_document()
MANIFEST = load_manifest(encode(DOCUMENT)).manifest
SPEC = MANIFEST.services.api
DIGESTS = {name: DOCUMENT["images"][name]["arm64_digest"] for name in DOCUMENT["images"]}


def migration_evidence():
    """Independent receipt producer: literal envelope, not the evaluator's merge."""
    observed_task = {
        "taskArn": "arn:aws:ecs:us-east-1:111122223333:task/sentry-staging/migration",
        "taskDefinitionArn": DOCUMENT["jobs"][0]["task"]["task_definition"],
        "lastStatus": "STOPPED",
        "startedBy": "launch-token",
        "stopCode": "EssentialContainerExited",
        "containers": [
            {"name": "init", "imageDigest": DIGESTS["search"], "exitCode": 0},
            {"name": "migration", "imageDigest": DIGESTS["runtime"], "exitCode": 0},
        ],
    }
    receipt = {
        "schema": "sentry.release.migrate.v1",
        "release_id": DOCUMENT["release_id"],
        "job_id": "runtime-migrate",
        "task_arn": observed_task["taskArn"],
        "status": "succeeded",
        "result": {
            "database": "runtime_db",
            "principal": "runtime_owner",
            "schema": "goose:1,2,3",
        },
    }
    return observed_task, receipt


def evaluate_migration(receipt):
    observed_task, _ = migration_evidence()
    return evaluate_job(
        MANIFEST.jobs[0],
        DIGESTS,
        release_id=MANIFEST.release_id,
        token="launch-token",
        task=observed_task,
        receipt=receipt,
    )


def test_job_receipt_keeps_versioned_envelope_and_database_schema_separate():
    _, receipt = migration_evidence()
    assert evaluate_migration(receipt) is None
    assert receipt["schema"] != receipt["result"]["schema"]
    assert migration_schemas(MANIFEST, {"runtime-migrate": "succeeded"})["runtime"] == (
        receipt["result"]["schema"]
    )


@pytest.mark.parametrize("field", ["schema", "release_id", "job_id", "task_arn", "status"])
def test_job_receipt_rejects_wrong_envelope_even_with_correct_result(field):
    _, receipt = migration_evidence()
    receipt[field] = "forged"
    assert evaluate_migration(receipt) == "job_receipt_mismatch"


@pytest.mark.parametrize("field", ["database", "principal", "schema"])
def test_job_receipt_rejects_wrong_result_even_with_correct_envelope(field):
    _, receipt = migration_evidence()
    receipt["result"][field] = "forged"
    assert evaluate_migration(receipt) == "job_receipt_mismatch"


def test_old_flat_receipt_cannot_substitute_database_schema_for_envelope_version():
    _, receipt = migration_evidence()
    old_flat = copy.deepcopy(receipt)
    old_flat.update(old_flat.pop("result"))
    assert evaluate_migration(old_flat) == "job_receipt_mismatch"


def test_states_only_advance_one_proven_step_or_hold():
    for current, target in zip(FORWARD_STATES, FORWARD_STATES[1:]):
        check_transition(current, target)
        check_transition(current, State.HOLD)
    for illegal in [
        (State.PREPARED, State.QUIESCED),
        (State.MIGRATED, State.SERVICES_STARTED),
        (State.HOLD, State.LOCKED),
        (State.HELD_PAUSED, State.HOLD),
        (State.SERVICES_STARTED, State.MIGRATED),
    ]:
        with pytest.raises(ReleaseRejected) as error:
            check_transition(*illegal)
        assert error.value.code == "illegal_transition"


@pytest.mark.parametrize(
    "deadline_seconds, lifetime",
    [(900, timedelta(seconds=900 + 3600)), (86_400, timedelta(hours=24))],
)
def test_launch_token_lifetime_is_the_shorter_of_a_day_or_task_lifetime_plus_an_hour(
    deadline_seconds, lifetime
):
    assert token_expires_at(START, deadline_seconds) == START + lifetime


def task(arn: str, deployment: str, *, status="RUNNING", health="HEALTHY", definition=None):
    return {
        "taskArn": arn,
        "taskDefinitionArn": definition or SPEC.task_definition,
        "lastStatus": status,
        "healthStatus": health,
        "startedBy": deployment,
        "containers": [
            {"name": "init", "imageDigest": DIGESTS["search"]},
            {"name": "app", "imageDigest": DIGESTS["search"]},
        ],
    }


def service(*deployments, desired=1):
    return {
        "desiredCount": desired,
        "deployments": [
            {"id": ident, "status": status, "taskDefinition": SPEC.task_definition,
             "rolloutState": rollout}
            for ident, status, rollout in deployments
        ],
    }  # fmt: skip


def test_exactly_one_healthy_task_of_the_recorded_deployment_is_ready():
    snapshot = service(("new", "PRIMARY", "COMPLETED"))
    assert evaluate_service(SPEC, DIGESTS, snapshot, [task("a", "new")], "new") == (
        "ready",
        "a",
    )


@pytest.mark.parametrize(
    "snapshot, tasks, expected",
    [
        # Same revision in an older deployment can never satisfy the new one.
        (service(("old", "ACTIVE", "COMPLETED"), ("new", "PRIMARY", "IN_PROGRESS")),
         [task("o", "old")], ("waiting", "task_missing")),
        (service(("old", "ACTIVE", "COMPLETED"), ("new", "PRIMARY", "IN_PROGRESS")),
         [task("o", "old"), task("n", "new")], ("waiting", "task_count_drift")),
        (service(("new", "PRIMARY", "IN_PROGRESS")),
         [task("a", "new"), task("b", "new")], ("waiting", "task_count_drift")),
        (service(("new", "PRIMARY", "IN_PROGRESS")),
         [task("a", "new", health="UNKNOWN")], ("waiting", "task_unhealthy")),
        (service(("new", "PRIMARY", "IN_PROGRESS")),
         [task("a", "new", status="PENDING")], ("waiting", "task_not_running")),
        (service(), [], ("waiting", "deployment_not_visible")),
        (service(("new", "PRIMARY", "FAILED")), [], ("failed", "deployment_failed")),
        (service(("new", "ACTIVE", "COMPLETED"), ("later", "PRIMARY", "IN_PROGRESS")),
         [], ("failed", "deployment_superseded")),
        (service(("new", "PRIMARY", "COMPLETED"), desired=2),
         [task("a", "new")], ("failed", "task_count_drift")),
        (service(("new", "PRIMARY", "COMPLETED")),
         [task("a", "new", definition=SPEC.task_definition[:-1] + "8")],
         ("failed", "task_definition_mismatch")),
    ],
)  # fmt: skip
def test_partial_stale_or_drifting_service_observations_are_not_ready(snapshot, tasks, expected):
    assert evaluate_service(SPEC, DIGESTS, snapshot, tasks, "new") == expected


def test_wrong_image_digest_is_a_failure_not_a_wait():
    wrong = task("a", "new")
    wrong["containers"][1]["imageDigest"] = "sha256:" + "f" * 64
    snapshot = service(("new", "PRIMARY", "COMPLETED"))
    assert evaluate_service(SPEC, DIGESTS, snapshot, [wrong], "new") == (
        "failed",
        "task_image_mismatch",
    )
