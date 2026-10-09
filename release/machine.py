"""Pure release state machine and evidence evaluation.

Every function here is deterministic over its inputs. An observation proves
success only when it is complete and exact; anything partial, stale or
ambiguous is reported as waiting or as a bounded failure code, never success.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

from release.manifest import Job, Manifest, ReleaseRejected, TaskSpec


class State(StrEnum):
    PREPARED = "prepared"
    LOCKED = "locked"
    QUIESCED = "quiesced"
    MIGRATED = "migrated"
    GRANTS_VERIFIED = "grants_verified"
    SERVICES_STARTED = "services_started"
    OPERATIONAL_VERIFIED = "operational_verified"
    HELD_PAUSED = "held_paused"
    HOLD = "hold"


FORWARD_STATES = (
    State.PREPARED,
    State.LOCKED,
    State.QUIESCED,
    State.MIGRATED,
    State.GRANTS_VERIFIED,
    State.SERVICES_STARTED,
    State.OPERATIONAL_VERIFIED,
    State.HELD_PAUSED,
)
TERMINAL_STATES = frozenset({State.HELD_PAUSED, State.HOLD})
TOKEN_MAX_LIFETIME = timedelta(hours=24)
TOKEN_TASK_MARGIN = timedelta(hours=1)
SUCCESSFUL_STOP_CODES = frozenset({"EssentialContainerExited"})


def check_transition(current: State, target: State) -> None:
    """Advance one proven step, or hold from any non-terminal state."""
    if current in TERMINAL_STATES:
        raise ReleaseRejected("illegal_transition", f"{current}->{target}")
    if target == State.HOLD:
        return
    position = FORWARD_STATES.index(current)
    if FORWARD_STATES[position + 1 : position + 2] != (target,):
        raise ReleaseRejected("illegal_transition", f"{current}->{target}")


def token_expires_at(issued_at: datetime, deadline_seconds: int) -> datetime:
    """A launch token is reusable for the shorter of 24 h or task lifetime plus 1 h."""
    lifetime = timedelta(seconds=deadline_seconds) + TOKEN_TASK_MARGIN
    return issued_at + min(TOKEN_MAX_LIFETIME, lifetime)


def expected_digests(spec: TaskSpec, digests: Mapping[str, str]) -> dict[str, str]:
    return {container.name: digests[container.image] for container in spec.containers}


def _containers(task: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    return {item.get("name"): item for item in task.get("containers") or []}


def evaluate_job(
    job: Job,
    digests: Mapping[str, str],
    *,
    release_id: str,
    token: str,
    task: Mapping[str, Any] | None,
    receipt: Mapping[str, Any] | None,
) -> str | None:
    """Return None only for a STOPPED, exact, zero-exit task with its matching receipt."""
    if task is None:
        return "job_task_missing"
    if task.get("lastStatus") != "STOPPED":
        return "job_not_stopped"
    expected = expected_digests(job.task, digests)
    containers = _containers(task)
    if (
        task.get("taskDefinitionArn") != job.task.task_definition
        or task.get("startedBy") != token
        or set(containers) != set(expected)
    ):
        return "job_identity_mismatch"
    if any(containers[name].get("imageDigest") != value for name, value in expected.items()):
        return "job_image_mismatch"
    if task.get("stopCode") not in SUCCESSFUL_STOP_CODES:
        return "job_stopped_abnormally"
    exits = [containers[name].get("exitCode") for name in expected]
    if any(type(code) is not int for code in exits):
        return "job_exit_missing"
    if any(exits):
        return "job_container_failed"
    if receipt is None:
        return "job_receipt_missing"
    wanted = {
        "schema": job.receipt_schema,
        "release_id": release_id,
        "job_id": job.id,
        "task_arn": task.get("taskArn"),
        "status": "succeeded",
        # Result data can never replace the versioned receipt envelope. In
        # particular result.schema is the database revision, not receipt.schema.
        "result": dict(job.expect),
    }
    if dict(receipt) != wanted:
        return "job_receipt_mismatch"
    return None


def evaluate_service(
    spec: TaskSpec,
    digests: Mapping[str, str],
    service: Mapping[str, Any],
    tasks: list[Mapping[str, Any]],
    deployment_id: str,
) -> tuple[str, str]:
    """Classify one service observation as ("ready", task_arn), waiting or failed.

    Only a task started by the recorded deployment can count. A task from an older
    deployment of the same revision, a partial task set or count drift cannot.
    """
    deployments = {item.get("id"): item for item in service.get("deployments") or []}
    mine = deployments.get(deployment_id)
    if mine is None:
        return "waiting", "deployment_not_visible"
    if mine.get("rolloutState") == "FAILED":
        return "failed", "deployment_failed"
    if mine.get("status") != "PRIMARY":
        return "failed", "deployment_superseded"
    if mine.get("taskDefinition") != spec.task_definition:
        return "failed", "task_definition_mismatch"
    if service.get("desiredCount") != 1:
        return "failed", "task_count_drift"
    expected = expected_digests(spec, digests)
    candidates = [task for task in tasks if task.get("startedBy") == deployment_id]
    for task in candidates:
        if task.get("taskDefinitionArn") != spec.task_definition:
            return "failed", "task_definition_mismatch"
        containers = _containers(task)
        if set(containers) != set(expected) or any(
            containers[name].get("imageDigest") != value for name, value in expected.items()
        ):
            return "failed", "task_image_mismatch"
    if not candidates:
        return "waiting", "task_missing"
    if len(tasks) != 1:
        return "waiting", "task_count_drift"
    task = candidates[0]
    if task.get("lastStatus") != "RUNNING":
        return "waiting", "task_not_running"
    if task.get("healthStatus") != "HEALTHY":
        return "waiting", "task_unhealthy"
    return "ready", str(task.get("taskArn"))


def migration_schemas(manifest: Manifest, outcomes: Mapping[str, str]) -> dict[str, str]:
    """Actual schema per database from job outcomes.

    ``succeeded`` proves the expected schema. ``not_started`` (no launch, or a
    definitive launch failure) leaves it unchanged. Any task that ran or may have
    run without success is unknown: a failed exit does not prove SQL rolled back.
    """
    schemas = {}
    for job in manifest.jobs:
        if job.phase != "migrate":
            continue
        outcome = outcomes.get(job.id, "not_started")
        if outcome == "succeeded":
            schemas[job.database] = job.expect["schema"]
        elif outcome == "not_started":
            schemas[job.database] = "unchanged"
        else:
            schemas[job.database] = "unknown"
    return schemas


def plan_rollback(
    manifest: Manifest, outcomes: Mapping[str, str], *, services_touched: bool
) -> dict[str, Any]:
    """Describe the manual recovery path for a hold. Nothing here is executed."""
    schemas = migration_schemas(manifest, outcomes)
    rollback = manifest.rollback
    # Any platform's manifest: the rollback's kind, not its class, decides.
    if rollback.kind != "compatible_release":
        actions = [
            (
                "set_started_services_desired_zero"
                if services_touched
                else "keep_services_desired_zero"
            ),
            "retain_resources_and_evidence",
        ]
        values = set(schemas.values())
        if "unknown" in values or ("unchanged" in values and len(values) > 1):
            actions.append("reconcile_partial_migration_before_rerun")
        return {"kind": "empty_hold", "automatic": False, "actions": actions}
    compatible = {
        "runtime": rollback.compatible_schemas.runtime,
        "product": rollback.compatible_schemas.product,
    }
    if "unknown" in schemas.values():
        actions = ["keep_writers_quiesced", "reconcile_unknown_schema_state"]
    elif all(value == "unchanged" or value in compatible[db] for db, value in schemas.items()):
        actions = [
            "quiesce_writers",
            "start_compatible_pair_paused",
            "repeat_readiness_denial_and_reconciliation",
            "remain_paused",
        ]
    else:
        actions = ["keep_writers_quiesced", "repair_forward_or_restore_isolated_copies"]
    return {
        "kind": "compatible_release",
        "prior_release_id": rollback.release_id,
        "actual_schemas": schemas,
        "automatic": False,
        "actions": actions,
    }
