"""Pure release state machine and evidence evaluation.

Every function here is deterministic over its inputs. An observation proves
success only when it is complete and exact; anything partial, stale or
ambiguous is reported as waiting or as a bounded failure code, never success.
"""

from __future__ import annotations

import re

from collections.abc import Mapping
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

from release.manifest import (
    CompatibleRelease,
    Job,
    Manifest,
    ObserverCheck,
    ReleaseRejected,
    TaskSpec,
)


class State(StrEnum):
    PREPARED = "prepared"
    LOCKED = "locked"
    QUIESCED = "quiesced"
    MIGRATED = "migrated"
    GRANTS_VERIFIED = "grants_verified"
    # Rollback runs only: the stated schemas reconciled, then proven.
    RECONCILED = "reconciled"
    PROVEN = "proven"
    SERVICES_STARTED = "services_started"
    OPERATIONAL_VERIFIED = "operational_verified"
    HELD_PAUSED = "held_paused"
    # Restore verification runs only: the restored instance reconciled, then proven.
    RESTORE_RECONCILED = "restore_reconciled"
    RESTORE_VERIFIED = "restore_verified"
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
# A rollback restores the retained prior pair: it reconciles and proves the
# stated schemas instead of migrating and granting, then starts and verifies
# the services exactly as a forward run does.
ROLLBACK_STATES = (
    State.PREPARED,
    State.LOCKED,
    State.QUIESCED,
    State.RECONCILED,
    State.PROVEN,
    State.SERVICES_STARTED,
    State.OPERATIONAL_VERIFIED,
    State.HELD_PAUSED,
)
# A restore verification proves one restored instance and touches nothing else: no
# quiesce, service, admission, migration, grant or bootstrap.
RESTORE_STATES = (
    State.PREPARED,
    State.LOCKED,
    State.RESTORE_RECONCILED,
    State.RESTORE_VERIFIED,
)
# The states a run finishes in successfully, and every terminal state.
FINISHED_STATES = frozenset({State.HELD_PAUSED, State.RESTORE_VERIFIED})
TERMINAL_STATES = FINISHED_STATES | {State.HOLD}
TOKEN_MAX_LIFETIME = timedelta(hours=24)
TOKEN_TASK_MARGIN = timedelta(hours=1)
SUCCESSFUL_STOP_CODES = frozenset({"EssentialContainerExited"})
# deploy/aws-staging/services owns these settings and the controller never writes
# them: no overlap during a deploy, and a failed deployment holds instead of
# rolling back to a binary that may not match the migrated schemas.
SERVICE_DEPLOYMENT_SETTINGS = {
    "minimumHealthyPercent": 0,
    "maximumPercent": 100,
    "deploymentCircuitBreaker": {"enable": True, "rollback": False},
}


def check_transition(
    current: State, target: State, sequence: tuple[State, ...] = FORWARD_STATES
) -> None:
    """Advance one proven step of this run's sequence, or hold from any non-terminal state."""
    if current in TERMINAL_STATES:
        raise ReleaseRejected("illegal_transition", f"{current}->{target}")
    if target == State.HOLD:
        return
    if current not in sequence:
        raise ReleaseRejected("illegal_transition", f"{current}->{target}")
    position = sequence.index(current)
    if sequence[position + 1 : position + 2] != (target,):
        raise ReleaseRejected("illegal_transition", f"{current}->{target}")


def token_expires_at(issued_at: datetime, deadline_seconds: int) -> datetime:
    """A launch token is reusable for the shorter of 24 h or task lifetime plus 1 h."""
    lifetime = timedelta(seconds=deadline_seconds) + TOKEN_TASK_MARGIN
    return issued_at + min(TOKEN_MAX_LIFETIME, lifetime)


def expected_digests(spec: TaskSpec, digests: Mapping[str, str]) -> dict[str, str]:
    return {container.name: digests[container.image] for container in spec.containers}


def _containers(task: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    return {item.get("name"): item for item in task.get("containers") or []}


def task_runtime_issue(task: Mapping[str, Any]) -> str | None:
    """None only when ECS reports no override of any kind and Exec disabled.

    ECS lists each container by name in ``containerOverrides``; anything beyond a
    name (command, environment, files, resources) or any task-level override
    (roles, CPU, memory, storage, accelerators) changes what the reviewed revision
    runs. A missing or malformed structure cannot show the absence of overrides.
    """
    overrides = task.get("overrides")
    if not isinstance(overrides, Mapping) or set(overrides) - {
        "containerOverrides",
        "inferenceAcceleratorOverrides",
    }:
        return "task_overrides_present"
    containers = overrides.get("containerOverrides")
    accelerators = overrides.get("inferenceAcceleratorOverrides", [])
    if (
        not isinstance(containers, list)
        or any(not isinstance(item, Mapping) or set(item) != {"name"} for item in containers)
        or accelerators != []
    ):
        return "task_overrides_present"
    if task.get("enableExecuteCommand") is not False:
        return "task_exec_enabled"
    return None


def evaluate_task(
    spec: TaskSpec, digests: Mapping[str, str], *, token: str, task: Mapping[str, Any] | None
) -> str | None:
    """Return None only for a STOPPED, exact, unmodified task whose containers all exited 0.

    The same platform evidence is required of database jobs and observer tasks;
    each then has its own receipt contract.
    """
    if task is None:
        return "job_task_missing"
    if task.get("lastStatus") != "STOPPED":
        return "job_not_stopped"
    expected = expected_digests(spec, digests)
    containers = _containers(task)
    if (
        task.get("taskDefinitionArn") != spec.task_definition
        or task.get("startedBy") != token
        or set(containers) != set(expected)
    ):
        return "job_identity_mismatch"
    if any(containers[name].get("imageDigest") != value for name, value in expected.items()):
        return "job_image_mismatch"
    issue = task_runtime_issue(task)
    if issue is not None:
        return issue
    if task.get("stopCode") not in SUCCESSFUL_STOP_CODES:
        return "job_stopped_abnormally"
    exits = [containers[name].get("exitCode") for name in expected]
    if any(type(code) is not int for code in exits):
        return "job_exit_missing"
    if any(exits):
        return "job_container_failed"
    return None


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
    issue = evaluate_task(job.task, digests, token=token, task=task)
    if issue is not None:
        return issue
    assert task is not None
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


# The fixed observer results; the API's refused protected route may answer 401,
# 403, or 503 while no authentication service is configured.
OBSERVER_OUTCOMES = {
    "runtime": {"tls": "verified", "checks": "healthz,readyz", "denials": "no_token,wrong_ca"},
    "api": {"tls": "none", "checks": "liveness,api_ready"},
}
API_DENIALS = frozenset({"unauthenticated:401", "unauthenticated:403", "unauthenticated:503"})


def evaluate_observation(
    check: ObserverCheck,
    *,
    release_id: str,
    task_arn: str,
    peer: str,
    receipt: Mapping[str, Any] | None,
) -> str | None:
    """Return None only for this observer task's passing receipt about the recorded peer.

    The receipt names the observer task (this task, never a service task), the
    exact target name and port, and the one address it connected to, which must
    be the network interface of the service task the controller recorded.
    """
    if receipt is None:
        return "operational_evidence_missing"
    result = receipt.get("result")
    if (
        set(receipt) != {"schema", "release_id", "check_id", "task_arn", "status", "result"}
        or receipt.get("schema") != check.receipt_schema
        or receipt.get("release_id") != release_id
        or receipt.get("check_id") != check.id
        or receipt.get("task_arn") != task_arn
        or receipt.get("status") != "passed"
        or not isinstance(result, Mapping)
    ):
        return "operational_receipt_mismatch"
    wanted = {
        "target": check.target,
        "host": check.host,
        "port": str(check.port),
        **OBSERVER_OUTCOMES[check.target],
    }
    keys = set(wanted) | {"peer"} | ({"denials"} if check.target == "api" else set())
    if set(result) != keys or any(result.get(key) != value for key, value in wanted.items()):
        return "operational_receipt_mismatch"
    if check.target == "api" and result.get("denials") not in API_DENIALS:
        return "operational_receipt_mismatch"
    if result.get("peer") != peer:
        # The address that answered is not the recorded task: stale DNS or another task.
        return "operational_peer_mismatch"
    return None


def task_network_address(
    task: Mapping[str, Any] | None, subnets: tuple[str, ...] | list[str]
) -> str | None:
    """The private IPv4 address of the task's one complete ENI, or None.

    The attachment must be the task's only ENI, attached, with exactly one
    interface id, one subnet among the release's approved subnets and one
    private IPv4 address. Anything less is not a known network identity.
    """
    if task is None:
        return None
    attachments = [
        item
        for item in task.get("attachments") or []
        if isinstance(item, Mapping) and item.get("type") == "ElasticNetworkInterface"
    ]
    if len(attachments) != 1 or attachments[0].get("status") != "ATTACHED":
        return None
    details: dict[str, list[Any]] = {}
    for detail in attachments[0].get("details") or []:
        if isinstance(detail, Mapping):
            details.setdefault(str(detail.get("name")), []).append(detail.get("value"))
    interface = details.get("networkInterfaceId", [])
    subnet = details.get("subnetId", [])
    addresses = details.get("privateIPv4Address", [])
    if (
        len(interface) != 1
        or not isinstance(interface[0], str)
        or not re.fullmatch(r"eni-[0-9a-f]{8,17}", interface[0])
        or len(subnet) != 1
        or subnet[0] not in subnets
        or len(addresses) != 1
        or not isinstance(addresses[0], str)
    ):
        return None
    parts = addresses[0].split(".")
    if len(parts) != 4 or not all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
        return None
    return addresses[0]


def service_settings_drift(service: Mapping[str, Any]) -> bool:
    """True unless ECS reports exactly the Terraform-owned settings the release relies on.

    Additional reported structures pass only when they cannot roll back or change
    the rolling strategy. A missing value is drift: it cannot be shown to match.
    """
    configuration = service.get("deploymentConfiguration")
    if not isinstance(configuration, Mapping):
        return True
    if any(configuration.get(key) != value for key, value in SERVICE_DEPLOYMENT_SETTINGS.items()):
        return True
    alarms = configuration.get("alarms")
    if alarms is not None and (
        not isinstance(alarms, Mapping) or alarms.get("rollback") is not False
    ):
        return True
    return (
        configuration.get("strategy", "ROLLING") != "ROLLING"
        or service.get("deploymentController") != {"type": "ECS"}
        or service.get("enableExecuteCommand") is not False
    )


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
    Terraform-owned setting drift fails at once.
    """
    if service_settings_drift(service):
        return "failed", "service_settings_drift"
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
        issue = task_runtime_issue(task)
        if issue is not None:
            return "failed", issue
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
    if manifest.execution == "restore_verify":
        # A held verification changed nothing but its own jobs: the restored instance
        # and the release are left exactly as they are.
        return {
            "kind": "restore_hold",
            "automatic": False,
            "actions": [
                "leave_restored_instance_untouched",
                "retain_resources_and_evidence",
                "review_restore_hold_before_any_retry",
            ],
        }
    if manifest.execution == "rollback":
        # A held rollback ran no migration: the schemas are the stated ones,
        # unless a reconcile job saw otherwise. Nothing is retried automatically.
        return {
            "kind": "rollback_hold",
            "automatic": False,
            "actions": [
                (
                    "set_started_services_desired_zero"
                    if services_touched
                    else "keep_services_desired_zero"
                ),
                "retain_resources_and_evidence",
                "review_rollback_hold_before_any_retry",
            ],
        }
    schemas = migration_schemas(manifest, outcomes)
    rollback = manifest.rollback
    if not isinstance(rollback, CompatibleRelease):
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
        if any(
            job.phase == "bootstrap" and outcomes.get(job.id, "not_started") == "unknown"
            for job in manifest.jobs
        ):
            # A bootstrap that may have run created or changed logins and databases.
            actions.append("reconcile_bootstrap_before_rerun")
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
