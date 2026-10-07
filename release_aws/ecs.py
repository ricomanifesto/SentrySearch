"""EcsPort over an injected ECS client: exact requests, complete enumerations."""

from __future__ import annotations

from typing import Any

from release.ports import AmbiguousResponse
from release_aws.errors import call, require_client

# The controller's launch request (release/controller.py) and nothing else: in
# particular no overrides, placement, capacity provider, group or volume
# configuration. Overrides seen on the resulting task are the controller's to hold.
RUN_TASK_KEYS = frozenset(
    {
        "cluster",
        "taskDefinition",
        "count",
        "launchType",
        "platformVersion",
        "networkConfiguration",
        "enableExecuteCommand",
        "startedBy",
        "clientToken",
        "tags",
    }
)
# Scale-to-zero, or deploy one task of a named revision as a fresh deployment.
# Deployment settings, Exec and networking belong to Terraform.
SCALE_KEYS = frozenset({"cluster", "service", "desiredCount"})
DEPLOY_KEYS = frozenset(
    {"cluster", "service", "taskDefinition", "desiredCount", "forceNewDeployment"}
)
DESCRIBE_TASKS_BATCH = 100
DESCRIBE_SERVICES_BATCH = 10
LIST_PAGE_SIZE = 100
# More tasks than this in one listing is not a release environment this
# controller understands; it is reported as an incomplete enumeration.
MAX_LIST_PAGES = 20


def _require(condition: bool, operation: str) -> None:
    if not condition:
        raise ValueError(f"{operation} request outside the release contract")


def _check_run_task(request: dict[str, Any]) -> None:
    network = request.get("networkConfiguration")
    vpc = network.get("awsvpcConfiguration") if isinstance(network, dict) else None
    tags = request.get("tags")
    _require(
        set(request) == RUN_TASK_KEYS
        and request["count"] == 1
        and request["launchType"] == "FARGATE"
        and request["enableExecuteCommand"] is False
        and request["startedBy"] == request["clientToken"]
        and isinstance(network, dict)
        and set(network) == {"awsvpcConfiguration"}
        and isinstance(vpc, dict)
        and set(vpc) == {"subnets", "securityGroups", "assignPublicIp"}
        and vpc["assignPublicIp"] == "DISABLED"
        and isinstance(tags, list)
        and all(isinstance(tag, dict) and set(tag) == {"key", "value"} for tag in tags),
        "RunTask",
    )


def _check_update_service(request: dict[str, Any]) -> None:
    keys = set(request)
    _require(
        (keys == SCALE_KEYS and request["desiredCount"] == 0)
        or (
            keys == DEPLOY_KEYS
            and request["desiredCount"] == 1
            and request["forceNewDeployment"] is True
        ),
        "UpdateService",
    )


def _list(value: Any, operation: str) -> list[Any]:
    if not isinstance(value, list):
        raise AmbiguousResponse(f"{operation}: malformed response")
    return value


def _require_covered(
    requested: list[str], found: list[Any], key: str, failures: list[Any], operation: str
) -> None:
    """Every requested ARN must come back described or as an explicit failure."""
    seen = {item.get(key) for item in found if isinstance(item, dict)}
    seen |= {item.get("arn") for item in failures if isinstance(item, dict)}
    if not set(requested) <= seen:
        raise AmbiguousResponse(f"{operation}: response omitted a requested resource")


class EcsAdapter:
    """One ECS cluster in one region; every method makes whole, unretried calls."""

    def __init__(self, client: Any, *, region: str, cluster_arn: str) -> None:
        require_client(client, service="ecs", region=region)
        self.client = client
        self.cluster = cluster_arn

    def _cluster(self, cluster: str) -> None:
        if cluster != self.cluster:
            raise ValueError("request names a cluster other than the manifest's")

    def run_task(self, request: dict[str, Any]) -> dict[str, Any]:
        self._cluster(request.get("cluster", ""))
        _check_run_task(request)
        response = call(self.client, "run_task", **request)
        return {
            "tasks": _list(response.get("tasks", []), "RunTask"),
            "failures": _list(response.get("failures", []), "RunTask"),
        }

    def describe_tasks(self, cluster: str, task_arns: list[str]) -> dict[str, Any]:
        """Every requested task, described or reported as a failure, or ambiguous."""
        self._cluster(cluster)
        tasks: list[Any] = []
        failures: list[Any] = []
        for start in range(0, len(task_arns), DESCRIBE_TASKS_BATCH):
            batch = task_arns[start : start + DESCRIBE_TASKS_BATCH]
            response = call(self.client, "describe_tasks", cluster=cluster, tasks=batch)
            found = _list(response.get("tasks", []), "DescribeTasks")
            missing = _list(response.get("failures", []), "DescribeTasks")
            _require_covered(batch, found, "taskArn", missing, "DescribeTasks")
            tasks += found
            failures += missing
        return {"tasks": tasks, "failures": failures}

    def _list_all(self, **filters: Any) -> list[str]:
        """Follow nextToken to the end, or report the enumeration as incomplete."""
        arns: list[str] = []
        token: str | None = None
        for _ in range(MAX_LIST_PAGES):
            params = {"cluster": self.cluster, "maxResults": LIST_PAGE_SIZE, **filters}
            if token is not None:
                params["nextToken"] = token
            response = call(self.client, "list_tasks", **params)
            # A page without its task list is not an empty page.
            page = _list(response.get("taskArns"), "ListTasks")
            if not all(isinstance(arn, str) for arn in page):
                raise AmbiguousResponse("ListTasks: malformed response")
            arns += page
            token = response.get("nextToken")
            if token is None:
                return arns
            if not isinstance(token, str) or not token:
                raise AmbiguousResponse("ListTasks: malformed response")
        raise AmbiguousResponse("ListTasks: enumeration exceeded its page bound")

    def _stopped(self) -> list[dict[str, Any]]:
        """Every task whose desired status is STOPPED, described completely."""
        arns = self._list_all(desiredStatus="STOPPED")
        described = self.describe_tasks(self.cluster, arns) if arns else {"tasks": []}
        if described.get("failures"):
            # A listed task that cannot be described cannot be shown to be stopped
            # or to carry a different launch token.
            raise AmbiguousResponse("DescribeTasks: stopped task not described")
        return [task for task in described["tasks"] if isinstance(task, dict)]

    def list_tasks(
        self, cluster: str, *, started_by: str | None = None, service_name: str | None = None
    ) -> list[str]:
        self._cluster(cluster)
        if started_by is not None and service_name is not None:
            raise ValueError("list by launch token or by service, not both")
        if started_by is not None:
            # ECS accepts startedBy only as the sole filter, which lists tasks it
            # still intends to run. A launch that already exited is still the
            # launch, so stopped tasks carrying the token are added.
            found = self._list_all(startedBy=started_by)
            exited = [
                str(task.get("taskArn"))
                for task in self._stopped()
                if task.get("startedBy") == started_by and task.get("taskArn") not in found
            ]
            return found + exited
        if service_name is not None:
            return self._list_all(serviceName=service_name, desiredStatus="RUNNING")
        # Cluster-wide: every task not yet stopped, including one whose stop was
        # requested but which may still be running its process.
        running = self._list_all(desiredStatus="RUNNING")
        stopping = [
            str(task.get("taskArn"))
            for task in self._stopped()
            if task.get("lastStatus") != "STOPPED" and task.get("taskArn") not in running
        ]
        return running + stopping

    def update_service(self, request: dict[str, Any]) -> dict[str, Any]:
        self._cluster(request.get("cluster", ""))
        _check_update_service(request)
        response = call(self.client, "update_service", **request)
        service = response.get("service")
        if not isinstance(service, dict):
            raise AmbiguousResponse("UpdateService: malformed response")
        return {"service": service}

    def describe_services(self, cluster: str, services: list[str]) -> list[dict[str, Any]]:
        self._cluster(cluster)
        found: list[dict[str, Any]] = []
        for start in range(0, len(services), DESCRIBE_SERVICES_BATCH):
            batch = services[start : start + DESCRIBE_SERVICES_BATCH]
            response = call(self.client, "describe_services", cluster=cluster, services=batch)
            described = _list(response.get("services", []), "DescribeServices")
            missing = _list(response.get("failures", []), "DescribeServices")
            _require_covered(batch, described, "serviceArn", missing, "DescribeServices")
            # Reported failures surface as absent services; the controller holds on them.
            found += described
        return found

    def stop_task(self, cluster: str, task_arn: str, reason: str) -> dict[str, Any]:
        self._cluster(cluster)
        if not 0 < len(reason) <= 255:
            raise ValueError("StopTask reason must be 1-255 characters")
        response = call(self.client, "stop_task", cluster=cluster, task=task_arn, reason=reason)
        return {"task": response.get("task")}
