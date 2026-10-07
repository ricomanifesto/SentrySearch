"""Deterministic in-memory fakes for offline release-controller tests.

Nothing here models IAM, networking or real ECS scheduling. The fakes reproduce
only the response shapes and failure modes the controller must reason about.
All identifiers use the documentation account and are not real resources.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import copy
import hashlib
import json
from typing import Any, Callable

from release.journal import PreconditionFailed
from release.ports import AmbiguousResponse
from release.readiness import WORKER_RECEIPT_KIND, WORKER_RECEIPT_MARKER

ACCOUNT = "111122223333"
REGION = "us-east-1"
CLUSTER = f"arn:aws:ecs:{REGION}:{ACCOUNT}:cluster/sentry-staging"
REGISTRY = f"{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com"
START = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)
RELEASE_ID = "0b9f7c1e-4d2a-4f6b-9a3e-2c1d0e9f8a7b"
PRIOR_RELEASE_ID = "5e6f7a8b-1c2d-4e3f-8a9b-0c1d2e3f4a5b"
# The settings deploy/aws-staging/services gives every service. Terraform owns
# them; the controller only reads them.
TERRAFORM_SERVICE_SETTINGS: dict[str, Any] = {
    "deploymentConfiguration": {
        "deploymentCircuitBreaker": {"enable": True, "rollback": False},
        "maximumPercent": 100,
        "minimumHealthyPercent": 0,
    },
    "deploymentController": {"type": "ECS"},
    "enableExecuteCommand": False,
}
# ECS defaults that a deploymentConfiguration without percentages may restore.
# Whether it does is unverified; the fake assumes the pessimistic case.
ECS_DEFAULT_PERCENTS = {"maximumPercent": 200, "minimumHealthyPercent": 100}
RUNTIME_GRANT = {
    "path": "db/roles/service.sql",
    "source_commit": "bb6e523da3c6f4bb186a548f3be696a40798fae9",
    "sha256": "02a2b55161506254b1977f26351ec3bbba4de7c94a54b3b697153d622ae02aa0",
}


def digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def sha(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def task_definition(family: str, revision: int = 7) -> str:
    return f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/{family}:{revision}"


def role(name: str) -> str:
    return f"arn:aws:iam::{ACCOUNT}:role/sentry-staging/{name}"


def secret(name: str) -> dict:
    return {
        "arn": f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:sentry-staging/{name}-AbC123",
        "version_id": hashlib.md5(name.encode()).hexdigest()[:8]
        + "-1111-4222-8333-"
        + hashlib.md5(name.encode()).hexdigest()[:12],
    }


def task_spec(name: str, app_image: str, *, revision: int = 7, app: str | None = None) -> dict:
    return {
        "task_definition": task_definition(f"sentry-staging-{name}", revision),
        "task_role": role(f"{name}-task"),
        "execution_role": role(f"{name}-execution"),
        "secrets": [
            secret(f"{name}-environment-r{revision}"),
            secret(f"{name}-material-r{revision}"),
        ],
        "security_groups": [f"sg-{sha(name)[:17]}"],
        "containers": [
            {"name": "init", "image": "search"},
            {"name": app or name, "image": app_image},
        ],
    }


def job(job_id: str, phase: str, database: str, *, image: str, expect: dict, sql=None) -> dict:
    spec = task_spec(job_id, image, app="migration" if phase == "migrate" else phase)
    result = {
        "id": job_id,
        "phase": phase,
        "database": database,
        "task": spec,
        "deadline_seconds": 900,
        "stop_grace_seconds": 30,
        "receipt_schema": (
            f"sentry.release.{phase}.v1" if phase == "migrate" else "sentry.release-tools.job.v1"
        ),
        "expect": expect,
    }
    if sql is not None:
        result["sql"] = sql
    return result


def services(revision: int = 7) -> dict:
    # deploy/aws-platform-fit names every service's application container "app".
    return {
        "runtime": task_spec("runtime", "runtime", revision=revision, app="app"),
        "api": task_spec("api", "search", revision=revision, app="app"),
        "worker": task_spec("worker", "search", revision=revision, app="app"),
    }


def image(name: str, label: str = "candidate") -> dict:
    return {
        "repository": f"{REGISTRY}/sentry-staging-{name}",
        "manifest_digest": digest(f"{name}-{label}-index"),
        "arm64_digest": digest(f"{name}-{label}-arm64"),
        "provenance_sha256": sha(f"{name}-{label}-provenance"),
        "sbom_sha256": sha(f"{name}-{label}-sbom"),
        "scan_sha256": sha(f"{name}-{label}-scan"),
    }


def manifest_document(*, rollback: str = "empty_hold") -> dict:
    db = {"database": "runtime_db", "principal": "runtime_owner"}
    product = {"database": "product_db", "principal": "product_owner"}
    document = {
        "schema_version": 1,
        "release_id": RELEASE_ID,
        "milestone": "operational-paused",
        "environment": {
            "name": "staging",
            "account_id": ACCOUNT,
            "region": REGION,
            "cluster_arn": CLUSTER,
            "services": {
                name: f"arn:aws:ecs:{REGION}:{ACCOUNT}:service/sentry-staging/{name}"
                for name in ("runtime", "api", "worker")
            },
        },
        "operator": "fixture-operator",
        "window": {
            "not_before": iso(START - timedelta(hours=1)),
            "expires_at": iso(START + timedelta(hours=6)),
            "total_seconds": 3600,
            "poll_seconds": 5,
            "service_start_seconds": 600,
        },
        # The release-tools image is built from the reviewed Search source.
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
        "network": {
            "subnets": ["subnet-0a1b2c3d4e5f60718", "subnet-0f1e2d3c4b5a69788"],
            "assign_public_ip": "DISABLED",
            "platform_version": "1.4.0",
        },
        "services": services(),
        "jobs": [
            job("runtime-migrate", "migrate", "runtime", image="runtime",
                expect={**db, "schema": "goose:1,2,3"}),
            job("product-migrate", "migrate", "product", image="search",
                expect={**product, "schema": "sentrysearch:1:" + sha("001_release.sql")[:16]}),
            job("runtime-grant", "grant", "runtime", image="release_tools",
                expect={**db, "service_role": "runtime_service",
                        "sql_digest": RUNTIME_GRANT["sha256"]},
                sql=dict(RUNTIME_GRANT)),
            job("product-grant", "grant", "product", image="release_tools",
                expect={**product, "service_role": "product_service",
                        "sql_digest": sha("product-grants")},
                sql={"path": "release_tools/sql/product/grants.sql", "source_commit": "c" * 40,
                     "sha256": sha("product-grants")}),
            job("runtime-proof", "proof", "runtime", image="release_tools",
                expect={"database": "runtime_db", "principal": "runtime_service",
                        "schema": "goose:1,2,3"}),
            job("product-proof", "proof", "product", image="release_tools",
                expect={"database": "product_db", "principal": "product_service",
                        "schema": "sentrysearch:1:" + sha("001_release.sql")[:16]}),
        ],  # fmt: skip
        "operational_checks": [
            {"id": "worker-readiness", "receipt_schema": "sentry.worker-readiness.v1"},
            {
                "id": "runtime-protected-readiness",
                "receipt_schema": "sentry.release.runtime-ready.v1",
            },
            {"id": "api-operational", "receipt_schema": "sentry.release.api-ready.v1"},
        ],
        "rollback": {"kind": "empty_hold"},
    }
    if rollback == "compatible_release":
        document["rollback"] = {
            "kind": "compatible_release",
            "release_id": PRIOR_RELEASE_ID,
            "images": {
                name: {
                    "repository": f"{REGISTRY}/sentry-staging-{name}",
                    "arm64_digest": digest(f"{name}-prior-arm64"),
                }
                for name in ("runtime", "search")
            },
            "services": services(revision=6),
            "trust_sha256": sha("prior-trust"),
            "compatible_schemas": {
                "runtime": ["goose:1,2,3"],
                "product": ["sentrysearch:1:" + sha("001_release.sql")[:16]],
            },
            "backups": {
                "runtime": f"arn:aws:rds:{REGION}:{ACCOUNT}:snapshot:runtime-pre-release",
                "product": f"arn:aws:rds:{REGION}:{ACCOUNT}:snapshot:product-pre-release",
            },
        }
    return document


def encode(document: dict) -> bytes:
    return json.dumps(document, indent=2).encode()


def approval_document(manifest_sha256: str, **changes: Any) -> dict:
    document = {
        "schema_version": 1,
        "kind": "release-approval",
        "release_id": RELEASE_ID,
        "manifest_sha256": manifest_sha256,
        "environment": "staging",
        "account_id": ACCOUNT,
        "region": REGION,
        "milestone": "operational-paused",
        "approved_by": "fixture-approver",
        "not_before": iso(START - timedelta(minutes=30)),
        "not_after": iso(START + timedelta(hours=4)),
    }
    document.update(changes)
    return document


class SimulatedCrash(BaseException):
    """Process loss: not an Exception, so the controller cannot record it."""


class FakeClock:
    def __init__(self, start: datetime = START) -> None:
        self.moment = start

    def now(self) -> datetime:
        return self.moment

    def sleep(self, seconds: float) -> None:
        self.moment += timedelta(seconds=seconds)

    def advance(self, **delta: float) -> None:
        self.moment += timedelta(**delta)


class Tokens:
    def __init__(self, prefix: str = "tok") -> None:
        self.prefix = prefix
        self.count = 0

    def __call__(self) -> str:
        self.count += 1
        return f"{self.prefix}{self.count:04d}" + "0" * 28


class Trace(list):
    """Shared ordering of journal writes and ECS mutations."""


class FakeStore:
    def __init__(self, trace: Trace | None = None) -> None:
        self.objects: dict[str, tuple[bytes, str]] = {}
        self.versions = 0
        self.trace = trace if trace is not None else Trace()
        self.before_replace: Callable[[str, bytes], None] | None = None

    def _etag(self) -> str:
        self.versions += 1
        return f'"etag-{self.versions}"'

    def create(self, key: str, body: bytes) -> str:
        if key in self.objects:
            raise PreconditionFailed(key)
        etag = self._etag()
        self.objects[key] = (body, etag)
        self.trace.append(("store", key, json.loads(body)))
        return etag

    def read(self, key: str) -> tuple[bytes, str] | None:
        return self.objects.get(key)

    def replace(self, key: str, body: bytes, *, if_match: str) -> str:
        if self.before_replace is not None:
            self.before_replace(key, body)
        current = self.objects.get(key)
        if current is None or current[1] != if_match:
            raise PreconditionFailed(key)
        etag = self._etag()
        self.objects[key] = (body, etag)
        self.trace.append(("store", key, json.loads(body)))
        return etag

    def delete(self, key: str, *, if_match: str) -> None:
        current = self.objects.get(key)
        if current is None or current[1] != if_match:
            raise PreconditionFailed(key)
        del self.objects[key]
        self.trace.append(("store-delete", key, None))

    def journal(self) -> dict:
        body = self.objects[f"releases/{RELEASE_ID}/journal.json"][0]
        return json.loads(body)


@dataclass
class JobPlan:
    seconds: float = 30
    exits: dict[str, int | None] = field(default_factory=dict)
    stop_code: str = "EssentialContainerExited"
    hang: bool = False
    launch_failure: str | None = None
    task_count: int = 1
    image_override: dict[str, str] = field(default_factory=dict)


@dataclass
class FakeTask:
    arn: str
    task_definition: str
    started_by: str
    group: str
    created: datetime
    containers: list[dict]
    plan: JobPlan | None = None
    stopped_at: datetime | None = None
    stop_code: str | None = None
    tags: dict[str, str] = field(default_factory=dict)
    health_after: float = 5


@dataclass
class FakeService:
    name: str
    task_definition: str
    desired: int = 0
    deployments: list[dict] = field(default_factory=list)
    extra_tasks: int = 0
    fail_rollout: bool = False
    replace_after: float | None = None
    linger_old: bool = False
    settings: dict = field(default_factory=lambda: copy.deepcopy(TERRAFORM_SERVICE_SETTINGS))


class FakeEcs:
    def __init__(self, clock: FakeClock, trace: Trace | None = None) -> None:
        self.clock = clock
        self.trace = trace if trace is not None else Trace()
        self.tasks: dict[str, FakeTask] = {}
        self.tokens: dict[str, tuple[str, list[str]]] = {}
        self.plans: dict[str, JobPlan] = {}
        self.services: dict[str, FakeService] = {}
        self.digests: dict[str, str] = {}
        self.visibility_delay = 0.0
        self.crash: dict[tuple[str, str], int] = {}
        self.ambiguous: dict[str, int] = {}
        self.mutations: list[tuple[str, dict]] = []
        # Task definition -> fields replacing the observed task's (overrides, Exec).
        self.quirks: dict[str, dict] = {}
        self.counter = 0

    # Test configuration -------------------------------------------------
    def configure(self, document: dict, *, running_prior: bool = False) -> None:
        images = document["images"]
        self.digests = {name: images[name]["arm64_digest"] for name in images}
        for name, arn in document["environment"]["services"].items():
            candidate = document["services"][name]["task_definition"]
            service = FakeService(name=name, task_definition=candidate)
            self.services[arn] = service
            if running_prior:
                prior = document["rollback"]["services"][name]
                service.task_definition = prior["task_definition"]
                service.desired = 1
                deployment = self._deployment(service, prior["task_definition"], 1)
                prior_digests = {
                    key: document["rollback"]["images"][key]["arm64_digest"]
                    for key in document["rollback"]["images"]
                }
                self._task(
                    prior["task_definition"], deployment["id"], f"service:{name}",
                    [(c["name"], prior_digests[c["image"]]) for c in prior["containers"]],
                )  # fmt: skip
        for item in document["jobs"]:
            self.plans.setdefault(item["task"]["task_definition"], JobPlan())
        self.containers = {
            spec["task_definition"]: [(c["name"], c["image"]) for c in spec["containers"]]
            for spec in [*document["services"].values(), *(j["task"] for j in document["jobs"])]
        }

    def _maybe_crash(self, method: str, when: str) -> None:
        remaining = self.crash.get((method, when), 0)
        if remaining:
            self.crash[(method, when)] = remaining - 1
            raise SimulatedCrash(f"{method} {when}")

    def _deployment(self, service: FakeService, definition: str, desired: int) -> dict:
        self.counter += 1
        for old in service.deployments:
            if old["status"] == "PRIMARY":
                old["status"] = "ACTIVE"
        deployment = {
            "id": f"ecs-svc/{self.counter:019d}",
            "status": "PRIMARY",
            "taskDefinition": definition,
            "desiredCount": desired,
            "createdAt": self.clock.now(),
            "rolloutState": "IN_PROGRESS",
        }
        service.deployments.append(deployment)
        return deployment

    def _task(self, definition, started_by, group, containers, plan=None, tags=None) -> FakeTask:
        self.counter += 1
        arn = f"arn:aws:ecs:{REGION}:{ACCOUNT}:task/sentry-staging/{self.counter:032x}"
        task = FakeTask(
            arn=arn,
            task_definition=definition,
            started_by=started_by,
            group=group,
            created=self.clock.now(),
            containers=[{"name": name, "imageDigest": value} for name, value in containers],
            plan=plan,
            tags=tags or {},
        )
        self.tasks[arn] = task
        return task

    # Derived task state --------------------------------------------------
    def _status(self, task: FakeTask) -> str:
        now = self.clock.now()
        if task.stopped_at is not None and now >= task.stopped_at:
            return "STOPPED"
        plan = task.plan
        if (
            plan is not None
            and not plan.hang
            and now >= task.created + timedelta(seconds=plan.seconds)
        ):
            task.stopped_at = task.created + timedelta(seconds=plan.seconds)
            task.stop_code = plan.stop_code
            return "STOPPED"
        return "RUNNING" if now >= task.created + timedelta(seconds=1) else "PENDING"

    def _visible(self, task: FakeTask) -> bool:
        return self.clock.now() >= task.created + timedelta(seconds=self.visibility_delay)

    def _describe(self, task: FakeTask) -> dict:
        status = self._status(task)
        containers = []
        for container in task.containers:
            item = dict(container)
            if status == "STOPPED":
                if task.plan is not None:
                    item["exitCode"] = task.plan.exits.get(container["name"], 0)
                    if item["exitCode"] is None:
                        del item["exitCode"]
                    if task.stop_code == "UserInitiated" and container["name"] != "init":
                        item["exitCode"] = 137
                else:
                    item["exitCode"] = 0
            containers.append(item)
        result = {
            "taskArn": task.arn,
            "clusterArn": CLUSTER,
            "taskDefinitionArn": task.task_definition,
            "lastStatus": status,
            # ECS flips the desired status as soon as a stop is requested.
            "desiredStatus": "STOPPED" if status == "STOPPED" or task.stopped_at else "RUNNING",
            "startedBy": task.started_by,
            "group": task.group,
            "containers": containers,
            # ECS reports every container by name, with nothing overridden.
            "overrides": {
                "containerOverrides": [{"name": c["name"]} for c in task.containers],
                "inferenceAcceleratorOverrides": [],
            },
            "enableExecuteCommand": False,
            **copy.deepcopy(self.quirks.get(task.task_definition, {})),
        }
        if status == "RUNNING" and task.plan is None:
            healthy = self.clock.now() >= task.created + timedelta(seconds=task.health_after)
            result["healthStatus"] = "HEALTHY" if healthy else "UNKNOWN"
        if status == "STOPPED":
            result["stopCode"] = task.stop_code or "EssentialContainerExited"
            result["stoppedReason"] = "fixture"
        return result

    # ECS-shaped API ------------------------------------------------------
    def run_task(self, request: dict) -> dict:
        self._maybe_crash("run_task", "before")
        self.mutations.append(("run_task", copy.deepcopy(request)))
        self.trace.append(("ecs", "run_task", request["clientToken"]))
        if self.ambiguous.get("run_task_before", 0):
            self.ambiguous["run_task_before"] -= 1
            raise AmbiguousResponse("connection reset before send completed")
        token = request["clientToken"]
        fingerprint = json.dumps(request, sort_keys=True)
        if token in self.tokens:
            stored, arns = self.tokens[token]
            if stored != fingerprint:
                raise ValueError("idempotent parameter mismatch")
            response = {"tasks": [self._describe(self.tasks[a]) for a in arns], "failures": []}
        else:
            plan = self.plans.get(request["taskDefinition"], JobPlan())
            if plan.launch_failure is not None:
                self.tokens[token] = (fingerprint, [])
                response = {
                    "tasks": [],
                    "failures": [{"arn": request["taskDefinition"], "reason": plan.launch_failure}],
                }
            else:
                arns = []
                for _ in range(plan.task_count):
                    containers = [
                        (name, plan.image_override.get(name, self.digests[image]))
                        for name, image in self.containers[request["taskDefinition"]]
                    ]
                    tags = {tag["key"]: tag["value"] for tag in request.get("tags", [])}
                    task = self._task(
                        request["taskDefinition"], request["startedBy"], "family:job", containers,
                        plan=plan, tags=tags,
                    )  # fmt: skip
                    arns.append(task.arn)
                self.tokens[token] = (fingerprint, arns)
                response = {"tasks": [self._describe(self.tasks[a]) for a in arns], "failures": []}
        if self.ambiguous.get("run_task_after", 0):
            self.ambiguous["run_task_after"] -= 1
            raise AmbiguousResponse("response lost after the request was applied")
        self._maybe_crash("run_task", "after")
        return response

    def describe_tasks(self, cluster: str, task_arns: list[str]) -> dict:
        assert cluster == CLUSTER
        tasks, failures = [], []
        for arn in task_arns:
            task = self.tasks.get(arn)
            if task is None or not self._visible(task):
                failures.append({"arn": arn, "reason": "MISSING"})
            else:
                tasks.append(self._describe(task))
        return {"tasks": tasks, "failures": failures}

    def list_tasks(self, cluster: str, *, started_by: str | None = None,
                   service_name: str | None = None) -> list[str]:  # fmt: skip
        assert cluster == CLUSTER
        self._converge()
        result = []
        for task in self.tasks.values():
            if not self._visible(task):
                continue
            # A launch-token listing includes stopped tasks; other listings do not.
            if started_by is None and self._status(task) == "STOPPED":
                continue
            if started_by is not None and task.started_by != started_by:
                continue
            if service_name is not None and (
                task.group != f"service:{service_name}" or task.stopped_at is not None
            ):
                # A service listing holds the tasks ECS still intends to run.
                continue
            result.append(task.arn)
        return result

    def update_service(self, request: dict) -> dict:
        self._maybe_crash("update_service", "before")
        self.mutations.append(("update_service", copy.deepcopy(request)))
        self.trace.append(("ecs", "update_service", request["service"]))
        service = self.services[request["service"]]
        if "deploymentConfiguration" in request:
            # A partial structure replaces Terraform's, percentages included.
            service.settings["deploymentConfiguration"] = {
                **ECS_DEFAULT_PERCENTS,
                **copy.deepcopy(request["deploymentConfiguration"]),
            }
        if "enableExecuteCommand" in request:
            service.settings["enableExecuteCommand"] = request["enableExecuteCommand"]
        if "taskDefinition" in request:
            service.task_definition = request["taskDefinition"]
        service.desired = request["desiredCount"]
        primary = next((d for d in service.deployments if d["status"] == "PRIMARY"), None)
        if (
            request.get("forceNewDeployment")
            or primary is None
            or (primary["taskDefinition"] != service.task_definition)
        ):
            primary = self._deployment(service, service.task_definition, service.desired)
        primary["desiredCount"] = service.desired
        if service.desired == 0:
            for task in self.tasks.values():
                if task.group == f"service:{service.name}" and task.stopped_at is None:
                    task.stopped_at = self.clock.now() + timedelta(seconds=10)
                    task.stop_code = "ServiceSchedulerInitiated"
        response = {"service": self._service(request["service"])}
        self._maybe_crash("update_service", "after")
        return response

    def _converge(self) -> None:
        now = self.clock.now()
        for service in self.services.values():
            primary = next((d for d in service.deployments if d["status"] == "PRIMARY"), None)
            group = f"service:{service.name}"
            live = [
                t for t in self.tasks.values() if t.group == group and self._status(t) != "STOPPED"
            ]
            for task in live:
                if primary is None or task.started_by != primary["id"]:
                    if not service.linger_old and task.stopped_at is None:
                        task.stopped_at = now + timedelta(seconds=10)
                        task.stop_code = "ServiceSchedulerInitiated"
            if primary is None or service.desired == 0:
                continue
            if service.fail_rollout:
                # Circuit-breaker failure: tasks never become healthy, then FAILED.
                if now >= primary["createdAt"] + timedelta(seconds=20):
                    primary["rolloutState"] = "FAILED"
                continue
            mine = [t for t in live if t.started_by == primary["id"] and t.stopped_at is None]
            if service.replace_after is not None and mine:
                first = mine[0]
                if now >= first.created + timedelta(seconds=service.replace_after):
                    first.stopped_at = now
                    first.stop_code = "TaskFailedToStart"
                    service.replace_after = None
                    mine = []
            wanted = service.desired + service.extra_tasks
            while len(mine) < wanted:
                containers = [
                    (name, self.digests[image])
                    for name, image in self.containers[primary["taskDefinition"]]
                ]
                mine.append(self._task(primary["taskDefinition"], primary["id"], group, containers))
            if len(mine) == service.desired:
                primary["rolloutState"] = "COMPLETED"

    def _service(self, arn: str) -> dict:
        self._converge()
        service = self.services[arn]
        group = f"service:{service.name}"
        live = [self._describe(t) for t in self.tasks.values() if t.group == group]
        running = [t for t in live if t["lastStatus"] == "RUNNING"]
        pending = [t for t in live if t["lastStatus"] == "PENDING"]
        deployments = []
        for deployment in service.deployments:
            if deployment["status"] == "INACTIVE":
                continue
            mine = [t for t in running if t["startedBy"] == deployment["id"]]
            if deployment["status"] == "ACTIVE" and not mine:
                deployment["status"] = "INACTIVE"
                continue
            item = {key: value for key, value in deployment.items() if key != "createdAt"}
            item["runningCount"] = len(mine)
            deployments.append(item)
        return {
            "serviceArn": arn,
            "clusterArn": CLUSTER,
            "taskDefinition": service.task_definition,
            "desiredCount": service.desired,
            "runningCount": len(running),
            "pendingCount": len(pending),
            "deployments": deployments,
            **copy.deepcopy(service.settings),
        }

    def describe_services(self, cluster: str, services: list[str]) -> list[dict]:
        assert cluster == CLUSTER
        return [self._service(arn) for arn in services]

    def stop_task(self, cluster: str, task_arn: str, reason: str) -> dict:
        assert cluster == CLUSTER
        self._maybe_crash("stop_task", "before")
        self.mutations.append(("stop_task", {"task": task_arn, "reason": reason}))
        self.trace.append(("ecs", "stop_task", task_arn))
        task = self.tasks[task_arn]
        if task.stopped_at is None:
            task.stopped_at = self.clock.now() + timedelta(seconds=10)
            task.stop_code = "UserInitiated"
        return {"task": self._describe(task)}

    def standalone(self, definition: str) -> FakeTask:
        """Start an unrelated writer that is not owned by any service."""
        return self._task(
            definition, "someone-else", "family:writer", [("app", "sha256:" + "0" * 64)]
        )


class FakeEvidence:
    """Sanitized receipts as an external log reader would return them."""

    def __init__(self, ecs: FakeEcs, document: dict) -> None:
        self.ecs = ecs
        self.jobs = {item["id"]: item for item in document["jobs"]}
        self.checks = {item["id"]: item for item in document["operational_checks"]}
        self.service_arns = document["environment"]["services"]
        self.missing_jobs: set[str] = set()
        self.job_changes: dict[str, dict] = {}
        self.missing_checks: set[str] = set()
        self.check_changes: dict[str, dict] = {}

    def job_receipt(self, release_id: str, job_id: str, task_arn: str) -> dict | None:
        task = self.ecs.tasks.get(task_arn)
        if job_id in self.missing_jobs or task is None or self.ecs._status(task) != "STOPPED":
            return None
        if task.plan is not None and any(
            task.plan.exits.get(c["name"], 0) for c in task.containers
        ):
            return None
        item = self.jobs[job_id]
        receipt = {
            "schema": item["receipt_schema"],
            "release_id": task.tags.get("sentry:release-id"),
            "job_id": task.tags.get("sentry:job-id"),
            "task_arn": task_arn,
            "status": "succeeded",
            "result": copy.deepcopy(item["expect"]),
        }
        receipt.update(self.job_changes.get(job_id, {}))
        return receipt

    def operational_receipt(self, release_id: str, check_id: str) -> dict | None:
        if check_id in self.missing_checks:
            return None
        tasks = {}
        for name, arn in self.service_arns.items():
            running = self.ecs.list_tasks(CLUSTER, service_name=name)
            tasks[name] = running[0] if running else ""
        receipt = {
            "schema": self.checks[check_id]["receipt_schema"],
            "release_id": release_id,
            "check_id": check_id,
            "status": "passed",
            "tasks": tasks,
        }
        receipt.update(self.check_changes.get(check_id, {}))
        return receipt


class FakeLogs:
    """Worker supervisor receipts as GetLogEvents pages for the observed task.

    Receipts follow the producer contract: one every 10 s from one second after
    task start, with uptime from process start. Knobs drop, edit, duplicate, delay
    or stall them, or make reads fail. Nothing here models CloudWatch ingestion,
    retention or IAM; ``delay`` is a fixed stand-in for ingestion latency.
    """

    def __init__(self, ecs: FakeEcs, document: dict) -> None:
        self.ecs = ecs
        self.release_id = document["release_id"]
        self.group = f"/{document['environment']['name']}/worker"
        self.delay = 1.0
        self.page_size = 100
        self.empty_pages = 0
        self.denied = False
        self.missing = False
        self.endless = False
        # (after_sequence, seconds): the loop stalls, then resumes without a gap.
        self.stall: tuple[int, float] | None = None
        # Replace each receipt with zero or more receipts (drop, edit, duplicate).
        self.edit: Callable[[int, dict], list[dict]] | None = None
        self.before_read: Callable[[], None] | None = None
        self.calls: list[dict] = []
        self.delivered: list[str] = []

    @staticmethod
    def boot_id(task: FakeTask) -> str:
        return hashlib.md5(task.arn.encode()).hexdigest()

    @staticmethod
    def observed(task: FakeTask, sequence: int, offset: float = 0) -> datetime:
        return task.created + timedelta(seconds=1 + 10 * (sequence - 1) + offset)

    def _events(self, task: FakeTask) -> list[tuple[datetime, str]]:
        now = self.ecs.clock.now()
        end = min(task.stopped_at or now, now)
        events, sequence, offset = [], 1, 0.0
        while True:
            if self.stall is not None and sequence == self.stall[0] + 1:
                offset += self.stall[1]
            at = self.observed(task, sequence, offset)
            if at > end:
                return events
            receipt = {
                "kind": WORKER_RECEIPT_KIND,
                "release_id": self.release_id,
                "boot_id": self.boot_id(task),
                "sequence": sequence,
                "observed_at": at.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                "uptime_seconds": 0.5 + (at - self.observed(task, 1)).total_seconds(),
                "alive": True,
                "ready": True,
                "draining": False,
                "phase": "generation" if sequence % 2 else "idle",
                "phase_elapsed_seconds": 1.0,
                "phase_budget_seconds": 62.0,
                "error_code": None,
            }
            for item in [receipt] if self.edit is None else self.edit(sequence, receipt):
                body = json.dumps(item, separators=(",", ":"))
                events.append((at, f"{WORKER_RECEIPT_MARKER} {body}"))
            events.append((at, "INFO sentrysearch worker loop"))  # ordinary output
            sequence += 1

    def get_log_events(
        self,
        log_group: str,
        log_stream: str,
        *,
        start_time_ms: int,
        end_time_ms: int,
        next_token: str | None,
        limit: int,
    ) -> dict:
        self.calls.append(
            {
                "log_group": log_group,
                "log_stream": log_stream,
                "start_time_ms": start_time_ms,
                "end_time_ms": end_time_ms,
                "next_token": next_token,
                "limit": limit,
                "at": self.ecs.clock.now(),
            }
        )
        if self.before_read is not None:
            self.before_read()
        if self.denied:
            raise PermissionError("AccessDeniedException")
        task = next(
            (
                item
                for item in self.ecs.tasks.values()
                if item.group == "service:worker"
                and log_stream == f"worker/{self.release_id}/app/" + item.arn.rsplit("/", 1)[1]
            ),
            None,
        )
        if self.missing or log_group != self.group or task is None:
            raise LookupError("ResourceNotFoundException")
        now = self.ecs.clock.now()
        visible = [
            {"timestamp": int(at.timestamp() * 1000), "message": message}
            for at, message in self._events(task)
            if start_time_ms <= at.timestamp() * 1000 < end_time_ms
            and at + timedelta(seconds=self.delay) <= now
        ]
        parts = (next_token or "f/0").split("/")
        position = int(parts[1])
        empty = int(parts[2][1:]) if len(parts) > 2 else 0
        if self.endless:
            return {"events": [], "nextForwardToken": f"f/{position}/x{len(self.calls)}"}
        if empty < self.empty_pages:
            # A new token with no events: not the end of the stream.
            return {"events": [], "nextForwardToken": f"f/{position}/e{empty + 1}"}
        page = visible[position : position + min(limit, self.page_size)]
        self.delivered.extend(str(event["message"]) for event in page)
        token = f"f/{position + len(page)}" if page else (next_token or "f/0")
        return {"events": page, "nextForwardToken": token}
