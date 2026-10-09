"""Deterministic offline fixtures for the Cloudflare release path.

Every identifier is synthetic: the account, zone, namespace, application and
version ids below are derived from labels and name no real resource.
"""

from __future__ import annotations

from datetime import timedelta
import hashlib
from typing import Any

from tests.release_fakes import (
    PRIOR_RELEASE_ID,
    RELEASE_ID,
    RUNTIME_GRANT,
    START,
    SimulatedCrash,
    digest,
    iso,
    sha,
)

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
            "bootstrap_control_protocol": "sentry.authority.v1",
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
            "control_protocol": "sentry.authority.v1",
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


# Platform fakes ---------------------------------------------------------------
#
# FakeDOControl is a transport for the real ControlClient: it parses each signed
# request and applies the object rules (signature over the canonical bytes,
# target, expiry and lifetime, same-release fence ordering or the cross-release
# allowlist, command-id replay, then the action). FakeVersions holds the
# Workers' versions and deployments, the container applications and their
# instance listings. Objects progress lazily with the shared fake clock.
# Nothing here models Cloudflare scheduling, networking, IAM or real latency.

import base64 as _base64
import copy as _copy
import json as _json
from dataclasses import dataclass as _dataclass
from dataclasses import field as _field
from datetime import datetime as _datetime
from typing import Callable as _Callable

from release.ports import AmbiguousResponse as _Ambiguous
from release.readiness import WORKER_RECEIPT_KIND as _RECEIPT_KIND
from release_cloudflare.control_client import (
    CommandNotSent as _NotSent,
    ControlCommand as _Command,
    TransportAmbiguous as _TransportAmbiguous,
    canonical_bytes as _canonical,
)
from release_cloudflare.ports import (
    ApplicationState as _Application,
    Deployment as _Deployment,
    InstancePage as _InstancePage,
    VersionInfo as _VersionInfo,
)

BOOTSTRAP_RELEASE = "00000000-0000-4000-8000-000000000000"
SERVICE_OBJECTS = {"runtime": "runtime-0", "api": "api-0", "worker": "worker-0"}
CROSS_RELEASE = {("GET", "status"), ("POST", "receipts"), ("POST", "receipt"), ("POST", "stop")}
LIVE = ("starting", "running", "draining")


def object_id(service: str, name: str) -> str:
    return hashlib.sha256(f"{service}/{name}".encode()).hexdigest()


def nonce_of(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()[:32]


class FakeVersions:
    """Worker versions, deployments, container applications and their instances."""

    def __init__(self, clock, document: dict, trace: list | None = None) -> None:
        self.clock = clock
        self.document = document
        self.trace = trace if trace is not None else []
        environment = document["environment"]
        self.scripts = dict(environment["workers"])
        self.release_of_version: dict[str, str] = {}
        for worker, version in environment["bootstrap_versions"].items():
            self.release_of_version[version] = BOOTSTRAP_RELEASE
        for worker, version in document["versions"].items():
            self.release_of_version[version] = document["release_id"]
        rollback = document["rollback"]
        if rollback["kind"] == "compatible_release":
            for worker, version in rollback["versions"].items():
                self.release_of_version[version] = rollback["release_id"]
        self.current = {
            script: _Deployment(
                f"dep-{worker}-0", ((environment["bootstrap_versions"][worker], 100),)
            )
            for worker, script in self.scripts.items()
        }
        self.apps = {
            worker: _Application(
                id=spec["id"],
                scheduling_policy=spec["scheduling_policy"],
                instance_type=spec["instance_type"],
                ssh_enabled=spec["ssh_enabled"],
                logs_enabled=spec["logs_enabled"],
                images=tuple(spec["images"]),
            )
            for worker, spec in document["applications"].items()
        }
        self.uploaded: dict[str, list[_VersionInfo]] = {
            script: [] for script in self.scripts.values()
        }
        self.faults: dict[str, list[str]] = {}
        self.calls: list[tuple] = []
        self.mutations: list[tuple] = []
        self.control: FakeDOControl | None = None
        self.standalone: dict[str, list[dict]] = {}
        self.page_size = 1
        self.endless_listing: set[str] = set()
        self.failing_listing: set[str] = set()
        self._deployments = 0
        self.before_read: _Callable[[str], None] | None = None

    # Helpers for tests --------------------------------------------------------

    def worker_of(self, script: str) -> str:
        return next(worker for worker, name in self.scripts.items() if name == script)

    def release_of(self, worker: str) -> str | None:
        deployment = self.current[self.scripts[worker]]
        if len(deployment.versions) != 1 or deployment.versions[0][1] != 100:
            return None
        return self.release_of_version.get(deployment.versions[0][0])

    def version_of(self, worker: str) -> str | None:
        deployment = self.current[self.scripts[worker]]
        return deployment.versions[0][0] if len(deployment.versions) == 1 else None

    def set_deployment(self, worker: str, *versions: tuple[str, int]) -> None:
        """Someone else changes a deployment (drift)."""
        self._deployments += 1
        self.current[self.scripts[worker]] = _Deployment(f"dep-other-{self._deployments}", versions)

    def fault(self, method: str, *actions: str) -> None:
        self.faults.setdefault(method, []).extend(actions)

    def _fault(self, method: str) -> str | None:
        queue = self.faults.get(method)
        return queue.pop(0) if queue else None

    # Port ---------------------------------------------------------------------

    def deployment(self, script: str):
        self.calls.append(("deployment", script, self.clock.now()))
        if self.before_read is not None:
            self.before_read("deployment")
        if self._fault("deployment") == "ambiguous":
            raise _Ambiguous("deployment read failed")
        return self.current[script]

    def deploy(self, script: str, version_id: str, *, message: str, not_after: _datetime):
        if self.clock.now() >= not_after:
            raise _NotSent("command_window_passed")
        fault = self._fault("deploy")
        self.calls.append(("deploy", script, version_id, self.clock.now()))
        if fault == "drop":
            raise _Ambiguous("deploy request lost")
        if fault == "crash_before":
            raise SimulatedCrash("controller lost before deploy")
        self.trace.append(("versions", "deploy", script, version_id))
        self.mutations.append(("deploy", script, version_id, message))
        self._deployments += 1
        self.current[script] = _Deployment(f"dep-{self._deployments}", ((version_id, 100),))
        if fault == "lose_reply":
            raise _Ambiguous("deploy reply lost")
        if fault == "crash_after":
            raise SimulatedCrash("controller lost after deploy")
        if fault == "drift_reply":
            return _Deployment(f"dep-{self._deployments}", ((version_id, 90), ("other", 10)))
        return self.current[script]

    def versions(self, script: str) -> list:
        self.calls.append(("versions", script))
        if self._fault("versions") == "ambiguous":
            raise _Ambiguous("versions read failed")
        return list(self.uploaded[script])

    def upload(self, script: str, *, tag: str, message: str, bundle_sha256: str,
               not_after: _datetime):  # fmt: skip
        if self.clock.now() >= not_after:
            raise _NotSent("command_window_passed")
        fault = self._fault("upload")
        self.calls.append(("upload", script, tag))
        if fault == "drop":
            raise _Ambiguous("upload request lost")
        version = _VersionInfo(
            uuid_of(f"{script}-{tag}-{len(self.uploaded[script])}"), tag, message
        )
        self.uploaded[script].append(version)
        self.mutations.append(("upload", script, tag))
        if fault == "lose_reply":
            raise _Ambiguous("upload reply lost")
        return version

    def application(self, application_id: str):
        self.calls.append(("application", application_id))
        return next(app for app in self.apps.values() if app.id == application_id)

    def instances(self, application_id: str, *, cursor: str | None):
        self.calls.append(("instances", application_id, cursor))
        worker = next(w for w, app in self.apps.items() if app.id == application_id)
        if worker in self.failing_listing:
            raise _Ambiguous("instance listing failed")
        running = [] if self.control is None else self.control.running_instances(worker)
        running += self.standalone.get(worker, [])
        if worker in self.endless_listing:
            return _InstancePage(tuple(running[:1]), f"c{len(self.calls)}")
        start = int(cursor or 0)
        page = running[start : start + self.page_size]
        following = start + len(page)
        return _InstancePage(tuple(page), str(following) if following < len(running) else None)


@_dataclass
class JobBehavior:
    seconds: float = 30
    exit_detail: str = "exit 0"
    receipt: str = "exact"  # exact, missing, mismatch, failed
    receipt_changes: dict = _field(default_factory=dict)
    hang: bool = False


@_dataclass
class FakeObject:
    service: str
    name: str
    id: str
    authority: dict | None = None
    replay: dict = _field(default_factory=dict)
    starts: list = _field(default_factory=list)
    running: bool = False
    restarts: int = 0
    # CF-04 code: no authority protocol, refuses every other release's command.
    legacy: bool = False


class FakeDOControl:
    """The release's Durable Objects behind the edge's control route (a Transport)."""

    def __init__(self, clock, versions: FakeVersions, document: dict, public_key: bytes,
                 trace: list | None = None) -> None:  # fmt: skip
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        self.clock = clock
        self.versions = versions
        versions.control = self
        self.document = document
        self.key = Ed25519PublicKey.from_public_bytes(public_key)
        self.trace = trace if trace is not None else []
        self.objects: dict[tuple[str, str], FakeObject] = {}
        self.faults: dict[tuple[str, str], list[str]] = {}
        self.delayed: list = []
        self.requests: list[dict] = []
        self.jobs: dict[str, JobBehavior] = {}
        self.boot_seconds = 10.0
        self.drain_seconds = 5.0
        self.grace_seconds = 30.0
        self.health: dict[str, str] = {}
        self.ready_after = 0.0
        self.receipt_edit: _Callable[[int, dict], list[dict]] | None = None
        self.receipt_stall: tuple[int, float] | None = None
        self.receipt_flags: dict[str, Any] = {}
        self.before_read: _Callable[[str, str], None] | None = None
        # Off, as jobs.ts: the JobRunner refuses migrate. A test that needs a
        # migration to run models the missing receipt producers by turning it on.
        self.wire_migrations = False
        self.image_override: dict[tuple[str, str], str] = {}

    # Test helpers -------------------------------------------------------------

    def fault(self, service: str, action: str, *actions: str) -> None:
        self.faults.setdefault((service, action), []).extend(actions)

    def object(self, service: str, name: str) -> FakeObject:
        key = (service, name)
        if key not in self.objects:
            self.objects[key] = FakeObject(service, name, object_id(service, name))
        return self.objects[key]

    def worker_for(self, service: str) -> str:
        return service

    def release_for(self, service: str) -> str | None:
        return self.versions.release_of(self.worker_for(service))

    def image_for(self, service: str, image_key: str) -> str | None:
        if (service, image_key) in self.image_override:
            return self.image_override[(service, image_key)]
        release = self.release_for(service)
        if release == self.document["release_id"]:
            spec = self.document["images"][image_key]
            return f"{spec['repository']}@{spec['amd64_digest']}"
        rollback = self.document["rollback"]
        if rollback["kind"] == "compatible_release" and release == rollback["release_id"]:
            spec = rollback["images"].get(image_key)
            return None if spec is None else f"{spec['repository']}@{spec['amd64_digest']}"
        return None

    def running_instances(self, worker: str) -> list[dict]:
        found = []
        for (service, _), item in self.objects.items():
            self._progress(item)
            if service == worker and item.running:
                found.append({"durable_object_id": item.id, "state": "running"})
        return found

    def start_prior(self, service: str) -> dict:
        """A prior release's service already running (an upgrade)."""
        item = self.object(service, SERVICE_OBJECTS[service])
        release = self.release_for(service)
        start = {
            "start_nonce": nonce_of(f"prior-{service}"),
            "release_id": release,
            "command_id": f"start-{service}-{release}",
            "version_id": self.versions.version_of(service),
            "image": self.image_for(service, "runtime" if service == "runtime" else "search"),
            "state": "running",
            "started_at": self.clock.now(),
            "drain_until": None,
            "exit_detail": None,
        }
        item.starts.append(start)
        item.running = True
        return start

    def start_foreign(self, service: str) -> dict:
        """A live start this release did not ask for (another operator or a bug)."""
        item = self.object(service, SERVICE_OBJECTS.get(service, service))
        current = self._current(item)
        if current is not None and current["state"] in LIVE:
            current.update(state="exited", exit_detail="replaced")
        start = {
            "start_nonce": nonce_of(f"foreign-{service}-{len(item.starts)}"),
            "release_id": self.release_for(service),
            "command_id": f"foreign-{len(item.starts)}",
            "version_id": self.versions.version_of(service),
            "image": self.image_for(service, "runtime" if service == "runtime" else "search"),
            "state": "running",
            "started_at": self.clock.now(),
            "drain_until": None,
            "exit_detail": None,
        }
        item.starts.append(start)
        item.running = True
        return start

    def exit_service(self, service: str, detail: str = "exit 1") -> None:
        """The service's container ends on its own."""
        item = self.object(service, SERVICE_OBJECTS[service])
        current = self._current(item)
        if current is not None:
            current.update(state="exited", exit_detail=detail)
        item.running = False

    def restart(self, service: str, name: str) -> None:
        """An object restart: storage survives; the container keeps running."""
        self.object(service, name).restarts += 1

    def deliver_delayed(self, index: int = 0) -> tuple[int, dict]:
        request = self.delayed.pop(index)
        return self._deliver(request)

    # Transport ----------------------------------------------------------------

    def send(self, request, *, timeout: float) -> tuple[int, bytes]:
        _, _, service, name, action = request.path.split("/")
        fault = (
            self.faults.get((service, action), [None]).pop(0)
            if self.faults.get((service, action))
            else None
        )
        if self.before_read is not None and request.method == "GET":
            self.before_read(service, action)
        if fault == "drop":
            raise _TransportAmbiguous("request lost")
        if fault == "crash_before":
            raise SimulatedCrash(f"controller lost before {service}/{action}")
        if fault == "delay":
            self.delayed.append(request)
            raise _TransportAmbiguous("request delayed")
        if fault == "5xx":
            return 502, b""
        if fault == "steal":
            # Someone else's start takes the object just before this request lands.
            self.start_foreign(service)
        status, body = self._deliver(request)
        if fault == "lose_reply":
            raise _TransportAmbiguous("reply lost")
        if fault == "crash_after":
            raise SimulatedCrash(f"controller lost after {service}/{action}")
        return status, _json.dumps(body).encode()

    def _deliver(self, request) -> tuple[int, dict]:
        _, _, service, name, action = request.path.split("/")
        headers = request.headers
        record = {"service": service, "name": name, "action": action, "method": request.method,
                  "command_id": headers.get("x-sentry-command-id"), "at": self.clock.now()}  # fmt: skip
        self.requests.append(record)
        try:
            expires = int(headers["x-sentry-expires-at"])
            command = _Command(
                method=request.method,
                target=f"{service}/{name}",
                action=action,
                body_sha256=hashlib.sha256(request.body).hexdigest(),
                release_id=headers["x-sentry-release-id"],
                session=headers["x-sentry-session"],
                fence=headers["x-sentry-fence"],
                command_id=headers["x-sentry-command-id"],
                expires_at=expires,
            )
            self.key.verify(_base64.b64decode(headers["x-sentry-signature"]), _canonical(command))
        except Exception:  # noqa: BLE001 - any malformed or unsigned request
            record["result"] = 401
            return 401, {"error": "signature does not verify", "code": "unauthenticated"}
        now = int(self.clock.now().timestamp())
        if expires <= now or expires - now > 300:
            record["result"] = 401
            return 401, {"error": "command expired", "code": "expired"}
        item = self.object(service, name)
        self._progress(item)
        release = self.release_for(service)
        if command.release_id != release:
            if item.legacy or (request.method, action) not in CROSS_RELEASE:
                record["result"] = 409
                return 409, {"error": "command is for another release", "code": "another_release"}
        else:
            fence = command.fence
            if not fence.isdigit() or fence.startswith("0") or int(fence) > 2**31 - 1:
                return 400, {"error": "invalid fence", "code": "invalid_request"}
            held = item.authority
            if held is None or held["release_id"] != release or int(fence) > held["fence"]:
                item.authority = {"release_id": release, "fence": int(fence),
                                  "session": command.session}  # fmt: skip
            elif not (int(fence) == held["fence"] and command.session == held["session"]):
                record["result"] = 409
                return 409, {"error": "superseded", "code": "superseded"}
        item.replay = {key: until for key, until in item.replay.items() if until >= now}
        if command.command_id in item.replay:
            record["result"] = 409
            return 409, {"error": "command id already accepted", "code": "replayed"}
        item.replay[command.command_id] = expires
        body = _json.loads(request.body) if request.body else None
        handler = getattr(self, f"_{'job' if service == 'jobs' else 'service'}_{action}", None)
        if handler is None:
            return 404, {"error": "unknown action", "code": "not_found"}
        status, reply = handler(item, command, body)
        record["result"] = status
        return status, reply

    # Lifecycle ------------------------------------------------------------------

    def _current(self, item: FakeObject) -> dict | None:
        return item.starts[-1] if item.starts else None

    def _progress(self, item: FakeObject) -> None:
        now = self.clock.now()
        start = self._current(item)
        if start is None:
            return
        if item.service == "jobs":
            self._progress_job(item, start, now)
            return
        if start["state"] == "draining" and now >= start["drain_until"]:
            start.update(state="exited", exit_detail="exit 0")
            item.running = False

    def _progress_job(self, item: FakeObject, row: dict, now: _datetime) -> None:
        behavior = self.jobs.get(row["job"], JobBehavior())
        if row["state"] in ("running", "signalled") and not behavior.hang:
            if now >= row["started_at"] + timedelta(seconds=behavior.seconds):
                detail = behavior.exit_detail
                if row["state"] == "signalled":
                    detail = "deadline; " + detail
                row.update(state="exited", exit_detail=detail)
                item.running = False
                self._complete_job(row, behavior)
                return
        if row["state"] == "running" and now >= row["deadline_at"]:
            row.update(state="signalled", signalled_at=now)
        if row["state"] == "signalled" and now >= row["signalled_at"] + timedelta(
            seconds=self.grace_seconds
        ):
            row.update(state="destroyed", exit_detail="job deadline exceeded")
            item.running = False

    def _complete_job(self, row: dict, behavior: JobBehavior) -> None:
        if behavior.receipt == "missing" or row["completion_receipt"] is not None:
            return
        job = next(j for j in self.document["jobs"] if j["id"] == row["job"])
        receipt = {
            "schema": job["receipt_schema"],
            "release_id": row["release_id"],
            "job_id": row["job"],
            "durable_object_id": row["object_id"],
            "launch_nonce": row["start_nonce"],
            "status": "succeeded",
            "result": _copy.deepcopy(job["expect"]),
        }
        if behavior.receipt == "failed" or behavior.exit_detail != "exit 0":
            receipt.update(
                status="failed", result={"reason": "sql_failed", "sql_outcome": "unknown"}
            )
        receipt.update(behavior.receipt_changes)
        row["completion_receipt"] = receipt

    # Service actions ------------------------------------------------------------

    def _service_status(self, item, command, body):
        start = self._current(item)
        now = self.clock.now()
        healthy = (
            item.running
            and start is not None
            and start["state"] == "running"
            and now >= start["started_at"] + timedelta(seconds=self.boot_seconds)
        )
        protocol = {} if item.legacy else {"control_protocol": "sentry.authority.v1"}
        return 200, {
            **protocol,
            "service": item.service,
            "object_id": item.id,
            "release_id": self.release_for(item.service),
            "version_id": self.versions.version_of(item.service),
            "running": item.running,
            "image": None if start is None else start["image"],
            "health": self.health.get(item.service, "healthy" if healthy else "unhealthy"),
            "inspect": {} if item.running else None,
            "start": None if start is None else _public_start(start),
        }

    def _service_start(self, item, command, body):
        expected = {
            "release_id": command.release_id,
            "version_id": self.versions.version_of(item.service),
        }
        if body != expected:
            return 409, {"error": "start does not match this version", "code": "version_mismatch"}
        for start in item.starts:
            if start["command_id"] == command.command_id:
                return 200, {"started": False, "replayed": True, **_public_start(start)}
        current = self._current(item)
        if item.running or (current is not None and current["state"] in LIVE):
            return 200, {"started": False, "start_nonce": None if current is None
                         else current["start_nonce"]}  # fmt: skip
        image_key = "runtime" if item.service == "runtime" else "search"
        start = {
            "start_nonce": nonce_of(f"{item.service}-{command.command_id}-{len(item.starts)}"),
            "release_id": command.release_id,
            "command_id": command.command_id,
            "version_id": self.versions.version_of(item.service),
            "image": self.image_for(item.service, image_key),
            "state": "running",
            "started_at": self.clock.now(),
            "drain_until": None,
            "exit_detail": None,
        }
        item.starts.append(start)
        item.running = True
        self.trace.append(("control", "start", item.service, command.command_id))
        return 200, {"started": True, **_public_start(start)}

    def _service_stop(self, item, command, body):
        current = self._current(item)
        if (
            current is None
            or not isinstance(body, dict)
            or body.get("start_nonce") != current["start_nonce"]
            or current["state"] != "running"
        ):
            return 200, {"stopping": False, "state": None if current is None else current["state"]}
        current.update(state="draining",
                       drain_until=self.clock.now() + timedelta(seconds=self.drain_seconds))  # fmt: skip
        self.trace.append(("control", "stop", item.service, command.command_id))
        return 200, {"stopping": True, "start_nonce": current["start_nonce"]}

    def _service_receipts(self, item, command, body):
        current = self._current(item)
        if current is None or body.get("start_nonce") != current["start_nonce"]:
            return 404, {"error": "no such start", "code": "not_found"}
        receipts = self._worker_receipts(current)
        after, limit = int(body.get("after", 0)), int(body.get("limit", 100))
        page = [(order, receipt) for order, receipt in receipts if order > after][: limit + 1]
        more = len(page) > limit
        page = page[:limit]
        return 200, {
            "startNonce": current["start_nonce"],
            "receipts": [receipt for _, receipt in page],
            "next": page[-1][0] if page else after,
            "more": more,
            "evictedAfterCursor": bool(self.receipt_flags.get("evicted")),
            "duplicatesConflicting": int(self.receipt_flags.get("conflicts", 0)),
            "refusedBoots": int(self.receipt_flags.get("refused", 0)),
            "ended": current["state"] not in LIVE,
            "unterminated": [],
        }

    def _worker_receipts(self, start: dict) -> list[tuple[int, dict]]:
        now = self.clock.now()
        end = (
            now if start["state"] in ("running", "starting") else (start.get("drain_until") or now)
        )
        first = start["started_at"] + timedelta(seconds=1)
        boot = hashlib.md5(start["start_nonce"].encode()).hexdigest()
        receipts, sequence, offset, order = [], 1, 0.0, 0
        while True:
            if self.receipt_stall is not None and sequence == self.receipt_stall[0] + 1:
                offset += self.receipt_stall[1]
            at = first + timedelta(seconds=10 * (sequence - 1) + offset)
            if at > end:
                return receipts
            receipt = {
                "kind": _RECEIPT_KIND,
                "release_id": start["release_id"],
                "boot_id": boot,
                "sequence": sequence,
                "observed_at": at.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                "uptime_seconds": 0.5 + (at - first).total_seconds(),
                "alive": True,
                "ready": (at - first).total_seconds() >= self.ready_after,
                "draining": False,
                "phase": "generation" if sequence % 2 else "idle",
                "phase_elapsed_seconds": 1.0,
                "phase_budget_seconds": 62.0,
                "error_code": None,
            }
            for item in (
                [receipt] if self.receipt_edit is None else self.receipt_edit(sequence, receipt)
            ):
                order += 1
                receipts.append((order, item))
            sequence += 1

    # Job actions ------------------------------------------------------------------

    def _job_status(self, item, command, body):
        row = self._current(item)
        identity = {
            "control_protocol": "sentry.authority.v1",
            "object_id": item.id,
            "release_id": self.release_for("jobs"),
            "version_id": self.versions.version_of("jobs"),
            "running": item.running,
        }
        if row is None:
            return 200, {**identity, "state": "none", "job": None}
        fields = _public_job(row)
        succeeded = (
            row["completion_receipt"] is not None
            and row["signalled_at"] is None
            and row["state"] == "exited"
            and row["exit_detail"] == "exit 0"
        )
        return 200, {
            **identity,
            **fields,
            "has_receipt": row["completion_receipt"] is not None,
            "sql_outcome": "applied" if succeeded else "unknown",
            "job": fields,
        }

    def _job_run(self, item, command, body):
        if item.running or item.starts:
            return 409, {"error": "this job object has already run", "code": "already_run"}
        fields = {"job_id", "phase", "database", "image", "deadline_seconds"}
        if not isinstance(body, dict) or set(body) != fields:
            return 400, {"error": "invalid job request", "code": "invalid_request"}
        expected_name = f"job-{command.release_id}-{body['job_id']}"
        if item.name != expected_name:
            return 400, {"error": "job does not match its object", "code": "invalid_request"}
        wired = body["phase"] in ("grant", "proof") and body["image"] == "release_tools"
        if not wired and not (self.wire_migrations and body["phase"] == "migrate"):
            # As jobs.ts: only grant and proof with the tools image are wired.
            return 400, {"error": "job is not wired on this platform", "code": "invalid_request"}
        now = self.clock.now()
        row = {
            "start_nonce": nonce_of(f"job-{item.name}-{command.command_id}"),
            "object_id": item.id,
            "release_id": command.release_id,
            "command_id": command.command_id,
            "version_id": self.versions.version_of("jobs"),
            "job": body["job_id"],
            "profile": "runtime-release" if body["database"] == "runtime" else "search-release",
            "image": self.image_for("jobs", body["image"]),
            "state": "running",
            "started_at": now,
            "deadline_at": now + timedelta(seconds=body["deadline_seconds"]),
            "signalled_at": None,
            "exit_detail": None,
            "completion_receipt": None,
        }
        item.starts.append(row)
        item.running = True
        self.trace.append(("control", "run", item.name, command.command_id))
        return 200, {"object_id": item.id, "start_nonce": row["start_nonce"],
                     "command_id": command.command_id,
                     "deadline_at": _millis(row["deadline_at"])}  # fmt: skip

    def _job_stop(self, item, command, body):
        row = self._current(item)
        if (
            row is None
            or body.get("start_nonce") != row["start_nonce"]
            or row["state"] != "running"
        ):
            return 200, {"stopping": False, "state": None if row is None else row["state"]}
        row.update(state="signalled", signalled_at=self.clock.now())
        self.trace.append(("control", "stop_job", item.name, command.command_id))
        return 200, {"stopping": True, "start_nonce": row["start_nonce"]}

    def _job_receipt(self, item, command, body):
        row = self._current(item)
        if (
            row is None
            or not isinstance(body, dict)
            or body.get("start_nonce") != row["start_nonce"]
        ):
            return 404, {"error": "no such start", "code": "not_found"}
        return 200, {"start_nonce": row["start_nonce"],
                     "receipt": _copy.deepcopy(row["completion_receipt"])}  # fmt: skip


def _millis(value):
    return None if value is None else int(value.timestamp() * 1000)


def _public_start(start: dict) -> dict:
    """A service start row as service.ts's status() returns it."""
    return {
        "start_nonce": start["start_nonce"],
        "release_id": start["release_id"],
        "started_at": _millis(start["started_at"]),
        "state": start["state"],
        "exit_detail": start["exit_detail"],
        "drain_deadline": _millis(start["drain_until"]),
        "command_id": start["command_id"],
        "version_id": start["version_id"],
        "image": start["image"],
    }


def _public_job(row: dict) -> dict:
    """A job row as jobs.ts's status() returns it (completion receipt withheld)."""
    return {
        "start_nonce": row["start_nonce"],
        "job": row["job"],
        "profile": row["profile"],
        "deadline_at": _millis(row["deadline_at"]),
        "state": row["state"],
        "exit_detail": row["exit_detail"],
        "signalled_at": _millis(row["signalled_at"]),
        "command_id": row["command_id"],
        "version_id": row["version_id"],
        "image": row["image"],
    }


class FakeReceipts:
    """Operational check receipts as the probes' sanitized results would report them."""

    def __init__(self, control: FakeDOControl, document: dict) -> None:
        self.control = control
        self.checks = {item["id"]: item for item in document["operational_checks"]}
        self.missing_checks: set[str] = set()
        self.check_changes: dict[str, dict] = {}

    def operational_receipt(self, release_id: str, check_id: str) -> dict | None:
        if check_id in self.missing_checks:
            return None
        instances = {}
        for service, name in SERVICE_OBJECTS.items():
            item = self.control.objects.get((service, name))
            start = None if item is None or not item.starts else item.starts[-1]
            running = item is not None and item.running and start is not None
            instances[service] = f"{item.id}/{start['start_nonce']}" if running else ""
        receipt = {
            "schema": self.checks[check_id]["receipt_schema"],
            "release_id": release_id,
            "check_id": check_id,
            "status": "passed",
            "instances": instances,
        }
        receipt.update(self.check_changes.get(check_id, {}))
        return receipt
