"""Container-backed ECS, Logs and store for the release canary (AWS-D012).

No ECS or CloudWatch Logs emulator exists. The canary keeps the controller-test
fakes' ECS bookkeeping (``tests.release_fakes.FakeEcs``: launch tokens,
deployments, task records) and backs every task with a real container on one
internal Docker network:

- RunTask starts the task definition's app container from the release's image,
  with the environment ``deploy/aws-platform-fit`` renders for it and its secrets
  resolved from the canary's custodian values. DescribeTasks reports the
  container's real state and exit code; StopTask and a service scale-down send
  SIGTERM, and Docker kills after the task's stop timeout.
- A service deployment starts the real Runtime, API or worker. The task's ENI
  address is the container's real address, so observer peers bind to it.
- GetLogEvents serves each task's actual output with Docker's timestamps: job and
  observer receipts and the worker's readiness receipts are the bytes the real
  producers wrote, never fabricated.
- The journal and lock live in an S3-compatible stand-in reached by the real
  store adapter (see dev/check_release_canary.py).

Init containers are not run: the harness writes the material their profiles
would, as the container suites do; the init profiles have their own suites.
Nothing here models Fargate, IAM, CloudWatch ingestion or real S3 consistency.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import shlex
import subprocess
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from dev.tls_fixtures import create_certificates
from release.readiness import WORKER_RECEIPT_MARKER
from release_tools.receipt import RECEIPT_MARKER
from tests.aws_offline import FakeAws, ServiceError
from tests.release_fakes import (
    ACCOUNT,
    OBSERVER_NAMESPACE,
    REGION,
    FakeEcs,
    FakeEvidence,
    FakeStore,
    FakeTask,
    evidence_release_id,
    task_definition,
)

SUBNET = "169.254.170.0/24"
METADATA_IP = "169.254.170.2"
POSTGRES_IMAGE = (
    "docker.io/library/postgres:16-alpine@sha256:"
    "cf78e76683b9ca8c5733cbbdce6c9262b45b6767934dd0a95e671f9a0fc20685"
)
PYTHON = ["--entrypoint", "/usr/local/bin/python3.11"]
RUNTIME_UID, PRODUCT_UID, OBSERVER_UID = 65532, 10001, 65532
# What each service writes once it serves: the canary's health signal.
READY = {
    "runtime": "runtime listening",
    "api": "Application startup complete",
    "worker": WORKER_RECEIPT_MARKER,
}
# The task-metadata stand-in answers /v4/<task id>/task with the ARN FakeEcs gave it.
METADATA_SERVER = (
    "import http.server, json, re\n"
    "class H(http.server.BaseHTTPRequestHandler):\n"
    "    def do_GET(self):\n"
    "        m = re.fullmatch(r'/v4/([0-9a-f]{32})/task', self.path)\n"
    f"        arn = 'arn:aws:ecs:{REGION}:{ACCOUNT}:task/sentry-staging/' + m.group(1) if m else ''\n"
    "        body = json.dumps({'TaskARN': arn}).encode()\n"
    "        self.send_response(200 if m else 404); self.end_headers(); self.wfile.write(body)\n"
    "    def log_message(self, *args): pass\n"
    "print('metadata listening', flush=True)\n"
    "http.server.ThreadingHTTPServer(('0.0.0.0', 80), H).serve_forever()\n"
)
PROVIDER_STUB = (
    "import socket\n"
    "server=socket.create_server(('0.0.0.0',9000))\n"
    "print('provider stub listening',flush=True)\n"
    "held=[]\n"
    "while True:\n"
    "    connection,_=server.accept(); held.append(connection)\n"
)
MATERIAL_SCRIPT = (
    "import json, os, sys\n"
    "spec = json.load(sys.stdin)\n"
    "for name, text in spec['files'].items():\n"
    "    fd = os.open('/run/material/' + name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)\n"
    "    os.write(fd, text.encode()); os.fchmod(fd, 0o400)\n"
    "    os.fchown(fd, spec['uid'], spec['uid']); os.close(fd)\n"
    "os.chmod('/run/material', 0o700)\n"
    "os.chown('/run/material', spec['uid'], spec['uid'])\n"
)


def docker(*args: str, check: bool = True, timeout: float = 180, stdin: str | None = None
           ) -> subprocess.CompletedProcess[str]:  # fmt: skip
    result = subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout, input=stdin
    )
    if check and result.returncode:
        raise AssertionError(f"docker {args[0]} exited {result.returncode}: {result.stderr}")
    return result


def stamp(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def docker_time(text: str) -> datetime:
    """Docker's RFC 3339 nanosecond time (trailing zeros trimmed) as UTC."""
    whole, _, fraction = text.rstrip("Z").partition(".")
    fraction = (fraction + "000000")[:6]
    return datetime.fromisoformat(f"{whole}.{fraction}+00:00")


def wait_for(description: str, predicate, *, timeout: float = 90) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.25)
    raise AssertionError(f"timed out waiting for {description}")


class WallClock:
    """The canary runs in real time: containers do not follow a fake clock."""

    def now(self) -> datetime:
        return datetime.now(UTC)

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)

    def advance(self, **_: float) -> None:
        raise AssertionError("the canary cannot advance real time")


@dataclass(frozen=True)
class Images:
    """Local image IDs to run, and the platform digests ECS reports for them."""

    runtime: str
    search: str
    tools: str
    digests: dict[str, str]


@dataclass
class ContainerSpec:
    image: str
    command: list[str]
    environment: dict[str, str]
    uid: int
    material: str | None = None
    material_target: str = "/run/material"
    mounts: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    stop_timeout: int = 30
    ready: str | None = None


@dataclass
class Database:
    key: str  # runtime | product
    host: str
    name: str
    owner: str
    service: str
    administrator: str
    ca: Path

    @property
    def uid(self) -> int:
        return RUNTIME_UID if self.key == "runtime" else PRODUCT_UID


class CanaryEnvironment:
    """One disposable environment: network, databases, material and service inputs.

    Every container, volume and network it creates is named with ``prefix`` and
    recorded, so teardown removes exactly what this environment created.
    """

    def __init__(self, root: Path, images: Images, *, label: str = "") -> None:
        self.root = root
        self.images = images
        self.prefix = f"aws06-canary{label}-{uuid.uuid4().hex[:6]}"
        self.network = self.prefix
        self.containers: list[str] = []
        self.volumes: list[str] = []
        self.secrets: dict[str, str] = {}
        self.databases: dict[str, Database] = {}
        self.material: dict[str, str] = {}
        self.pins: dict[str, Any] = {}
        self.tls: dict[str, Path] = {}

    # Lifecycle ---------------------------------------------------------------
    def start(self) -> None:
        docker("network", "create", "--internal", "--subnet", SUBNET, self.network)
        self.pins = json.loads(docker("run", "--rm", self.images.tools, "digest").stdout)
        self._metadata()
        for key, name, owner, service in (
            ("runtime", "runtime_db", "runtime_owner", "runtime_service"),
            ("product", "product_db", "product_owner", "product_service"),
        ):
            self._database(key, name, owner, service)
        self._service_material()
        provider = self.name("provider")
        self.run(self.images.search, provider, ["python", "-c", PROVIDER_STUB], {},
                 uid=PRODUCT_UID, aliases=["provider"])  # fmt: skip
        wait_for("provider stub", lambda: "listening" in self.logs(provider))

    def stop(self) -> None:
        for name in reversed(self.containers):
            docker("rm", "-f", "-v", name, check=False)
        for name in self.volumes:
            docker("volume", "rm", "-f", name, check=False)
        docker("network", "rm", self.network, check=False)

    def name(self, role: str) -> str:
        name = f"{self.prefix}-{role}"
        self.containers.append(name)
        return name

    def secret(self, name: str) -> str:
        return self.secrets.setdefault(name, secrets.token_urlsafe(30))

    def logs(self, container: str) -> str:
        result = docker("logs", container, check=False)
        return result.stdout + result.stderr

    def address(self, container: str) -> str:
        networks = json.loads(
            docker("inspect", "--format", "{{json .NetworkSettings.Networks}}", container).stdout
        )
        return networks[self.network]["IPAddress"]

    def run(self, image: str, name: str, command: list[str], environment: dict[str, str], *,
            uid: int, aliases: tuple[str, ...] | list[str] = (), extra: tuple[str, ...] = (),
            entrypoint: str | None = None) -> None:  # fmt: skip
        env_file = self.root / f"{name}.env"
        env_file.write_text("".join(f"{key}={value}\n" for key, value in environment.items()))
        env_file.chmod(0o600)
        docker(
            "run", "-d", "--name", name, "--network", self.network, "--read-only",
            "--tmpfs", "/tmp", "--tmpfs", "/var/lib/sentrysearch:uid=10001,gid=10001,mode=0700",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", f"{uid}:{uid}",
            *(item for alias in aliases for item in ("--network-alias", alias)),
            *(("--entrypoint", entrypoint) if entrypoint else ()),
            "--env-file", str(env_file), *extra, image, *command,
        )  # fmt: skip

    def _metadata(self) -> None:
        name = self.name("metadata")
        docker(
            "run", "-d", "--name", name, "--network", self.network, "--ip", METADATA_IP,
            "--read-only", "--cap-drop", "ALL", *PYTHON, self.images.tools, "-I", "-B", "-c",
            METADATA_SERVER,
        )  # fmt: skip
        wait_for("metadata", lambda: "listening" in self.logs(name))

    def _volume(self, label: str, uid: int, files: dict[str, str]) -> str:
        name = f"{self.prefix}-material-{label}"
        docker("volume", "create", name)
        self.volumes.append(name)
        docker(
            "run", "--rm", "-i", "--network", "none", "--user", "0", "--mount",
            f"type=volume,source={name},target=/run/material", *PYTHON, self.images.tools,
            "-I", "-B", "-c", MATERIAL_SCRIPT, stdin=json.dumps({"uid": uid, "files": files}),
        )  # fmt: skip
        return name

    def _database(self, key: str, name: str, owner: str, service: str) -> None:
        host = f"{key}-db.{OBSERVER_NAMESPACE}"
        directory = self.root / f"{key}-db"
        certificates = create_certificates(directory, hostname=host)
        for path in directory.iterdir():
            path.chmod(0o644)
        directory.chmod(0o755)
        administrator = f"{key}_admin"
        for role in ("postgres", administrator, owner, service):
            self.secret(f"{key}:{role}")
        container = self.name(f"{key}-db")
        setup = (
            "install -o postgres -g postgres -m 0600 /tls-source/server-key.pem"
            " /var/lib/postgresql/server.key && install -o postgres -g postgres -m 0644"
            " /tls-source/server.pem /var/lib/postgresql/server.crt && "
        )
        server = ["postgres", "-c", "ssl=on", "-c", "ssl_cert_file=/var/lib/postgresql/server.crt",
                  "-c", "ssl_key_file=/var/lib/postgresql/server.key",
                  "-c", "password_encryption=scram-sha-256", "-c", "log_connections=on",
                  "-c", "log_line_prefix=%m [%p] app=%a "]  # fmt: skip
        docker(
            "run", "-d", "--name", container, "--network", self.network, "--network-alias", host,
            "-e", f"POSTGRES_PASSWORD={self.secrets[f'{key}:postgres']}",
            "-e", "POSTGRES_HOST_AUTH_METHOD=scram-sha-256",
            "-v", f"{directory}:/tls-source:ro", "--entrypoint", "sh", POSTGRES_IMAGE,
            "-c", setup + "exec docker-entrypoint.sh " + shlex.join(server),
        )  # fmt: skip
        wait_for(
            f"{key} database",
            lambda: docker("exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "postgres",
                           check=False).returncode == 0
            and "database system is ready to accept connections"
            in self.logs(container),  # fmt: skip
        )
        # An RDS-like administrator: CREATEROLE and CREATEDB, not superuser. It owns
        # the maintenance database and keeps SET on the roles it creates (modelled;
        # the real administrator's memberships are AWS-07b evidence).
        password = self.secrets[f"{key}:{administrator}"]
        for statement in (
            f"CREATE ROLE {administrator} LOGIN CREATEROLE CREATEDB PASSWORD '{password}'",
            f"ALTER ROLE {administrator} SET createrole_self_grant = 'set, inherit'",
            f"ALTER DATABASE postgres OWNER TO {administrator}",
        ):
            self.sql(container, "postgres", statement)
        self.databases[key] = Database(key, host, name, owner, service, administrator,
                                       certificates.ca)  # fmt: skip
        self.material[key] = self._volume(
            key, RUNTIME_UID if key == "runtime" else PRODUCT_UID,
            {"postgres-ca.pem": certificates.ca.read_text()},
        )  # fmt: skip

    def sql(self, container: str, database: str, statement: str) -> str:
        return docker(
            "exec", container, "psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d",
            database, "-tAc", statement,
        ).stdout.strip()  # fmt: skip

    def database_container(self, key: str) -> str:
        return f"{self.prefix}-{key}-db"

    def _service_material(self) -> None:
        directory = self.root / "runtime-tls"
        certificates = create_certificates(directory, hostname=f"runtime.{OBSERVER_NAMESPACE}")
        for path in directory.iterdir():
            path.chmod(0o644)
        directory.chmod(0o755)
        self.tls["runtime"] = directory
        trust = self.root / "trust"
        trust.mkdir(mode=0o755)
        for name, path in (
            ("runtime-ca.pem", certificates.ca),
            ("runtime-db-ca.pem", self.databases["runtime"].ca),
            ("product-db-ca.pem", self.databases["product"].ca),
        ):
            (trust / name).write_text(path.read_text())
            (trust / name).chmod(0o644)
        self.tls["trust"] = trust
        for name in ("producer", "worker", "probe"):
            self.secret(f"token:{name}")
        self.material["runtime-observer"] = self._volume(
            "runtime-observer", OBSERVER_UID,
            {"runtime-ca.pem": certificates.ca.read_text(),
             "probe-token": self.secrets["token:probe"]},
        )  # fmt: skip


# Task definitions --------------------------------------------------------------------


def _database_url(database: Database, user: str, password: str, ca: str) -> str:
    return (
        f"postgres://{user}:{password}@{database.host}:5432/{database.name}"
        f"?sslmode=verify-full&sslrootcert={ca}"
    )


class RevisionConflict(Exception):
    """A task-definition revision named with anything but what it was registered with."""


class TaskDefinitions:
    """Each registered revision's app container.

    A revision is immutable, as in ECS: its release, deadline and budget are the
    values it was first registered with. Registering the same ARN again with any
    other value raises ``RevisionConflict``. A release registers the whole
    catalog its plan creates, once, including the reconcile revisions a later
    rollback run launches; a rollback run registers nothing and may name only
    revisions its prior release already holds (``require_retained``).

    Job, bootstrap, reconcile and observer containers get exactly the environment
    deploy/aws-platform-fit renders for them. Service containers follow it with
    local differences, listed in docs/release-canary.md: material under
    ``/run/trust`` and ``/run/tls``, no Runtime probe settings, static local
    credentials and extra settings for the Search services, a held-open provider
    stub for the worker,
    a 30-second API stop timeout, and health taken from a readiness line rather than
    the task definitions' health commands. Release, deadline and budget are the
    revision's fixed values; secrets resolve to the canary custodian's values.
    """

    def __init__(self, env: CanaryEnvironment) -> None:
        self.env = env
        self.specs: dict[str, tuple[str, dict]] = {}

    @staticmethod
    def _revisions(document: dict) -> dict[str, tuple[str, dict]]:
        """What a manifest says about each revision it names, without release or deadline."""
        found: dict[str, tuple[str, dict]] = {}
        for job in document["jobs"]:
            found[job["task"]["task_definition"]] = ("job", {
                "job": {key: job[key] for key in ("id", "phase", "database")},
            })  # fmt: skip
        for check in document["operational_checks"]:
            if "task" in check:
                found[check["task"]["task_definition"]] = ("observer", {
                    "check": {key: check[key] for key in ("id", "target", "host", "port")},
                })  # fmt: skip
        for name, service in document["services"].items():
            found[service["task_definition"]] = ("service", {"service": name})
        return found

    def register(self, document: dict, *, not_after: datetime, budget_seconds: int = 900) -> None:
        """Register the revisions a forward release's plan creates, under its fixed deadline.

        deploy/aws-platform-fit defines reconcile jobs for every release beside
        its proof jobs. A forward manifest names none, so they are added here,
        at the proof jobs' revision: a later rollback run finds them retained.
        """
        release_id = document["release_id"]
        revisions = self._revisions(document)
        for job in document["jobs"]:
            if job["phase"] == "proof":
                database = job["database"]
                number = int(job["task"]["task_definition"].rsplit(":", 1)[1])
                sibling = task_definition(f"sentry-staging-{database}-reconcile", number)
                revisions.setdefault(sibling, ("job", {
                    "job": {"id": f"{database}-reconcile", "phase": "reconcile",
                            "database": database},
                }))  # fmt: skip
        fixed = {"job": {"not_after": not_after, "budget": budget_seconds},
                 "observer": {"not_after": not_after}, "service": {}}  # fmt: skip
        entries = {arn: (kind, {**data, "release_id": release_id, **fixed[kind]})
                   for arn, (kind, data) in revisions.items()}  # fmt: skip
        rollback = document.get("rollback") or {}
        for name, service in (rollback.get("services") or {}).items():
            # The retained prior services, as the prior release registered them.
            entries[service["task_definition"]] = ("service", {
                "service": name, "release_id": rollback["release_id"],
            })  # fmt: skip
        conflicts = sorted(arn for arn, entry in entries.items()
                           if self.specs.get(arn, entry) != entry)  # fmt: skip
        if conflicts:
            raise RevisionConflict(f"already registered with other values: {conflicts}")
        self.specs.update(entries)

    def require_retained(self, document: dict) -> None:
        """A rollback run names only revisions its prior release already registered.

        Nothing is registered and no deadline is taken from the run: each
        revision keeps the one its release fixed, however much later the run's
        own window ends.
        """
        release_id = evidence_release_id(document)
        missing = []
        for arn, (kind, data) in self._revisions(document).items():
            held_kind, held = self.specs.get(arn, ("", {}))
            if held_kind != kind or {**held, **data} != held or held["release_id"] != release_id:
                missing.append(arn)
        if missing:
            raise RevisionConflict(f"not retained revisions of {release_id}: {sorted(missing)}")

    def spec(self, definition: str, task_id: str) -> ContainerSpec:
        kind, data = self.specs[definition]
        metadata = {"ECS_CONTAINER_METADATA_URI_V4": f"http://{METADATA_IP}/v4/{task_id}"}
        if kind == "job":
            return self._job(data, metadata)
        if kind == "observer":
            return self._observer(data, metadata)
        return self._service(data)

    def _job(self, data: dict, metadata: dict) -> ContainerSpec:
        env, images = self.env, self.env.images
        job = data["job"]
        database = env.databases[job["database"]]
        common = {
            "RELEASE_ID": data["release_id"],
            "RELEASE_JOB_ID": job["id"],
            "RELEASE_NOT_AFTER": stamp(data["not_after"]),
            "RELEASE_JOB_BUDGET_SECONDS": str(data["budget"]),
        }
        ca = "/run/material/postgres-ca.pem"
        secret = lambda role: env.secrets[f"{database.key}:{role}"]  # noqa: E731
        phase = job["phase"]
        if phase == "migrate":
            expect = {"RELEASE_EXPECT_DATABASE": database.name,
                      "RELEASE_EXPECT_PRINCIPAL": database.owner}  # fmt: skip
            if database.key == "runtime":
                return ContainerSpec(
                    images.runtime, ["/app/migrate", "-release-job"],
                    {"SENTRYRUNTIME_MIGRATIONS_DIRECTORY": "/app/db/migrations", **common,
                     **expect, **metadata,
                     "DATABASE_URL": _database_url(database, database.owner,
                                                   secret(database.owner), ca)},
                    database.uid, env.material[database.key],
                )  # fmt: skip
            return ContainerSpec(
                images.search, ["python", "-m", "dev.migrate_storage", "--release-job"],
                {"ENVIRONMENT": "staging", "DB_SSLMODE": "verify-full", "DB_SSLROOTCERT": ca,
                 "DB_DEBUG": "false", "PYTHON_DOTENV_DISABLED": "1", **common, **expect,
                 **metadata, **_db_keys(database, database.owner, secret(database.owner))},
                database.uid, env.material[database.key],
            )  # fmt: skip
        from release_tools.config import MAIN_SQL

        sql = env.pins["sql"][MAIN_SQL[(phase, database.key)]]
        tools = {**common, "RELEASE_DATABASE": database.key,
                 "RELEASE_TOOLS_SHA256": env.pins["tools_sha256"], "RELEASE_SQL_SHA256": sql}  # fmt: skip
        if phase == "bootstrap":
            values = {
                **tools,
                "RELEASE_EXPECT_DATABASE": "postgres",
                "RELEASE_EXPECT_PRINCIPAL": database.administrator,
                "RELEASE_TARGET_DATABASE": database.name,
                "RELEASE_OWNER_ROLE": database.owner,
                "RELEASE_SERVICE_ROLE": database.service,
                "RELEASE_OWNER_PASSWORD": secret(database.owner),
                "RELEASE_SERVICE_PASSWORD": secret(database.service),
                "DB_HOST": database.host, "DB_PORT": "5432", "DB_NAME": "postgres",
                "DB_USER": database.administrator, "DB_PASSWORD": secret(database.administrator),
            }  # fmt: skip
            return ContainerSpec(images.tools, ["bootstrap"], {**values, **metadata},
                                 database.uid, env.material[database.key])  # fmt: skip
        principal = database.service if phase == "proof" else database.owner
        values = {**tools, "RELEASE_EXPECT_DATABASE": database.name,
                  "RELEASE_EXPECT_PRINCIPAL": principal}  # fmt: skip
        if phase == "grant":
            values["RELEASE_SERVICE_ROLE"] = database.service
        if phase == "proof":
            values["RELEASE_OWNER_ROLE"] = database.owner
        if database.key == "runtime":
            values["DATABASE_URL"] = _database_url(database, principal, secret(principal), ca)
        else:
            values.update(_db_keys(database, principal, secret(principal)))
        return ContainerSpec(images.tools, [phase], {**values, **metadata}, database.uid,
                             env.material[database.key])  # fmt: skip

    def _observer(self, data: dict, metadata: dict) -> ContainerSpec:
        check = data["check"]
        target = check["target"]
        values = {
            "RELEASE_ID": data["release_id"],
            "RELEASE_CHECK_ID": check["id"],
            "RELEASE_NOT_AFTER": stamp(data["not_after"]),
            "RELEASE_CHECK_BUDGET_SECONDS": "300",
            "RELEASE_TARGET_HOST": check["host"],
            "RELEASE_TARGET_PORT": str(check["port"]),
            **metadata,
        }
        material = self.env.material["runtime-observer"] if target == "runtime" else None
        return ContainerSpec(self.env.images.tools, [f"observe-{target}"], values, OBSERVER_UID,
                             material)  # fmt: skip

    def _service(self, data: dict) -> ContainerSpec:
        env, images = self.env, self.env.images
        name = data["service"]
        trust = ["-v", f"{env.tls['trust']}:/run/trust:ro"]
        if name == "runtime":
            database = env.databases["runtime"]
            credentials = [
                {"token_sha256": hashlib.sha256(env.secrets[f"token:{role}"].encode()).hexdigest(),
                 "role": "worker" if role == "worker" else "producer", "product": "sentrysearch",
                 "workflow_name": "generate_report", "workflow_version": "v1"}
                for role in ("producer", "worker", "probe")
            ]  # fmt: skip
            return ContainerSpec(
                images.runtime, [],
                {"DATABASE_URL": _database_url(database, database.service,
                                               env.secrets[f"runtime:{database.service}"],
                                               "/run/trust/runtime-db-ca.pem"),
                 "SENTRYRUNTIME_LISTEN_ADDRESS": "0.0.0.0:8443",
                 "SENTRYRUNTIME_AUTH_MODE": "token",
                 "SENTRYRUNTIME_AUTH_CREDENTIALS": json.dumps(credentials),
                 "SENTRYRUNTIME_TLS_CERT_FILE": "/run/tls/server.pem",
                 "SENTRYRUNTIME_TLS_KEY_FILE": "/run/tls/server-key.pem"},
                RUNTIME_UID, mounts=[*trust, "-v", f"{env.tls['runtime']}:/run/tls:ro"],
                aliases=[f"runtime.{OBSERVER_NAMESPACE}"], ready=READY["runtime"],
            )  # fmt: skip
        database = env.databases["product"]
        product = {
            "ENVIRONMENT": "staging", "DB_SSLMODE": "verify-full",
            "DB_SSLROOTCERT": "/run/trust/product-db-ca.pem", "DB_DEBUG": "false",
            "PYTHON_DOTENV_DISABLED": "1",
            **_db_keys(database, database.service, env.secrets[f"product:{database.service}"]),
            "AWS_S3_BUCKET": "canary-bucket", "AWS_REGION": REGION,
            "AWS_ACCESS_KEY_ID": "canary-unused", "AWS_SECRET_ACCESS_KEY": env.secret("aws"),
            "AWS_EC2_METADATA_DISABLED": "true",
            "SENTRYRUNTIME_URL": f"https://runtime.{OBSERVER_NAMESPACE}:8443",
            "SENTRYRUNTIME_CA_FILE": "/run/trust/runtime-ca.pem",
        }  # fmt: skip
        if name == "api":
            return ContainerSpec(
                images.search, ["python", "/app/run_api.py"],
                {**product, "PORT": "8001", "SENTRYSEARCH_EXECUTION_MODE": "paused"},
                PRODUCT_UID, mounts=trust, aliases=[f"api.{OBSERVER_NAMESPACE}"],
                ready=READY["api"],
            )  # fmt: skip
        return ContainerSpec(
            images.search,
            ["python", "-m", "dev.run_runtime_worker", "--health-port", "8081",
             "--drain-seconds", "30"],
            {**product, "SENTRYSEARCH_EXECUTION_MODE": "runtime",
             "SENTRYSEARCH_RELEASE_ID": data["release_id"],
             "SENTRYRUNTIME_PRODUCER_TOKEN": env.secrets["token:producer"],
             "SENTRYRUNTIME_WORKER_TOKEN": env.secrets["token:worker"],
             "OPENROUTER_API_KEY": env.secret("provider"),
             "OPENROUTER_BASE_URL": "http://provider:9000/api/v1"},
            PRODUCT_UID, mounts=trust, stop_timeout=60, ready=READY["worker"],
        )  # fmt: skip


def _db_keys(database: Database, user: str, password: str) -> dict[str, str]:
    return {"DB_HOST": database.host, "DB_PORT": "5432", "DB_NAME": database.name,
            "DB_USER": user, "DB_PASSWORD": password}  # fmt: skip


# Container-backed ECS -----------------------------------------------------------------


class CanaryEcs(FakeEcs):
    """FakeEcs bookkeeping; every task is a real container."""

    def __init__(self, env: CanaryEnvironment, definitions: TaskDefinitions) -> None:
        super().__init__(WallClock())  # ty: ignore[invalid-argument-type]
        self.env = env
        self.definitions = definitions
        self.names: dict[str, str] = {}
        self.ready: dict[str, str | None] = {}
        self.stopping: set[str] = set()
        self.lock = threading.RLock()
        # Fault hooks by job or check id: before the container starts (synchronous)
        # and after it started (in its own thread, so the controller keeps polling).
        self.before_start: dict[str, Callable[[FakeTask], None]] = {}
        self.after_start: dict[str, Callable[[FakeTask, str], None]] = {}

    def _task(self, definition, started_by, group, containers, plan=None, tags=None) -> FakeTask:
        with self.lock:
            task = super()._task(definition, started_by, group, containers, plan=plan, tags=tags)
            task_id = task.arn.rsplit("/", 1)[1]
            spec = self.definitions.spec(definition, task_id)
            hook_id = (tags or {}).get("sentry:job-id", "")
            if hook_id in self.before_start:
                self.before_start.pop(hook_id)(task)
            name = f"{self.env.prefix}-task-{task_id[-12:]}"
            self.env.containers.append(name)
            extra: list[str] = list(spec.mounts)
            if spec.material:
                extra += ["--mount", f"type=volume,source={spec.material},"
                          f"target={spec.material_target},readonly,volume-nocopy"]  # fmt: skip
            self.env.run(spec.image, name, spec.command, spec.environment, uid=spec.uid,
                         aliases=spec.aliases,
                         extra=("--stop-timeout", str(spec.stop_timeout), *extra))  # fmt: skip
            self.names[task.arn] = name
            self.ready[task.arn] = spec.ready
            # The ENI the controller records is the container's real address.
            for detail in self.attachments[task.arn][0]["details"]:
                if detail["name"] == "privateIPv4Address":
                    detail["value"] = self.env.address(name)
            if hook_id in self.after_start:
                hook = self.after_start.pop(hook_id)
                threading.Thread(target=hook, args=(task, name), daemon=True).start()
            return task

    def _state(self, task: FakeTask) -> dict[str, Any] | None:
        name = self.names.get(task.arn)
        if name is None:
            return None
        result = docker("inspect", "--format", "{{json .State}}", name, check=False)
        return json.loads(result.stdout) if result.returncode == 0 else None

    def _request_stop(self, task: FakeTask) -> None:
        if task.arn in self.stopping or task.arn not in self.names:
            return
        self.stopping.add(task.arn)
        # Like ECS: SIGTERM now, SIGKILL after the container's stop timeout.
        subprocess.Popen(["docker", "stop", self.names[task.arn]],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # fmt: skip

    def _status(self, task: FakeTask) -> str:
        state = self._state(task)
        if state is None:
            return "STOPPED" if task.arn in self.names else "PENDING"
        if state.get("Status") in {"exited", "dead"}:
            finished = docker_time(state["FinishedAt"])
            if task.stop_code is None:
                task.stop_code = "EssentialContainerExited"
            task.stopped_at = finished
            return "STOPPED"
        if task.stopped_at is not None:
            self._request_stop(task)
        return "RUNNING" if state.get("Running") else "PENDING"

    def _describe(self, task: FakeTask) -> dict:
        result = super()._describe(task)
        if result["lastStatus"] == "STOPPED":
            state = self._state(task) or {}
            code = state.get("ExitCode")
            for item in result["containers"]:
                if item["name"] == "init":
                    item["exitCode"] = 0  # simulated: the harness wrote its material
                elif isinstance(code, int):
                    item["exitCode"] = code
                else:
                    item.pop("exitCode", None)
        elif result["lastStatus"] == "RUNNING" and task.plan is None:
            marker = self.ready.get(task.arn)
            name = self.names.get(task.arn)
            healthy = marker is not None and name is not None and marker in self.env.logs(name)
            result["healthStatus"] = "HEALTHY" if healthy else "UNKNOWN"
        return result

    def lines(self, task: FakeTask) -> list[tuple[int, str]]:
        """The task container's output as (epoch ms, line), stdout and stderr together."""
        name = self.names.get(task.arn)
        if name is None:
            return []
        result = docker("logs", "--timestamps", name, check=False)
        events: list[tuple[int, str]] = []
        for line in (result.stdout + result.stderr).splitlines():
            moment, _, message = line.partition(" ")
            try:
                at = docker_time(moment)
            except ValueError:
                continue
            events.append((int(at.timestamp() * 1000), message))
        return sorted(events, key=lambda item: item[0])

    def kill(self, task_arn: str, signal: str = "KILL") -> None:
        docker("kill", "--signal", signal, self.names[task_arn], check=False)


class CanaryLogs:
    """GetLogEvents over the real worker container's output."""

    def __init__(self, ecs: CanaryEcs, document: dict) -> None:
        self.ecs = ecs
        self.release_id = evidence_release_id(document)
        self.group = f"/{document['environment']['name']}/worker"
        self.calls: list[dict] = []
        # Runs once before the first worker-stream read (replaced-task faults).
        self.before_read: Callable[[FakeTask], None] | None = None

    def get_log_events(self, log_group: str, log_stream: str, *, start_time_ms: int,
                       end_time_ms: int, next_token: str | None, limit: int) -> dict:  # fmt: skip
        self.calls.append({"log_stream": log_stream, "next_token": next_token})
        task = next(
            (item for item in self.ecs.tasks.values() if item.group == "service:worker"
             and log_stream == f"worker/{self.release_id}/app/" + item.arn.rsplit("/", 1)[1]),
            None,
        )  # fmt: skip
        if log_group != self.group or task is None:
            raise LookupError("ResourceNotFoundException")
        if self.before_read is not None:
            hook, self.before_read = self.before_read, None
            hook(task)
        events = [
            {"timestamp": at, "message": message}
            for at, message in self.ecs.lines(task)
            if start_time_ms <= at < end_time_ms
        ]
        position = int((next_token or "f/0").split("/")[1])
        page = events[position : position + min(limit, 100)]
        return {"events": page, "nextForwardToken": f"f/{position + len(page)}"}


class CanaryAws(FakeAws):
    """FakeAws whose job and observer streams are the real containers' output."""

    def __init__(self, ecs: CanaryEcs, document: dict) -> None:
        logs = CanaryLogs(ecs, document)
        super().__init__(ecs, logs, FakeEvidence(ecs, document),  # ty: ignore[invalid-argument-type]
                         FakeStore(), document)  # fmt: skip
        self.canary_logs = logs
        # Later releases in the same environment (an upgrade, a rollback run).
        self.documents: list[dict] = []
        self.canary_ecs = ecs
        self.job_noise = ()
        # Job or check id -> lines appended to its real stream (forged-receipt faults).
        self.appended: dict[str, list[str]] = {}
        # Job or check id -> a rewrite of its real receipt (substituted-receipt faults).
        self.rewritten: dict[str, Callable[[dict], dict]] = {}

    def _job_lines(self, group: str, stream: str) -> list[str]:
        prefix, container, task_id = stream.split("/")
        task = next(
            (t for arn, t in self.canary_ecs.tasks.items() if arn.endswith("/" + task_id)), None
        )
        if task is None:
            raise ServiceError("ResourceNotFoundException", 400)
        job_id = task.tags.get("sentry:job-id")
        environment = self.document["environment"]["name"]
        documents = [self.document, *self.documents]
        job = next((j for d in documents for j in d["jobs"] if j["id"] == job_id
                    and j["task"]["task_definition"] == task.task_definition), None)  # fmt: skip
        check = next((c for d in documents for c in d["operational_checks"]
                      if c["id"] == job_id and "task" in c
                      and c["task"]["task_definition"] == task.task_definition), None)  # fmt: skip
        if check is not None:
            if group != f"/{environment}/observe" or (prefix, container) != (job_id, "observer"):
                raise ServiceError("ResourceNotFoundException", 400)
        elif (
            job is None
            or group != f"/{environment}/{job['database']}-release"
            or prefix
            != (f"{job['database']}-release" if job["phase"] == "migrate"
                else f"{job['database']}-{job['phase']}")  # fmt: skip
            or container not in {c["name"] for c in job["task"]["containers"]}
        ):
            raise ServiceError("ResourceNotFoundException", 400)
        lines = [message for _, message in self.canary_ecs.lines(task)]
        rewrite = self.rewritten.get(job_id or "")
        if rewrite is not None:
            lines = [rewritten_receipt(line, rewrite) for line in lines]
        return lines + list(self.appended.get(job_id or "", []))


def receipt_lines(lines: list[str]) -> list[str]:
    return [line for line in lines if line.startswith(RECEIPT_MARKER + " ")]


def rewritten_receipt(line: str, rewrite: Callable[[dict], dict]) -> str:
    """The line, or its receipt rewritten and re-serialized as producers write it."""
    if not line.startswith(RECEIPT_MARKER + " "):
        return line
    document = rewrite(json.loads(line[len(RECEIPT_MARKER) + 1 :]))
    return f"{RECEIPT_MARKER} {json.dumps(document, separators=(',', ':'), sort_keys=True)}"


def wall_window(minutes: int = 120) -> tuple[datetime, datetime]:
    now = datetime.now(UTC).replace(microsecond=0)
    return now - timedelta(minutes=2), now + timedelta(minutes=minutes)


def iter_tasks(ecs: CanaryEcs) -> Iterator[FakeTask]:
    yield from ecs.tasks.values()
