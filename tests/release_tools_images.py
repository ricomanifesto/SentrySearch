"""Explicit release-tools container suite; run with dev/check_release_tools.py.

One internal Docker network without an outbound route holds a disposable TLS
PostgreSQL server, a stand-in ECS task-metadata endpoint at its link-local address
and the job containers. Every job runs read-only, without capabilities, as the
release-material uid. Databases, credentials and certificates exist for one run.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shlex
import subprocess
import tempfile
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.engine import URL

from dev.tls_fixtures import create_certificates
from release_tools import digest, receipt, session
from src.storage.schema import migrate

REPO = Path(__file__).resolve().parents[1]
# Keep aligned with tests/service_images.py and the SentryRuntime development image.
POSTGRES_IMAGE = (
    "docker.io/library/postgres:16-alpine@sha256:"
    "cf78e76683b9ca8c5733cbbdce6c9262b45b6767934dd0a95e671f9a0fc20685"
)
TOOLS_IMAGE = os.environ.get("RELEASE_TOOLS_TEST_IMAGE", "")
RUNTIME_IMAGE = os.environ.get("SENTRYRUNTIME_TEST_IMAGE", "")
SUBNET = "169.254.170.0/24"
METADATA_IP = "169.254.170.2"
POSTGRES_IP = "169.254.170.10"
PYTHON = ["--entrypoint", "/usr/local/bin/python3.11"]
PSQL = ["--entrypoint", str(session.PSQL)]
RUNTIME_UID, PRODUCT_UID = 65532, 10001
LOG_KEYS = receipt.LOG_FIELDS | {"event"}
METADATA_SERVER = (
    "import hashlib, http.server, json\n"
    "class H(http.server.BaseHTTPRequestHandler):\n"
    "    def do_GET(self):\n"
    "        parts = self.path.split('/')\n"
    "        ok = len(parts) == 4 and parts[1] == 'v4' and parts[3] == 'task'\n"
    "        arn = 'arn:aws:ecs:us-east-1:111122223333:task/sentry-release-check/'"
    " + hashlib.md5(parts[2].encode()).hexdigest() if ok else ''\n"
    "        body = json.dumps({'TaskARN': arn}).encode()\n"
    "        self.send_response(200 if ok else 404); self.end_headers(); self.wfile.write(body)\n"
    "    def log_message(self, *args): pass\n"
    "print('metadata listening', flush=True)\n"
    "http.server.ThreadingHTTPServer(('0.0.0.0', 80), H).serve_forever()\n"
)
# Every ELF object in the image must resolve its libraries inside the image.
CLOSURE_CHECK = (
    "import pathlib, struct, subprocess, sys\n"
    "def dynamic(data):\n"
    "    phoff, = struct.unpack_from('<Q', data, 32)\n"
    "    size, count = struct.unpack_from('<HH', data, 54)\n"
    "    return any(struct.unpack_from('<I', data, phoff + i * size)[0] == 2"
    " for i in range(count))\n"
    "loader = next(p for p in ('/lib64/ld-linux-x86-64.so.2', '/lib/ld-linux-aarch64.so.1')"
    " if pathlib.Path(p).exists())\n"
    "count = 0\n"
    "for root in ('/usr/lib', '/usr/local/bin', '/usr/local/lib'):\n"
    "    for path in sorted(pathlib.Path(root).rglob('*')):\n"
    "        if path.is_symlink() or not path.is_file() or path.read_bytes()[:4] != b'\\x7fELF':\n"
    "            continue\n"
    "        if path.resolve() == pathlib.Path(loader).resolve() or not dynamic(path.read_bytes()):\n"
    "            continue\n"
    "        out = subprocess.run([loader, '--list', str(path)], capture_output=True, text=True)\n"
    "        text = out.stdout + out.stderr\n"
    "        if 'not found' in text or (out.returncode and 'not a dynamic' not in text):\n"
    "            sys.exit(f'unresolved {path}: {text}')\n"
    "        count += 1\n"
    "print(count)\n"
)
TOOLS_PACKAGES = {
    "postgresql-client-16",
    "libpq5",
    "libreadline8t64",
    "readline-common",
    "libtinfo6",
    "libgssapi-krb5-2",
    "libkrb5-3",
    "libk5crypto3",
    "libkrb5support0",
    "libcom-err2",
    "libkeyutils1",
    "libldap2",
    "libsasl2-2",
}


def docker(
    *args: str, check: bool = True, timeout: float = 120, stdin: str | None = None
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout, input=stdin
    )
    if check and result.returncode:
        raise AssertionError(f"docker {args[0]} exited {result.returncode}: {result.stderr}")
    return result


def stamp(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def task_arn(name: str) -> str:
    return "arn:aws:ecs:us-east-1:111122223333:task/sentry-release-check/" + (
        hashlib.md5(name.encode()).hexdigest()  # noqa: S324 - fixture identifier only
    )


@dataclass
class JobRun:
    name: str
    code: int
    stdout: str
    stderr: str
    elapsed: float

    @property
    def receipt(self) -> dict | None:
        return receipt.extract_receipt(self.stdout.splitlines())

    @property
    def events(self) -> list[dict]:
        return [json.loads(line) for line in self.stderr.splitlines() if line]


@dataclass
class Stack:
    network: str
    root: Path
    secrets: dict[str, str]
    release_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    containers: list[str] = field(default_factory=list)
    volumes: list[str] = field(default_factory=list)
    pins: dict = field(default_factory=dict)
    material: dict[str, str] = field(default_factory=dict)

    @property
    def postgres(self) -> str:
        return f"{self.network}-postgres"

    def name(self, role: str) -> str:
        name = f"{self.network}-{role}-{uuid.uuid4().hex[:6]}"
        self.containers.append(name)
        return name

    def sql(self, database: str, statement: str, *, user: str = "postgres") -> str:
        """Superuser (or owner) SQL over the server's local socket, for fixtures only."""
        return docker(
            "exec",
            self.postgres,
            "psql",
            "-X",
            "-v",
            "ON_ERROR_STOP=1",
            "-U",
            user,
            "-d",
            database,
            "-tAc",
            statement,
        ).stdout.strip()

    def server_log(self) -> str:
        result = docker("logs", self.postgres, check=False)
        return result.stdout + result.stderr

    def volume(self, uid: int, ca: Path | None) -> str:
        """The init profile's result: a private dir and an owner-only CA file."""
        name = f"{self.network}-material-{len(self.volumes)}"
        docker("volume", "create", name)
        self.volumes.append(name)
        script = (
            "import os, sys\n"
            "data = sys.stdin.read()\n"
            "if data:\n"
            "    fd = os.open('/run/material/postgres-ca.pem', os.O_CREAT | os.O_EXCL | os.O_WRONLY,"
            " 0o600)\n"
            "    os.write(fd, data.encode()); os.fchmod(fd, 0o400)\n"
            f"    os.fchown(fd, {uid}, {uid}); os.close(fd)\n"
            "os.chmod('/run/material', 0o700)\n"
            f"os.chown('/run/material', {uid}, {uid})\n"
        )
        docker(
            "run",
            "--rm",
            "-i",
            "--network",
            "none",
            "--user",
            "0",
            "--mount",
            f"type=volume,source={name},target=/run/material",
            *PYTHON,
            TOOLS_IMAGE,
            "-I",
            "-B",
            "-c",
            script,
            stdin=ca.read_text() if ca is not None else "",
        )
        return name

    def environment(self, kind: str, database: str, **overrides: str) -> dict[str, str]:
        dbname = "sentryruntime" if database == "runtime" else "sentrysearch"
        owner, service = (
            ("runtime_owner", "runtime_app")
            if database == "runtime"
            else ("search_owner", "search_app")
        )
        principal = {"grant": owner, "reconcile": owner, "proof": service, "bootstrap": "postgres"}
        values = {
            "RELEASE_ID": self.release_id,
            "RELEASE_JOB_ID": f"{database}-{kind}",
            "RELEASE_DATABASE": database,
            "RELEASE_NOT_AFTER": stamp(datetime.now(UTC) + timedelta(minutes=10)),
            "RELEASE_JOB_BUDGET_SECONDS": "600",
            "RELEASE_TOOLS_SHA256": self.pins["tools_sha256"],
            "RELEASE_SQL_SHA256": self.pins["sql"][session_main(kind, database)],
            "RELEASE_EXPECT_DATABASE": "postgres" if kind == "bootstrap" else dbname,
            "RELEASE_EXPECT_PRINCIPAL": principal[kind],
        }
        if kind in {"grant", "bootstrap"}:
            values["RELEASE_SERVICE_ROLE"] = service
        if kind in {"proof", "bootstrap"}:
            values["RELEASE_OWNER_ROLE"] = owner
        if kind == "bootstrap":
            values["RELEASE_TARGET_DATABASE"] = dbname
            values["RELEASE_OWNER_PASSWORD"] = self.secrets[owner]
            values["RELEASE_SERVICE_PASSWORD"] = self.secrets[service]
        values.update(
            DB_HOST="postgres",
            DB_PORT="5432",
            DB_NAME=values["RELEASE_EXPECT_DATABASE"],
            DB_USER=values["RELEASE_EXPECT_PRINCIPAL"],
            DB_PASSWORD=self.secrets[values["RELEASE_EXPECT_PRINCIPAL"]],
        )
        values.update(overrides)
        return values

    def start_job(
        self, kind: str, database: str, *, material: str | None = None, uid: int | None = None,
        **overrides: str,
    ) -> str:  # fmt: skip
        name = self.name(f"{database}-{kind}")
        env = self.environment(kind, database, **overrides)
        env["ECS_CONTAINER_METADATA_URI_V4"] = f"http://{METADATA_IP}/v4/{name}"
        env_file = self.root / f"{name}.env"
        env_file.write_text("".join(f"{key}={value}\n" for key, value in env.items()))
        env_file.chmod(0o600)
        uid = uid if uid is not None else (RUNTIME_UID if database == "runtime" else PRODUCT_UID)
        volume = material or self.material[database]
        docker(
            "run",
            "-d",
            "--name",
            name,
            "--network",
            self.network,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--user",
            f"{uid}:{uid}",
            "--stop-timeout",
            "30",
            "--mount",
            f"type=volume,source={volume},target=/run/material,readonly,volume-nocopy",
            "--env-file",
            str(env_file),
            TOOLS_IMAGE,
            kind,
        )
        return name

    def finish(self, name: str, started: float, *, timeout: float = 120) -> JobRun:
        code = int(docker("wait", name, timeout=timeout).stdout.strip())
        elapsed = time.monotonic() - started
        logs = docker("logs", name)
        run = JobRun(name, code, logs.stdout, logs.stderr, elapsed)
        self.assert_redacted(run)
        return run

    def job(self, kind: str, database: str, **options) -> JobRun:
        started = time.monotonic()
        return self.finish(self.start_job(kind, database, **options), started)

    def assert_redacted(self, run: JobRun) -> None:
        output = run.stdout + run.stderr
        for value in self.secrets.values():
            assert value not in output, "job output exposed a disposable secret"
        assert "SCRAM-SHA-256" not in output and "psql:" not in output
        for event in run.events:
            assert set(event) <= LOG_KEYS, event
        for line in run.stdout.splitlines():
            assert line.startswith(receipt.RECEIPT_MARKER + " "), line

    def acl_snapshot(self, database: str) -> str:
        return self.sql(
            database,
            "SELECT string_agg(x, ';' ORDER BY x) FROM ("
            " SELECT 'db:' || datname || ':' || coalesce(datacl::text, '') FROM pg_database"
            " UNION ALL SELECT 'ns:' || nspname || ':' || coalesce(nspacl::text, '')"
            " FROM pg_namespace WHERE nspname = 'public'"
            " UNION ALL SELECT 'rel:' || relname || ':' || coalesce(relacl::text, '')"
            " FROM pg_class WHERE relnamespace = 'public'::regnamespace"
            " UNION ALL SELECT 'col:' || attrelid::regclass || '.' || attname || ':' || attacl::text"
            " FROM pg_attribute WHERE attacl IS NOT NULL"
            " AND attrelid IN (SELECT oid FROM pg_class WHERE relnamespace = 'public'::regnamespace)"
            ") AS acl(x)",
        )

    def backend(self, application_name: str) -> list[str]:
        return self.sql(
            "postgres",
            "SELECT pid || '|' || coalesce(wait_event_type, '') FROM pg_stat_activity"
            f" WHERE application_name = '{application_name}'",
        ).splitlines()


def session_main(kind: str, database: str) -> str:
    from release_tools.config import MAIN_SQL

    return MAIN_SQL[(kind, database)]


def wait_for(description: str, predicate, *, timeout: float = 60) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.1)
    raise AssertionError(f"timed out waiting for {description}")


def _start_postgres(stack: Stack, *, name: str, ssl: bool, ip: str | None, alias: str) -> None:
    stack.containers.append(name)
    server = ["postgres", "-c", "log_connections=on", "-c", "log_disconnections=on"]
    server += ["-c", "log_statement=ddl", "-c", "log_line_prefix=%m [%p] app=%a "]
    if ssl:
        server += ["-c", "ssl=on", "-c", "ssl_cert_file=/var/lib/postgresql/server.crt"]
        server += ["-c", "ssl_key_file=/var/lib/postgresql/server.key"]
    setup = (
        "install -o postgres -g postgres -m 0600 /tls-source/server-key.pem"
        " /var/lib/postgresql/server.key && install -o postgres -g postgres -m 0644"
        " /tls-source/server.pem /var/lib/postgresql/server.crt && "
    )
    docker(
        "run",
        "-d",
        "--name",
        name,
        "--network",
        stack.network,
        *(("--ip", ip) if ip else ()),
        "--network-alias",
        alias,
        *(("--network-alias", "db-other") if ssl else ()),
        "-e",
        f"POSTGRES_PASSWORD={stack.secrets['postgres']}",
        "-v",
        f"{stack.root / 'postgres'}:/tls-source:ro",
        "--entrypoint",
        "sh",
        POSTGRES_IMAGE,
        "-c",
        (setup if ssl else "") + "exec docker-entrypoint.sh " + shlex.join(server),
    )
    wait_for(
        "PostgreSQL",
        lambda: docker(
            "exec", name, "pg_isready", "-h", "127.0.0.1", "-U", "postgres", check=False
        ).returncode
        == 0
        and "database system is ready to accept connections" in stack.server_log(),
    )


def _migrate(stack: Stack) -> None:
    runtime_url = (
        f"postgres://runtime_owner:{stack.secrets['runtime_owner']}@postgres:5432/sentryruntime"
        "?sslmode=verify-full&sslrootcert=/run/material/postgres-ca.pem"
    )
    env_file = stack.root / "runtime-migrate.env"
    env_file.write_text(f"DATABASE_URL={runtime_url}\n")
    env_file.chmod(0o600)
    docker(
        "run",
        "--rm",
        "--name",
        stack.name("runtime-migrate"),
        "--network",
        stack.network,
        "--read-only",
        "--cap-drop",
        "ALL",
        "--user",
        f"{RUNTIME_UID}:{RUNTIME_UID}",
        "--mount",
        f"type=volume,source={stack.material['runtime']},target=/run/material,readonly,volume-nocopy",
        "--env-file",
        str(env_file),
        RUNTIME_IMAGE,
        "/app/migrate",
        timeout=180,
    )
    # The product migration runs from this checkout over verified TLS, as the owner.
    engine = create_engine(
        URL.create(
            "postgresql+psycopg",
            username="search_owner",
            password=stack.secrets["search_owner"],
            host="postgres",
            port=5432,
            database="sentrysearch",
            query={
                "sslmode": "verify-full",
                "sslrootcert": str(stack.root / "postgres" / "ca.pem"),
                "hostaddr": POSTGRES_IP,
                "gssencmode": "disable",
            },
        ),
        hide_parameters=True,
    )
    try:
        migrate(engine)
    finally:
        engine.dispose()


@pytest.fixture(scope="module")
def stack() -> Iterator[Stack]:
    if not TOOLS_IMAGE or not RUNTIME_IMAGE:
        pytest.fail("RELEASE_TOOLS_TEST_IMAGE and SENTRYRUNTIME_TEST_IMAGE are required")
    names = ("postgres", "runtime_owner", "runtime_app", "search_owner", "search_app")
    with tempfile.TemporaryDirectory(prefix="release-tools-") as directory:
        root = Path(directory)
        root.chmod(0o755)
        stack = Stack(
            network="release-tools-" + uuid.uuid4().hex[:8],
            root=root,
            secrets={name: secrets.token_urlsafe(30) for name in names},
        )
        docker("network", "create", "--internal", "--subnet", SUBNET, stack.network)
        try:
            for name, host in (("postgres", "postgres"), ("wrong", "postgres")):
                create_certificates(root / name, hostname=host)
            for path in (root / "postgres").iterdir():
                path.chmod(0o644)
            (root / "postgres").chmod(0o755)
            stack.pins = json.loads(docker("run", "--rm", TOOLS_IMAGE, "digest").stdout)
            metadata = stack.name("metadata")
            docker(
                "run",
                "-d",
                "--name",
                metadata,
                "--network",
                stack.network,
                "--ip",
                METADATA_IP,
                "--read-only",
                "--cap-drop",
                "ALL",
                *PYTHON,
                TOOLS_IMAGE,
                "-I",
                "-B",
                "-c",
                METADATA_SERVER,
            )
            wait_for("metadata", lambda: "listening" in docker("logs", metadata).stdout)
            _start_postgres(stack, name=stack.postgres, ssl=True, ip=POSTGRES_IP, alias="postgres")
            ca = root / "postgres" / "ca.pem"
            stack.material = {
                "runtime": stack.volume(RUNTIME_UID, ca),
                "product": stack.volume(PRODUCT_UID, ca),
            }
            yield stack
        finally:
            for name in reversed(stack.containers):
                docker("rm", "-f", "-v", name, check=False)
            for name in stack.volumes:
                docker("volume", "rm", "-f", name, check=False)
            docker("network", "rm", stack.network, check=False)


@pytest.fixture(scope="module")
def released(stack: Stack) -> dict[str, JobRun]:
    """Bootstrap, migrate, grant and prove both databases; reruns must converge."""
    runs = {}
    for database in ("runtime", "product"):
        runs[f"{database}-bootstrap"] = stack.job("bootstrap", database)
        runs[f"{database}-bootstrap-again"] = stack.job("bootstrap", database)
    _migrate(stack)
    for database in ("runtime", "product"):
        runs[f"{database}-grant"] = stack.job("grant", database)
        before = stack.acl_snapshot("sentryruntime" if database == "runtime" else "sentrysearch")
        runs[f"{database}-grant-again"] = stack.job("grant", database)
        after = stack.acl_snapshot("sentryruntime" if database == "runtime" else "sentrysearch")
        assert before == after, "a grant rerun changed privileges"
        runs[f"{database}-proof"] = stack.job("proof", database)
    for key, run in runs.items():
        assert run.code == 0, (key, run.stdout, run.stderr)
    return runs


# --- image -------------------------------------------------------------------


def test_image_is_nonroot_pinned_and_self_contained(stack):
    config = json.loads(docker("image", "inspect", TOOLS_IMAGE).stdout)[0]["Config"]
    assert config["User"] == "65532:65532"
    assert config["Entrypoint"] == [
        "/usr/local/bin/tini",
        "--",
        "/usr/local/bin/python3.11",
        "-I",
        "-B",
        "-m",
        "release_tools",
    ]
    assert not config.get("Cmd")
    assert stack.pins == json.loads(json.dumps(digest.report()))
    run = docker(
        "run", "--rm", "--read-only", "--network", "none", *PYTHON, TOOLS_IMAGE, "-I", "-B",
        "-c", CLOSURE_CHECK,
    )  # fmt: skip
    assert int(run.stdout) > 20
    version = docker(
        "run", "--rm", "--read-only", "--network", "none", *PSQL, TOOLS_IMAGE, "--version"
    ).stdout
    assert version.startswith("psql (PostgreSQL) 16.15 ")
    listing = docker(
        "run", "--rm", "--network", "none", *PYTHON, TOOLS_IMAGE, "-I", "-c",
        "import os; print('\\n'.join(sorted(os.listdir('/var/lib/dpkg/status.d'))));"
        "print('BIN', *sorted(os.listdir('/usr/lib/postgresql/16/bin')))",
    ).stdout  # fmt: skip
    bytecode = docker(
        "run", "--rm", "--network", "none", *PYTHON, TOOLS_IMAGE, "-I", "-B", "-c",
        "import os, release_tools; root = os.path.dirname(release_tools.__file__);"
        "print(sum(1 for _, dirs, files in os.walk(root) for name in dirs + files"
        " if name == '__pycache__' or name.endswith('.pyc')))",
    ).stdout  # fmt: skip
    assert bytecode.strip() == "0", "the digest covers sources; no unhashed bytecode may ship"
    packages = {line for line in listing.splitlines() if not line.endswith(".md5sums")}
    assert TOOLS_PACKAGES <= packages
    assert "BIN psql" in listing
    for shell in ("/bin/sh", "/usr/bin/apt-get", "/usr/bin/pip"):
        probe = docker("run", "--rm", "--network", "none", "--entrypoint", shell, TOOLS_IMAGE,
                       check=False)  # fmt: skip
        assert probe.returncode != 0


def test_unknown_command_runs_nothing(stack):
    run = docker("run", "--rm", "--network", "none", TOOLS_IMAGE, "shell", check=False)
    assert run.returncode == 2 and json.loads(run.stderr)["reason"] == "command_invalid"


# --- happy path, idempotence and isolation ------------------------------------


def test_bootstrap_creates_private_databases_and_converges(stack, released):
    for database, dbname, owner, service in (
        ("runtime", "sentryruntime", "runtime_owner", "runtime_app"),
        ("product", "sentrysearch", "search_owner", "search_app"),
    ):
        for key in (f"{database}-bootstrap", f"{database}-bootstrap-again"):
            run = released[key]
            assert run.receipt == {
                "schema": receipt.RECEIPT_SCHEMA,
                "release_id": stack.release_id,
                "job_id": f"{database}-bootstrap",
                "task_arn": task_arn(run.name),
                "status": "succeeded",
                "result": {
                    "database": dbname,
                    "principal": "postgres",
                    "owner_role": owner,
                    "service_role": service,
                },
            }
        assert (
            stack.sql(
                "postgres",
                f"SELECT r.rolname FROM pg_database d JOIN pg_roles r ON r.oid = d.datdba"
                f" WHERE d.datname = '{dbname}'",
            )
            == owner
        )
        attributes = stack.sql(
            "postgres",
            "SELECT bool_or(rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication"
            f" OR rolbypassrls) FROM pg_roles WHERE rolname IN ('{owner}', '{service}')",
        )
        assert attributes == "f"
        defaults = stack.sql(
            "postgres",
            "SELECT array_to_string(setconfig, ',') FROM pg_db_role_setting"
            f" WHERE setrole = '{owner}'::regrole",
        )
        assert "statement_timeout=60s" in defaults
        assert "client_connection_check_interval=1s" in defaults
    log = stack.server_log()
    for value in stack.secrets.values():
        assert value not in log, "server statement log exposed a plaintext password"


def test_grants_and_proofs_report_exact_identity_digest_and_schema(stack, released):
    expected_product_schema = (
        "sentrysearch:1:"
        + hashlib.sha256(
            (REPO / "src/storage/migrations/001_release.sql").read_bytes()
        ).hexdigest()[:16]
    )
    cases = {
        "runtime-grant": {
            "database": "sentryruntime",
            "principal": "runtime_owner",
            "service_role": "runtime_app",
            "sql_digest": stack.pins["sql"]["sql/runtime/service.sql"],
        },
        "product-grant": {
            "database": "sentrysearch",
            "principal": "search_owner",
            "service_role": "search_app",
            "sql_digest": stack.pins["sql"]["sql/product/grants.sql"],
        },
        "runtime-proof": {
            "database": "sentryruntime",
            "principal": "runtime_app",
            "schema": "goose:1,2,3",
        },
        "product-proof": {
            "database": "sentrysearch",
            "principal": "search_app",
            "schema": expected_product_schema,
        },
    }
    for key, result in cases.items():
        for run in (released[key], released.get(f"{key}-again")):
            if run is None:
                continue
            assert run.receipt == {
                "schema": receipt.RECEIPT_SCHEMA,
                "release_id": stack.release_id,
                "job_id": key,
                "task_arn": task_arn(run.name),
                "status": "succeeded",
                "result": result,
            }
    assert cases["runtime-grant"]["sql_digest"] == (
        "02a2b55161506254b1977f26351ec3bbba4de7c94a54b3b697153d622ae02aa0"
    )


def test_service_logins_reach_only_their_own_database(stack, released):
    for user, allowed, denied in (
        ("runtime_app", "sentryruntime", ("sentrysearch", "postgres")),
        ("search_app", "sentrysearch", ("sentryruntime", "postgres")),
    ):
        url = f"postgresql://{user}@postgres:5432/{{}}?sslmode=verify-full"
        for database, ok in ((allowed, True), *((name, False) for name in denied)):
            run = docker(
                "run", "--rm", "--network", stack.network, "--read-only", "--cap-drop", "ALL",
                "--user", f"{RUNTIME_UID}", "-e", f"PGPASSWORD={stack.secrets[user]}",
                "-e", "PGSSLROOTCERT=/run/material/postgres-ca.pem",
                "--mount", f"type=volume,source={stack.material['runtime']},"
                "target=/run/material,readonly,volume-nocopy",
                *PSQL, TOOLS_IMAGE, "-X", "-tAc", "SELECT 1", url.format(database),
                check=False,
            )  # fmt: skip
            if ok:
                assert run.returncode == 0 and run.stdout.strip() == "1", run.stderr
            else:
                assert run.returncode == 2 and "permission denied for database" in run.stderr


def test_runtime_grant_refuses_the_product_database_even_as_its_owner(stack, released):
    before = stack.acl_snapshot("sentrysearch")
    as_runtime_owner = stack.job(
        "grant", "runtime", RELEASE_EXPECT_DATABASE="sentrysearch", DB_NAME="sentrysearch"
    )
    assert as_runtime_owner.code == 10
    assert as_runtime_owner.receipt["result"] == {
        "reason": "connect_denied",
        "sql_outcome": "none",
    }
    as_product_owner = stack.job(
        "grant",
        "runtime",
        RELEASE_EXPECT_DATABASE="sentrysearch",
        RELEASE_EXPECT_PRINCIPAL="search_owner",
        RELEASE_SERVICE_ROLE="search_app",
        DB_NAME="sentrysearch",
        DB_USER="search_owner",
        DB_PASSWORD=stack.secrets["search_owner"],
        uid=RUNTIME_UID,
    )
    assert as_product_owner.code == 11
    assert as_product_owner.receipt["result"] == {"reason": "sql_error", "sql_outcome": "unknown"}
    assert stack.acl_snapshot("sentrysearch") == before


def test_proofs_detect_excess_privileges(stack, released):
    cases = (
        ("product", "sentrysearch", "GRANT TRUNCATE ON public.report_tags TO search_app",
         "REVOKE TRUNCATE ON public.report_tags FROM search_app"),
        ("runtime", "postgres", "GRANT CONNECT ON DATABASE postgres TO runtime_app",
         "REVOKE CONNECT ON DATABASE postgres FROM runtime_app"),
        ("runtime", "sentryruntime", "GRANT runtime_owner TO runtime_app",
         "REVOKE runtime_owner FROM runtime_app"),
    )  # fmt: skip
    for database, dbname, grant, revoke in cases:
        stack.sql(dbname, grant)
        try:
            run = stack.job("proof", database)
        finally:
            stack.sql(dbname, revoke)
        assert run.code == 11, grant
        assert run.receipt["result"] == {
            "reason": "privilege_inventory_mismatch",
            "sql_outcome": "unknown",
        }
    assert stack.job("proof", "runtime").code == 0


def test_product_grant_rejects_a_privileged_owner_without_changing_privileges(stack, released):
    before = stack.acl_snapshot("sentrysearch")
    stack.sql("postgres", "GRANT pg_signal_backend TO search_owner")
    try:
        run = stack.job("grant", "product")
    finally:
        stack.sql("postgres", "REVOKE pg_signal_backend FROM search_owner")
    assert run.code == 11
    assert run.receipt["result"] == {"reason": "sql_error", "sql_outcome": "unknown"}
    assert stack.acl_snapshot("sentrysearch") == before
    assert stack.job("grant", "product").code == 0


def test_other_members_of_owner_or_service_logins_are_rejected(stack, released):
    stack.sql("postgres", "CREATE ROLE mallory NOLOGIN")
    try:
        # ADMIN alone lets mallory grant herself SET and become the login.
        stack.sql(
            "postgres", "GRANT runtime_app TO mallory WITH ADMIN TRUE, INHERIT FALSE, SET FALSE"
        )
        proof = stack.job("proof", "runtime")
        bootstrap = stack.job("bootstrap", "runtime")
        stack.sql("postgres", "REVOKE runtime_app FROM mallory")
        stack.sql(
            "postgres", "GRANT search_owner TO mallory WITH ADMIN TRUE, INHERIT FALSE, SET FALSE"
        )
        before = stack.acl_snapshot("sentrysearch")
        grant = stack.job("grant", "product")
        assert stack.acl_snapshot("sentrysearch") == before
        product_proof = stack.job("proof", "product")
    finally:
        stack.sql("postgres", "DROP ROLE mallory")
    assert proof.code == 11
    assert proof.receipt["result"]["reason"] == "privilege_inventory_mismatch"
    assert bootstrap.code == 11 and bootstrap.receipt["result"]["reason"] == "bootstrap_conflict"
    assert grant.code == 11 and grant.receipt["result"]["reason"] == "sql_error"
    assert product_proof.code == 11
    assert product_proof.receipt["result"]["reason"] == "privilege_inventory_mismatch"
    assert stack.job("proof", "runtime").code == 0


def test_bootstrap_as_a_non_superuser_administrator_fails_closed(stack, released):
    """An RDS-like administrator: CREATEROLE/CREATEDB, not superuser."""
    for name in ("rds_admin", "probe_owner", "probe_app"):
        stack.secrets[name] = secrets.token_urlsafe(30)
    admin = stack.secrets["rds_admin"]
    stack.sql("postgres", f"CREATE ROLE rds_admin LOGIN CREATEROLE CREATEDB PASSWORD '{admin}'")
    stack.sql("postgres", "GRANT CONNECT ON DATABASE postgres TO rds_admin")
    probe = {
        "RELEASE_JOB_ID": "probe-bootstrap",
        "RELEASE_TARGET_DATABASE": "rds_probe",
        "RELEASE_OWNER_ROLE": "probe_owner",
        "RELEASE_SERVICE_ROLE": "probe_app",
        "RELEASE_EXPECT_PRINCIPAL": "rds_admin",
        "RELEASE_OWNER_PASSWORD": stack.secrets["probe_owner"],
        "RELEASE_SERVICE_PASSWORD": stack.secrets["probe_app"],
        "DB_USER": "rds_admin",
        "DB_PASSWORD": admin,
    }
    try:
        # PostgreSQL 16 requires SET on the owner role to create its database.
        without_set = stack.job("bootstrap", "runtime", **probe)
        stack.sql("postgres", "GRANT probe_owner TO rds_admin WITH INHERIT FALSE, SET TRUE")
        # The target revoke runs as the owner. The maintenance database belongs to
        # another role, so the administrator's revoke there is only a warning.
        stack.sql("postgres", "GRANT CONNECT ON DATABASE postgres TO PUBLIC")
        not_owner = stack.job("bootstrap", "runtime", **probe)
        target_public = stack.sql(
            "postgres",
            "SELECT count(*) FROM pg_database d, aclexplode(coalesce(d.datacl,"
            " acldefault('d', d.datdba))) a WHERE d.datname = 'rds_probe' AND a.grantee = 0",
        )
        stack.sql("postgres", "ALTER DATABASE postgres OWNER TO rds_admin")
        owner = stack.job("bootstrap", "runtime", **probe)
    finally:
        stack.sql("postgres", "ALTER DATABASE postgres OWNER TO postgres")
        stack.sql("postgres", "REVOKE ALL ON DATABASE postgres FROM PUBLIC")
        stack.sql("postgres", "DROP DATABASE IF EXISTS rds_probe")
        stack.sql("postgres", "DROP OWNED BY rds_admin")
        stack.sql("postgres", "DROP ROLE IF EXISTS probe_app, probe_owner, rds_admin")
    assert without_set.code == 11
    assert without_set.receipt["result"] == {
        "reason": "permission_denied",
        "sql_outcome": "unknown",
    }
    assert not_owner.code == 11 and target_public == "0"
    assert not_owner.receipt["result"] == {"reason": "bootstrap_conflict", "sql_outcome": "unknown"}
    assert owner.code == 0 and owner.receipt["result"] == {
        "database": "rds_probe",
        "principal": "rds_admin",
        "owner_role": "probe_owner",
        "service_role": "probe_app",
    }


# --- failures before any SQL --------------------------------------------------


def test_wrong_credentials_and_untrusted_tls_never_run_sql(stack, released):
    wrong_ca = stack.volume(RUNTIME_UID, stack.root / "wrong" / "ca.pem")
    cases = [
        ({"DB_PASSWORD": "not-the-owner-password-at-all"}, {}, "auth_failed"),
        ({}, {"material": wrong_ca}, "tls_untrusted"),
        ({"DB_HOST": "db-other"}, {}, "tls_untrusted"),
    ]
    for overrides, options, reason in cases:
        run = stack.job("reconcile", "runtime", **options, **overrides)
        assert run.code == 10, (reason, run.stderr)
        assert run.receipt["result"] == {"reason": reason, "sql_outcome": "none"}
    plain = stack.name("plain-postgres")
    _start_postgres(stack, name=plain, ssl=False, ip=None, alias="plain")
    run = stack.job("reconcile", "runtime", DB_HOST="plain")
    assert run.code == 10
    assert run.receipt["result"] == {"reason": "tls_unavailable", "sql_outcome": "none"}
    plain_log = docker("logs", plain).stderr
    assert f"release:{stack.release_id}" not in plain_log


def test_failed_or_foreign_init_material_fails_before_connecting(stack, released):
    empty = stack.volume(RUNTIME_UID, None)
    foreign = stack.material["product"]  # owner-only and owned by the product uid
    for index, material in enumerate((empty, foreign)):
        job_id = f"material-check-{index}"
        run = stack.job("grant", "runtime", material=material, RELEASE_JOB_ID=job_id)
        assert run.code == 5
        assert run.receipt["result"] == {"reason": "material_invalid", "sql_outcome": "none"}
        assert f"release:{stack.release_id}:{job_id}" not in stack.server_log()


def test_expired_deadline_is_rejected_before_any_connection(stack, released):
    job_id = "expired-grant"
    run = stack.job(
        "grant",
        "runtime",
        RELEASE_JOB_ID=job_id,
        RELEASE_NOT_AFTER=stamp(datetime.now(UTC) - timedelta(seconds=1)),
    )
    assert run.code == 4 and run.receipt is None
    assert run.events[-1] == {
        "event": "job_failed",
        "reason": "deadline_expired",
        "sql_outcome": "none",
        "exit_code": "4",
    }
    assert f"release:{stack.release_id}:{job_id}" not in stack.server_log()


# --- bounded execution ---------------------------------------------------------


def _hold_grant_lock(stack: Stack) -> subprocess.Popen[str]:
    """Hold the runtime_runs catalog row in an open transaction until stdin closes.

    GRANT/REVOKE update the relation's pg_class row without a relation lock, so
    the fixture changes that row (reverted on rollback) to make the grant wait.
    """
    holder = subprocess.Popen(
        ["docker", "exec", "-i", stack.postgres, "psql", "-X", "-U", "postgres", "-d",
         "sentryruntime", "-v", "ON_ERROR_STOP=1"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )  # fmt: skip
    assert holder.stdin is not None
    holder.stdin.write(
        "BEGIN; LOCK TABLE public.runtime_runs IN ACCESS EXCLUSIVE MODE;"
        " ALTER TABLE public.runtime_runs SET (fillfactor = 100); SELECT 'locked';\n"
    )
    holder.stdin.flush()
    wait_for(
        "fixture lock",
        lambda: stack.sql(
            "sentryruntime",
            "SELECT count(*) FROM pg_locks WHERE relation = 'public.runtime_runs'::regclass"
            " AND mode = 'AccessExclusiveLock' AND granted",
        )
        == "1",
    )
    return holder


def _release(holder: subprocess.Popen[str]) -> None:
    assert holder.stdin is not None
    holder.stdin.write("ROLLBACK;\n")
    holder.stdin.close()
    holder.wait(timeout=30)


def test_lock_wait_is_bounded_per_session(stack, released):
    holder = _hold_grant_lock(stack)
    try:
        run = stack.job("grant", "runtime")
    finally:
        _release(holder)
    assert run.code == 11 and run.elapsed < 20
    assert run.receipt["result"] == {"reason": "lock_timeout", "sql_outcome": "unknown"}


def test_hung_session_is_stopped_by_the_in_image_deadline_without_a_controller(stack, released):
    # Sentinel: a committed grant would restore it; the rollback must leave it.
    stack.sql("sentryruntime", "REVOKE SELECT ON public.goose_db_version FROM runtime_app")
    holder = _hold_grant_lock(stack)
    tag = f"release:{stack.release_id}:runtime-grant"
    not_after = datetime.now(UTC) + timedelta(seconds=16)
    started = time.monotonic()
    name = stack.start_job("grant", "runtime", RELEASE_NOT_AFTER=stamp(not_after))
    try:
        wait_for("blocked grant", lambda: any(row.endswith("|Lock") for row in stack.backend(tag)))
        pid = stack.backend(tag)[0].split("|")[0]
        docker("exec", stack.postgres, "kill", "-STOP", pid)
        # Nobody stops the task: the job's own watchdog must end it by the deadline.
        run = stack.finish(name, started)
        assert datetime.now(UTC) <= not_after + timedelta(seconds=2)
    finally:
        for row in stack.backend(tag):
            docker("exec", stack.postgres, "kill", "-CONT", row.split("|")[0], check=False)
        _release(holder)
    assert run.code == 124
    assert run.receipt["result"] == {"reason": "deadline_exceeded", "sql_outcome": "unknown"}
    wait_for("abandoned backend to exit", lambda: not stack.backend(tag), timeout=15)
    assert (
        stack.sql(
            "sentryruntime",
            "SELECT has_table_privilege('runtime_app', 'public.goose_db_version', 'SELECT')",
        )
        == "f"
    )
    # Unknown outcomes are reconciled by an exact, idempotent rerun.
    rerun = stack.job("grant", "runtime")
    assert rerun.code == 0 and rerun.receipt["status"] == "succeeded"
    assert (
        stack.sql(
            "sentryruntime",
            "SELECT has_table_privilege('runtime_app', 'public.goose_db_version', 'SELECT')",
        )
        == "t"
    )


def test_stop_signal_terminates_and_reaps_the_client(stack, released):
    holder = _hold_grant_lock(stack)
    tag = f"release:{stack.release_id}:runtime-grant"
    started = time.monotonic()
    name = stack.start_job("grant", "runtime")
    try:
        wait_for("blocked grant", lambda: any(row.endswith("|Lock") for row in stack.backend(tag)))
        stopped = time.monotonic()
        docker("kill", "--signal", "SIGTERM", name)
        run = stack.finish(name, started)
        assert time.monotonic() - stopped < 8
    finally:
        _release(holder)
    assert run.code == 143
    assert run.receipt["result"] == {"reason": "terminated", "sql_outcome": "unknown"}
    wait_for("terminated backend to exit", lambda: not stack.backend(tag), timeout=15)


def _client_query(stack: Stack, name: str, check_interval_ms: int, sql: str) -> None:
    options = (
        "-c statement_timeout=60000 -c lock_timeout=3000"
        f" -c idle_in_transaction_session_timeout=10000"
        f" -c client_connection_check_interval={check_interval_ms}"
    )
    stack.containers.append(name)
    docker(
        "run", "-d", "--name", name, "--network", stack.network, "--read-only",
        "--cap-drop", "ALL", "--user", f"{RUNTIME_UID}",
        "--mount", f"type=volume,source={stack.material['runtime']},"
        "target=/run/material,readonly,volume-nocopy",
        "-e", f"PGPASSWORD={stack.secrets['runtime_owner']}", "-e", f"PGOPTIONS={options}",
        "-e", f"PGAPPNAME={name}", "-e", "PGSSLROOTCERT=/run/material/postgres-ca.pem",
        *PSQL, TOOLS_IMAGE, "-X", "-c", sql,
        "postgresql://runtime_owner@postgres:5432/sentryruntime?sslmode=verify-full",
    )  # fmt: skip


def test_server_query_stops_soon_after_its_client_is_killed(stack, released):
    guarded = f"{stack.network}-guarded"
    unguarded = f"{stack.network}-unguarded"
    _client_query(stack, guarded, 1000, "SELECT pg_sleep(45)")
    _client_query(stack, unguarded, 0, "SELECT pg_sleep(45)")
    wait_for("both queries", lambda: stack.backend(guarded) and stack.backend(unguarded))
    docker("kill", "--signal", "SIGKILL", guarded, unguarded)
    killed = time.monotonic()
    wait_for("guarded backend to exit", lambda: not stack.backend(guarded), timeout=10)
    assert time.monotonic() - killed < 10
    # Without the check interval the server keeps working for a vanished client.
    assert stack.backend(unguarded)
    stack.sql("postgres", f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity"
                          f" WHERE application_name = '{unguarded}'")  # fmt: skip


def test_statement_limit_is_capped_by_the_remaining_budget(stack, released):
    limits = session.limits(remaining_seconds=6.0)
    assert limits.statement_ms == 4000
    name = stack.name("statement-limit")
    options = (
        f"-c statement_timeout={limits.statement_ms} -c lock_timeout={limits.lock_ms}"
        f" -c idle_in_transaction_session_timeout={limits.idle_ms}"
        f" -c client_connection_check_interval={limits.check_interval_ms}"
    )
    started = time.monotonic()
    run = docker(
        "run", "--rm", "--name", name, "--network", stack.network, "--read-only",
        "--cap-drop", "ALL", "--user", f"{RUNTIME_UID}",
        "--mount", f"type=volume,source={stack.material['runtime']},"
        "target=/run/material,readonly,volume-nocopy",
        "-e", f"PGPASSWORD={stack.secrets['runtime_owner']}", "-e", f"PGOPTIONS={options}",
        "-e", "PGSSLROOTCERT=/run/material/postgres-ca.pem",
        *PSQL, TOOLS_IMAGE, "-X", "-v", "VERBOSITY=sqlstate", "-c", "SELECT pg_sleep(30)",
        "postgresql://runtime_owner@postgres:5432/sentryruntime?sslmode=verify-full",
        check=False,
    )  # fmt: skip
    assert run.returncode != 0 and "57014" in run.stderr
    assert 3.5 < time.monotonic() - started < 15


# --- reconciliation ------------------------------------------------------------


def test_reconcile_reports_exact_release_sessions_read_only(stack, released):
    tag = f"release:{stack.release_id}:runtime-grant"
    docker(
        "exec", "-d", "-e", f"PGAPPNAME={tag}", stack.postgres, "psql", "-X", "-U",
        "runtime_owner", "-d", "sentryruntime", "-c", "SELECT pg_sleep(30)",
    )  # fmt: skip
    proof_tag = f"release:{stack.release_id}:runtime-proof"
    docker(
        "exec", "-d", "-e", f"PGAPPNAME={proof_tag}", stack.postgres, "psql", "-X", "-U",
        "runtime_app", "-d", "sentryruntime", "-c", "SELECT pg_sleep(30)",
    )  # fmt: skip
    wait_for("tagged sessions", lambda: stack.backend(tag) and stack.backend(proof_tag))
    proof_pid = stack.backend(proof_tag)[0].split("|")[0]
    identity = stack.sql(
        "postgres",
        "SELECT pid || '|' || to_char(backend_start AT TIME ZONE 'UTC',"
        ' \'YYYY-MM-DD"T"HH24:MI:SS.US"Z"\') FROM pg_stat_activity'
        f" WHERE application_name = '{tag}'",
    )
    pid, backend_start = identity.split("|")
    try:
        run = stack.job("reconcile", "runtime")
    finally:
        stack.sql(
            "postgres", f"SELECT pg_terminate_backend({pid}), pg_terminate_backend({proof_pid})"
        )
    assert run.code == 0
    result = run.receipt["result"]
    assert result["release_sessions"] == "2" and result["schema"] == "goose:1,2,3"
    assert {
        "event": "session_observed",
        "pid": proof_pid,
        "backend_start": "unknown",
        "database": "sentryruntime",
        "principal": "runtime_app",
        "application_name": proof_tag,
        "state": "unknown",
    } in run.events
    assert {
        "event": "session_observed",
        "pid": pid,
        "backend_start": backend_start,
        "database": "sentryruntime",
        "principal": "runtime_owner",
        "application_name": tag,
        "state": "active",
    } in run.events


def test_receipts_are_unique_per_task_stream(stack, released):
    arns = {run.receipt["task_arn"] for run in released.values() if run.receipt}
    assert len(arns) == len(released)
    for run in released.values():
        assert sum(line.startswith(receipt.RECEIPT_MARKER) for line in run.stdout.splitlines()) == 1
