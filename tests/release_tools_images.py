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

from dev.tls_fixtures import create_certificates
from release_tools import digest, receipt, session
from tests.release_tools_privilege_cases import privilege_drifts

REPO = Path(__file__).resolve().parents[1]
# Keep aligned with tests/service_images.py and the SentryRuntime development image.
POSTGRES_IMAGE = (
    "docker.io/library/postgres:16-alpine@sha256:"
    "cf78e76683b9ca8c5733cbbdce6c9262b45b6767934dd0a95e671f9a0fc20685"
)
TOOLS_IMAGE = os.environ.get("RELEASE_TOOLS_TEST_IMAGE", "")
RUNTIME_IMAGE = os.environ.get("SENTRYRUNTIME_TEST_IMAGE", "")
SEARCH_IMAGE = os.environ.get("SENTRYSEARCH_TEST_IMAGE", "")
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
        principal = {"grant": owner, "reconcile": owner, "proof": service, "bootstrap": "postgres",
                     "rv-recon": owner, "rv-proof": service}  # fmt: skip
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
        if kind in {"proof", "rv-proof", "bootstrap"}:
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


def lock_waiter(stack: Stack, tag: str, *, freeze: bool = False, timeout: int = 60) -> list[str]:
    """``pid|user|database|ssl|sessions`` once a session tagged ``tag`` waits on a lock.

    ``sessions`` counts every session with that tag, waiting or not.

    The wait runs inside the server's container: polling from the host costs one
    ``docker exec`` per look, which a loaded host stretches past a job's three-second
    lock limit. With ``freeze`` the backend is stopped there, before any server-side
    limit can end its statement.
    """
    query = (
        "SELECT a.pid || '|' || a.usename || '|' || a.datname || '|' || s.ssl || '|' ||"
        f" (SELECT count(*) FROM pg_stat_activity WHERE application_name = '{tag}')"
        " FROM pg_stat_activity a JOIN pg_stat_ssl s USING (pid)"
        f" WHERE a.application_name = '{tag}' AND a.wait_event_type = 'Lock' LIMIT 1"
    )
    act = 'kill -STOP "${row%%|*}"; ' if freeze else ""
    script = (
        f"end=$(( $(date +%s) + {timeout} )); "
        "while [ $(date +%s) -lt $end ]; do "
        f'row=$(psql -X -U postgres -d postgres -tAc "{query}"); '
        f'if [ -n "$row" ]; then {act}echo "$row"; exit 0; fi; sleep 0.05; done; exit 1'
    )
    return (
        docker("exec", stack.postgres, "sh", "-c", script, timeout=timeout + 30)
        .stdout.strip()
        .split("|")
    )


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
    # Keep both real migration entry points inside the isolated network. Hosts
    # running Docker Desktop cannot route directly to the VM's bridge addresses.
    product_env = {
        "ENVIRONMENT": "production",
        "DB_HOST": "postgres",
        "DB_PORT": "5432",
        "DB_NAME": "sentrysearch",
        "DB_USER": "search_owner",
        "DB_PASSWORD": stack.secrets["search_owner"],
        "DB_SSLMODE": "verify-full",
        "DB_SSLROOTCERT": "/run/material/postgres-ca.pem",
    }
    env_file = stack.root / "product-migrate.env"
    env_file.write_text("".join(f"{key}={value}\n" for key, value in product_env.items()))
    env_file.chmod(0o600)
    docker(
        "run",
        "--rm",
        "--name",
        stack.name("product-migrate"),
        "--network",
        stack.network,
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--user",
        f"{PRODUCT_UID}:{PRODUCT_UID}",
        "--mount",
        f"type=volume,source={stack.material['product']},target=/run/material,readonly,volume-nocopy",
        "--env-file",
        str(env_file),
        SEARCH_IMAGE,
        "python",
        "-m",
        "dev.migrate_storage",
        timeout=180,
    )


@pytest.fixture(scope="module")
def stack() -> Iterator[Stack]:
    if not TOOLS_IMAGE or not RUNTIME_IMAGE or not SEARCH_IMAGE:
        pytest.fail(
            "RELEASE_TOOLS_TEST_IMAGE, SENTRYRUNTIME_TEST_IMAGE and SENTRYSEARCH_TEST_IMAGE are required"
        )
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


@pytest.mark.parametrize("database", ["runtime", "product"])
def test_proofs_reject_column_reads_and_delegation(stack, released, database):
    dbname, service = (
        ("sentryruntime", "runtime_app")
        if database == "runtime"
        else ("sentrysearch", "search_app")
    )
    for drift in privilege_drifts(database):
        stack.sql(dbname, drift.setup)
        try:
            # psql's -c mode also prints command tags for the delegation GRANT.
            assert (
                stack.sql(dbname, drift.exercise, user=service).splitlines()[-1] == drift.expected
            )
            run = stack.job("proof", database)
            assert run.code == 11, (drift.name, run.stdout, run.stderr)
            assert run.receipt["result"] == {
                "reason": "privilege_inventory_mismatch",
                "sql_outcome": "unknown",
            }
        finally:
            stack.sql(dbname, drift.cleanup)
        assert stack.job("proof", database).code == 0, drift.name


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
        lock_waiter(stack, tag, freeze=True)
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
        lock_waiter(stack, tag)
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


# --- restore verification: foreign sessions (F077, plan sections 13 RV2 and 15 RV4) -----


def held_session(stack: Stack, user: str, database: str, tag: str) -> str:
    """A session held open by another connection; returns its pid."""
    docker(
        "exec", "-d", "-e", f"PGAPPNAME={tag}", stack.postgres, "psql", "-X", "-U", user,
        "-d", database, "-c", "SELECT pg_sleep(60)",
    )  # fmt: skip
    wait_for(f"session {tag}", lambda: stack.backend(tag))
    return stack.backend(tag)[0].split("|")[0]


def end_sessions(stack: Stack, *pids: str) -> None:
    """Terminate the held sessions and wait (up to five seconds each) until they exit."""
    if pids:
        stack.sql("postgres", "SELECT " + ", ".join(f"pg_terminate_backend({pid}, 5000)"
                                                    for pid in pids))  # fmt: skip


def settled(stack: Stack) -> None:
    """No earlier test's client session is still leaving the Runtime database."""
    wait_for("earlier sessions to exit", lambda: stack.sql(
        "postgres", "SELECT count(*) FROM pg_stat_activity WHERE datname = 'sentryruntime'"
                    " AND backend_type = 'client backend'") == "0")  # fmt: skip


def rv_recon(stack: Stack) -> tuple[dict[str, str], list[dict]]:
    run = stack.job("rv-recon", "runtime")
    assert run.code == 0 and run.receipt is not None, run.stderr
    return run.receipt["result"], run.events


def test_a_restore_reconcile_with_only_its_own_session_counts_none(stack, released):
    settled(stack)
    result, _events = rv_recon(stack)
    assert result["foreign_sessions"] == "0"
    assert result["release_sessions"] == result["owner_sessions"] == "0"
    assert result["host"] == "postgres"


def test_a_held_service_login_is_a_foreign_session_listed_and_left_alone(stack, released):
    settled(stack)
    pid = held_session(stack, "runtime_app", "sentryruntime", "held-service")
    try:
        result, events = rv_recon(stack)
        assert result["foreign_sessions"] == "1"
        assert {"event": "session_observed", "pid": pid, "backend_start": "unknown",
                "database": "sentryruntime", "principal": "runtime_app",
                "application_name": "held-service", "state": "unknown"} in events  # fmt: skip
        assert stack.backend("held-service"), "the job terminated the session"
    finally:
        end_sessions(stack, pid)


def test_an_owner_session_counts_as_owner_and_foreign(stack, released):
    settled(stack)
    pid = held_session(stack, "runtime_owner", "sentryruntime", "held-owner")
    try:
        result, _events = rv_recon(stack)
        assert result["owner_sessions"] == "1" and result["foreign_sessions"] == "1"
    finally:
        end_sessions(stack, pid)


def test_another_releases_session_the_old_counters_miss_is_foreign(stack, released):
    settled(stack)
    tag = "release:11111111-2222-4333-8444-555555555555:x"
    pid = held_session(stack, "runtime_app", "sentryruntime", tag)
    try:
        result, _events = rv_recon(stack)
        assert result["release_sessions"] == "0" and result["foreign_sessions"] == "1"
    finally:
        end_sessions(stack, pid)


def test_the_bootstrap_superusers_session_is_not_foreign(stack, released):
    settled(stack)
    pid = held_session(stack, "postgres", "sentryruntime", "held-superuser")
    try:
        assert rv_recon(stack)[0]["foreign_sessions"] == "0"
    finally:
        end_sessions(stack, pid)


def test_a_session_in_another_database_of_the_instance_is_not_foreign(stack, released):
    settled(stack)
    pid = held_session(stack, "search_owner", "sentrysearch", "held-other-database")
    try:
        assert rv_recon(stack)[0]["foreign_sessions"] == "0"
    finally:
        end_sessions(stack, pid)


def test_the_forward_reconcile_on_the_same_stack_is_unchanged(stack, released):
    settled(stack)
    run = stack.job("reconcile", "runtime")
    assert run.code == 0 and run.receipt is not None
    assert run.receipt["result"] == {"database": "sentryruntime", "principal": "runtime_owner",
                                     "schema": "goose:1,2,3", "release_sessions": "0",
                                     "owner_sessions": "0"}  # fmt: skip
    assert not [event for event in run.events if event["event"] == "session_observed"]


# RV4 (plan section 15): the predicate counts login sessions only. A fixture view that
# shadows pg_stat_activity gives the unmodified program each row shape at once.
FIXTURE_SCHEMA = "rv4_fixture"
FIXTURE_ROWS = """
    (900001, timestamptz '2026-10-18 00:00:01+00', 'sentryruntime'::name, NULL::oid,
     NULL::name, ''::text, NULL::text),
    (900002, timestamptz '2026-10-18 00:00:02+00', 'sentryruntime', 10::oid,
     'postgres', 'psql', 'idle'),
    (900003, timestamptz '2026-10-18 00:00:03+00', 'sentryruntime',
     'runtime_app'::regrole::oid, 'runtime_app', 'held-service', NULL),
    (900004, timestamptz '2026-10-18 00:00:04+00', 'sentryruntime',
     'runtime_owner'::regrole::oid, 'runtime_owner', 'held-owner', 'idle'),
    (900005, timestamptz '2026-10-18 00:00:05+00', 'sentryruntime',
     'runtime_app'::regrole::oid, 'runtime_app',
     'release:11111111-2222-4333-8444-555555555555:x', NULL),
    (900006, timestamptz '2026-10-18 00:00:06+00', 'sentrysearch',
     'search_owner'::regrole::oid, 'search_owner', 'psql', 'idle')
"""


def test_the_restore_program_counts_only_login_sessions_in_its_database(stack, released):
    # Rows: (1) an engine worker without a user (the autovacuum shape), (2) the
    # bootstrap superuser, (3) the service login, (4) the owner, (5) the service login
    # tagged as another release, (6) a login in another database. Only 3, 4 and 5 count.
    stack.sql("sentryruntime", f"CREATE SCHEMA {FIXTURE_SCHEMA}", user="runtime_owner")
    try:
        stack.sql("sentryruntime", f"CREATE VIEW {FIXTURE_SCHEMA}.pg_stat_activity"
                  " (pid, backend_start, datname, usesysid, usename, application_name, state)"
                  f" AS VALUES {FIXTURE_ROWS}", user="runtime_owner")  # fmt: skip
        program = (REPO / "release_tools/sql/restore_sessions.sql").read_text()
        # The unmodified file through psql as the owner; pg_catalog later in the path
        # lets the fixture schema shadow the view.
        run = docker(
            "exec", "-i", "-e", f"PGOPTIONS=-c search_path={FIXTURE_SCHEMA},pg_catalog",
            stack.postgres, "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-U", "runtime_owner",
            "-d", "sentryruntime", "-tA", "-f", "-", stdin=program,
        )  # fmt: skip
    finally:
        stack.sql("sentryruntime", f"DROP SCHEMA {FIXTURE_SCHEMA} CASCADE", user="runtime_owner")
    lines = [line for line in run.stdout.splitlines() if line]
    assert [line for line in lines if line.startswith("result|")] == ["result|foreign_sessions|3"]
    assert [line for line in lines if line.startswith("session|")] == [
        "session|900003|2026-10-18T00:00:03.000000Z|sentryruntime|runtime_app|held-service|unknown",
        "session|900004|2026-10-18T00:00:04.000000Z|sentryruntime|runtime_owner|held-owner|idle",
        "session|900005|2026-10-18T00:00:05.000000Z|sentryruntime|runtime_app|"
        "release:11111111-2222-4333-8444-555555555555:x|unknown",
    ]


def test_engine_processes_carry_no_user_in_the_owners_view(stack, released):
    # The live catalog, read as the owner: processes without a user exist, show no user
    # name, and those of the launcher, checkpointer and writers have no database. This
    # proves the representation; the fixture view above proves the same-database case.
    def owner(statement: str) -> str:
        return stack.sql("sentryruntime", statement, user="runtime_owner")

    assert int(owner("SELECT count(*) FROM pg_stat_activity WHERE usesysid IS NULL"
                     " AND usename IS NULL AND datname IS NULL")) >= 1  # fmt: skip
    assert owner("SELECT count(*) FROM pg_stat_activity"
                 " WHERE usesysid IS NULL AND usename IS NOT NULL") == "0"  # fmt: skip
    # The superuser sees which processes those are: never a client backend.
    assert stack.sql("postgres", "SELECT count(*) FROM pg_stat_activity"
                     " WHERE usesysid IS NULL AND backend_type = 'client backend'") == "0"  # fmt: skip


def test_receipts_are_unique_per_task_stream(stack, released):
    arns = {run.receipt["task_arn"] for run in released.values() if run.receipt}
    assert len(arns) == len(released)
    for run in released.values():
        assert sum(line.startswith(receipt.RECEIPT_MARKER) for line in run.stdout.splitlines()) == 1


# --- migration release jobs in their own images --------------------------------

VERSION_TABLES = {
    "runtime": ("sentryruntime", "public.goose_db_version"),
    "product": ("sentrysearch", "public.sentrysearch_schema_migrations"),
}


def migration_environment(
    stack: Stack, database: str, name: str, **overrides: str
) -> dict[str, str]:
    """The migration release job's settings exactly as deploy/aws-platform-fit sets them."""
    dbname, _ = VERSION_TABLES[database]
    owner = "runtime_owner" if database == "runtime" else "search_owner"
    values = {
        "RELEASE_ID": stack.release_id,
        "RELEASE_JOB_ID": f"{database}-migrate",
        "RELEASE_NOT_AFTER": stamp(datetime.now(UTC) + timedelta(minutes=10)),
        "RELEASE_JOB_BUDGET_SECONDS": "600",
        "RELEASE_EXPECT_DATABASE": dbname,
        "RELEASE_EXPECT_PRINCIPAL": owner,
        "ECS_CONTAINER_METADATA_URI_V4": f"http://{METADATA_IP}/v4/{name}",
    }
    if database == "runtime":
        values["SENTRYRUNTIME_MIGRATIONS_DIRECTORY"] = "/app/db/migrations"
        values["DATABASE_URL"] = (
            f"postgres://{owner}:{stack.secrets[owner]}@postgres:5432/{dbname}"
            "?sslmode=verify-full&sslrootcert=/run/material/postgres-ca.pem"
        )
    else:
        values.update(
            ENVIRONMENT="staging", DB_HOST="postgres", DB_PORT="5432", DB_NAME=dbname,
            DB_USER=owner, DB_PASSWORD=stack.secrets[owner], DB_SSLMODE="verify-full",
            DB_SSLROOTCERT="/run/material/postgres-ca.pem", DB_DEBUG="false",
            PYTHON_DOTENV_DISABLED="1",
        )  # fmt: skip
    values.update(overrides)
    return values


def start_migration(stack: Stack, database: str, **overrides: str) -> str:
    """Run the real migrator's release-job mode in its own image, as the owner uid."""
    name = stack.name(f"{database}-migrate-job")
    env_file = stack.root / f"{name}.env"
    env = migration_environment(stack, database, name, **overrides)
    env_file.write_text("".join(f"{key}={value}\n" for key, value in env.items()))
    env_file.chmod(0o600)
    uid = RUNTIME_UID if database == "runtime" else PRODUCT_UID
    command = (
        [RUNTIME_IMAGE, "/app/migrate", "-release-job"]
        if database == "runtime"
        else [SEARCH_IMAGE, "python", "-m", "dev.migrate_storage", "--release-job"]
    )
    docker(
        "run", "-d", "--name", name, "--network", stack.network, "--read-only",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", f"{uid}:{uid}",
        "--stop-timeout", "30", "--mount",
        f"type=volume,source={stack.material[database]},target=/run/material,readonly,volume-nocopy",
        "--env-file", str(env_file), *command,
    )  # fmt: skip
    return name


def migration_receipt(run: JobRun) -> dict:
    document = receipt.parse_receipt(run.stdout.splitlines(), "migration")
    assert document is not None, (run.code, run.stdout, run.stderr)
    return document


def connections_tagged(stack: Stack, tag: str) -> int:
    """Server log lines from sessions that started with this application name.

    The server logs the name once start-up has read it, so this counts sessions,
    not TCP attempts abandoned before start-up.
    """
    return sum(f"app={tag} " in line for line in stack.server_log().splitlines())


@pytest.mark.parametrize("database", ["runtime", "product"])
def test_migration_release_job_receipt_names_the_proofs_schema(stack, released, database):
    started = time.monotonic()
    name = start_migration(stack, database)
    run = stack.finish(name, started, timeout=180)
    assert run.code == 0, (run.stdout, run.stderr)
    dbname, _ = VERSION_TABLES[database]
    assert migration_receipt(run) == {
        "schema": "sentry.release-migration.v1",
        "release_id": stack.release_id,
        "job_id": f"{database}-migrate",
        "task_arn": task_arn(name),
        "status": "succeeded",
        "result": {
            "database": dbname,
            "principal": "runtime_owner" if database == "runtime" else "search_owner",
            # The schema the migrator applied is exactly what the proof observed.
            "schema": released[f"{database}-proof"].receipt["result"]["schema"],
        },
    }
    assert not stack.backend(f"release:{stack.release_id}:{database}-migrate")
    # The positive control for the refusal case's "no connection" check.
    assert connections_tagged(stack, f"release:{stack.release_id}:{database}-migrate") >= 1


@pytest.mark.parametrize("database", ["runtime", "product"])
def test_migration_release_job_without_time_for_a_statement_never_connects(
    stack, released, database
):
    # The deadline is checked before the task identity is read, so there is no
    # ARN to bind a receipt to: the job refuses with its event only. The
    # controller holds on the nonzero exit (job_container_failed).
    release_id = str(uuid.uuid4())
    tag = f"release:{release_id}:{database}-migrate"
    started = time.monotonic()
    name = start_migration(
        stack, database, RELEASE_ID=release_id,
        RELEASE_NOT_AFTER=stamp(datetime.now(UTC) + timedelta(seconds=6)),
    )  # fmt: skip
    run = stack.finish(name, started)
    assert run.code == 4, (run.stdout, run.stderr)
    assert run.stdout == ""
    assert {
        "event": "job_failed",
        "reason": "deadline_expired",
        "sql_outcome": "none",
        "exit_code": "4",
        "release_id": release_id,
        "job_id": f"{database}-migrate",
    } in run.events
    assert connections_tagged(stack, tag) == 0


def _hold_version_table(stack: Stack, database: str) -> subprocess.Popen[str]:
    """An open transaction holding the migrator's version table exclusively."""
    dbname, table = VERSION_TABLES[database]
    holder = subprocess.Popen(
        ["docker", "exec", "-i", stack.postgres, "psql", "-X", "-U", "postgres", "-d", dbname,
         "-v", "ON_ERROR_STOP=1"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )  # fmt: skip
    assert holder.stdin is not None
    holder.stdin.write(f"BEGIN; LOCK TABLE {table} IN ACCESS EXCLUSIVE MODE; SELECT 'locked';\n")
    holder.stdin.flush()
    wait_for(
        "version table lock",
        lambda: stack.sql(
            dbname,
            f"SELECT count(*) FROM pg_locks WHERE relation = '{table}'::regclass"
            " AND mode = 'AccessExclusiveLock' AND granted",
        )
        == "1",
    )
    return holder


@pytest.mark.parametrize("database", ["runtime", "product"])
def test_migration_release_job_stops_on_sigterm_with_its_verified_session_gone(
    stack, released, database
):
    dbname, _ = VERSION_TABLES[database]
    owner = "runtime_owner" if database == "runtime" else "search_owner"
    tag = f"release:{stack.release_id}:{database}-migrate"
    holder = _hold_version_table(stack, database)
    started = time.monotonic()
    name = start_migration(stack, database)
    try:
        # One session, the expected owner on the expected database, over TLS.
        _, *identity, sessions = lock_waiter(stack, tag)
        stopped = time.monotonic()
        docker("kill", "--signal", "SIGTERM", name)
        run = stack.finish(name, started)
        assert time.monotonic() - stopped < 8
    finally:
        _release(holder)
    assert (identity, sessions) == ([owner, dbname, "true"], "1")
    assert run.code == 143, (run.stdout, run.stderr)
    document = migration_receipt(run)
    assert (document["task_arn"], document["status"]) == (task_arn(name), "failed")
    assert document["result"] == {"reason": "terminated", "sql_outcome": "unknown"}
    wait_for("terminated migration backend to exit", lambda: not stack.backend(tag), timeout=15)


@pytest.mark.parametrize("database", ["runtime", "product"])
def test_migration_release_job_reaching_its_deadline_mid_statement_exits_124(
    stack, released, database
):
    """A hung session: nobody stops the task, and its own deadline ends it.

    The blocked backend is frozen, so no server-side limit can end the statement
    first; only the job's watchdog can.
    """
    tag = f"release:{stack.release_id}:{database}-migrate"
    holder = _hold_version_table(stack, database)
    not_after = datetime.now(UTC) + timedelta(seconds=16)
    started = time.monotonic()
    name = start_migration(stack, database, RELEASE_NOT_AFTER=stamp(not_after))
    try:
        lock_waiter(stack, tag, freeze=True)
        run = stack.finish(name, started)
        assert datetime.now(UTC) <= not_after + timedelta(seconds=3)
    finally:
        for row in stack.backend(tag):
            docker("exec", stack.postgres, "kill", "-CONT", row.split("|")[0], check=False)
        _release(holder)
    assert run.code == 124, (run.stdout, run.stderr)
    document = migration_receipt(run)
    assert (document["task_arn"], document["status"]) == (task_arn(name), "failed")
    assert document["result"] == {"reason": "deadline_exceeded", "sql_outcome": "unknown"}
    wait_for("abandoned migration backend to exit", lambda: not stack.backend(tag), timeout=15)
