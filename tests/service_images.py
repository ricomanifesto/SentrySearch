"""Explicit container suite; run with dev/check_service_images.py.

Every container joins one internal Docker network with no outbound route. The
product and runtime databases use verified TLS, the runtime uses verified HTTPS
with scoped tokens, and the model provider is a local stub that never answers.
All secrets and certificates are generated per run and discarded.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tarfile
import tempfile
import time
import uuid

import pytest

from dev.tls_fixtures import create_certificates

REPO = Path(__file__).resolve().parents[1]
# Keep aligned with the SentryRuntime development database image.
POSTGRES_IMAGE = (
    "docker.io/library/postgres:16-alpine@sha256:"
    "cf78e76683b9ca8c5733cbbdce6c9262b45b6767934dd0a95e671f9a0fc20685"
)
SEARCH_IMAGE = os.environ.get("SENTRYSEARCH_TEST_IMAGE", "")
RUNTIME_IMAGE = os.environ.get("SENTRYRUNTIME_TEST_IMAGE", "")
WORKER = ["python", "-m", "dev.run_runtime_worker", "--health-port", "8081"]
FAST_WORKER = [*WORKER, "--poll-seconds", "1", "--lease-seconds", "5", "--drain-seconds", "3"]
API = ["python", "/app/run_api.py"]
RELEASE = ["python", "-m", "dev.migrate_storage"]
CHECK = [*RELEASE, "--check"]
APP_TABLES = (
    "reports, report_runtime_dispatches, report_disposition_events, report_searches, report_tags"
)

LOCAL_PROBE = (
    "import http.client,sys\n"
    "c=http.client.HTTPConnection('127.0.0.1',int(sys.argv[1]),timeout=3)\n"
    "c.request('GET',sys.argv[2]);r=c.getresponse()\n"
    "print(r.status);print(r.read().decode())"
)
# Documented exec readiness probe in docs/service-images.md; keep the two aligned.
WORKER_READINESS_PROBE = (
    "import http.client as h;c=h.HTTPConnection('127.0.0.1',8081,timeout=2);"
    "c.request('GET','/readyz');raise SystemExit(c.getresponse().status!=200)"
)
RUNTIME_GET = (
    "import http.client,ssl,sys\n"
    "ctx=ssl.create_default_context(cafile='/run/trust/runtime-ca.pem')\n"
    "c=http.client.HTTPSConnection('runtime',8443,context=ctx,timeout=5)\n"
    "c.request('GET',sys.argv[1],headers={'Authorization':'Bearer '+sys.stdin.read().strip()})\n"
    "r=c.getresponse();print(r.status);print(r.read().decode())"
)
PROVIDER_STUB = (
    "import socket\n"
    "server=socket.create_server(('0.0.0.0',9000))\n"
    "print('provider stub listening',flush=True)\n"
    "held=[]\n"
    "while True:\n"
    "    held.append(server.accept()[0])\n"
    "    print('provider stub accepted a connection',flush=True)\n"
)


def docker(
    *args: str, check: bool = True, timeout: float = 120, stdin: str | None = None
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout, input=stdin
    )
    if check and result.returncode:
        raise AssertionError(f"docker {args[0]} exited {result.returncode}: {result.stderr}")
    return result


@dataclass
class Stack:
    network: str
    root: Path
    secrets: dict[str, str]
    containers: list[str] = field(default_factory=list)
    hostnames: dict[str, str] = field(default_factory=dict)
    provider: str = ""

    @property
    def trust(self) -> Path:
        return self.root / "trust"

    def name(self, role: str) -> str:
        name = f"{self.network}-{role}-{uuid.uuid4().hex[:6]}"
        self.containers.append(name)
        self.hostnames[name] = role
        return name

    def psql(self, database: str, sql: str) -> str:
        return docker(
            "exec",
            f"{self.network}-postgres",
            "psql",
            "-v",
            "ON_ERROR_STOP=1",
            "-U",
            "postgres",
            "-d",
            database,
            "-tAc",
            sql,
        ).stdout.strip()

    def product_env(self, *, role: str = "app", database: str = "sentrysearch") -> dict[str, str]:
        return {
            "ENVIRONMENT": "staging",
            "DB_HOST": "postgres",
            "DB_PORT": "5432",
            "DB_NAME": database,
            "DB_USER": f"search_{role}",
            "DB_PASSWORD": self.secrets[f"search_{role}"],
            "DB_SSLMODE": "verify-full",
            "DB_SSLROOTCERT": "/run/trust/postgres-ca.pem",
            "DB_DEBUG": "false",
            "AWS_S3_BUCKET": "image-check-bucket",
            "AWS_REGION": "us-east-1",
            # Non-empty disposable values only satisfy SDK resolution; no route exists.
            "AWS_ACCESS_KEY_ID": "image-check-access-key",
            "AWS_SECRET_ACCESS_KEY": self.secrets["aws"],
            "AWS_EC2_METADATA_DISABLED": "true",
            "SENTRYSEARCH_EXECUTION_MODE": "runtime",
            "SENTRYRUNTIME_URL": "https://runtime:8443",
            "SENTRYRUNTIME_CA_FILE": "/run/trust/runtime-ca.pem",
        }

    def worker_env(self) -> dict[str, str]:
        return {
            **self.product_env(),
            "SENTRYRUNTIME_PRODUCER_TOKEN": self.secrets["producer"],
            "SENTRYRUNTIME_WORKER_TOKEN": self.secrets["worker"],
            "OPENROUTER_API_KEY": self.secrets["provider"],
            "OPENROUTER_BASE_URL": "http://provider:9000/api/v1",
        }

    def run(
        self,
        image: str,
        name: str,
        env: dict[str, str],
        command: list[str],
        *,
        detach: bool,
        options: tuple[str, ...] = (),
        stdin: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env_file = self.root / f"{name}.env"
        env_file.write_text("".join(f"{key}={value}\n" for key, value in env.items()))
        env_file.chmod(0o600)
        scratch = "/var/lib/sentrysearch:uid=10001,gid=10001,mode=0700"
        hardening = ("--read-only", "--tmpfs", "/tmp", "--tmpfs", scratch, "--cap-drop", "ALL")
        return docker(
            "run",
            "-d" if detach else "--rm",
            *(("-i",) if stdin is not None else ()),
            "--name",
            name,
            "--hostname",
            self.hostnames[name],
            "--network",
            self.network,
            *hardening,
            "--security-opt",
            "no-new-privileges",
            "--env-file",
            str(env_file),
            "-v",
            f"{self.trust}:/run/trust:ro",
            *options,
            image,
            *command,
            check=detach,
            stdin=stdin,
            timeout=180,
        )

    def assert_no_secrets(self, output: str) -> None:
        for secret in self.secrets.values():
            assert secret not in output, "container output exposed a disposable secret"

    def runtime_get(self, path: str) -> tuple[int, dict]:
        result = self.run(
            SEARCH_IMAGE,
            self.name("probe"),
            {},
            ["python", "-c", RUNTIME_GET, path],
            detach=False,
            stdin=self.secrets["producer"],
        )
        status, body = result.stdout.split("\n", 1)
        return int(status), json.loads(body)


def logs(name: str) -> str:
    result = docker("logs", name, check=False)
    return result.stdout + result.stderr


def wait_for(description: str, predicate, *, timeout: float = 60, container: str = "") -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        if (
            container
            and docker("inspect", "--format", "{{.State.Running}}", container).stdout.strip()
            != "true"
        ):
            raise AssertionError(f"{container} exited before {description}:\n{logs(container)}")
        time.sleep(0.25)
    raise AssertionError(f"timed out waiting for {description}:\n{logs(container)}")


def local_probe(name: str, path: str) -> tuple[int, dict]:
    result = docker("exec", name, "python", "-c", LOCAL_PROBE, "8081", path, check=False)
    if result.returncode:
        return 0, {}
    status, body = result.stdout.split("\n", 1)
    return int(status), json.loads(body)


def stop(name: str, *, timeout: float = 30) -> tuple[int, float]:
    started = time.monotonic()
    docker("kill", "--signal", "SIGTERM", name)
    code = int(docker("wait", name, timeout=timeout).stdout.strip())
    return code, time.monotonic() - started


def _certificates(stack: Stack) -> None:
    stack.trust.mkdir(mode=0o755)
    for name, host in (("postgres", "postgres"), ("runtime", "runtime"), ("wrong", "postgres")):
        cert = create_certificates(stack.root / name, hostname=host)
        shutil.copy(cert.ca, stack.trust / f"{name}-ca.pem")
        if name != "wrong":
            # Disposable material readable by non-root service users; never real keys.
            for path in (cert.certificate, cert.key):
                path.chmod(0o644)
            (stack.root / name).chmod(0o755)
    for path in stack.trust.iterdir():
        path.chmod(0o644)


def _start_postgres(stack: Stack) -> None:
    name = f"{stack.network}-postgres"
    stack.containers.append(name)
    docker(
        "run",
        "-d",
        "--name",
        name,
        "--network",
        stack.network,
        "--network-alias",
        "postgres",
        "-e",
        f"POSTGRES_PASSWORD={stack.secrets['postgres']}",
        "-v",
        f"{stack.root / 'postgres'}:/tls-source:ro",
        "--entrypoint",
        "sh",
        POSTGRES_IMAGE,
        "-c",
        "install -o postgres -g postgres -m 0600 /tls-source/server-key.pem /var/lib/postgresql/server.key"
        " && install -o postgres -g postgres -m 0644 /tls-source/server.pem /var/lib/postgresql/server.crt"
        " && exec docker-entrypoint.sh postgres -c ssl=on"
        " -c ssl_cert_file=/var/lib/postgresql/server.crt -c ssl_key_file=/var/lib/postgresql/server.key",
    )
    wait_for(
        "PostgreSQL",
        lambda: docker(
            "exec", name, "pg_isready", "-h", "127.0.0.1", "-U", "postgres", check=False
        ).returncode
        == 0,
        container=name,
    )
    for role in ("runtime_owner", "runtime_app", "search_release", "search_app"):
        stack.psql("postgres", f"CREATE ROLE {role} LOGIN PASSWORD '{stack.secrets[role]}'")
    stack.psql("postgres", "CREATE DATABASE sentryruntime OWNER runtime_owner")
    for database in ("sentrysearch", "release_proof", "unreleased"):
        stack.psql("postgres", f"CREATE DATABASE {database} OWNER search_release")


def release(stack: Stack, database: str) -> None:
    result = stack.run(
        SEARCH_IMAGE,
        stack.name("release"),
        stack.product_env(role="release", database=database),
        RELEASE,
        detach=False,
    )
    assert result.returncode == 0 and "Storage schema ready" in result.stdout, result.stderr
    stack.psql(database, "GRANT USAGE ON SCHEMA public TO search_app")
    stack.psql(database, f"GRANT SELECT, INSERT, UPDATE, DELETE ON {APP_TABLES} TO search_app")
    stack.psql(database, "GRANT SELECT ON sentrysearch_schema_migrations TO search_app")


@pytest.fixture(scope="module")
def stack() -> Iterator[Stack]:
    if not SEARCH_IMAGE or not RUNTIME_IMAGE:
        pytest.fail("SENTRYSEARCH_TEST_IMAGE and SENTRYRUNTIME_TEST_IMAGE are required")
    names = (
        "postgres",
        "runtime_owner",
        "runtime_app",
        "search_release",
        "search_app",
        "producer",
        "worker",
        "provider",
        "aws",
    )
    with tempfile.TemporaryDirectory(prefix="service-images-") as directory:
        root = Path(directory)
        root.chmod(0o755)
        stack = Stack(
            network="search-images-" + uuid.uuid4().hex[:8],
            root=root,
            secrets={name: secrets.token_hex(24) for name in names},
        )
        docker("network", "create", "--internal", stack.network)
        try:
            _certificates(stack)
            _start_postgres(stack)
            runtime_db = (
                f"postgres://runtime_owner:{stack.secrets['runtime_owner']}@postgres:5432/"
                "sentryruntime?sslmode=verify-full&sslrootcert=/run/trust/postgres-ca.pem"
            )
            migrated = stack.run(
                RUNTIME_IMAGE,
                stack.name("runtime-migrate"),
                {"DATABASE_URL": runtime_db},
                ["/app/migrate"],
                detach=False,
            )
            assert migrated.returncode == 0, migrated.stderr
            # Exercise the runtime's canonical operator script as its DDL owner,
            # then serve under a distinct login that cannot migrate or rewrite events.
            grants = Path(os.environ["SENTRYRUNTIME_TEST_REPO"]) / "db/roles/service.sql"
            docker(
                "exec",
                "-i",
                f"{stack.network}-postgres",
                "psql",
                "-X",
                "-v",
                "ON_ERROR_STOP=1",
                "-v",
                "database_name=sentryruntime",
                "-v",
                "service_role=runtime_app",
                "-U",
                "runtime_owner",
                "-d",
                "sentryruntime",
                stdin=grants.read_text(),
            )
            runtime_db = (
                f"postgres://runtime_app:{stack.secrets['runtime_app']}@postgres:5432/"
                "sentryruntime?sslmode=verify-full&sslrootcert=/run/trust/postgres-ca.pem"
            )
            credentials = [
                {
                    "token_sha256": hashlib.sha256(stack.secrets[role].encode()).hexdigest(),
                    "role": role,
                    "product": "sentrysearch",
                    "workflow_name": "generate_report",
                    "workflow_version": "v1",
                }
                for role in ("producer", "worker")
            ]
            runtime = stack.name("runtime")
            stack.run(
                RUNTIME_IMAGE,
                runtime,
                {
                    "DATABASE_URL": runtime_db,
                    "SENTRYRUNTIME_LISTEN_ADDRESS": "0.0.0.0:8443",
                    "SENTRYRUNTIME_AUTH_MODE": "token",
                    "SENTRYRUNTIME_AUTH_CREDENTIALS": json.dumps(credentials),
                    "SENTRYRUNTIME_TLS_CERT_FILE": "/run/tls/server.pem",
                    "SENTRYRUNTIME_TLS_KEY_FILE": "/run/tls/server-key.pem",
                },
                [],
                detach=True,
                options=("--network-alias", "runtime", "-v", f"{root / 'runtime'}:/run/tls:ro"),
            )
            wait_for("runtime", lambda: "runtime listening" in logs(runtime), container=runtime)
            provider = stack.provider = stack.name("provider")
            stack.run(
                SEARCH_IMAGE,
                provider,
                {},
                ["python", "-c", PROVIDER_STUB],
                detach=True,
                options=("--network-alias", "provider"),
            )
            wait_for("provider stub", lambda: "listening" in logs(provider), container=provider)
            release(stack, "sentrysearch")
            yield stack
        finally:
            for name in reversed(stack.containers):
                docker("rm", "-f", "-v", name, check=False)
            docker("network", "rm", stack.network, check=False)


def test_image_contract_ships_only_root_owned_release_files():
    if not SEARCH_IMAGE:
        pytest.fail("SENTRYSEARCH_TEST_IMAGE is required")
    config = json.loads(
        docker("image", "inspect", "--format", "{{json .Config}}", SEARCH_IMAGE).stdout
    )
    assert config["User"] == "10001:10001"
    assert config["Entrypoint"] == ["/usr/local/bin/tini", "--"]
    assert not config.get("Cmd"), "each service must choose its role command"
    assert config["WorkingDir"] == "/var/lib/sentrysearch"
    assert "PYTHON_DOTENV_DISABLED=1" in config["Env"]
    baked = {entry.split("=", 1)[0] for entry in config["Env"]}
    assert not {
        name
        for name in baked
        if name.startswith(("DB_", "AWS_", "OPENROUTER_", "SUPABASE_", "SENTRYRUNTIME_"))
    }

    container = docker("create", SEARCH_IMAGE).stdout.strip()
    try:
        with tempfile.TemporaryFile() as archive:
            subprocess.run(["docker", "export", container], stdout=archive, check=True)
            archive.seek(0)
            members = {}
            with tarfile.open(fileobj=archive) as image:
                for member in image:
                    if member.isfile():
                        assert member.mode & 0o6000 == 0, member.name
                    if member.name == "var/lib/sentrysearch/":
                        assert (member.uid, member.gid, member.mode) == (10001, 10001, 0o700)
                    elif member.name.startswith("var/lib/sentrysearch/"):
                        raise AssertionError(f"scratch directory is not empty: {member.name}")
                    if member.name.startswith("app/") or member.name == "usr/local/bin/tini":
                        if not member.issym():
                            assert member.uid == 0 and member.gid == 0, member.name
                            assert member.mode & 0o022 == 0, member.name
                        if member.isfile():
                            data = image.extractfile(member)
                            assert data is not None
                            members[member.name] = hashlib.sha256(data.read()).hexdigest()
    finally:
        docker("rm", container)

    tracked = subprocess.run(
        ["git", "ls-files", "src", "certs"], cwd=REPO, capture_output=True, text=True, check=True
    ).stdout.split()
    expected = {f"app/{path}" for path in [*tracked, "run_api.py"]} | {
        "app/dev/run_runtime_worker.py",
        "app/dev/migrate_storage.py",
        "app/dev/prepare_service_volumes.py",
    }
    shipped = {name for name in members if name.startswith("app/") and "/.venv/" not in name}
    assert shipped == expected
    for name in expected:
        assert members[name] == hashlib.sha256((REPO / name[4:]).read_bytes()).hexdigest(), name
    assert "usr/local/bin/tini" in members
    assert not any(Path(name).name.startswith(".env") for name in members)


def test_release_image_has_no_installers_or_vendored_build_tools():
    # Check the application environment AND the global base interpreter. Removing
    # a vulnerable vendored copy from only one of them leaves it in the image.
    for interpreter in ("/app/.venv/bin/python", "/usr/local/bin/python"):
        result = docker(
            "run",
            "--rm",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            SEARCH_IMAGE,
            interpreter,
            "-c",
            "import importlib.util; "
            "names=('pip','setuptools','pkg_resources','wheel','ensurepip'); "
            "present=[name for name in names if importlib.util.find_spec(name)]; "
            "assert not present, present",
            check=False,
        )
        assert result.returncode == 0, result.stderr


def test_invalid_configuration_fails_closed_without_exposing_secrets(stack: Stack):
    plaintext = {**stack.product_env(), "ENVIRONMENT": "production", "DB_SSLMODE": "disable"}
    plaintext.pop("DB_SSLROOTCERT")
    untrusted = {**stack.product_env(), "DB_SSLROOTCERT": "/run/trust/wrong-ca.pem"}
    local_remote = {**stack.worker_env(), "SENTRYRUNTIME_LOCAL_URL": "http://runtime:8443"}
    local_remote.pop("SENTRYRUNTIME_URL")
    local_remote.pop("SENTRYRUNTIME_CA_FILE")
    shared_token = {**stack.worker_env(), "SENTRYRUNTIME_WORKER_TOKEN": stack.secrets["producer"]}
    cases = [
        ("deployed plaintext database", plaintext, CHECK, "Storage release check failed"),
        (
            "application role cannot release",
            stack.product_env(database="unreleased"),
            RELEASE,
            "Storage release check failed",
        ),
        (
            "unreleased schema",
            stack.product_env(database="unreleased"),
            API,
            "Storage schema unavailable or incompatible",
        ),
        ("untrusted database CA", untrusted, API, "Storage schema unavailable or incompatible"),
        ("plaintext non-loopback runtime", local_remote, WORKER, "worker_error"),
        ("shared runtime credentials", shared_token, WORKER, "worker_error"),
    ]
    for description, env, command, message in cases:
        result = stack.run(SEARCH_IMAGE, stack.name("negative"), env, command, detach=False)
        output = result.stdout + result.stderr
        assert result.returncode != 0, description
        assert message in output, f"{description}:\n{output}"
        assert "Application startup complete" not in output, description
        stack.assert_no_secrets(output)


def test_untrusted_runtime_certificate_keeps_worker_unready(stack: Stack):
    worker = stack.name("worker-untrusted")
    env = {**stack.worker_env(), "SENTRYRUNTIME_CA_FILE": "/run/trust/wrong-ca.pem"}
    stack.run(SEARCH_IMAGE, worker, env, FAST_WORKER, detach=True)
    wait_for(
        "runtime trust failure",
        lambda: local_probe(worker, "/status")[1].get("error_code") == "runtime_unavailable",
        container=worker,
    )
    assert local_probe(worker, "/readyz")[0] == 503
    # Drain is clean, but the unresolved runtime error remains the exit status.
    assert stop(worker)[0] == 1
    stack.assert_no_secrets(logs(worker))


def test_release_job_separates_schema_owner_from_application_role(stack: Stack):
    app = stack.product_env(database="release_proof")
    checked = stack.run(SEARCH_IMAGE, stack.name("check"), app, CHECK, detach=False)
    assert checked.returncode == 1 and "Storage release check failed" in checked.stderr
    release(stack, "release_proof")
    release(stack, "release_proof")  # An applied revision is checked, not reapplied.
    checked = stack.run(SEARCH_IMAGE, stack.name("check"), app, CHECK, detach=False)
    assert checked.returncode == 0 and "Storage schema ready" in checked.stdout
    denied = docker(
        "exec",
        "-e",
        f"PGPASSWORD={stack.secrets['search_app']}",
        f"{stack.network}-postgres",
        "psql",
        "-h",
        "127.0.0.1",
        "-U",
        "search_app",
        "-d",
        "release_proof",
        "-c",
        "CREATE TABLE forbidden(id int)",
        check=False,
    )
    assert denied.returncode != 0 and "permission denied" in denied.stderr


def test_runtime_service_role_cannot_migrate_or_rewrite_history(stack: Stack):
    for statement in (
        "CREATE TABLE public.forbidden(id int)",
        "UPDATE runtime_run_events SET actor_id='forbidden'",
        "DELETE FROM runtime_runs",
        "UPDATE goose_db_version SET is_applied=false",
    ):
        result = docker(
            "exec",
            f"{stack.network}-postgres",
            "psql",
            "-X",
            "-v",
            "ON_ERROR_STOP=1",
            "-U",
            "runtime_app",
            "-d",
            "sentryruntime",
            "-c",
            statement,
            check=False,
        )
        assert result.returncode != 0 and "permission denied" in result.stderr


def test_api_serves_readiness_and_stops_gracefully_on_sigterm(stack: Stack):
    api = stack.name("api")
    stack.run(SEARCH_IMAGE, api, stack.product_env(), API, detach=True)
    wait_for("API startup", lambda: "Application startup complete" in logs(api), container=api)
    probe = (
        "import http.client,json\n"
        "c=http.client.HTTPConnection('127.0.0.1',8001,timeout=3);c.request('GET','/api/ready')\n"
        "r=c.getresponse();print(r.status, json.loads(r.read())['schema'])"
    )
    assert docker("exec", api, "python", "-c", probe).stdout.split() == ["200", "compatible"]
    code, elapsed = stop(api)
    output = logs(api)
    # Uvicorn completes graceful shutdown, then re-raises SIGTERM: 128 + 15.
    assert code == 143 and elapsed < 10, output
    assert "Application shutdown complete" in output and "Finished server process" in output
    stack.assert_no_secrets(output)


def test_idle_worker_is_ready_runs_as_non_root_and_drains_on_sigterm(stack: Stack):
    worker = stack.name("worker-idle")
    stack.run(SEARCH_IMAGE, worker, stack.worker_env(), FAST_WORKER, detach=True)
    wait_for("worker readiness", lambda: local_probe(worker, "/readyz")[0] == 200, container=worker)
    probe = docker("exec", worker, "python", "-c", WORKER_READINESS_PROBE, check=False)
    assert probe.returncode == 0, probe.stderr
    processes = docker("top", worker, "-o", "pid,ppid,uid,args").stdout.strip().splitlines()[1:]
    assert {line.split()[2] for line in processes} == {"10001"}
    assert processes[0].split()[3:5] == ["/usr/local/bin/tini", "--"]
    supervisor = [line for line in processes[1:] if "dev.run_runtime_worker" in line]
    assert len(supervisor) == 1 and supervisor[0].split()[1] == processes[0].split()[0]
    children = [line for line in processes if line.split()[1] == supervisor[0].split()[0]]
    assert any("multiprocessing.spawn" in line for line in children), processes

    code, elapsed = stop(worker)
    output = logs(worker)
    assert code == 0 and elapsed < 10, output
    final = json.loads(output.rsplit("Worker supervisor stopped: ", 1)[1].splitlines()[0])
    assert final["draining"] and not final["alive"] and final["error_code"] is None
    stack.assert_no_secrets(output)


def test_busy_worker_drain_deadline_kills_child_and_restart_recovers_lease(stack: Stack):
    report_id = str(uuid.uuid4())
    create = (
        "import sys\nfrom src.storage.report_service import report_service\n"
        "report_service.create_pending_report(sys.argv[1], 'Image check synthetic target',"
        " 'image-check-user', runtime_dispatch=True)"
    )
    created = stack.run(
        SEARCH_IMAGE,
        stack.name("admit"),
        stack.product_env(),
        ["python", "-c", create, report_id],
        detach=False,
    )
    assert created.returncode == 0, created.stderr

    def fence() -> tuple[str, str, int]:
        row = stack.psql(
            "sentrysearch",
            "SELECT coalesce(runtime_run_id::text, ''), coalesce(lease_owner, ''), lease_version"
            f" FROM report_runtime_dispatches WHERE report_id = '{report_id}'",
        )
        run_id, owner, version = row.split("|")
        return run_id, owner, int(version)

    first = stack.name("worker-a")
    stack.run(SEARCH_IMAGE, first, stack.worker_env(), FAST_WORKER, detach=True)
    wait_for("first product fence", lambda: fence()[1].startswith("worker-a-"), container=first)
    run_id, first_owner, first_version = fence()
    status = local_probe(first, "/status")[1]
    report = stack.psql(
        "sentrysearch",
        "SELECT status, generation_stage, coalesce(generation_error_code, ''),"
        f" coalesce(generation_failure::text, '') FROM reports WHERE id = '{report_id}'",
    )
    assert status["phase"] == "generation" and status["ready"], f"{status}\n{report}"
    # Generation is blocked on the local stub, not on any external provider.
    assert "provider stub accepted a connection" in logs(stack.provider)

    docker("kill", "--signal", "SIGTERM", first)
    draining = local_probe(first, "/readyz")
    assert draining[0] == 503 and draining[1]["draining"], draining
    # Readiness withdraws admission while the living child is still draining.
    assert local_probe(first, "/healthz")[0] == 200
    code = int(docker("wait", first, timeout=30).stdout.strip())
    output = logs(first)
    assert code == 124, output
    final = json.loads(output.rsplit("Worker supervisor stopped: ", 1)[1].splitlines()[0])
    assert final["error_code"] == "drain_deadline_exceeded" and not final["alive"]
    status_code, run = stack.runtime_get(f"/v1/runs/{run_id}")
    assert status_code == 200 and run["state"] == "running" and run["attempt"] == 1, run

    second = stack.name("worker-b")
    stack.run(SEARCH_IMAGE, second, stack.worker_env(), FAST_WORKER, detach=True)
    wait_for(
        "recovered product fence",
        lambda: fence()[1].startswith("worker-b-"),
        timeout=90,
        container=second,
    )
    recovered_run, second_owner, second_version = fence()
    assert recovered_run == run_id and second_version > first_version
    assert second_owner != first_owner
    status_code, run = stack.runtime_get(f"/v1/runs/{run_id}")
    assert run["state"] == "running" and run["attempt"] == 2, run
    assert run["lease_owner"] == second_owner and run["lease_version"] == second_version
    assert stop(second)[0] == 124
    for name in (first, second):
        stack.assert_no_secrets(logs(name))
