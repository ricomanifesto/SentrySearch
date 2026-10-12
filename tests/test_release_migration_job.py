"""Search migration release job: every refusal before a database connection.

Database behavior (verified TLS, bounded session, receipts, stop and deadline) is
covered against real PostgreSQL 16 by tests/release_migration_native.py.
"""

from __future__ import annotations

import ast
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from release_tools import contract
from src.storage import release_job

REPO = Path(__file__).resolve().parents[1]
RELEASE = "0b9f7c1e-4d2a-4f6b-9a3e-2c1d0e9f8a7b"
TASK = "arn:aws:ecs:us-east-1:111122223333:task/sentry-staging/" + "c" * 32
START = datetime(2026, 10, 7, 12, 0, tzinfo=UTC)
PASSWORD = "fixture-product-owner-password-0001"


class _Metadata(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - http.server API
        self.send_response(200 if self.path.endswith("/task") else 404)
        self.end_headers()
        self.wfile.write(json.dumps({"TaskARN": TASK}).encode())

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - http.server API
        pass


@pytest.fixture
def metadata():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Metadata)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}/v4/fixture"
    server.shutdown()


@pytest.fixture
def ca(tmp_path, monkeypatch) -> Path:
    path = tmp_path.resolve() / "postgres-ca.pem"
    path.write_text("-----BEGIN CERTIFICATE-----\nZml4dHVyZQ==\n-----END CERTIFICATE-----\n")
    path.chmod(0o400)
    monkeypatch.setattr(release_job, "CA_FILE", str(path))
    return path


def environment(metadata: str, ca: Path, **changes: str) -> dict[str, str]:
    base = {
        "RELEASE_ID": RELEASE,
        "RELEASE_JOB_ID": "product-migrate",
        "RELEASE_NOT_AFTER": (START + timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "RELEASE_JOB_BUDGET_SECONDS": "900",
        "RELEASE_EXPECT_DATABASE": "product_db",
        "RELEASE_EXPECT_PRINCIPAL": "product_owner",
        "ECS_CONTAINER_METADATA_URI_V4": metadata,
        "ENVIRONMENT": "staging",
        "DB_HOST": "product-db.internal",
        "DB_PORT": "5432",
        "DB_NAME": "product_db",
        "DB_USER": "product_owner",
        "DB_PASSWORD": PASSWORD,
        "DB_SSLMODE": "verify-full",
        "DB_SSLROOTCERT": str(ca),
        "DB_DEBUG": "false",
    }
    base.update(changes)
    return {key: value for key, value in base.items() if value != "<unset>"}


class Engines:
    """Records every engine the job asks for; connecting always fails."""

    def __init__(self) -> None:
        self.requests: list[dict] = []

    def __call__(self, connect_args: dict):
        self.requests.append(connect_args)

        class Unreachable:
            def connect(self):
                raise OSError("could not translate host name")

            def dispose(self):
                pass

        return Unreachable()


def run(env: dict[str, str], monkeypatch, capsys, *, now=START) -> tuple[int, list, list, Engines]:
    for key in list(env):
        monkeypatch.setenv(key, env[key])
    for key in ("DB_SSLROOTCERT", "DB_SSLMODE", "ENVIRONMENT", "DB_USER", "DB_NAME"):
        if key not in env:
            monkeypatch.delenv(key, raising=False)
    engines = Engines()
    code = release_job.main(env, now=lambda: now, engine_factory=engines,
                            exit=lambda c: None, install_signals=False)  # fmt: skip
    captured = capsys.readouterr()
    receipts = [
        json.loads(line.split(" ", 1)[1])
        for line in captured.out.splitlines()
        if line.startswith("SENTRY_RELEASE_RECEIPT ")
    ]
    assert len(receipts) == len(captured.out.splitlines()), "stdout carries only receipts"
    events = [json.loads(line) for line in captured.err.splitlines()]
    assert PASSWORD not in captured.out + captured.err
    return code, receipts, events, engines


@pytest.mark.parametrize(
    "changes, reason",
    [
        ({"RELEASE_ID": "x"}, "release_id_invalid"),
        ({"RELEASE_JOB_ID": "Product"}, "job_id_invalid"),
        ({"RELEASE_NOT_AFTER": "2026-10-07 12:30:00"}, "not_after_invalid"),
        ({"RELEASE_JOB_BUDGET_SECONDS": "59"}, "budget_invalid"),
        ({"RELEASE_EXPECT_PRINCIPAL": "other_owner"}, "principal_mismatch"),
        ({"RELEASE_EXPECT_DATABASE": "other_db"}, "database_mismatch"),
        ({"DB_SSLMODE": "disable"}, "storage_settings_invalid"),
        # Verified TLS must be stated, not inherited from a deployed default.
        ({"DB_SSLMODE": "<unset>"}, "storage_settings_invalid"),
        ({"DB_SSLROOTCERT": "/tmp/other-ca.pem"}, "storage_settings_invalid"),
        ({"ENVIRONMENT": "development"}, "storage_settings_invalid"),
        ({"DB_DEBUG": "true"}, "storage_settings_invalid"),
        ({"DB_HOST": "a,b"}, "storage_settings_invalid"),
    ],
)
def test_configuration_errors_never_connect(metadata, ca, monkeypatch, capsys, changes, reason):
    code, receipts, events, engines = run(environment(metadata, ca, **changes), monkeypatch, capsys)
    assert code == release_job.EXIT_CONFIG and receipts == [] and engines.requests == []
    assert events[-1] == {"event": "job_failed", "reason": reason, "sql_outcome": "none",
                          "exit_code": "2"} or events[-1]["reason"] == reason  # fmt: skip


def test_too_little_time_or_no_task_identity_never_connects(metadata, ca, monkeypatch, capsys):
    late = START + timedelta(minutes=30) - timedelta(seconds=7.999)
    code, receipts, events, engines = run(environment(metadata, ca), monkeypatch, capsys, now=late)
    assert (code, receipts, engines.requests) == (release_job.EXIT_DEADLINE_EXPIRED, [], [])
    assert events[-1]["reason"] == "deadline_expired"
    for uri in ("", "http://192.0.2.1/v4/x", metadata.replace("http://", "https://")):
        code, receipts, events, engines = run(
            environment(metadata, ca, ECS_CONTAINER_METADATA_URI_V4=uri or "<unset>"),
            monkeypatch, capsys,
        )  # fmt: skip
        assert (code, receipts, engines.requests) == (release_job.EXIT_TASK_IDENTITY, [], [])
        assert events[-1]["reason"] == "task_identity_unavailable"


@pytest.mark.parametrize("mode", [0o440, 0o640, 0o404])
def test_ca_material_that_is_not_owner_only_fails_with_a_receipt(
    metadata, ca, monkeypatch, capsys, mode
):
    ca.chmod(mode)
    code, receipts, events, engines = run(environment(metadata, ca), monkeypatch, capsys)
    assert code == release_job.EXIT_MATERIAL and engines.requests == []
    assert receipts == [
        {
            "schema": "sentry.release-migration.v1",
            "release_id": RELEASE,
            "job_id": "product-migrate",
            "task_arn": TASK,
            "status": "failed",
            "result": {"reason": "material_invalid", "sql_outcome": "none"},
        }
    ]


def test_the_session_is_requested_with_its_tag_and_bounds_and_a_connect_failure_is_sql_none(
    metadata, ca, monkeypatch, capsys
):
    near = START + timedelta(minutes=30) - timedelta(seconds=20)
    code, receipts, events, engines = run(environment(metadata, ca), monkeypatch, capsys, now=near)
    assert code == release_job.EXIT_CONNECTION
    assert receipts[0]["result"] == {"reason": "unreachable", "sql_outcome": "none"}
    (request,) = engines.requests
    assert request["application_name"] == f"release:{RELEASE}:product-migrate"
    # 20 s left: 5 s grace, 2 s reserve, so 13 s statements; locks 3 s; idle 10 s.
    assert request["options"].split() == [
        "-c", "search_path=public", "-c", "statement_timeout=13000", "-c", "lock_timeout=3000",
        "-c", "idle_in_transaction_session_timeout=10000",
        "-c", "client_connection_check_interval=1000",
    ]  # fmt: skip


def test_close_to_the_deadline_every_session_limit_shrinks_to_the_statement_bound(
    metadata, ca, monkeypatch, capsys
):
    near = START + timedelta(minutes=30) - timedelta(seconds=10)
    code, receipts, events, engines = run(environment(metadata, ca), monkeypatch, capsys, now=near)
    assert code == release_job.EXIT_CONNECTION
    (request,) = engines.requests
    # 10 s left: 5 s grace and 2 s reserve leave 3 s for statements, locks and idle time.
    assert request["options"].split()[3:8:2] == [
        "statement_timeout=3000", "lock_timeout=3000", "idle_in_transaction_session_timeout=3000"
    ]  # fmt: skip
    assert contract.session_limits(3.999) == (1999, 1999, 1999)
    with pytest.raises(contract.ContractError):
        contract.session_limits(2.999)


def test_the_schema_query_is_the_product_proof_computation():
    proof = (REPO / "release_tools" / "sql" / "schema_product.sql").read_text()
    body = " ".join(line for line in proof.splitlines() if not line.startswith("--"))
    expected = re.sub(r"\s+", " ", body.replace("'result|schema|sentrysearch:'", "'sentrysearch:'"))
    assert re.sub(r"\s+", " ", release_job.SCHEMA_SQL + ";").strip() == expected.strip()


def _imports(path: Path) -> set[str]:
    names = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            names |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module)
            names |= {f"{node.module}.{alias.name}" for alias in node.names}
    return names


SHARED = ("__init__.py", "contract.py", "receipt.py")


def test_the_shared_release_modules_are_a_closed_stdlib_only_set():
    for name in SHARED:
        for module in _imports(REPO / "release_tools" / name):
            top = module.split(".")[0]
            assert top in sys.stdlib_module_names or module in {
                "release_tools", "release_tools.contract", "release_tools.receipt"
            }, (name, module)  # fmt: skip
    used = {
        m for m in _imports(REPO / "src" / "storage" / "release_job.py") if "release_tools" in m
    }
    assert used <= {"release_tools", "release_tools.contract", "release_tools.receipt"}


def test_the_search_image_carries_exactly_the_shared_release_modules():
    dockerfile = (REPO / "container" / "Dockerfile").read_text()
    ignore = (REPO / "container" / "Dockerfile.dockerignore").read_text().splitlines()
    copied = [
        line
        for line in dockerfile.splitlines()
        if line.startswith("COPY") and "release_tools" in line
    ]
    assert copied == [
        "COPY " + " ".join(f"release_tools/{name}" for name in SHARED) + " /app/release_tools/"
    ]
    allowed = {line for line in ignore if line.startswith("!release_tools")}
    assert allowed == {f"!release_tools/{name}" for name in SHARED}
    assert contract.STOP_GRACE_SECONDS == 5.0


def test_time_spent_after_the_preflight_still_refuses_before_connecting(
    metadata, ca, monkeypatch, capsys
):
    """The task identity read can use up the preflight's margin: no connection, a receipt."""
    env = environment(metadata, ca)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    moment = [START]
    original = contract.task_identity

    def slow_identity(environ):
        arn = original(environ)
        # 7.5 s before the deadline (the 900 s budget ends first): the 5 s grace
        # and 2 s reserve leave 0.5 s, less than one bounded statement.
        moment[0] = START + timedelta(seconds=900) - timedelta(seconds=7.5)
        return arn

    monkeypatch.setattr(contract, "task_identity", slow_identity)
    engines = Engines()
    code = release_job.main(env, now=lambda: moment[0], engine_factory=engines,
                            exit=lambda c: None, install_signals=False)  # fmt: skip
    captured = capsys.readouterr()
    assert code == release_job.EXIT_DEADLINE_EXPIRED and engines.requests == []
    (line,) = captured.out.splitlines()
    assert json.loads(line.split(" ", 1)[1])["result"] == {
        "reason": "deadline_expired",
        "sql_outcome": "none",
    }
    assert "Traceback" not in captured.err
    assert all(json.loads(event)["event"] for event in captured.err.splitlines())


def test_every_job_id_a_manifest_accepts_fits_the_producers_session_name():
    """Manifest ids and the migrators' application_name cap must agree (both twins: 63)."""
    from release.manifest import ObserverCheck, load_manifest
    from tests.release_fakes import encode, forward_document, manifest_document

    for document in (manifest_document(), forward_document()):
        manifest = load_manifest(encode(document)).manifest
        subjects = [job.id for job in manifest.jobs] + [
            check.id for check in manifest.operational_checks if isinstance(check, ObserverCheck)
        ]
        for subject in subjects:
            identity = contract.load_identity(
                {
                    "RELEASE_ID": manifest.release_id,
                    "RELEASE_JOB_ID": subject,
                    "RELEASE_NOT_AFTER": "2026-10-07T12:30:00Z",
                    "RELEASE_JOB_BUDGET_SECONDS": "900",
                }
            )
            assert len(identity.application_name) <= contract.MAX_APPLICATION_NAME


# Stop and deadline when the database cancellation itself never returns ----------------


class NeverReturns:
    """A database connection whose cancellation blocks for as long as the network does."""

    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()

    def cancel(self) -> None:
        self.entered.set()
        self.release.wait()


def receipts_written(capsys) -> list[dict]:
    lines = capsys.readouterr().out.splitlines()
    return [json.loads(line.split(" ", 1)[1]) for line in lines
            if line.startswith("SENTRY_RELEASE_RECEIPT ")]  # fmt: skip


@pytest.mark.parametrize("sql_attempted, sql_outcome", [(False, "none"), (True, "unknown")])
@pytest.mark.parametrize(
    "path, code, reason",
    [("stop", release_job.EXIT_TERMINATED, "terminated"),
     ("deadline", release_job.EXIT_DEADLINE, "deadline_exceeded")],
)  # fmt: skip
def test_a_cancellation_that_never_returns_cannot_delay_the_hard_exit(
    monkeypatch, capsys, path, code, reason, sql_attempted, sql_outcome
):
    # A hung server connection is why the watchdog exists, and the cancellation
    # request travels the same network. The bound must not wait for it.
    grace = 0.05
    monkeypatch.setattr(contract, "STOP_GRACE_SECONDS", grace)
    exits: list[int] = []
    exited = threading.Event()
    started = datetime.now(UTC)
    # stop: the deadline is far away. deadline: the session ends now, the job 0.2 s later.
    deadline = started + (timedelta(seconds=60) if path == "stop" else timedelta(seconds=0.2))
    identity = contract.ReleaseIdentity(RELEASE, "product-migrate", deadline, 60)
    job = release_job.ReleaseJob(
        identity, release_job.Expected("product_db", "product_owner"), TASK, deadline,
        now=lambda: datetime.now(UTC), engine_factory=lambda _: None,
        exit=lambda value: (exits.append(value), exited.set()),
    )  # fmt: skip
    connection = NeverReturns()
    job._dbapi = connection
    job.sql_attempted = sql_attempted
    began = time.monotonic()
    try:
        if path == "stop":
            # A signal handler runs on the main thread: it must not wait either.
            handler = threading.Thread(target=job.stop, daemon=True)
            handler.start()
            handler.join(0.5)
            assert not handler.is_alive(), "the stop handler waited for the cancellation"
            bound = grace
        else:
            threading.Thread(target=job._deadline_timer, daemon=True).start()
            bound = 0.2
        assert exited.wait(bound + 1.0), "no hard exit while the cancellation is blocked"
        elapsed = time.monotonic() - began
        assert connection.entered.wait(1.0), "the cancellation was still requested"
        assert not connection.release.is_set() and exits == [code]
        assert bound <= elapsed < bound + 1.0, elapsed
        # One receipt, with the conservative SQL outcome; a later failure on the
        # job's own thread neither writes a second one nor changes the code.
        late = job.fail(release_job.JobFailed("sql_error", "unknown", release_job.EXIT_SQL))
        assert late == code
        assert receipts_written(capsys) == [
            {"schema": "sentry.release-migration.v1", "release_id": RELEASE,
             "job_id": "product-migrate", "task_arn": TASK, "status": "failed",
             "result": {"reason": reason, "sql_outcome": sql_outcome}}
        ]  # fmt: skip
    finally:
        connection.release.set()
        job.done.set()


BLOCKED_JOB = """
import os, sys, threading
sys.path.insert(0, {repo!r})
from release_tools import contract
from src.storage import release_job

release_job.CA_FILE = os.environ["DB_SSLROOTCERT"]
contract.STOP_GRACE_SECONDS = float(os.environ["FIXTURE_GRACE_SECONDS"])
forever = threading.Event()


class Dbapi:
    def cancel(self):
        forever.wait()  # the cancellation request never completes


class Connection:
    connection = type("Pool", (), {{"dbapi_connection": Dbapi()}})()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, *_args):
        print("statement outstanding", file=sys.stderr, flush=True)
        forever.wait()  # the server never answers


class Engine:
    def connect(self):
        return Connection()

    def dispose(self):
        pass


raise SystemExit(release_job.main(dict(os.environ), engine_factory=lambda _args: Engine()))
"""


def test_sigterm_ends_the_process_within_the_grace_when_the_cancellation_hangs(
    metadata, ca, tmp_path
):
    """Real signals and a real exit: the statement and its cancellation both hang."""
    grace = 0.5
    not_after = (datetime.now(UTC) + timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    env = environment(metadata, ca, RELEASE_NOT_AFTER=not_after, FIXTURE_GRACE_SECONDS=str(grace),
                      PYTHON_DOTENV_DISABLED="1", PATH=os.environ.get("PATH", ""))  # fmt: skip
    process = subprocess.Popen(
        [sys.executable, "-B", "-c", BLOCKED_JOB.format(repo=str(REPO))], env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )  # fmt: skip
    try:
        assert process.stderr is not None and process.stdout is not None
        seen = []
        while "statement outstanding" not in "".join(seen):
            line = process.stderr.readline()
            assert line, "the job ended before its statement: " + "".join(seen)
            seen.append(line)
        sent = time.monotonic()
        process.send_signal(signal.SIGTERM)
        code = process.wait(timeout=grace + 5)
        elapsed = time.monotonic() - sent
    finally:
        process.kill()
        process.wait()
    assert code == release_job.EXIT_TERMINATED
    assert grace <= elapsed < grace + 3, elapsed
    lines = process.stdout.read().splitlines()
    assert [json.loads(line.split(" ", 1)[1])["result"] for line in lines] == [
        # The verification statement had not finished: no migration SQL was sent.
        {"reason": "terminated", "sql_outcome": "none"}
    ]
