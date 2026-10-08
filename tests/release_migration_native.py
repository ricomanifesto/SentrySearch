"""Search migration release job against disposable PostgreSQL 16 with verified TLS.

Explicit native suite, like release_tools_native.py: set SENTRYSEARCH_TEST_PG_BIN
to PostgreSQL 16 server binaries. The server accepts only verified TLS with SCRAM
passwords. Covers the exact success receipt and an idempotent rerun, refused
TLS, a wrong password, a blocked statement abandoned at its server bound with no
session left behind, and SIGTERM in a real process.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

import psycopg
import pytest

from dev.tls_fixtures import create_certificates
from src.storage import release_job
from tests.test_release_migration_job import TASK, _Metadata

REPO = Path(__file__).resolve().parents[1]
RELEASE = "0b9f7c1e-4d2a-4f6b-9a3e-2c1d0e9f8a7b"
OWNER_PASSWORD = "fixture-product-owner-password-0001"
APPLICATION = f"release:{RELEASE}:product-migrate"


@dataclass
class Cluster:
    root: Path
    port: int
    socket: Path
    ca: Path

    def admin(self, statement: str, dbname: str = "postgres") -> list:
        with psycopg.connect(host=str(self.socket), port=self.port, user="postgres",
                             dbname=dbname, autocommit=True) as conn:  # fmt: skip
            cursor = conn.execute(statement)  # ty: ignore[no-matching-overload]
            return cursor.fetchall() if cursor.description else []

    def release_sessions(self) -> int:
        rows = self.admin(
            f"SELECT count(*) FROM pg_stat_activity WHERE application_name = '{APPLICATION}'"
        )
        return int(rows[0][0])


@pytest.fixture(scope="module")
def cluster():
    pg_bin = Path(os.environ["SENTRYSEARCH_TEST_PG_BIN"])
    with tempfile.TemporaryDirectory(prefix="release-migration-", dir="/tmp") as directory:
        root = Path(directory)
        data, socket_dir = root / "data", root / "s"
        socket_dir.mkdir()
        cert = create_certificates(root / "tls", hostname="localhost")
        cert.key.chmod(0o600)
        subprocess.run(
            [str(pg_bin / "initdb"), "-D", str(data), "-U", "postgres", "--auth-local=trust",
             "--auth-host=reject", "--no-locale", "--encoding=UTF8"],
            check=True, capture_output=True, timeout=60,
        )  # fmt: skip
        (data / "pg_hba.conf").write_text(
            "local all postgres trust\nhostssl all all 127.0.0.1/32 scram-sha-256\n"
            "host all all 127.0.0.1/32 reject\n"
        )
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        options = (
            f"-h 127.0.0.1 -p {port} -k '{socket_dir}' -c ssl=on "
            f"-c ssl_cert_file='{cert.certificate}' -c ssl_key_file='{cert.key}' "
            "-c password_encryption=scram-sha-256"
        )
        subprocess.run([str(pg_bin / "pg_ctl"), "-D", str(data), "-o", options, "-w", "start"],
                       check=True, stdout=subprocess.DEVNULL, timeout=60)  # fmt: skip
        ca = root / "postgres-ca.pem"
        ca.write_bytes(cert.ca.read_bytes())
        ca.chmod(0o400)
        try:
            found = Cluster(root, port, socket_dir, ca)
            found.admin(f"CREATE ROLE product_owner LOGIN PASSWORD '{OWNER_PASSWORD}'")
            yield found
        finally:
            subprocess.run([str(pg_bin / "pg_ctl"), "-D", str(data), "-m", "immediate", "-w",
                            "stop"], check=True, stdout=subprocess.DEVNULL, timeout=60)  # fmt: skip


@pytest.fixture(scope="module")
def metadata():
    from http.server import ThreadingHTTPServer

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Metadata)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}/v4/fixture"
    server.shutdown()


def environment(cluster: Cluster, metadata: str, database: str, *, seconds: float = 1800,
                password: str = OWNER_PASSWORD, ca: Path | None = None) -> dict[str, str]:  # fmt: skip
    not_after = datetime.now(UTC) + timedelta(seconds=seconds)
    return {
        "RELEASE_ID": RELEASE,
        "RELEASE_JOB_ID": "product-migrate",
        "RELEASE_NOT_AFTER": not_after.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "RELEASE_JOB_BUDGET_SECONDS": "900",
        "RELEASE_EXPECT_DATABASE": database,
        "RELEASE_EXPECT_PRINCIPAL": "product_owner",
        "ECS_CONTAINER_METADATA_URI_V4": metadata,
        "ENVIRONMENT": "staging",
        "DB_HOST": "127.0.0.1",
        "DB_PORT": str(cluster.port),
        "DB_NAME": database,
        "DB_USER": "product_owner",
        "DB_PASSWORD": password,
        "DB_SSLMODE": "verify-full",
        "DB_SSLROOTCERT": str(ca or cluster.ca),
        "DB_DEBUG": "false",
        "PYTHON_DOTENV_DISABLED": "1",
    }


def run_job(env: dict[str, str], monkeypatch, capsys) -> tuple[int, dict]:
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(release_job, "CA_FILE", env["DB_SSLROOTCERT"])
    code = release_job.main(env, exit=lambda c: None, install_signals=False)
    captured = capsys.readouterr()
    lines = captured.out.splitlines()
    assert len(lines) == 1 and lines[0].startswith("SENTRY_RELEASE_RECEIPT "), captured.out
    assert OWNER_PASSWORD not in captured.out + captured.err
    return code, json.loads(lines[0].split(" ", 1)[1])


def expected_schema() -> str:
    from src.storage.schema import _revision

    version, checksum = _revision()
    return f"sentrysearch:{version}:{checksum[:16]}"


def test_success_receipt_and_idempotent_rerun(cluster, metadata, monkeypatch, capsys):
    cluster.admin("CREATE DATABASE product_db OWNER product_owner")
    for _ in range(2):
        code, receipt = run_job(environment(cluster, metadata, "product_db"), monkeypatch, capsys)
        assert code == 0, receipt
        assert receipt == {
            "schema": "sentry.release-migration.v1",
            "release_id": RELEASE,
            "job_id": "product-migrate",
            "task_arn": TASK,
            "status": "succeeded",
            "result": {"database": "product_db", "principal": "product_owner",
                       "schema": expected_schema()},
        }  # fmt: skip
    assert cluster.release_sessions() == 0


@pytest.mark.parametrize("case", ["wrong_password", "wrong_ca", "plaintext"])
def test_connection_refusals_are_sql_none(cluster, metadata, monkeypatch, capsys, case, tmp_path):
    cluster.admin(f"CREATE DATABASE product_{case} OWNER product_owner")
    env = environment(cluster, metadata, f"product_{case}")
    expected = {"wrong_password": "auth_failed", "wrong_ca": "tls_untrusted",
                "plaintext": "tls_unavailable"}[case]  # fmt: skip
    if case == "wrong_password":
        env["DB_PASSWORD"] = "wrong-fixture-password-for-test-0001"
    elif case == "wrong_ca":
        other = create_certificates(tmp_path / "other", hostname="localhost").ca
        ca = tmp_path / "other-ca.pem"
        ca.write_bytes(other.read_bytes())
        ca.chmod(0o400)
        env["DB_SSLROOTCERT"] = str(ca)
    else:
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen()

        def refuse_tls():
            conn, _ = listener.accept()
            with conn:
                conn.recv(8)
                conn.sendall(b"N")
                time.sleep(0.5)

        threading.Thread(target=refuse_tls, daemon=True).start()
        env["DB_PORT"] = str(listener.getsockname()[1])
    code, receipt = run_job(env, monkeypatch, capsys)
    assert code == release_job.EXIT_CONNECTION
    assert receipt["result"] == {"reason": expected, "sql_outcome": "none"}


def test_a_blocked_statement_is_abandoned_at_its_server_bound(cluster, metadata, monkeypatch,
                                                              capsys):  # fmt: skip
    cluster.admin("CREATE DATABASE product_blocked OWNER product_owner")
    with psycopg.connect(host=str(cluster.socket), port=cluster.port, user="postgres",
                         dbname="product_blocked") as holder:  # fmt: skip
        holder.execute(
            "CREATE TABLE sentrysearch_schema_migrations (version INTEGER PRIMARY KEY, "
            "checksum VARCHAR(64) NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())"
        )
        holder.execute("ALTER TABLE sentrysearch_schema_migrations OWNER TO product_owner")
        holder.execute("LOCK TABLE sentrysearch_schema_migrations IN ACCESS EXCLUSIVE MODE")
        started = time.monotonic()
        code, receipt = run_job(environment(cluster, metadata, "product_blocked"), monkeypatch,
                                capsys)  # fmt: skip
        holder.rollback()
    assert code == release_job.EXIT_SQL
    assert receipt["result"] == {"reason": "lock_timeout", "sql_outcome": "unknown"}
    assert time.monotonic() - started < 10
    assert cluster.release_sessions() == 0


def test_sigterm_in_a_real_process_exits_143_and_leaves_no_session(cluster, metadata):
    cluster.admin("CREATE DATABASE product_stop OWNER product_owner")
    env = {**os.environ, **environment(cluster, metadata, "product_stop")}
    with psycopg.connect(host=str(cluster.socket), port=cluster.port, user="postgres",
                         dbname="product_stop") as holder:  # fmt: skip
        holder.execute(
            "CREATE TABLE sentrysearch_schema_migrations (version INTEGER PRIMARY KEY, "
            "checksum VARCHAR(64) NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())"
        )
        holder.execute("ALTER TABLE sentrysearch_schema_migrations OWNER TO product_owner")
        holder.execute("LOCK TABLE sentrysearch_schema_migrations IN ACCESS EXCLUSIVE MODE")
        process = subprocess.Popen(
            [sys.executable, "-B", str(REPO / "tests" / "release_migration_process.py"),
             str(cluster.ca)],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=REPO,
        )  # fmt: skip
        deadline = time.monotonic() + 20
        while cluster.release_sessions() == 0 or not cluster.admin(
            "SELECT 1 FROM pg_stat_activity WHERE application_name = "
            f"'{APPLICATION}' AND wait_event_type = 'Lock'"
        ):
            assert time.monotonic() < deadline, "the job never waited on the lock"
            time.sleep(0.05)
        stopped = time.monotonic()
        process.send_signal(signal.SIGTERM)
        out, err = process.communicate(timeout=15)
        holder.rollback()
    assert process.returncode == release_job.EXIT_TERMINATED, (out, err)
    assert time.monotonic() - stopped < 6
    (line,) = out.splitlines()
    receipt = json.loads(line.split(" ", 1)[1])
    assert receipt["result"] == {"reason": "terminated", "sql_outcome": "unknown"}
    assert OWNER_PASSWORD not in out + err
    gone = time.monotonic() + 5
    while cluster.release_sessions():
        assert time.monotonic() < gone, "the stopped job's session kept running"
        time.sleep(0.1)
