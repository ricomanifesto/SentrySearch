"""Actual libpq TLS checks against disposable loopback PostgreSQL servers."""

import os
from pathlib import Path
import socket
import subprocess
import tempfile

import pytest

from dev.tls_fixtures import create_certificates
from src.storage.database import DatabaseManager


@pytest.mark.parametrize("case", ["trusted", "wrong_ca", "wrong_hostname", "expired", "plaintext"])
def test_database_tls_verifies_server_and_has_no_plaintext_fallback(case, monkeypatch, caplog):
    pg_bin = Path(os.environ["SENTRYSEARCH_TEST_PG_BIN"])
    with tempfile.TemporaryDirectory(prefix="storage-tls-", dir="/tmp") as directory:
        root = Path(directory)
        data, socket_dir = root / "data", root / "socket"
        socket_dir.mkdir()
        cert = create_certificates(
            root / "tls",
            hostname="wrong.example.test" if case == "wrong_hostname" else "localhost",
            expired=case == "expired",
        )
        cert.key.chmod(0o600)
        trusted_ca = create_certificates(root / "other").ca if case == "wrong_ca" else cert.ca
        subprocess.run(
            [
                str(pg_bin / "initdb"),
                "-D",
                str(data),
                "-U",
                "postgres",
                "--auth=trust",
                "--no-locale",
                "--encoding=UTF8",
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        options = f"-h 127.0.0.1 -p {port} -k '{socket_dir}'"
        if case != "plaintext":
            options += (
                f" -c ssl=on -c ssl_cert_file='{cert.certificate}' -c ssl_key_file='{cert.key}'"
            )
        subprocess.run(
            [str(pg_bin / "pg_ctl"), "-D", str(data), "-o", options, "-w", "start"],
            check=True,
            stdout=subprocess.DEVNULL,
            timeout=30,
        )
        try:
            for key, value in {
                "ENVIRONMENT": "production",
                "DB_HOST": "127.0.0.1",
                "DB_PORT": str(port),
                "DB_NAME": "postgres",
                "DB_USER": "postgres",
                "DB_PASSWORD": "private-fixture-password",
                "DB_SSLMODE": "verify-full",
                "DB_SSLROOTCERT": str(trusted_ca),
                "DB_DEBUG": "false",
            }.items():
                monkeypatch.setenv(key, value)
            manager = DatabaseManager()
            try:
                assert manager.test_connection() is (case == "trusted")
                if case == "trusted":
                    from sqlalchemy import text

                    with manager.engine.connect() as conn:
                        assert (
                            conn.execute(
                                text("SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()")
                            ).scalar()
                            is True
                        )
            finally:
                manager.engine.dispose()
            assert "private-fixture-password" not in caplog.text
        finally:
            subprocess.run(
                [str(pg_bin / "pg_ctl"), "-D", str(data), "-m", "immediate", "-w", "stop"],
                check=True,
                stdout=subprocess.DEVNULL,
                timeout=30,
            )
