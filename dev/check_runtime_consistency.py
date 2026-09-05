"""Run product consistency proofs with isolated PostgreSQL and SentryRuntime."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

import httpx


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-repo", type=Path, required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    runtime_repo = args.runtime_repo.resolve()
    pg_bin = (
        Path(subprocess.check_output(["brew", "--prefix", "postgresql@16"], text=True).strip())
        / "bin"
    )
    with tempfile.TemporaryDirectory(prefix="report-proof-", dir="/tmp") as root:
        scratch = Path(root)
        data, pg_socket = scratch / "data", scratch / "socket"
        pg_socket.mkdir()
        binary = scratch / "runtime"
        subprocess.run(
            ["go", "build", "-o", str(binary), "./cmd/sentryruntime"], cwd=runtime_repo, check=True
        )
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
            stdout=subprocess.DEVNULL,
        )
        subprocess.run(
            [
                str(pg_bin / "pg_ctl"),
                "-D",
                str(data),
                "-o",
                f"-h '' -k '{pg_socket}'",
                "-w",
                "start",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        server = None
        try:
            env = {
                key: value
                for key, value in os.environ.items()
                if not key.startswith(
                    (
                        "AWS_",
                        "OPENROUTER_",
                        "SUPABASE_",
                        "DB_",
                        "SENTRYRUNTIME_",
                        "SENTRYSEARCH_TEST_",
                    )
                )
            }
            env["PYTHON_DOTENV_DISABLED"] = "1"
            env["DATABASE_URL"] = f"postgres://postgres@/postgres?host={pg_socket}&sslmode=disable"
            env["SENTRYSEARCH_TEST_DATABASE_URL"] = (
                f"postgresql+psycopg://postgres@/postgres?host={pg_socket}&sslmode=disable"
            )
            subprocess.run(["go", "run", "./cmd/migrate"], cwd=runtime_repo, env=env, check=True)
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            env["SENTRYRUNTIME_LISTEN_ADDRESS"] = f"127.0.0.1:{port}"
            env["SENTRYRUNTIME_LOCAL_URL"] = f"http://127.0.0.1:{port}"
            env["SENTRYRUNTIME_AUTH_MODE"] = "token"
            entries = []
            for role in ("producer", "worker"):
                token = f"fixture-{role}-" * 4
                env[f"SENTRYRUNTIME_{role.upper()}_TOKEN"] = token
                entries.append(
                    {
                        "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
                        "role": role,
                        "product": "sentrysearch",
                        "workflow_name": "generate_report",
                        "workflow_version": "v1",
                    }
                )
            env["SENTRYRUNTIME_AUTH_CREDENTIALS"] = json.dumps(entries)
            server = subprocess.Popen([str(binary)], cwd=runtime_repo, env=env)
            with httpx.Client(trust_env=False, timeout=1) as probe:
                for _ in range(100):
                    if server.poll() is not None:
                        raise RuntimeError("runtime exited before readiness")
                    try:
                        if (
                            probe.get(
                                env["SENTRYRUNTIME_LOCAL_URL"] + "/v1/runs/invalid"
                            ).status_code
                            == 401
                        ):
                            break
                    except httpx.RequestError:
                        pass
                    time.sleep(0.1)
                else:
                    raise RuntimeError("runtime did not become ready")
            subprocess.run(
                [sys.executable, "-m", "pytest", "tests/runtime_postgres.py", "-v"],
                cwd=repo,
                env=env,
                check=True,
            )
        finally:
            if server is not None:
                server.terminate()
                try:
                    server.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=5)
            subprocess.run(
                [str(pg_bin / "pg_ctl"), "-D", str(data), "-m", "immediate", "-w", "stop"],
                check=True,
                stdout=subprocess.DEVNULL,
            )


if __name__ == "__main__":
    main()
