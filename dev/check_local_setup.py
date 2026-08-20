#!/usr/bin/env python3
"""Validate local setup contracts without production credentials."""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
LOCAL_API_URL = "http://localhost:8001"
PYTHON_VALIDATION_PATHS = [
    "run_api.py",
    "src",
    "dev",
    "tests",
]


def read_text(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def require_contains(relative_path: str, expected: str) -> None:
    content = read_text(relative_path)
    if expected not in content:
        raise AssertionError(f"{relative_path} must contain {expected!r}")


def require_not_contains(relative_path: str, unexpected: str) -> None:
    content = read_text(relative_path)
    if unexpected in content:
        raise AssertionError(f"{relative_path} must not contain {unexpected!r}")


def validate_api_url_contract() -> None:
    checks = [
        (".env.example", f"PORT=8001"),
        (".env.example", f"NEXT_PUBLIC_API_URL={LOCAL_API_URL}"),
        ("frontend/.env.example", f"NEXT_PUBLIC_API_URL={LOCAL_API_URL}"),
        ("frontend/src/lib/api.ts", f"'{LOCAL_API_URL}'"),
        ("README.md", f"`NEXT_PUBLIC_API_URL={LOCAL_API_URL}`"),
        ("frontend/README.md", f"NEXT_PUBLIC_API_URL={LOCAL_API_URL}"),
    ]
    for relative_path, expected in checks:
        require_contains(relative_path, expected)

    require_not_contains("frontend/README.md", "localhost:8000")
    require_not_contains("frontend/src/lib/api.ts", "localhost:8000")
    require_not_contains("frontend/src/app/page.tsx", "NEXT_PUBLIC_API_URL")
    require_not_contains("frontend/src/app/page.tsx", LOCAL_API_URL)
    require_not_contains("frontend/src/app/page.tsx", "localhost:8000")


def validate_auth_env_contract() -> None:
    for relative_path in [".env.example", "frontend/.env.example"]:
        require_contains(relative_path, "NEXT_PUBLIC_SUPABASE_URL=")
        require_contains(relative_path, "NEXT_PUBLIC_SUPABASE_ANON_KEY=")
    require_contains(".env.example", "SUPABASE_SERVICE_ROLE_KEY=")
    require_contains(".env.example", "SENTRYRUNTIME_LOCAL_URL=")


def validate_python_tooling_contract() -> None:
    require_contains("pyproject.toml", "[dependency-groups]")
    require_contains("pyproject.toml", '"ruff>=')
    require_contains("pyproject.toml", '"black>=')
    require_contains("pyproject.toml", '"ty>=')
    require_contains("uv.lock", 'name = "ruff"')
    require_contains("uv.lock", 'name = "black"')
    require_contains("uv.lock", 'name = "ty"')
    require_contains("requirements.txt", "\nhttpx==")
    require_not_contains("requirements.txt", "\nopenai==")

    exported = subprocess.run(
        ["uv", "export", "--frozen", "--no-dev", "--no-hashes", "--no-header"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    requirements_lines = read_text("requirements.txt").splitlines()
    while requirements_lines and (
        not requirements_lines[0].strip() or requirements_lines[0].lstrip().startswith("#")
    ):
        requirements_lines.pop(0)
    if "\n".join(requirements_lines).strip() != exported:
        raise AssertionError(
            "requirements.txt must match uv.lock; run the export command recorded in its header"
        )


def validate_railway_config_contract() -> None:
    railway_config = json.loads(read_text("railway.json"))
    build_config = railway_config.get("build")
    deploy_config = railway_config.get("deploy")
    if build_config != {"builder": "RAILPACK"}:
        raise AssertionError("railway.json build config must use the current Railpack builder")
    if not isinstance(deploy_config, dict):
        raise AssertionError("railway.json must define deploy config")
    if deploy_config.get("startCommand") != "python run_api.py":
        raise AssertionError("railway.json must start the FastAPI launcher")
    if deploy_config.get("healthcheckPath") != "/api/ready":
        raise AssertionError("railway.json must healthcheck the FastAPI readiness endpoint")
    if deploy_config.get("restartPolicyType") != "ON_FAILURE":
        raise AssertionError("railway.json must restart failed containers")
    if deploy_config.get("restartPolicyMaxRetries") != 10:
        raise AssertionError("railway.json must keep the bounded restart retry policy")


def run_command(command: list[str]) -> None:
    print(f"Running: {' '.join(command)}")
    subprocess.run(command, cwd=REPO_ROOT, check=True)


async def main() -> int:
    validate_api_url_contract()
    validate_auth_env_contract()
    validate_python_tooling_contract()
    validate_railway_config_contract()

    run_command(["ruff", "check", *PYTHON_VALIDATION_PATHS])
    run_command(["black", "--check", *PYTHON_VALIDATION_PATHS])
    run_command(["ty", "check", *PYTHON_VALIDATION_PATHS])
    run_command([sys.executable, "-B", "-m", "pytest", "tests"])
    sys.path.insert(0, str(REPO_ROOT))
    from dev.smoke_api import run_checks  # pylint: disable=import-outside-toplevel

    await run_checks()
    print("Local setup contract checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
