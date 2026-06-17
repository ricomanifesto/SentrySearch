#!/usr/bin/env python3
"""Validate local setup contracts without production credentials."""

from __future__ import annotations

import asyncio
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEV_ROOT = REPO_ROOT / "dev"
LOCAL_API_URL = "http://localhost:8001"
PYTHON_RUFF_PATHS = [
    "run_api.py",
    "run_app.py",
    "src",
    "dev",
    "tests",
]
PYTHON_FORMAT_TYPE_PATHS = [
    "run_api.py",
    "run_app.py",
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
        ("frontend/src/app/page.tsx", f"'{LOCAL_API_URL}'"),
        ("README.md", f"`NEXT_PUBLIC_API_URL={LOCAL_API_URL}`"),
        ("frontend/README.md", f"NEXT_PUBLIC_API_URL={LOCAL_API_URL}"),
    ]
    for relative_path, expected in checks:
        require_contains(relative_path, expected)

    require_not_contains("frontend/README.md", "localhost:8000")
    require_not_contains("frontend/src/lib/api.ts", "localhost:8000")
    require_not_contains("frontend/src/app/page.tsx", "localhost:8000")


def validate_auth_env_contract() -> None:
    for relative_path in [".env.example", "frontend/.env.example"]:
        require_contains(relative_path, "NEXT_PUBLIC_SUPABASE_URL=")
        require_contains(relative_path, "NEXT_PUBLIC_SUPABASE_ANON_KEY=")
    require_contains(".env.example", "SUPABASE_SERVICE_ROLE_KEY=")


def validate_python_tooling_contract() -> None:
    require_contains("pyproject.toml", "[dependency-groups]")
    require_contains("pyproject.toml", '"ruff>=')
    require_contains("pyproject.toml", '"black>=')
    require_contains("pyproject.toml", '"ty>=')
    require_contains("uv.lock", 'name = "ruff"')
    require_contains("uv.lock", 'name = "black"')
    require_contains("uv.lock", 'name = "ty"')


def run_command(command: list[str]) -> None:
    print(f"Running: {' '.join(command)}")
    subprocess.run(command, cwd=REPO_ROOT, check=True)


async def main() -> int:
    validate_api_url_contract()
    validate_auth_env_contract()
    validate_python_tooling_contract()

    run_command(["ruff", "check", *PYTHON_RUFF_PATHS])
    run_command(["black", "--check", *PYTHON_FORMAT_TYPE_PATHS])
    run_command(["ty", "check", *PYTHON_FORMAT_TYPE_PATHS])
    run_command([sys.executable, "-B", "-m", "pytest", "tests"])

    sys.path.insert(0, str(DEV_ROOT))
    from smoke_api import run_checks  # pylint: disable=import-outside-toplevel

    await run_checks()
    print("Local setup contract checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
