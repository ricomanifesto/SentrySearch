import asyncio
import os
from pathlib import Path

from dev.smoke_api import configure_local_environment, run_checks

REPO_ROOT = Path(__file__).resolve().parents[1]


def read_text(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_configure_local_environment_sets_harmless_defaults(monkeypatch):
    defaults = {
        "DB_HOST": "localhost",
        "DB_PORT": "5432",
        "DB_NAME": "sentrysearch",
        "DB_USER": "postgres",
        "DB_DEBUG": "false",
        "AWS_REGION": "us-east-1",
        "AWS_S3_BUCKET": "sentrysearch-local-dev",
    }

    for name in defaults:
        monkeypatch.delenv(name, raising=False)

    configure_local_environment()

    for name, value in defaults.items():
        assert os.environ[name] == value


def test_smoke_api_exercises_local_auth_boundary_without_live_services():
    assert asyncio.run(run_checks()) == 0


def test_python_tooling_is_uv_managed():
    pyproject = read_text("pyproject.toml")
    lockfile = read_text("uv.lock")

    assert "[dependency-groups]" in pyproject
    for tool in ["ruff", "black", "ty", "pytest"]:
        assert f'"{tool}>=' in pyproject
        assert f'name = "{tool}"' in lockfile


def test_public_docs_do_not_reference_private_workflow_sources():
    public_text = "\n".join(
        read_text(path)
        for path in [
            "AGENTS.md",
            "README.md",
            "dev/check_local_setup.py",
            "tests/test_smoke_api.py",
        ]
    )

    private_markers = [
        "irr" + "-fai",
        "eval" + "-harness",
        "/".join(["", "Users", "michaelrico", "Projects", "irr" + "-fai"]),
    ]
    for marker in private_markers:
        assert marker not in public_text
