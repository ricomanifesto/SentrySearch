import asyncio
import logging
import os
from pathlib import Path

import pytest
from fastapi import HTTPException

from src.auth import supabase_auth
from src.api import main as api_main
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


def test_health_check_redacts_internal_exception(monkeypatch):
    def fail_connection():
        raise RuntimeError("database password leaked")

    monkeypatch.setattr(api_main.report_service, "test_connection", fail_connection)

    response = asyncio.run(api_main.health_check())

    assert response.status_code == 503
    assert response.body == b'{"status":"unhealthy","error":"Health check failed"}'


def test_verify_jwt_token_redacts_internal_exception(monkeypatch, caplog):
    class FailingAuth:
        def get_user(self, token: str):
            raise RuntimeError(f"token backend leaked {token}")

    class FailingSupabase:
        auth = FailingAuth()

    monkeypatch.setattr(supabase_auth, "supabase", FailingSupabase())

    with caplog.at_level(logging.WARNING):
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(supabase_auth.verify_jwt_token("Bearer secret-token"))

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Invalid or expired token"
    assert "secret-token" not in caplog.text


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


def test_threat_profile_modules_use_domain_names():
    assert (
        read_text("src/core/threat_profile_generator.py").count("class ThreatProfileGenerator") == 1
    )
    assert (
        read_text("src/core/cached_threat_profile_generator.py").count(
            "class CachedThreatProfileGenerator"
        )
        == 1
    )
    assert (
        read_text("src/search/threat_knowledge_retriever.py").count(
            "class ThreatKnowledgeRetriever"
        )
        == 1
    )
    assert not (REPO_ROOT / "src/search/ml_agentic_retriever.py").exists()
