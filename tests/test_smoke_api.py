import asyncio
import logging
import os
from pathlib import Path

from httpx import ASGITransport, AsyncClient
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


def test_verify_jwt_token_uses_server_controlled_app_metadata(monkeypatch):
    class SupabaseUser:
        id = "user-1"
        email = "user@example.com"
        user_metadata = {"role": "admin"}
        app_metadata = {"role": "analyst"}

    class SupabaseResponse:
        user = SupabaseUser()

    class Auth:
        def get_user(self, token: str):
            return SupabaseResponse()

    class Supabase:
        auth = Auth()

    monkeypatch.setattr(supabase_auth, "supabase", Supabase())

    user = asyncio.run(supabase_auth.verify_jwt_token("Bearer test-token"))

    assert user.metadata == {"role": "analyst"}


def test_admin_update_categorizations_requires_auth_before_mutation(monkeypatch):
    mutation_called = False

    def update_existing_categorizations():
        nonlocal mutation_called
        mutation_called = True
        return 1

    monkeypatch.setattr(
        api_main.report_service,
        "update_existing_categorizations",
        update_existing_categorizations,
    )
    monkeypatch.setattr(
        api_main.report_service,
        "get_threat_type_stats",
        lambda: {"malware": 1},
    )

    async def request_admin_update():
        transport = ASGITransport(app=api_main.app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            return await client.post("/api/admin/update-categorizations")

    response = asyncio.run(request_admin_update())

    assert response.status_code in {401, 403, 503}
    assert mutation_called is False


def test_admin_update_categorizations_rejects_non_admin_before_mutation(monkeypatch):
    mutation_called = False

    def update_existing_categorizations():
        nonlocal mutation_called
        mutation_called = True
        return 1

    monkeypatch.setattr(
        api_main.report_service,
        "update_existing_categorizations",
        update_existing_categorizations,
    )

    user = supabase_auth.AuthenticatedUser(
        user_id="analyst-user",
        email="analyst@example.com",
        metadata={"role": "analyst"},
    )

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(api_main.update_categorizations(user))

    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "Admin privileges required"
    assert mutation_called is False


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


def test_frontend_supabase_client_is_build_safe_without_preview_env():
    supabase_client = read_text("frontend/src/lib/supabase.ts")
    api_client = read_text("frontend/src/lib/api.ts")
    auth_context = read_text("frontend/src/contexts/AuthContext.tsx")

    assert "function hasSupabaseConfig()" in supabase_client
    assert "Supabase configuration is missing" in supabase_client
    assert "private supabase = createClient()" not in api_client
    assert "private getSupabase()" in api_client
    assert "return config;" in api_client
    assert "hasSupabaseConfig() ? createClient() : null" in auth_context
    assert "Authentication is not configured" in auth_context
