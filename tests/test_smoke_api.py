import asyncio
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from httpx import ASGITransport, AsyncClient
import pytest
from fastapi import HTTPException

from src.auth import supabase_auth
from src.api import main as api_main
from src.core.markdown_generator import generate_markdown
from src.storage.models import Report
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


def test_readiness_check_fails_when_database_is_disconnected(monkeypatch):
    monkeypatch.setattr(api_main.report_service, "test_connection", lambda: False)

    response = asyncio.run(api_main.readiness_check())

    assert response.status_code == 503
    assert response.body == b'{"status":"unready","database":"disconnected"}'


def test_readiness_check_passes_when_database_is_connected(monkeypatch):
    monkeypatch.setattr(api_main.report_service, "test_connection", lambda: True)

    response = asyncio.run(api_main.readiness_check())

    assert response == {"status": "ready", "database": "connected"}


def test_readiness_check_redacts_internal_exception(monkeypatch):
    def fail_connection():
        raise RuntimeError("readiness password leaked")

    monkeypatch.setattr(api_main.report_service, "test_connection", fail_connection)

    response = asyncio.run(api_main.readiness_check())

    assert response.status_code == 503
    assert response.body == b'{"status":"unready","error":"Readiness check failed"}'


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


def test_list_reports_requires_auth_before_storage_read(monkeypatch):
    storage_called = False

    def list_reports(*args, **kwargs):
        nonlocal storage_called
        storage_called = True
        return []

    monkeypatch.setattr(api_main.report_service, "list_reports", list_reports)
    monkeypatch.setattr(api_main.report_service, "count_reports", lambda **kwargs: 0)

    async def request_reports():
        transport = ASGITransport(app=api_main.app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            return await client.get("/api/reports")

    response = asyncio.run(request_reports())

    assert response.status_code in {401, 403, 503}
    assert storage_called is False


def test_get_report_requires_auth_before_storage_read(monkeypatch):
    storage_called = False

    def get_report(report_id: str, include_content: bool = True):
        nonlocal storage_called
        storage_called = True
        return {"id": report_id}

    monkeypatch.setattr(api_main.report_service, "get_report", get_report)

    async def request_report():
        transport = ASGITransport(app=api_main.app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            return await client.get("/api/reports/report-1")

    response = asyncio.run(request_report())

    assert response.status_code in {401, 403, 503}
    assert storage_called is False


def test_report_model_exposes_owner_for_api_authorization():
    report = Report(
        id=uuid.uuid4(),
        tool_name="Example",
        category="malware",
        threat_type="trojan",
        created_at=datetime.now(timezone.utc),
        user_id="owner-user",
    )

    assert report.to_dict()["user_id"] == "owner-user"


def test_create_report_redacts_generation_failure_detail(monkeypatch):
    class FailingGenerator:
        enable_ml_guidance = True

        def get_threat_intelligence(self, tool_name: str):
            return {"error": f"provider key leaked for {tool_name}"}

    monkeypatch.setattr(api_main, "ThreatProfileGenerator", FailingGenerator)

    user = supabase_auth.AuthenticatedUser(
        user_id="analyst-user",
        email="analyst@example.com",
        metadata={"role": "analyst"},
    )

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(api_main.create_report(api_main.ReportCreate(tool_name="SecretTool"), user))

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "Failed to generate threat intelligence"
    assert "provider key" not in exc_info.value.detail
    assert "SecretTool" not in exc_info.value.detail


def test_markdown_generation_redacts_internal_exception_detail():
    markdown = generate_markdown(
        {
            "coreMetadata": {"name": "SecretTool"},
            "_quality_assessment": {"overall_score": "secret-score"},
        }
    )

    assert markdown == (
        "# Error in Markdown Generation\n\n"
        "The report could not be rendered. Please retry generation."
    )
    assert "not supported" not in markdown
    assert "SecretTool" not in markdown


def test_markdown_generation_redacts_ml_guidance_error_detail():
    markdown = generate_markdown(
        {
            "coreMetadata": {"name": "ExampleTool"},
            "mlGuidance": {
                "enabled": False,
                "error": "provider token leaked for ExampleTool",
                "fallbackGuidance": "Use behavioral anomaly detection.",
            },
        }
    )

    assert "ML guidance generation failed" in markdown
    assert "**Error**: ML guidance could not be generated." in markdown
    assert "Use behavioral anomaly detection." in markdown
    assert "provider token" not in markdown
    assert "**Error**: ML guidance could not be generated for ExampleTool" not in markdown


def test_legacy_ui_generation_redacts_internal_exception_detail(monkeypatch):
    from src.ui import app as ui_app

    class FailingGenerator:
        enable_quality_control = True

        def __init__(self, *args, **kwargs):
            pass

        def get_threat_intelligence(self, tool_name: str, progress_callback=None):
            if progress_callback:
                progress_callback(0.5, "Normal generation progress")
                progress_callback(1.0, f"❌ Error: provider token leaked for {tool_name}")
            raise RuntimeError(f"provider token leaked for {tool_name}")

    progress_updates = []

    def progress(value, message):
        progress_updates.append((value, message))

    monkeypatch.setattr(ui_app, "CachedThreatProfileGenerator", FailingGenerator)

    message, quality = ui_app.generate_threat_profile("SecretTool", True, progress=progress)

    assert message == "Error generating profile. Please try again."
    assert quality is None
    assert progress_updates[-1] == (1.0, "Error generating profile. Please try again.")
    assert progress_updates[0] == (0.1, "🔄 Initializing threat intelligence generation...")
    assert progress_updates[1] == (0.5, "Normal generation progress")
    assert "provider token" not in message
    assert "SecretTool" not in message
    assert all("provider token" not in update[1] for update in progress_updates)
    assert all("SecretTool" not in update[1] for update in progress_updates)


def test_search_reports_requires_auth_before_storage_read(monkeypatch):
    storage_called = False

    def search_reports(*args, **kwargs):
        nonlocal storage_called
        storage_called = True
        return []

    monkeypatch.setattr(api_main.report_service, "search_reports", search_reports)
    monkeypatch.setattr(api_main.report_service, "count_search_results", lambda **kwargs: 0)

    async def request_search():
        transport = ASGITransport(app=api_main.app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            return await client.post("/api/search", json={"query": "example"})

    response = asyncio.run(request_search())

    assert response.status_code in {401, 403, 503}
    assert storage_called is False


def test_search_reports_filters_by_authenticated_non_admin(monkeypatch):
    captured_search_kwargs = {}
    captured_count_kwargs = {}

    def search_reports(**kwargs):
        captured_search_kwargs.update(kwargs)
        return []

    def count_search_results(**kwargs):
        captured_count_kwargs.update(kwargs)
        return 0

    monkeypatch.setattr(api_main.report_service, "search_reports", search_reports)
    monkeypatch.setattr(api_main.report_service, "count_search_results", count_search_results)

    user = supabase_auth.AuthenticatedUser(
        user_id="analyst-user",
        email="analyst@example.com",
        metadata={"role": "analyst"},
    )

    response = asyncio.run(
        api_main.search_reports(
            api_main.SearchFilters(query="example"),
            api_main.PaginationParams(),
            user,
        )
    )

    assert response["reports"] == []
    assert captured_search_kwargs["user_id"] == "analyst-user"
    assert captured_count_kwargs["user_id"] == "analyst-user"


def test_search_filters_requires_auth_before_storage_read(monkeypatch):
    storage_called = False

    def get_unique_threat_types(*args, **kwargs):
        nonlocal storage_called
        storage_called = True
        return []

    monkeypatch.setattr(api_main.report_service, "get_unique_threat_types", get_unique_threat_types)
    monkeypatch.setattr(api_main.report_service, "get_unique_categories", lambda **kwargs: [])
    monkeypatch.setattr(api_main.report_service, "get_popular_tags", lambda **kwargs: [])

    async def request_filters():
        transport = ASGITransport(app=api_main.app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            return await client.get("/api/search/filters")

    response = asyncio.run(request_filters())

    assert response.status_code in {401, 403, 503}
    assert storage_called is False


def test_search_filters_scope_by_authenticated_non_admin(monkeypatch):
    captured_threat_kwargs = {}
    captured_category_kwargs = {}
    captured_tag_kwargs = {}

    def get_unique_threat_types(**kwargs):
        captured_threat_kwargs.update(kwargs)
        return []

    def get_unique_categories(**kwargs):
        captured_category_kwargs.update(kwargs)
        return []

    def get_popular_tags(**kwargs):
        captured_tag_kwargs.update(kwargs)
        return []

    monkeypatch.setattr(api_main.report_service, "get_unique_threat_types", get_unique_threat_types)
    monkeypatch.setattr(api_main.report_service, "get_unique_categories", get_unique_categories)
    monkeypatch.setattr(api_main.report_service, "get_popular_tags", get_popular_tags)

    user = supabase_auth.AuthenticatedUser(
        user_id="analyst-user",
        email="analyst@example.com",
        metadata={"role": "analyst"},
    )

    response = asyncio.run(api_main.get_search_filters(user))

    assert response["threat_types"] == []
    assert captured_threat_kwargs["user_id"] == "analyst-user"
    assert captured_category_kwargs["user_id"] == "analyst-user"
    assert captured_tag_kwargs["user_id"] == "analyst-user"


def test_report_responses_default_null_quality_score(monkeypatch):
    stored_report = {
        "id": "report-1",
        "tool_name": "Example",
        "category": None,
        "threat_type": None,
        "created_at": datetime.now(timezone.utc),
        "quality_score": None,
        "processing_time_ms": None,
        "user_id": "analyst-user",
    }
    user = supabase_auth.AuthenticatedUser(
        user_id="analyst-user",
        email="analyst@example.com",
        metadata={"role": "analyst"},
    )

    monkeypatch.setattr(api_main.report_service, "list_reports", lambda **kwargs: [stored_report])
    monkeypatch.setattr(api_main.report_service, "count_reports", lambda **kwargs: 1)

    response = asyncio.run(api_main.list_reports(api_main.PaginationParams(), user))

    assert response["reports"][0].quality_score == 0.0
    assert response["reports"][0].processing_time_ms == 0
    assert response["reports"][0].category == "unknown"
    assert response["reports"][0].threat_type == "unknown"


def test_report_detail_defaults_null_quality_score(monkeypatch):
    stored_report = {
        "id": "report-1",
        "tool_name": "Example",
        "category": None,
        "threat_type": None,
        "created_at": datetime.now(timezone.utc),
        "quality_score": None,
        "processing_time_ms": None,
        "user_id": "analyst-user",
    }
    user = supabase_auth.AuthenticatedUser(
        user_id="analyst-user",
        email="analyst@example.com",
        metadata={"role": "analyst"},
    )

    monkeypatch.setattr(
        api_main.report_service, "get_report", lambda *args, **kwargs: stored_report
    )

    response = asyncio.run(api_main.get_report("report-1", True, user))

    assert response.quality_score == 0.0
    assert response.processing_time_ms == 0
    assert response.category == "unknown"
    assert response.threat_type == "unknown"


def test_search_results_default_null_quality_score(monkeypatch):
    stored_report = {
        "id": "report-1",
        "tool_name": "Example",
        "category": None,
        "threat_type": None,
        "created_at": datetime.now(timezone.utc),
        "quality_score": None,
        "processing_time_ms": None,
        "user_id": "analyst-user",
    }
    user = supabase_auth.AuthenticatedUser(
        user_id="analyst-user",
        email="analyst@example.com",
        metadata={"role": "analyst"},
    )

    monkeypatch.setattr(api_main.report_service, "search_reports", lambda **kwargs: [stored_report])
    monkeypatch.setattr(api_main.report_service, "count_search_results", lambda **kwargs: 1)

    response = asyncio.run(
        api_main.search_reports(
            api_main.SearchFilters(query="example"),
            api_main.PaginationParams(),
            user,
        )
    )

    assert response["reports"][0].quality_score == 0.0
    assert response["reports"][0].processing_time_ms == 0
    assert response["reports"][0].category == "unknown"
    assert response["reports"][0].threat_type == "unknown"


def test_analytics_requires_auth_before_storage_read(monkeypatch):
    storage_called = False

    def count_reports(**kwargs):
        nonlocal storage_called
        storage_called = True
        return 0

    monkeypatch.setattr(api_main.report_service, "count_reports", count_reports)

    async def request_analytics():
        transport = ASGITransport(app=api_main.app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            return await client.get("/api/analytics")

    response = asyncio.run(request_analytics())

    assert response.status_code in {401, 403, 503}
    assert storage_called is False


def test_dashboard_analytics_requires_auth_before_storage_read(monkeypatch):
    storage_called = False

    def count_reports(**kwargs):
        nonlocal storage_called
        storage_called = True
        return 0

    monkeypatch.setattr(api_main.report_service, "count_reports", count_reports)

    async def request_dashboard_analytics():
        transport = ASGITransport(app=api_main.app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            return await client.get("/api/analytics/dashboard")

    response = asyncio.run(request_dashboard_analytics())

    assert response.status_code in {401, 403, 503}
    assert storage_called is False


def test_analytics_filters_report_reads_by_authenticated_non_admin(monkeypatch):
    captured_count_kwargs = []
    captured_quality_kwargs = {}
    captured_threat_kwargs = {}
    captured_list_kwargs = {}

    def count_reports(**kwargs):
        captured_count_kwargs.append(kwargs)
        return 0

    def get_quality_score_distribution(**kwargs):
        captured_quality_kwargs.update(kwargs)
        return {"average": 0.0, "distribution": {}, "total_scored": 0}

    def get_threat_type_stats(**kwargs):
        captured_threat_kwargs.update(kwargs)
        return {}

    def list_reports(**kwargs):
        captured_list_kwargs.update(kwargs)
        return []

    monkeypatch.setattr(api_main.report_service, "count_reports", count_reports)
    monkeypatch.setattr(
        api_main.report_service,
        "get_quality_score_distribution",
        get_quality_score_distribution,
    )
    monkeypatch.setattr(api_main.report_service, "get_threat_type_stats", get_threat_type_stats)
    monkeypatch.setattr(api_main.report_service, "list_reports", list_reports)

    user = supabase_auth.AuthenticatedUser(
        user_id="analyst-user",
        email="analyst@example.com",
        metadata={"role": "analyst"},
    )

    response = asyncio.run(api_main.get_analytics("30d", user))

    assert response["overview"]["total_reports"] == 0
    assert all(kwargs["user_id"] == "analyst-user" for kwargs in captured_count_kwargs)
    assert captured_quality_kwargs["user_id"] == "analyst-user"
    assert captured_threat_kwargs["user_id"] == "analyst-user"
    assert captured_list_kwargs["user_id"] == "analyst-user"


def test_dashboard_analytics_filters_report_reads_by_authenticated_non_admin(monkeypatch):
    captured_count_kwargs = []
    captured_quality_kwargs = {}
    captured_threat_kwargs = {}
    captured_list_kwargs = {}

    def count_reports(**kwargs):
        captured_count_kwargs.append(kwargs)
        return 0

    def get_quality_score_distribution(**kwargs):
        captured_quality_kwargs.update(kwargs)
        return {"average": 0.0, "distribution": [], "total_scored": 0}

    def get_threat_type_stats(**kwargs):
        captured_threat_kwargs.update(kwargs)
        return {}

    def list_reports(**kwargs):
        captured_list_kwargs.update(kwargs)
        return []

    monkeypatch.setattr(api_main.report_service, "count_reports", count_reports)
    monkeypatch.setattr(
        api_main.report_service,
        "get_quality_score_distribution",
        get_quality_score_distribution,
    )
    monkeypatch.setattr(api_main.report_service, "get_threat_type_stats", get_threat_type_stats)
    monkeypatch.setattr(api_main.report_service, "list_reports", list_reports)

    user = supabase_auth.AuthenticatedUser(
        user_id="analyst-user",
        email="analyst@example.com",
        metadata={"role": "analyst"},
    )

    response = asyncio.run(api_main.get_dashboard_analytics(user))

    assert response["summary"]["total_reports"] == 0
    assert all(kwargs["user_id"] == "analyst-user" for kwargs in captured_count_kwargs)
    assert captured_quality_kwargs["user_id"] == "analyst-user"
    assert captured_threat_kwargs["user_id"] == "analyst-user"
    assert captured_list_kwargs["user_id"] == "analyst-user"


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
