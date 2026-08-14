import asyncio
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from httpx import ASGITransport, AsyncClient
import pytest
from fastapi import HTTPException, BackgroundTasks

from src.auth import supabase_auth
from src.api import main as api_main
from src.core.markdown_generator import generate_markdown
from src.domain.reports import (
    GenerationProgress,
    GenerationStage,
    ReportAnalyticsRecord,
    ReportStatus,
)
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
        status="generating",
        generation_stage="researching",
    )

    assert report.to_dict()["user_id"] == "owner-user"
    assert report.to_dict()["generation_stage"] == "researching"


def test_create_report_starts_background_job_without_synchronous_generation(monkeypatch):
    generation_called = False

    class Generator:
        def get_threat_intelligence(self, tool_name: str, progress_callback=None):
            nonlocal generation_called
            generation_called = True
            return {"tool_name": tool_name}

    monkeypatch.setattr(api_main, "ThreatProfileGenerator", Generator)

    created = {}

    def create_pending_report(report_id, tool_name, user_id=None):
        created.update(report_id=report_id, tool_name=tool_name, user_id=user_id)
        return report_id

    monkeypatch.setattr(api_main.report_service, "create_pending_report", create_pending_report)

    user = supabase_auth.AuthenticatedUser(
        user_id="analyst-user",
        email="analyst@example.com",
        metadata={"role": "analyst"},
    )
    background_tasks = BackgroundTasks()

    response = asyncio.run(
        api_main.create_report(
            api_main.ReportCreate(tool_name="Cobalt Strike"),
            background_tasks,
            user,
        )
    )

    assert response["status"] == "generating"
    assert response["report_id"] == created["report_id"]
    assert created["tool_name"] == "Cobalt Strike"
    assert created["user_id"] == "analyst-user"
    # Generation must be deferred to the background task, never run on the request path.
    assert generation_called is False
    assert len(background_tasks.tasks) == 1


@pytest.mark.parametrize("tool_name", ["   ", "x" * 256])
def test_create_report_rejects_invalid_targets_before_storage(monkeypatch, tool_name):
    storage_called = False

    def create_pending_report(*_args, **_kwargs):
        nonlocal storage_called
        storage_called = True

    monkeypatch.setattr(
        api_main.report_service,
        "create_pending_report",
        create_pending_report,
    )
    user = supabase_auth.AuthenticatedUser(
        user_id="analyst-user",
        email="analyst@example.com",
        metadata={"role": "analyst"},
    )

    async def authenticated_user():
        return user

    async def request_report():
        api_main.app.dependency_overrides[api_main.verify_jwt_token] = authenticated_user
        try:
            transport = ASGITransport(app=api_main.app)
            async with AsyncClient(
                transport=transport,
                base_url="http://testserver",
            ) as client:
                return await client.post(
                    "/api/reports",
                    json={"tool_name": tool_name},
                )
        finally:
            api_main.app.dependency_overrides.clear()

    response = asyncio.run(request_report())

    assert response.status_code == 422
    assert storage_called is False


def test_report_create_normalizes_target_whitespace():
    request = api_main.ReportCreate(tool_name="  Cobalt Strike  ")

    assert request.tool_name == "Cobalt Strike"


def test_background_generation_marks_failed_without_leaking_detail(monkeypatch):
    class FailingGenerator:
        def get_threat_intelligence(self, tool_name: str, progress_callback=None):
            return {"error": f"provider key leaked for {tool_name}"}

    monkeypatch.setattr(api_main, "ThreatProfileGenerator", FailingGenerator)

    marked = {}

    def mark_report_failed(report_id):
        marked["report_id"] = report_id
        return True

    def finalize_report(*args, **kwargs):
        raise AssertionError("finalize_report must not run when generation fails")

    monkeypatch.setattr(api_main.report_service, "mark_report_failed", mark_report_failed)
    monkeypatch.setattr(api_main.report_service, "finalize_report", finalize_report)

    # Must not raise, and must record the failure on the row rather than surface detail.
    api_main.run_report_generation("report-1", "SecretTool", "analyst-user")

    assert marked["report_id"] == "report-1"


def test_background_generation_maps_profile_to_storage_schema(monkeypatch):
    profile = {
        "coreMetadata": {"name": "Cobalt Strike"},
        "category": "malware",
        "threatType": "post_exploitation_framework",
        "webSearchSources": {
            "primarySources": [
                {
                    "title": "MITRE ATT&CK: Cobalt Strike",
                    "url": "https://attack.mitre.org/software/S0154/",
                    "domain": "attack.mitre.org",
                    "accessDate": "2026-08-13",
                    "relevanceScore": "0.96",
                    "contentType": "Knowledge base",
                    "keyFindings": "Maps observed behavior to ATT&CK techniques.",
                }
            ]
        },
        "_quality_assessment": {"overall_score": 4.1},
        "_processing_time_ms": 965000,
        "_generation_route": {
            "requested_models": ["google/gemma-4-26b-a4b-it:free"],
            "requested_providers": ["google-ai-studio"],
            "selected_models": ["google/gemma-4-26b-a4b-it"],
            "actual_models": ["google/gemma-4-26b-a4b-it"],
            "providers": ["Google AI Studio"],
            "used_fallback": True,
            "request_count": 4,
        },
        "_evaluation_route": {
            "requested_models": ["google/gemma-4-31b-it:free"],
            "requested_providers": ["google-ai-studio"],
            "selected_models": ["google/gemma-4-31b-it:free"],
            "actual_models": ["google/gemma-4-31b-it:free"],
            "providers": ["Google AI Studio"],
            "used_fallback": False,
            "request_count": 12,
        },
    }

    class Generator:
        def get_threat_intelligence(self, tool_name: str, progress_callback=None):
            if progress_callback:
                progress_callback(
                    GenerationProgress(
                        progress=0.2,
                        stage=GenerationStage.RESEARCHING,
                        message="Processing can be reworded without changing this stage.",
                    )
                )
                progress_callback(
                    GenerationProgress(
                        progress=0.7,
                        stage=GenerationStage.SYNTHESIZING,
                        message="Research wording cannot pull this stage backward.",
                    )
                )
                progress_callback(
                    GenerationProgress(
                        progress=0.75,
                        stage=GenerationStage.VALIDATING,
                        message="Checking the structured response.",
                    )
                )
                progress_callback(
                    GenerationProgress(
                        progress=1.0,
                        stage=GenerationStage.FINALIZING,
                        message="Saving the review record.",
                    )
                )
            return profile

    monkeypatch.setattr(api_main, "ThreatProfileGenerator", Generator)

    captured = {}
    captured_stages = []

    def finalize_report(report_id, report_data, user_id=None):
        captured.update(report_id=report_id, report_data=report_data, user_id=user_id)
        return report_id

    monkeypatch.setattr(api_main.report_service, "finalize_report", finalize_report)
    monkeypatch.setattr(
        api_main.report_service,
        "update_generation_stage",
        lambda report_id, stage: captured_stages.append((report_id, stage)),
        raising=False,
    )

    api_main.run_report_generation("report-9", "Cobalt Strike", "analyst-user")

    data = captured["report_data"]
    assert captured["user_id"] == "analyst-user"
    # The raw profile is persisted as structured extraction data, plus a rendered
    # narrative, the quality score, real timing, and search tags.
    assert data["threat_data"] is not profile
    assert "_generation_route" not in data["threat_data"]
    assert "_evaluation_route" not in data["threat_data"]
    assert data["generation_route"] == profile["_generation_route"]
    assert data["evaluation_route"] == profile["_evaluation_route"]
    assert data["quality_score"] == 4.1
    assert data["processing_time_ms"] == 965000
    assert data["threat_type"] == "post_exploitation_framework"
    assert data["web_sources"] == profile["webSearchSources"]["primarySources"]
    assert "cobalt strike" in data["search_tags"]
    assert isinstance(data["markdown_content"], str) and data["markdown_content"]
    assert captured_stages == [
        ("report-9", "researching"),
        ("report-9", "synthesizing"),
        ("report-9", "validating"),
        ("report-9", "finalizing"),
    ]


def test_background_generation_does_not_infer_stage_from_progress_copy():
    source = read_text("src/api/main.py")

    assert "generation_stage_from_progress" not in source
    assert ".message.casefold()" not in source


def test_unknown_stored_generation_stage_falls_back_to_report_status():
    assert (
        api_main.get_generation_stage(
            {"status": "generating", "generation_stage": "legacy-unknown-stage"}
        )
        == api_main.GenerationStage.QUEUED
    )


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
            api_main.SearchFilters(
                query="example",
                threat_types=["malware"],
                tags=["apt"],
                min_quality_score=3.0,
                date_range_days=30,
            ),
            api_main.PaginationParams(sort_by="quality_score", sort_order="desc"),
            user,
        )
    )

    assert response["reports"] == []
    assert captured_search_kwargs["user_id"] == "analyst-user"
    assert captured_search_kwargs["search_query"] == "example"
    assert captured_search_kwargs["threat_types"] == ["malware"]
    assert captured_search_kwargs["tags"] == ["apt"]
    assert captured_search_kwargs["min_quality_score"] == 3.0
    assert captured_search_kwargs["sort_by"] == "quality_score"
    assert captured_search_kwargs["sort_order"] == "desc"
    assert "created_after" in captured_search_kwargs
    assert captured_count_kwargs["user_id"] == "analyst-user"
    assert captured_count_kwargs["search_query"] == "example"
    assert captured_count_kwargs["threat_types"] == ["malware"]
    assert captured_count_kwargs["tags"] == ["apt"]
    assert captured_count_kwargs["min_quality_score"] == 3.0
    assert "created_after" in captured_count_kwargs


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

    assert response["reports"][0].quality_score is None
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

    assert response.quality_score is None
    assert response.processing_time_ms == 0
    assert response.category == "unknown"
    assert response.threat_type == "unknown"
    assert response.web_sources == []
    assert response.generation_route is None
    assert response.evaluation_route is None


def test_report_detail_returns_persisted_model_route_provenance(monkeypatch):
    route = {
        "requested_models": ["google/gemma-4-26b-a4b-it:free"],
        "requested_providers": ["google-ai-studio"],
        "selected_models": ["google/gemma-4-26b-a4b-it"],
        "actual_models": ["google/gemma-4-26b-a4b-it"],
        "providers": ["Google AI Studio"],
        "used_fallback": True,
        "request_count": 4,
    }
    stored_report = {
        "id": "report-fallback",
        "tool_name": "Sliver",
        "category": "malware",
        "threat_type": "post_exploitation_framework",
        "created_at": datetime.now(timezone.utc),
        "quality_score": 4.0,
        "processing_time_ms": 1200,
        "user_id": "analyst-user",
        "generation_route": route,
        "evaluation_route": None,
    }
    user = supabase_auth.AuthenticatedUser(
        user_id="analyst-user",
        email="analyst@example.com",
        metadata={"role": "analyst"},
    )
    monkeypatch.setattr(
        api_main.report_service, "get_report", lambda *args, **kwargs: stored_report
    )

    response = asyncio.run(api_main.get_report("report-fallback", True, user))

    assert response.generation_route is not None
    assert response.generation_route.used_fallback is True
    assert response.generation_route.actual_models == ["google/gemma-4-26b-a4b-it"]


def test_report_detail_derives_structured_sources_from_legacy_profile(monkeypatch):
    stored_report = {
        "id": "report-legacy",
        "tool_name": "Cobalt Strike",
        "category": "malware",
        "threat_type": "post_exploitation_framework",
        "created_at": datetime.now(timezone.utc),
        "quality_score": 4.1,
        "processing_time_ms": 1200,
        "generation_stage": "validating",
        "user_id": "analyst-user",
        "threat_data": {
            "webSearchSources": {
                "primarySources": [
                    {
                        "title": "MITRE ATT&CK: Cobalt Strike",
                        "url": "https://attack.mitre.org/software/S0154/",
                        "domain": "attack.mitre.org",
                        "accessDate": "2026-08-13",
                        "relevanceScore": "0.96",
                        "contentType": "Knowledge base",
                        "keyFindings": "Maps observed behavior to ATT&CK techniques.",
                    }
                ]
            }
        },
    }
    user = supabase_auth.AuthenticatedUser(
        user_id="analyst-user",
        email="analyst@example.com",
        metadata={"role": "analyst"},
    )

    monkeypatch.setattr(
        api_main.report_service, "get_report", lambda *args, **kwargs: stored_report
    )

    response = asyncio.run(api_main.get_report("report-legacy", True, user))

    assert len(response.web_sources) == 1
    source = response.web_sources[0]
    assert source.title == "MITRE ATT&CK: Cobalt Strike"
    assert source.url == "https://attack.mitre.org/software/S0154/"
    assert source.access_date == "2026-08-13"
    assert source.key_findings.startswith("Maps observed behavior")
    assert response.generation_stage == "validating"


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

    assert response["reports"][0].quality_score is None
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
    captured_analytics_kwargs = {}
    captured_list_kwargs = {}

    def count_reports(**kwargs):
        captured_count_kwargs.append(kwargs)
        return 0

    def list_analytics_records(**kwargs):
        captured_analytics_kwargs.update(kwargs)
        return []

    def list_reports(**kwargs):
        captured_list_kwargs.update(kwargs)
        return []

    monkeypatch.setattr(api_main.report_service, "count_reports", count_reports)
    monkeypatch.setattr(api_main.report_service, "list_analytics_records", list_analytics_records)
    monkeypatch.setattr(api_main.report_service, "list_reports", list_reports)

    user = supabase_auth.AuthenticatedUser(
        user_id="analyst-user",
        email="analyst@example.com",
        metadata={"role": "analyst"},
    )

    response = asyncio.run(api_main.get_analytics("30d", user))

    assert response["overview"]["total_reports"] == 0
    assert all(kwargs["user_id"] == "analyst-user" for kwargs in captured_count_kwargs)
    assert captured_analytics_kwargs["user_id"] == "analyst-user"
    assert "created_after" in captured_analytics_kwargs
    assert captured_list_kwargs["user_id"] == "analyst-user"


def test_analytics_trends_are_derived_from_persisted_records():
    start = datetime(2026, 8, 10, tzinfo=timezone.utc)
    records = [
        ReportAnalyticsRecord(
            created_at=start,
            quality_score=4.5,
            processing_time_ms=1000,
            status=ReportStatus.COMPLETED,
            threat_type="malware",
        ),
        ReportAnalyticsRecord(
            created_at=start + timedelta(days=1),
            quality_score=2.5,
            processing_time_ms=3000,
            status=ReportStatus.FAILED,
            threat_type="malware",
        ),
    ]

    trends = api_main.build_analytics_trends(records, start_date=start, days=1)

    assert [point["count"] for point in trends["daily_reports"]] == [1, 1]
    assert [point["avg_time_ms"] for point in trends["processing_time_trends"]] == [
        1000,
        3000,
    ]
    assert trends["threat_type_distribution"] == [
        {"threat_type": "malware", "count": 2, "percentage": 100.0}
    ]
    assert [bucket["count"] for bucket in trends["quality_score_distribution"]] == [
        1,
        0,
        1,
        0,
        0,
    ]


def test_route_performance_separates_primary_fallback_and_legacy_reports():
    start = datetime(2026, 8, 14, tzinfo=timezone.utc)
    records = [
        ReportAnalyticsRecord(
            created_at=start,
            quality_score=4.0,
            processing_time_ms=1000,
            status=ReportStatus.COMPLETED,
            threat_type="malware",
            generation_used_fallback=False,
        ),
        ReportAnalyticsRecord(
            created_at=start,
            quality_score=3.0,
            processing_time_ms=3000,
            status=ReportStatus.COMPLETED,
            threat_type="malware",
            generation_used_fallback=True,
        ),
        ReportAnalyticsRecord(
            created_at=start,
            quality_score=None,
            processing_time_ms=5000,
            status=ReportStatus.COMPLETED,
            threat_type="malware",
            generation_used_fallback=None,
        ),
        ReportAnalyticsRecord(
            created_at=start,
            quality_score=None,
            processing_time_ms=None,
            status=ReportStatus.FAILED,
            threat_type="malware",
            generation_used_fallback=None,
        ),
    ]

    comparison = api_main.build_route_performance(records)

    assert comparison == [
        {
            "route": "primary",
            "report_count": 1,
            "avg_quality_score": 4.0,
            "avg_processing_time_ms": 1000.0,
        },
        {
            "route": "fallback",
            "report_count": 1,
            "avg_quality_score": 3.0,
            "avg_processing_time_ms": 3000.0,
        },
        {
            "route": "unrecorded",
            "report_count": 1,
            "avg_quality_score": None,
            "avg_processing_time_ms": 5000.0,
        },
    ]


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
        return {"average": None, "distribution": [], "total_scored": 0}

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
    assert response["summary"]["avg_quality_score"] is None
    assert all(kwargs["user_id"] == "analyst-user" for kwargs in captured_count_kwargs)
    assert captured_quality_kwargs["user_id"] == "analyst-user"
    assert captured_threat_kwargs["user_id"] == "analyst-user"
    assert captured_list_kwargs["user_id"] == "analyst-user"


def test_python_tooling_is_uv_managed():
    pyproject = read_text("pyproject.toml")
    lockfile = read_text("uv.lock")
    railway_requirements = read_text("requirements.txt")

    assert "[dependency-groups]" in pyproject
    for tool in ["ruff", "black", "ty", "pytest"]:
        assert f'"{tool}>=' in pyproject
        assert f'name = "{tool}"' in lockfile
    assert "\nhttpx==" in railway_requirements
    assert "\nopenai==" not in railway_requirements


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


def test_retired_retrieval_stack_is_absent():
    assert (
        read_text("src/core/threat_profile_generator.py").count("class ThreatProfileGenerator") == 1
    )
    assert not (REPO_ROOT / "src/core/cached_threat_profile_generator.py").exists()
    assert not (REPO_ROOT / "src/ui/app.py").exists()
    assert "class SectionImprover" not in read_text("src/core/section_validator.py")
    assert "self.improver" not in read_text("src/core/threat_profile_generator.py")
    assert not (REPO_ROOT / "src/data/ml_knowledge_base_builder.py").exists()
    assert not (REPO_ROOT / "src/search/bm25_retriever.py").exists()
    assert not (REPO_ROOT / "src/search/ml_agentic_retriever.py").exists()
    for retired_path in [
        "worker.js",
        "wrangler.toml",
        "dev/check_worker.mjs",
        "src/core/ml_guidance_generator.py",
        "src/search/threat_knowledge_retriever.py",
    ]:
        assert not (REPO_ROOT / retired_path).exists()

    product_sources = "\n".join(
        read_text(path)
        for path in [
            ".env.example",
            "README.md",
            "pyproject.toml",
            "src/api/contracts.py",
            "src/api/main.py",
            "src/core/markdown_generator.py",
            "src/core/threat_profile_generator.py",
            "src/core/trace_exporter.py",
            "frontend/src/app/generate/page.tsx",
            "frontend/src/lib/api-contracts.ts",
        ]
    )
    for retired_marker in [
        "enable_ml_guidance",
        "mlGuidance",
        "PINECONE",
        "WORKERS_URL",
        "Cloudflare Worker",
    ]:
        assert retired_marker not in product_sources


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


def test_shared_report_contracts_have_one_backend_and_frontend_owner():
    api_main = read_text("src/api/main.py")
    api_contracts = read_text("src/api/contracts.py")
    report_domain = read_text("src/domain/reports.py")
    api_client = read_text("frontend/src/lib/api.ts")
    frontend_contracts = read_text("frontend/src/lib/api-contracts.ts")
    report_query = read_text("frontend/src/lib/report-query.ts")

    assert "class SearchFilters" not in api_main
    assert "class SearchFilters" in api_contracts
    assert "class ReportSortField" in report_domain
    assert "export interface Report" not in api_client
    assert "export interface Report" in frontend_contracts
    assert "export const defaultReportQuery" in report_query
    assert "export function toListReportFilters" in report_query
