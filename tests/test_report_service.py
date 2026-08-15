from datetime import datetime, timezone
from contextlib import contextmanager
from typing import Any, cast
import uuid

import pytest
from pydantic import ValidationError
from sqlalchemy.dialects import postgresql

from src.api.contracts import ModelRouteProvenance, PaginationParams, ReportDetail, SearchFilters
from src.domain.model_routes import generation_fallback_state
from src.domain.reports import (
    AnalystDisposition,
    ClassificationStatus,
    ReportFilters,
    ReportSortField,
    ReportStatus,
    ReviewStatus,
    SortOrder,
)
from src.storage.report_service import ReportStorageService
from src.storage.models import Report, ReportDispositionEvent
from src.storage.database import DatabaseManager


def compile_sort(sort_by: str, sort_order: str) -> str:
    expression = ReportStorageService._report_sort_expression(sort_by, sort_order)
    return str(expression.compile(dialect=postgresql.dialect()))


def test_metric_sort_orders_null_values_last():
    assert compile_sort("quality_score", "desc") == "reports.quality_score DESC NULLS LAST"
    assert compile_sort("processing_time_ms", "desc") == (
        "reports.processing_time_ms DESC NULLS LAST"
    )


def test_unknown_sort_field_falls_back_to_created_at_with_nulls_last():
    assert compile_sort("unsupported_field", "desc") == "reports.created_at DESC NULLS LAST"


def test_report_contracts_reject_unknown_sort_fields():
    with pytest.raises(ValidationError):
        PaginationParams(sort_by=cast(Any, "unsupported_field"))


def test_report_contract_collection_defaults_are_isolated():
    first_filters = SearchFilters()
    second_filters = SearchFilters()
    first_filters.tags.append("reviewed")

    first_report = ReportDetail(
        id="one",
        tool_name="Example",
        category="malware",
        threat_type="trojan",
        quality_score=4.0,
        created_at=datetime(2026, 8, 12, 12, tzinfo=timezone.utc),
    )
    second_report = ReportDetail(
        id="two",
        tool_name="Another",
        category="malware",
        threat_type="trojan",
        quality_score=4.0,
        created_at=datetime(2026, 8, 12, 12, tzinfo=timezone.utc),
    )
    first_report.search_tags.append("reviewed")

    assert second_filters.tags == []
    assert second_report.search_tags == []


def test_report_schema_and_contract_preserve_route_provenance():
    assert "generation_route" in Report.__table__.c
    assert "research_route" in Report.__table__.c
    assert "synthesis_route" in Report.__table__.c
    assert "evaluation_route" in Report.__table__.c

    route = ModelRouteProvenance(
        requested_models=["google/gemma-4-26b-a4b-it:free"],
        requested_providers=["google-ai-studio"],
        selected_models=["google/gemma-4-26b-a4b-it"],
        actual_models=["google/gemma-4-26b-a4b-it"],
        providers=["Google AI Studio"],
        used_fallback=True,
        request_count=4,
    )

    assert route.used_fallback is True
    assert generation_fallback_state(route.model_dump()) is True
    assert generation_fallback_state(None) is None


def test_additive_migration_creates_model_route_columns():
    statements: list[str] = []

    class FakeConnection:
        def execute(self, statement):
            statements.append(str(statement))

    class FakeEngine:
        @contextmanager
        def begin(self):
            yield FakeConnection()

    manager = DatabaseManager.__new__(DatabaseManager)
    manager.engine = cast(Any, FakeEngine())

    manager.migrate_schema()

    assert "ALTER TABLE reports ADD COLUMN IF NOT EXISTS generation_route JSONB" in statements
    assert "ALTER TABLE reports ADD COLUMN IF NOT EXISTS research_route JSONB" in statements
    assert "ALTER TABLE reports ADD COLUMN IF NOT EXISTS synthesis_route JSONB" in statements
    assert "ALTER TABLE reports ADD COLUMN IF NOT EXISTS evaluation_route JSONB" in statements
    assert (
        "ALTER TABLE reports ADD COLUMN IF NOT EXISTS evaluation_status VARCHAR(20)" in statements
    )
    assert (
        "ALTER TABLE reports ADD COLUMN IF NOT EXISTS evaluation_error_code VARCHAR(50)"
        in statements
    )
    assert (
        "ALTER TABLE reports ADD COLUMN IF NOT EXISTS evaluation_attempts INTEGER DEFAULT 0"
        in statements
    )
    assert "ALTER TABLE reports ADD COLUMN IF NOT EXISTS evaluated_at TIMESTAMPTZ" in statements
    assert "ALTER TABLE reports ADD COLUMN IF NOT EXISTS content_preview TEXT" in statements
    assert "ALTER TABLE reports ADD COLUMN IF NOT EXISTS review_status VARCHAR(30)" in statements
    assert (
        "ALTER TABLE reports ADD COLUMN IF NOT EXISTS classification_status VARCHAR(30)"
        in statements
    )
    assert (
        "ALTER TABLE reports ADD COLUMN IF NOT EXISTS generation_failure_stage VARCHAR(20)"
        in statements
    )
    assert any(
        "CREATE TABLE IF NOT EXISTS report_disposition_events" in item for item in statements
    )


def test_report_filters_are_immutable_and_normalize_collections():
    filters = ReportFilters(
        threat_types=("trojan", "ransomware"),
        tags=("endpoint",),
        statuses=(ReportStatus.COMPLETED,),
        review_statuses=(ReviewStatus.NEEDS_ATTENTION,),
        sort_by=ReportSortField.QUALITY_SCORE,
        sort_order=SortOrder.ASCENDING,
    )

    assert filters.threat_types == ("trojan", "ransomware")
    assert filters.tags == ("endpoint",)
    assert filters.statuses == (ReportStatus.COMPLETED,)
    assert filters.review_statuses == (ReviewStatus.NEEDS_ATTENTION,)
    assert filters.sort_by is ReportSortField.QUALITY_SCORE
    assert filters.sort_order is SortOrder.ASCENDING

    with pytest.raises(AttributeError):
        setattr(filters, "sort_by", ReportSortField.CREATED_AT)


def test_search_filter_expression_has_each_advertised_text_field_once():
    filters = ReportFilters(search_query="example")

    expressions = ReportStorageService._report_filter_expressions(filters)
    compiled = " ".join(
        str(expression.compile(dialect=postgresql.dialect())) for expression in expressions
    )

    assert compiled.count("reports.tool_name ILIKE") == 1
    assert compiled.count("reports.category ILIKE") == 1
    assert compiled.count("reports.threat_type ILIKE") == 1


def test_review_and_generation_statuses_are_queryable_contract_fields():
    filters = ReportFilters(
        statuses=(ReportStatus.COMPLETED,),
        review_statuses=(ReviewStatus.REVIEWABLE, ReviewStatus.NEEDS_ATTENTION),
    )
    compiled = " ".join(
        str(
            expression.compile(
                dialect=postgresql.dialect(),
                compile_kwargs={"literal_binds": True},
            )
        )
        for expression in ReportStorageService._report_filter_expressions(filters)
    )

    assert "reports.status IN" in compiled
    assert "reports.review_status IN" in compiled


def test_actionable_filter_uses_current_evaluation_disposition_without_backfill():
    filters = ReportFilters(requires_action=True)
    compiled = " ".join(
        str(
            expression.compile(
                dialect=postgresql.dialect(),
                compile_kwargs={"literal_binds": True},
            )
        )
        for expression in ReportStorageService._report_filter_expressions(filters)
    )

    assert (
        "report_disposition_events.evaluation_attempt = coalesce(reports.evaluation_attempts"
        in compiled
    )
    assert "needs_revision" in compiled
    assert "reviewable" in compiled


def test_fresh_evaluation_vintage_returns_to_unreviewed_without_deleting_history():
    report = Report(
        id="ad0a93e1-4d27-4388-83f0-c1c8fa688a2e",
        tool_name="Havoc",
        status="completed",
        evaluation_status="completed",
        evaluation_attempts=2,
        quality_score=4.0,
    )
    event = ReportDispositionEvent(
        id="bd0a93e1-4d27-4388-83f0-c1c8fa688a2e",
        report_id=report.id,
        reviewer_user_id="analyst-user",
        disposition=AnalystDisposition.ACCEPTED.value,
        evaluation_attempt=1,
        created_at=datetime(2026, 8, 14, 12, tzinfo=timezone.utc),
    )

    class FakeQuery:
        def filter(self, *args):
            return self

        def order_by(self, *args):
            return self

        def all(self):
            return [event]

    class FakeSession:
        def query(self, *args):
            return FakeQuery()

    projected = ReportStorageService._attach_disposition_state(
        FakeSession(), [report], include_history=True
    )[0]

    assert projected["analyst_disposition"] == AnalystDisposition.UNREVIEWED.value
    assert projected["current_disposition"] is None
    assert len(projected["disposition_history"]) == 1
    assert projected["disposition_history"][0]["is_current"] is False


def test_re_evaluation_advances_the_vintage_without_touching_disposition_events():
    report = Report(
        id="ad0a93e1-4d27-4388-83f0-c1c8fa688a2e",
        tool_name="Havoc",
        status="completed",
        evaluation_status="completed",
        evaluation_attempts=1,
        quality_score=4.0,
        web_sources=[{"url": "https://example.com"}],
        quality_assessment={"summary": {"passed_sections": 1}},
    )

    class FakeQuery:
        def filter(self, *args):
            return self

        def with_for_update(self):
            return self

        def first(self):
            return report

    class FakeSession:
        def query(self, *args):
            assert args == (Report,)
            return FakeQuery()

        def commit(self):
            return None

    class FakeDatabaseManager:
        @contextmanager
        def get_session(self):
            yield FakeSession()

    service = ReportStorageService.__new__(ReportStorageService)
    service.db_manager = cast(Any, FakeDatabaseManager())

    assert service.begin_report_evaluation(str(report.id), user_id="analyst-user") is True
    assert report.evaluation_attempts == 2
    assert report.evaluation_status == "pending"
    assert report.review_status == "evaluation_pending"


def test_disposition_append_records_the_current_evaluation_vintage():
    report = Report(
        id="ad0a93e1-4d27-4388-83f0-c1c8fa688a2e",
        tool_name="Havoc",
        status="completed",
        evaluation_status="completed",
        evaluation_attempts=3,
        quality_score=4.0,
    )
    added: list[ReportDispositionEvent] = []

    class FakeQuery:
        def filter(self, *args):
            return self

        def with_for_update(self):
            return self

        def first(self):
            return report

    class FakeSession:
        def query(self, *args):
            assert args == (Report,)
            return FakeQuery()

        def add(self, event):
            added.append(event)

        def flush(self):
            event = cast(Any, added[0])
            event.id = uuid.UUID("bd0a93e1-4d27-4388-83f0-c1c8fa688a2e")
            event.created_at = datetime(2026, 8, 14, 12, tzinfo=timezone.utc)

        def refresh(self, event):
            return None

        def commit(self):
            return None

    class FakeDatabaseManager:
        @contextmanager
        def get_session(self):
            yield FakeSession()

    service = ReportStorageService.__new__(ReportStorageService)
    service.db_manager = cast(Any, FakeDatabaseManager())

    result = service.append_report_disposition(
        str(report.id),
        disposition=AnalystDisposition.NEEDS_REVISION,
        note="  Reconcile the timeline.  ",
        reviewer_user_id="analyst-user",
        owner_user_id="analyst-user",
    )

    assert len(added) == 1
    assert added[0].evaluation_attempt == 3
    assert added[0].reviewer_user_id == "analyst-user"
    assert result is not None
    assert result["disposition"] == "needs_revision"
    assert result["note"] == "Reconcile the timeline."
    assert result["is_current"] is True


def test_legacy_classification_reconciliation_keeps_unknown_reasons_distinct():
    service = ReportStorageService.__new__(ReportStorageService)

    reconciled = service.resolve_classification(
        tool_name="Havoc",
        threat_data={"coreMetadata": {"category": "Post-exploitation C2 framework"}},
        stored_category="unknown",
        stored_threat_type="unknown",
        legacy=True,
    )
    unmapped = service.resolve_classification(
        tool_name="Example",
        threat_data={"coreMetadata": {"category": "Bespoke research artifact"}},
        stored_category="unknown",
        stored_threat_type="unknown",
        legacy=True,
    )
    unrecorded = service.resolve_classification(
        tool_name="Example",
        threat_data={},
        stored_category="unknown",
        stored_threat_type="unknown",
        legacy=True,
    )
    already_reconciled = service.resolve_classification(
        tool_name="Havoc",
        threat_data={"coreMetadata": {"category": "Post-exploitation C2 framework"}},
        stored_category="malware",
        stored_threat_type="post_exploitation_framework",
        stored_status="reconciled",
        legacy=True,
    )

    assert reconciled == (
        "malware",
        "post_exploitation_framework",
        ClassificationStatus.RECONCILED,
    )
    assert unmapped[2] is ClassificationStatus.UNMAPPED
    assert unrecorded[2] is ClassificationStatus.UNRECORDED
    assert already_reconciled[2] is ClassificationStatus.RECONCILED


def test_failed_generation_preserves_the_last_observed_stage_for_recovery():
    report = Report(
        id="ad0a93e1-4d27-4388-83f0-c1c8fa688a2e",
        tool_name="Havoc",
        status="generating",
        generation_stage="validating",
    )

    class FakeQuery:
        def filter(self, *args):
            return self

        def first(self):
            return report

    class FakeSession:
        def query(self, *args):
            return FakeQuery()

        def commit(self):
            return None

    class FakeDatabaseManager:
        @contextmanager
        def get_session(self):
            yield FakeSession()

    service = ReportStorageService.__new__(ReportStorageService)
    service.db_manager = cast(Any, FakeDatabaseManager())

    assert service.mark_report_failed(str(report.id)) is True
    assert report.generation_failure_stage == "validating"
    assert report.status == "failed"
    assert report.review_status == "generation_failed"


def test_empty_quality_distribution_has_no_average_score():
    class FakeQuery:
        def __init__(self, *, scalar_value=None, rows=None):
            self.scalar_value = scalar_value
            self.rows = rows or []

        def filter(self, *args):
            return self

        def scalar(self):
            return self.scalar_value

        def all(self):
            return self.rows

    class FakeSession:
        def __init__(self):
            self.queries = [FakeQuery(scalar_value=None), FakeQuery(rows=[])]

        def query(self, *args):
            return self.queries.pop(0)

    class FakeDatabaseManager:
        @contextmanager
        def get_session(self):
            yield FakeSession()

    service = ReportStorageService()
    service.db_manager = cast(Any, FakeDatabaseManager())

    result = service.get_quality_score_distribution(user_id="new-workspace")

    assert result["average"] is None
    assert result["total_scored"] == 0
