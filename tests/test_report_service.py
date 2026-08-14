from datetime import datetime, timezone
from contextlib import contextmanager
from typing import Any, cast

import pytest
from pydantic import ValidationError
from sqlalchemy.dialects import postgresql

from src.api.contracts import ModelRouteProvenance, PaginationParams, ReportDetail, SearchFilters
from src.domain.model_routes import generation_fallback_state
from src.domain.reports import ReportFilters, ReportSortField, SortOrder
from src.storage.report_service import ReportStorageService
from src.storage.models import Report
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
    assert "ALTER TABLE reports ADD COLUMN IF NOT EXISTS evaluation_route JSONB" in statements


def test_report_filters_are_immutable_and_normalize_collections():
    filters = ReportFilters(
        threat_types=("trojan", "ransomware"),
        tags=("endpoint",),
        sort_by=ReportSortField.QUALITY_SCORE,
        sort_order=SortOrder.ASCENDING,
    )

    assert filters.threat_types == ("trojan", "ransomware")
    assert filters.tags == ("endpoint",)
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
