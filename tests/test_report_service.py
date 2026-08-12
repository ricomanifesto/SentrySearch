from datetime import datetime, timezone
from typing import Any, cast

import pytest
from pydantic import ValidationError
from sqlalchemy.dialects import postgresql

from src.api.contracts import PaginationParams, ReportDetail, SearchFilters
from src.domain.reports import ReportFilters, ReportSortField, SortOrder
from src.storage.report_service import ReportStorageService


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
