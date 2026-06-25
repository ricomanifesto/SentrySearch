from sqlalchemy.dialects import postgresql

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
