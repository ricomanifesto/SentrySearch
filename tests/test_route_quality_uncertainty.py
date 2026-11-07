"""Per-route quality uncertainty in the analytics read model (synthetic records)."""

from datetime import datetime, timezone

import pytest

from src.api import main as api_main
from src.core.sample_bounds import half_width
from src.domain.reports import GenerationRouteScope, ReportAnalyticsRecord, ReportStatus

CREATED_AT = datetime(2026, 8, 14, 12, 0, tzinfo=timezone.utc)


def completed(
    quality_score: float | None,
    *,
    used_fallback: bool | None = False,
    scope: GenerationRouteScope = GenerationRouteScope.SYNTHESIS,
) -> ReportAnalyticsRecord:
    return ReportAnalyticsRecord(
        created_at=CREATED_AT,
        quality_score=quality_score,
        processing_time_ms=1000,
        status=ReportStatus.COMPLETED,
        threat_type="malware",
        generation_used_fallback=used_fallback,
        generation_route_scope=scope,
    )


def by_route(records):
    return {route["route"]: route for route in api_main.build_route_performance(records)}


def native_width(n: int) -> float:
    return half_width(n, 0.05) * 5


def test_unscored_routes_report_no_interval():
    routes = by_route([completed(None), completed(None, used_fallback=True)])

    for name in ("primary", "fallback", "legacy_aggregate", "unrecorded"):
        assert routes[name]["scored_report_count"] == 0
        assert routes[name]["quality_half_width"] is None
        assert routes[name]["quality_interval"] is None
        assert routes[name]["distinguishable_from"] == []


def test_single_scored_report_interval_covers_the_native_range():
    routes = by_route([completed(4.0)])

    assert routes["primary"]["quality_half_width"] == pytest.approx(native_width(1))
    assert routes["primary"]["quality_interval"] == [0.0, 5.0]
    assert routes["primary"]["distinguishable_from"] == []


@pytest.mark.parametrize(("n", "expected_width"), [(20, 1.52), (185, 0.50)])
def test_scored_route_width_shrinks_with_sample_size(n, expected_width):
    routes = by_route([completed(3.0) for _ in range(n)])

    width = routes["primary"]["quality_half_width"]
    assert width == pytest.approx(expected_width, abs=0.01)
    assert routes["primary"]["quality_interval"] == pytest.approx([3.0 - width, 3.0 + width])


def test_interval_is_clipped_to_native_score_range():
    routes = by_route([completed(4.8) for _ in range(20)])

    low, high = routes["primary"]["quality_interval"]
    assert low == pytest.approx(4.8 - native_width(20))
    assert high == 5.0


def test_overlapping_intervals_are_not_distinguishable_at_twenty_reports():
    records = [completed(4.0) for _ in range(20)]
    records += [completed(3.0, used_fallback=True) for _ in range(20)]

    routes = by_route(records)

    assert routes["primary"]["avg_quality_score"] == pytest.approx(4.0)
    assert routes["fallback"]["avg_quality_score"] == pytest.approx(3.0)
    assert routes["primary"]["distinguishable_from"] == []
    assert routes["fallback"]["distinguishable_from"] == []


def test_non_overlapping_intervals_name_each_other_at_185_reports():
    records = [completed(4.5) for _ in range(185)]
    records += [completed(3.0, used_fallback=True) for _ in range(185)]
    records += [completed(4.0, used_fallback=None, scope=GenerationRouteScope.UNRECORDED)]

    routes = by_route(records)

    assert routes["primary"]["distinguishable_from"] == ["fallback"]
    assert routes["fallback"]["distinguishable_from"] == ["primary"]
    assert routes["unrecorded"]["quality_interval"] == [0.0, 5.0]
    assert routes["unrecorded"]["distinguishable_from"] == []


def test_legacy_and_unrecorded_routes_keep_existing_fields():
    records = [
        completed(2.0, used_fallback=None, scope=GenerationRouteScope.LEGACY_AGGREGATE),
        completed(None, used_fallback=None, scope=GenerationRouteScope.LEGACY_AGGREGATE),
        completed(3.0, used_fallback=None, scope=GenerationRouteScope.UNRECORDED),
    ]

    routes = by_route(records)

    assert {
        key: routes["legacy_aggregate"][key]
        for key in (
            "report_count",
            "scored_report_count",
            "runtime_recorded_count",
            "avg_quality_score",
            "avg_processing_time_ms",
        )
    } == {
        "report_count": 2,
        "scored_report_count": 1,
        "runtime_recorded_count": 2,
        "avg_quality_score": 2.0,
        "avg_processing_time_ms": 1000.0,
    }
    assert routes["unrecorded"]["report_count"] == 1
    assert routes["unrecorded"]["avg_quality_score"] == 3.0
    assert list(api_main.build_route_performance(records)[0]) == [
        "route",
        "report_count",
        "scored_report_count",
        "runtime_recorded_count",
        "avg_quality_score",
        "avg_processing_time_ms",
        "quality_half_width",
        "quality_interval",
        "distinguishable_from",
    ]
