import asyncio
from copy import deepcopy
from datetime import datetime, timezone
from unittest.mock import Mock
from threading import Event

import pytest

from fastapi import HTTPException

from src.api import main as api
from src.auth.supabase_auth import AuthenticatedUser
from src.domain.reports import ReportAnalyticsRecord, ReportStatus
from tests.test_virtual_event_promotions import collection_report

USER = AuthenticatedUser(user_id="reader", email="reader@example.com", metadata={})


@pytest.mark.parametrize(
    "field,method",
    [
        ("tags", "get_popular_tags"),
        ("categories", "get_unique_categories"),
        ("threat_types", "get_unique_threat_types"),
    ],
)
def test_search_facets_do_not_expose_formatted_promotions(monkeypatch, field, method):
    service = Mock()
    service.get_popular_tags.return_value = ["ordinary"]
    service.get_unique_categories.return_value = ["ordinary"]
    service.get_unique_threat_types.return_value = ["ordinary"]
    values = ["ordinary", "[**Virtual** Event]", "&#91;Virtual Event&#93;", "incident-response"]
    getattr(service, method).return_value = values
    original = deepcopy(values)
    monkeypatch.setattr(api, "report_service", service)
    result = asyncio.run(api.get_search_filters(USER))
    assert result[field] == ["ordinary", "incident-response"]
    assert values == original
    assert getattr(service, method).call_args.kwargs["user_id"] == USER.id


@pytest.mark.parametrize("dashboard,limit", [(True, 5), (False, 10)])
@pytest.mark.parametrize("available", [0, 2, 20])
def test_activity_finds_clean_rows_after_multiple_excluded_batches(
    monkeypatch, dashboard, limit, available
):
    rows = [collection_report(f"blocked-{i}", blocked=True) for i in range(limit * 2)]
    rows += [collection_report(f"clean-{i}") for i in range(available)]
    original = deepcopy(rows)
    service = Mock()
    service.count_reports.return_value = len(rows)
    service.list_analytics_records.return_value = []
    service.get_threat_type_stats.return_value = {}
    service.get_quality_score_distribution.return_value = {}

    def read(*, limit, offset=0, **kwargs):
        assert kwargs["user_id"] == USER.id
        assert kwargs["sort_by"] == "created_at"
        assert kwargs["sort_order"] == "desc"
        return rows[offset : offset + limit]

    service.list_reports.side_effect = read
    monkeypatch.setattr(api, "report_service", service)
    result = asyncio.run(
        api.get_dashboard_analytics(USER) if dashboard else api.get_analytics("30d", USER)
    )
    assert [r["id"] for r in result["recent_activity"]] == [
        f"clean-{i}" for i in range(min(limit, available))
    ]
    assert result["recent_activity_excluded_count"] == limit * 2
    assert result["recent_activity_scan_limited"] is False
    assert rows == original


@pytest.mark.parametrize("admin", [False, True])
def test_aggregate_threat_labels_do_not_expose_prohibited_content(monkeypatch, admin):
    service = Mock()
    service.get_threat_type_stats.return_value = {"ordinary": 2, "[**Virtual** Event]": 7}
    service.get_quality_score_distribution.return_value = {}
    service.list_analytics_records.return_value = []
    service.list_reports.return_value = []
    service.count_reports.return_value = 0
    service.update_existing_categorizations.return_value = 0
    monkeypatch.setattr(api, "report_service", service)
    if admin:
        user = AuthenticatedUser(
            user_id="admin", email="admin@example.com", metadata={"role": "admin"}
        )
        result = asyncio.run(api.update_categorizations(user))["new_distribution"]
    else:
        result = asyncio.run(api.get_dashboard_analytics(USER))["threat_distribution"]
    assert result == {"ordinary": 2}
    assert service.get_threat_type_stats.return_value == {"ordinary": 2, "[**Virtual** Event]": 7}


def test_analytics_trends_exclude_prohibited_labels_before_ranking_and_percentages():
    now = datetime.now(timezone.utc)
    records = [
        ReportAnalyticsRecord(
            created_at=now,
            quality_score=None,
            processing_time_ms=None,
            status=ReportStatus.COMPLETED,
            threat_type=label,
        )
        for label in ["ordinary", "[Virtual Event]"]
    ]
    result = api.build_analytics_trends(records, start_date=now, days=0)
    assert result["threat_type_distribution"] == [
        {"threat_type": "ordinary", "count": 1, "percentage": 100.0}
    ]
    assert result["daily_reports"][0]["count"] == 2


def test_backfill_does_not_hide_later_storage_failures(monkeypatch):
    service = Mock()
    service.count_reports.return_value = 10
    service.list_analytics_records.return_value = []
    service.get_threat_type_stats.return_value = {}
    service.get_quality_score_distribution.return_value = {}
    service.list_reports.side_effect = [
        [collection_report(str(i), blocked=True) for i in range(5)],
        RuntimeError("storage unavailable"),
    ]
    monkeypatch.setattr(api, "report_service", service)
    with pytest.raises(HTTPException) as error:
        asyncio.run(api.get_dashboard_analytics(USER))
    assert error.value.status_code == 500
    assert service.list_reports.call_count == 2


@pytest.mark.parametrize("dashboard", [False, True])
def test_activity_stops_after_one_hundred_stored_rows(monkeypatch, dashboard):
    service = Mock()
    service.count_reports.return_value = 1000
    service.list_analytics_records.return_value = []
    service.get_threat_type_stats.return_value = {}
    service.get_quality_score_distribution.return_value = {}
    service.list_reports.side_effect = lambda *, limit, offset=0, **_: [
        {**collection_report(str(i)), "_markdown_s3_key": f"{i}.md"}
        for i in range(offset, offset + limit)
    ]
    service.s3_manager.download_content.return_value = "[Virtual Event] Register now"
    monkeypatch.setattr(api, "report_service", service)
    result = asyncio.run(
        api.get_dashboard_analytics(USER) if dashboard else api.get_analytics("30d", USER)
    )
    assert result["recent_activity"] == []
    assert service.s3_manager.download_content.call_count == 100
    assert result["recent_activity_excluded_count"] == 100
    assert result["recent_activity_scan_limited"] is True


def test_activity_deadline_cancels_wait_without_releasing_running_object_capacity(monkeypatch):
    from src.storage.retained_content import RetainedContentReader, RetainedContentUnavailable

    release = Event()
    calls = []
    reader = RetainedContentReader(max_workers=4, timeout_seconds=0.06)
    service = Mock()
    service.count_reports.return_value = 1000
    service.list_analytics_records.return_value = []
    service.get_threat_type_stats.return_value = {}
    service.get_quality_score_distribution.return_value = {}
    service.list_reports.side_effect = lambda *, limit, offset=0, **_: [
        {**collection_report(str(i)), "_markdown_s3_key": f"{i}.md"}
        for i in range(offset, offset + limit)
    ]

    def load(key):
        calls.append(key)
        release.wait(1)
        return "Security analysis"

    service.s3_manager.download_content.side_effect = load
    monkeypatch.setattr(api, "report_service", service)
    monkeypatch.setattr(api, "retained_content_reader", reader)
    monkeypatch.setattr(api, "RECENT_ACTIVITY_TIMEOUT_SECONDS", 0.02, raising=False)

    async def check():
        result = await api.get_dashboard_analytics(USER)
        assert result["recent_activity"] == []
        assert result["recent_activity_scan_limited"] is True
        with pytest.raises(RetainedContentUnavailable):
            await reader.read_many(["probe"], load)
        assert len(calls) == 4
        assert "probe" not in calls

    try:
        asyncio.run(check())
    finally:
        release.set()
        reader.close()
