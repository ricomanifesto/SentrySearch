from copy import deepcopy
import asyncio
from datetime import datetime, timezone
import json
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import pytest
from pydantic import ValidationError
from fastapi import HTTPException

from src.api import main as api_main
from src.auth.supabase_auth import AuthenticatedUser
from src.api.main import get_validated_evidence_admissibility, reader_safe_threat_data
from src.core.evidence_admissibility import assess_profile_evidence, classify_research_sources
from src.core.generation_failures import EvidenceAdmissibilityError, EvidenceUnavailableError
from src.core.markdown_generator import generate_markdown
from src.core.threat_profile_generator import ThreatProfileGenerator
from src.core.threat_profile_schema import attest_profile_sources
from src.core.source_ledger import canonicalize_profile_sources
from src.storage.models import Report
from src.storage.report_service import ReportStorageService
from test_evidence_admissibility import OPERATIONAL_SOURCE

MARKERS = [
    "[Virtual Event]",
    "[ vIrTuAl \n\t EvEnT ]",
    "&#91;Virtual&nbsp;Event&#93;",
    "&lbrack;Virtual&NewLine;Event&rbrack;",
    r"\[Virtual Event\]",
    r"\&#91;Virtual&#160;Event\&#93;",
    "[<strong>Virtual</strong> <em>Event</em>]",
]


@pytest.mark.parametrize("marker", MARKERS)
@pytest.mark.parametrize("field", ["title", "snippet", "snapshot"])
def test_tagged_source_is_excluded_as_a_whole(marker, field):
    source = deepcopy(OPERATIONAL_SOURCE)
    promotion = f"{marker} Join our threat detection briefing"
    if field == "snapshot":
        source["contentSnapshot"]["text"] += f" {promotion}"
    else:
        source[field] = promotion

    [classified] = classify_research_sources([source])

    assert classified["evidencePurpose"] == "excluded_non_operational"
    assert classified["evidenceDisposition"] == "excluded"
    assert classified["evidenceRuleId"] == "source.virtual-event-promotion"
    assert classified["title"] == source["title"]
    assert classified["contentSnapshot"] == source["contentSnapshot"]


@pytest.mark.parametrize(
    "text",
    [
        "Security events reveal malware activity.",
        "A virtual event discussed threat detection.",
        "[Event] Incident response and threat analysis",
        "[Virtual Events] Threat detection notes",
    ],
)
def test_generic_security_event_articles_remain_operational(text):
    source = deepcopy(OPERATIONAL_SOURCE)
    source["title"] = text
    assert classify_research_sources([source])[0]["evidencePurpose"] == "operational"


@pytest.mark.parametrize("surface", ["narrative", "primary", "reference"])
@pytest.mark.parametrize("marker", MARKERS)
def test_profile_gate_blocks_tagged_reader_content(threat_profile_data, surface, marker):
    if surface == "narrative":
        threat_profile_data["toolOverview"]["description"] = f"{marker} Join the briefing"
    elif surface == "primary":
        threat_profile_data["webSearchSources"]["primarySources"][0]["title"] = marker
    else:
        threat_profile_data["referencesAndIntelligenceSharing"]["sources"][0]["title"] = marker

    with pytest.raises(EvidenceAdmissibilityError) as error:
        assess_profile_evidence(threat_profile_data, [OPERATIONAL_SOURCE])
    assert error.value.assessment["status"] == "blocked"
    assert any("virtual-event promotion" in finding for finding in error.value.findings)


class SynthesisReached(Exception):
    pass


@pytest.mark.parametrize("tag_location", ["title", "snapshot", "dossier"])
def test_synthesis_never_receives_promotion_or_its_untagged_prose(monkeypatch, tag_location):
    generator = ThreatProfileGenerator.__new__(ThreatProfileGenerator)
    generator.enable_metrics = generator.enable_tracing = False
    safe = deepcopy(OPERATIONAL_SOURCE)
    promotion = deepcopy(OPERATIONAL_SOURCE)
    promotion.update(sourceId="S2", url="https://research.vendor-security.com/briefing")
    promotion["title"] = "Threat detection briefing"
    if tag_location == "title":
        promotion["title"] += " [Virtual Event]"
    if tag_location == "snapshot":
        promotion["contentSnapshot"]["text"] += " [Virtual Event] Register now"
    dossier = "Exclusive giveaway: register now to win a ticket."
    if tag_location == "dossier":
        dossier += r" \[Virtual Event\]"
    sources = [safe] if tag_location == "dossier" else [safe, promotion]
    generator._research_evidence = lambda _: SimpleNamespace(
        content=[SimpleNamespace(type="text", text=dossier)], web_search_sources=sources
    )
    captured = []

    def capture(items):
        captured.extend(items)
        return items

    def synthesis(**kwargs):
        prompt = str(kwargs["messages"])
        assert "Exclusive giveaway" not in prompt
        assert "register now" not in prompt
        assert promotion["url"] not in prompt
        assert safe["contentSnapshot"]["text"] in prompt
        raise SynthesisReached

    monkeypatch.setattr("src.core.threat_profile_generator.capture_source_snapshots", capture)
    generator._request_model = synthesis
    with pytest.raises(SynthesisReached):
        generator.get_threat_intelligence("Example Threat")
    if tag_location == "title":
        assert [item["url"] for item in captured] == [safe["url"]]


def test_only_promotions_stop_before_capture_and_synthesis(monkeypatch):
    generator = ThreatProfileGenerator.__new__(ThreatProfileGenerator)
    generator.enable_metrics = generator.enable_tracing = False
    generator._research_evidence = lambda _: SimpleNamespace(
        content=[SimpleNamespace(type="text", text="Register for the threat detection briefing")],
        web_search_sources=[{**OPERATIONAL_SOURCE, "title": "[Virtual Event] Threat detection"}],
    )
    capture = Mock(return_value=[])
    request = Mock(side_effect=AssertionError("Synthesis must not run"))
    monkeypatch.setattr("src.core.threat_profile_generator.capture_source_snapshots", capture)
    generator._request_model = request
    with pytest.raises(EvidenceUnavailableError):
        generator.get_threat_intelligence("Example Threat")
    assert not capture.called or capture.call_args.args == ([],)
    request.assert_not_called()


def test_duplicate_source_cannot_hide_a_promotion_tag(monkeypatch):
    generator = ThreatProfileGenerator.__new__(ThreatProfileGenerator)
    generator.enable_metrics = generator.enable_tracing = False
    generator._research_evidence = lambda _: SimpleNamespace(
        content=[SimpleNamespace(type="text", text="Join the threat detection briefing")],
        web_search_sources=[
            deepcopy(OPERATIONAL_SOURCE),
            {
                **OPERATIONAL_SOURCE,
                "url": OPERATIONAL_SOURCE["url"] + "/",
                "title": "[Virtual Event] Threat detection",
            },
        ],
    )
    capture = Mock(side_effect=lambda sources: sources)
    monkeypatch.setattr("src.core.threat_profile_generator.capture_source_snapshots", capture)
    generator._request_model = Mock(side_effect=AssertionError("Synthesis must not run"))
    with pytest.raises(EvidenceUnavailableError):
        generator.get_threat_intelligence("Example Threat")
    assert not capture.called or capture.call_args.args == ([],)


@pytest.mark.parametrize("surface", ["primary", "reference", "community"])
def test_attestation_rejects_relabelled_promotion_links(threat_profile_data, surface):
    source = {**OPERATIONAL_SOURCE, "url": "https://example.com/report"}
    promotion = {
        **OPERATIONAL_SOURCE,
        "sourceId": "S2",
        "url": "https://research.vendor-security.com/briefing",
        "title": "[Virtual Event] Threat detection",
    }
    if surface == "primary":
        target = threat_profile_data["webSearchSources"]["primarySources"][0]
        target["domain"] = "research.vendor-security.com"
        for claim in threat_profile_data["claimAttribution"]["claims"]:
            if claim["sourceIds"]:
                claim["sourceIds"] = ["S2"]
    elif surface == "reference":
        target = threat_profile_data["referencesAndIntelligenceSharing"]["sources"][0]
    else:
        target = threat_profile_data["operationalGuidance"]["communityResources"][0]
    target["url"] = promotion["url"]
    with pytest.raises(ValueError, match="excluded virtual-event promotion"):
        attest_profile_sources(threat_profile_data, [source, promotion])


def test_excluded_promotion_does_not_reappear_in_reader_audit_or_markdown(threat_profile_data):
    promotion = {
        **OPERATIONAL_SOURCE,
        "sourceId": "S2",
        "url": "https://research.vendor-security.com/briefing",
        "title": "[Virtual Event] Threat detection",
    }
    assessment = assess_profile_evidence(threat_profile_data, [OPERATIONAL_SOURCE, promotion])
    assert assessment["status"] == "passed"
    assert assessment["summary"]["excludedSources"] == 1
    assert [source["sourceId"] for source in assessment["sourceObservations"]] == ["S1", "S2"]
    private_before = deepcopy(threat_profile_data)
    public = get_validated_evidence_admissibility({"threat_data": threat_profile_data})
    assert [source.source_id for source in public.source_observations] == ["S1"]
    assert "[Virtual Event]" not in json.dumps(
        reader_safe_threat_data({"threat_data": threat_profile_data})
    )
    assert threat_profile_data == private_before
    markdown = generate_markdown(threat_profile_data)
    assert promotion["url"] not in markdown
    assert promotion["title"] not in markdown


def test_public_projection_validates_excluded_records_before_filtering():
    malformed = {
        "schemaVersion": "1",
        "status": "passed",
        "sourceObservations": [
            {"title": "[Virtual Event] Invalid audit", "ruleId": "source.virtual-event-promotion"}
        ],
    }
    with pytest.raises(ValidationError):
        get_validated_evidence_admissibility({"evidence_admissibility": malformed})


@pytest.mark.parametrize(
    "method", ["store_report", "finalize_report", "complete_report_evaluation"]
)
def test_mixed_sources_persist_without_exposing_private_promotion_audit(
    threat_profile_data, method
):
    threat_profile_data["webSearchSources"]["primarySources"][0]["url"] = OPERATIONAL_SOURCE["url"]
    profile, sources = canonicalize_profile_sources(threat_profile_data)
    promotion = {
        **OPERATIONAL_SOURCE,
        "sourceId": "S2",
        "title": "[Virtual Event] Register now",
        "url": "https://research.vendor-security.com/briefing",
    }
    assessment = assess_profile_evidence(profile, [OPERATIONAL_SOURCE, promotion])
    markdown = generate_markdown(profile)
    data = {
        "id": "test",
        "tool_name": "Example Threat",
        "threat_data": profile,
        "web_sources": sources,
        "markdown_content": markdown,
        "evidence_admissibility": assessment,
    }
    service = ReportStorageService.__new__(ReportStorageService)
    service.db_manager = MagicMock()
    session = service.db_manager.get_session.return_value.__enter__.return_value
    service.s3_manager = Mock()
    service.s3_manager.upload_markdown_report.return_value = "private-test-key"
    report = Report(
        id="test",
        status="generating",
        evidence_admissibility=assessment,
        evidence_admissibility_status="passed",
        web_sources=sources,
    )
    service._generation_report = Mock(return_value=report)
    service._evaluation_report = Mock(return_value=report)
    if method == "store_report":
        assert service.store_report(data) == "test"
        report = session.add.call_args.args[0]
    elif method == "finalize_report":
        assert service.finalize_report("test", data) == "test"
    else:
        assert service.complete_report_evaluation(
            "test",
            evaluation_lease="lease",
            quality_assessment={},
            evaluation_route={},
            threat_data=profile,
            markdown_content=markdown,
        )
    session.commit.assert_called_once()
    service.s3_manager.upload_markdown_report.assert_called_once_with("test", markdown)
    assert promotion["title"] not in markdown
    assert promotion["url"] not in markdown
    assert [source["sourceId"] for source in report.web_sources] == ["S1"]
    assert report.threat_data["evidenceAdmissibility"] == assessment
    assert len(report.evidence_admissibility["sourceObservations"]) == 2
    public = get_validated_evidence_admissibility(
        {"evidence_admissibility": report.evidence_admissibility}
    )
    assert [source.source_id for source in public.source_observations] == ["S1"]


@pytest.mark.parametrize(
    "method", ["store_report", "finalize_report", "complete_report_evaluation"]
)
@pytest.mark.parametrize("surface", ["markdown", "narrative", "primary"])
def test_persistence_refuses_tagged_content_before_any_io(threat_profile_data, method, surface):
    profile = deepcopy(threat_profile_data)
    profile["evidenceAdmissibility"] = {"schemaVersion": "1", "status": "passed"}
    markdown = "Legitimate threat analysis"
    marker = r"\[Virtual&#160;Event\]"
    if surface == "markdown":
        markdown = f"{marker} Register for a briefing"
    elif surface == "narrative":
        profile["toolOverview"]["description"] = marker
    else:
        profile["webSearchSources"]["primarySources"][0]["title"] = marker
    service = ReportStorageService.__new__(ReportStorageService)
    service.db_manager = Mock()
    service.db_manager.get_session.side_effect = AssertionError("No database access expected")
    service.s3_manager = Mock()
    data = {"id": "test", "threat_data": profile, "markdown_content": markdown}
    with pytest.raises(ValueError, match="virtual-event promotion"):
        if method == "complete_report_evaluation":
            service.complete_report_evaluation(
                "test",
                evaluation_lease="lease",
                quality_assessment={},
                evaluation_route={},
                threat_data=profile,
                markdown_content=markdown,
            )
        elif method == "finalize_report":
            service.finalize_report("test", data)
        else:
            service.store_report(data)
    service.db_manager.get_session.assert_not_called()
    assert not service.s3_manager.mock_calls


@pytest.mark.parametrize("surface", ["markdown", "title", "narrative", "primary", "preview"])
@pytest.mark.parametrize("marker", MARKERS)
def test_retained_report_read_rejects_prohibited_content_without_mutation(
    monkeypatch, threat_profile_data, surface, marker
):
    report = {
        "id": "retained",
        "tool_name": "Example Threat",
        "user_id": "reader",
        "created_at": datetime.now(timezone.utc),
        "threat_data": threat_profile_data,
        "markdown_content": "Legitimate security analysis",
        "content_preview": "Security events",
    }
    if surface == "markdown":
        report["markdown_content"] = f"{marker} Register now"
    elif surface == "title":
        report["tool_name"] = marker
    elif surface == "preview":
        report["content_preview"] = marker
    elif surface == "narrative":
        threat_profile_data["toolOverview"]["description"] = marker
    else:
        threat_profile_data["webSearchSources"]["primarySources"][0]["title"] = marker
    original = deepcopy(report)
    monkeypatch.setattr(api_main.report_service, "get_report", lambda *args, **kwargs: report)
    user = AuthenticatedUser(user_id="reader", email="reader@example.com", metadata={})
    with pytest.raises(HTTPException) as error:
        asyncio.run(api_main.get_report("retained", True, user))
    assert error.value.status_code == 404
    assert error.value.detail == "Report unavailable under content policy"
    assert report == original
    if surface != "markdown":
        with pytest.raises(ValueError, match="virtual-event promotion"):
            api_main.report_response_fields(report)


def test_reader_safe_profile_rejects_retained_narrative(threat_profile_data):
    threat_profile_data["toolOverview"]["description"] = "[Virtual Event] Register now"
    with pytest.raises(ValueError, match="virtual-event promotion"):
        reader_safe_threat_data({"threat_data": threat_profile_data})


def test_retained_clean_report_with_private_audit_remains_readable(
    monkeypatch, threat_profile_data
):
    promotion = {**OPERATIONAL_SOURCE, "sourceId": "S2", "title": "[Virtual Event] Register now"}
    assess_profile_evidence(threat_profile_data, [OPERATIONAL_SOURCE, promotion])
    report = {
        "id": "retained",
        "tool_name": "Example Threat",
        "user_id": "reader",
        "created_at": datetime.now(timezone.utc),
        "threat_data": threat_profile_data,
        "markdown_content": generate_markdown(threat_profile_data),
    }
    original = deepcopy(report)
    monkeypatch.setattr(api_main.report_service, "get_report", lambda *args, **kwargs: report)
    user = AuthenticatedUser(user_id="reader", email="reader@example.com", metadata={})
    response = asyncio.run(api_main.get_report("retained", True, user))
    assert "[Virtual Event]" not in response.model_dump_json()
    assert report == original


@pytest.mark.parametrize("surface", ["markdown", "narrative"])
def test_retained_markdown_cannot_bypass_guard_through_presigned_export(
    threat_profile_data, surface
):
    service = ReportStorageService.__new__(ReportStorageService)
    service.db_manager = MagicMock()
    service.s3_manager = Mock()
    report = Report(id="retained", markdown_s3_key="private-key", threat_data=threat_profile_data)
    session = service.db_manager.get_session.return_value.__enter__.return_value
    session.query.return_value.filter.return_value.first.return_value = report
    service.s3_manager.download_content.return_value = (
        r"\[Virtual&#160;Event\] Register now" if surface == "markdown" else "Legitimate analysis"
    )
    if surface == "narrative":
        threat_profile_data["toolOverview"]["description"] = "[Virtual Event] Register now"
    with pytest.raises(ValueError, match="virtual-event promotion"):
        service.get_download_url("retained")
    service.s3_manager.get_presigned_url.assert_not_called()
    session.commit.assert_not_called()


def test_content_policy_rejection_has_a_distinct_exception():
    from src.core.evidence_admissibility import assert_no_virtual_event_promotions

    with pytest.raises(ValueError) as error:
        assert_no_virtual_event_promotions("[Virtual Event] Register now")
    assert type(error.value).__name__ == "ContentPolicyExclusion"


def collection_report(report_id, *, blocked=False):
    return {
        "id": report_id,
        "tool_name": "[Virtual Event] Register now" if blocked else "Security event analysis",
        "user_id": "reader",
        "created_at": datetime.now(timezone.utc),
        "status": "completed",
    }


@pytest.mark.parametrize("endpoint", ["list", "search"])
@pytest.mark.parametrize(
    "blocked_flags", [(False, True, False), (True, True, True), (False, False, False)]
)
def test_collection_policy_exclusion_preserves_clean_rows_and_stored_pagination(
    monkeypatch, endpoint, blocked_flags
):
    rows = [
        collection_report(str(index), blocked=blocked)
        for index, blocked in enumerate(blocked_flags)
    ]
    original = deepcopy(rows)
    read = Mock(return_value=rows)
    count = Mock(return_value=11)
    monkeypatch.setattr(
        api_main.report_service,
        f"{endpoint}_reports" if endpoint == "list" else "search_reports",
        read,
    )
    monkeypatch.setattr(
        api_main.report_service,
        "count_reports" if endpoint == "list" else "count_search_results",
        count,
    )
    user = AuthenticatedUser(user_id="reader", email="reader@example.com", metadata={})
    pagination = api_main.PaginationParams(page=2, limit=3)
    if endpoint == "list":
        result = asyncio.run(api_main.list_reports(pagination, user))
    else:
        result = asyncio.run(api_main.search_reports(api_main.SearchFilters(), pagination, user))
    assert [report.id for report in result["reports"]] == [
        str(i) for i, blocked in enumerate(blocked_flags) if not blocked
    ]
    assert all(report.status == "completed" for report in result["reports"])
    assert result["pagination"] == {
        "page": 2,
        "limit": 3,
        "total": 11,
        "pages": 4,
        "excluded_on_page": sum(blocked_flags),
        "total_includes_excluded": True,
    }
    assert read.call_count == count.call_count == 1
    assert read.call_args.kwargs["offset"] == 3
    assert read.call_args.kwargs["limit"] == 3
    assert rows == original


@pytest.mark.parametrize("endpoint", ["list", "search"])
def test_collection_policy_does_not_swallow_unrelated_validation_errors(monkeypatch, endpoint):
    rows = [
        collection_report("clean"),
        {**collection_report("invalid"), "quality_score": "invalid"},
    ]
    monkeypatch.setattr(
        api_main.report_service,
        "list_reports" if endpoint == "list" else "search_reports",
        lambda **_: rows,
    )
    monkeypatch.setattr(
        api_main.report_service,
        "count_reports" if endpoint == "list" else "count_search_results",
        lambda **_: 2,
    )
    user = AuthenticatedUser(user_id="reader", email="reader@example.com", metadata={})
    with pytest.raises(HTTPException) as error:
        if endpoint == "list":
            asyncio.run(api_main.list_reports(api_main.PaginationParams(), user))
        else:
            asyncio.run(
                api_main.search_reports(api_main.SearchFilters(), api_main.PaginationParams(), user)
            )
    assert error.value.status_code == 500


@pytest.mark.parametrize("dashboard", [False, True])
def test_analytics_policy_exclusion_keeps_clean_activity_and_original_counts(
    monkeypatch, dashboard
):
    rows = [collection_report("clean"), collection_report("blocked", blocked=True)]
    original = deepcopy(rows)
    monkeypatch.setattr(api_main.report_service, "list_reports", lambda **_: rows)
    monkeypatch.setattr(api_main.report_service, "count_reports", lambda **_: 11)
    monkeypatch.setattr(api_main.report_service, "list_analytics_records", lambda **_: [])
    monkeypatch.setattr(api_main.report_service, "get_threat_type_stats", lambda **_: {})
    monkeypatch.setattr(api_main.report_service, "get_quality_score_distribution", lambda **_: {})
    user = AuthenticatedUser(user_id="reader", email="reader@example.com", metadata={})
    result = asyncio.run(
        api_main.get_dashboard_analytics(user) if dashboard else api_main.get_analytics("30d", user)
    )
    assert [report["id"] for report in result["recent_activity"]] == ["clean"]
    assert result["recent_activity"][0]["status"] == "completed"
    assert result["recent_activity_excluded_count"] == 1
    assert result["summary" if dashboard else "overview"]["total_reports"] == 11
    assert rows == original
