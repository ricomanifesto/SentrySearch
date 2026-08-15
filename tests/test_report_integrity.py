from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from src.core.source_ledger import (
    SourceLedgerError,
    assert_claim_attribution_consistent,
    assert_markdown_source_ledger_consistent,
    assert_source_ledger_consistent,
    canonicalize_profile_sources,
    claim_attribution_status,
    materialize_claim_attribution,
    materialize_cited_sources,
)
from src.core.validation_criteria import SECTION_CRITERIA, build_section_evaluation_prompt
from src.core.validation_criteria import ConsistencyEvaluation
from src.core.section_validator import SectionValidator
from src.core import section_validator as section_validator_module
from src.core.markdown_generator import generate_markdown
from src.domain.reports import (
    ClaimAttributionStatus,
    EvidenceAdmissibilityStatus,
    EvaluationStatus,
    GenerationRouteScope,
    ReportStatus,
    ReviewStatus,
    derive_generation_route_scope,
    derive_review_status,
    evaluation_conflict_count,
    is_judgment_eligible,
    is_reuse_eligible,
)
from src.storage.models import Report
from src.storage.report_service import ReportStorageService


def source_profile() -> dict:
    return {
        "coreMetadata": {"name": "SocGholish", "category": "Malware loader/downloader"},
        "toolOverview": {
            "description": "A source-backed description with enough detail for the saved preview."
        },
        "webSearchSources": {
            "primarySources": [
                {
                    "title": "Primary analysis",
                    "url": "https://EXAMPLE.com/report#finding",
                    "accessDate": "2026-08-14",
                    "relevanceScore": "High",
                    "contentType": "Analysis",
                    "keyFindings": "Observed delivery behavior.",
                }
            ]
        },
        "referencesAndIntelligenceSharing": {"sources": []},
        "operationalGuidance": {"communityResources": []},
        "comprehensiveWebSearchSources": {"totalSourcesAnalyzed": 15},
    }


def test_source_ledger_derives_every_reader_source_surface_from_primary_sources():
    profile, sources = canonicalize_profile_sources(source_profile())

    expected_url = "https://example.com/report"
    assert [source["url"] for source in sources] == [expected_url]
    assert [source["url"] for source in profile["referencesAndIntelligenceSharing"]["sources"]] == [
        expected_url
    ]
    assert [source["url"] for source in profile["operationalGuidance"]["communityResources"]] == [
        expected_url
    ]
    assert "comprehensiveWebSearchSources" not in profile
    assert_source_ledger_consistent(profile, sources)


def test_claim_attribution_v2_is_explicit_and_legacy_claims_are_never_inferred():
    legacy = source_profile()
    assert claim_attribution_status(legacy) == (ClaimAttributionStatus.LEGACY, None)

    attributed = source_profile()
    attributed["webSearchSources"]["primarySources"][0]["sourceId"] = "S1"
    attributed.update(
        {
            "threatIntelligence": {"activity": "Observed campaign activity"},
            "forensicArtifacts": {"fileSystemArtifacts": ["example.exe"]},
            "detectionAndMitigation": {"behavioralIndicators": ["Service creation"]},
            "mitigationAndResponse": {"responseActions": ["Isolate the host"]},
            "claimAttribution": {
                "schemaVersion": "2",
                "claims": [
                    {
                        "claimClass": "threat_activity",
                        "claim": "Observed campaign activity",
                        "sourceIds": ["S1"],
                    },
                    {
                        "claimClass": "forensic_artifact",
                        "claim": "example.exe",
                        "sourceIds": ["S1"],
                    },
                    {
                        "claimClass": "detection_indicator",
                        "claim": "Service creation",
                        "sourceIds": ["S1"],
                    },
                    {
                        "claimClass": "mitigation_action",
                        "claim": "Isolate the host",
                        "sourceIds": ["S1"],
                    },
                ],
            },
        }
    )

    assert claim_attribution_status(attributed) == (ClaimAttributionStatus.ATTRIBUTED, "2")
    assert_claim_attribution_consistent(attributed)

    attributed["claimAttribution"]["claims"][0]["sourceIds"] = ["S99"]
    assert claim_attribution_status(attributed) == (ClaimAttributionStatus.UNATTRIBUTED, "2")
    with pytest.raises(SourceLedgerError, match="inconsistent"):
        assert_claim_attribution_consistent(attributed)


def test_claim_attribution_v3_materializes_explicit_structured_selectors():
    profile = source_profile()
    profile["webSearchSources"]["primarySources"][0]["sourceId"] = "S1"
    profile.update(
        {
            "threatIntelligence": {"riskAssessment": {"riskFactors": ["Remote access"]}},
            "forensicArtifacts": {"memoryArtifacts": ["Injected Beacon payload"]},
            "detectionAndMitigation": {
                "iocs": {"hashes": [], "domains": [], "ips": [], "urls": [], "filenames": []},
                "behavioralIndicators": ["Periodic callbacks"],
            },
            "mitigationAndResponse": {"responseActions": ["Isolate affected hosts"]},
            "claimAttribution": {
                "schemaVersion": "3",
                "claims": [
                    {
                        "claimClass": "threat_activity",
                        "claimField": "riskFactors",
                        "claimIndex": 0,
                        "sourceIds": ["S1"],
                    },
                    {
                        "claimClass": "forensic_artifact",
                        "claimField": "memoryArtifacts",
                        "claimIndex": 0,
                        "sourceIds": ["S1"],
                    },
                    {
                        "claimClass": "detection_indicator",
                        "claimField": "behavioralIndicators",
                        "claimIndex": 0,
                        "sourceIds": ["S1"],
                    },
                    {
                        "claimClass": "mitigation_action",
                        "claimField": "responseActions",
                        "claimIndex": 0,
                        "sourceIds": ["S1"],
                    },
                ],
            },
        }
    )

    materialize_claim_attribution(profile)
    profile["claimAttribution"]["claims"][0]["sourceIds"] = ["S2"]

    assert claim_attribution_status(profile) == (ClaimAttributionStatus.UNATTRIBUTED, "3")

    materialize_cited_sources(
        profile,
        [
            {"sourceId": "S1", "url": "https://example.com/report", "title": "Example"},
            {
                "sourceId": "S2",
                "url": "https://example.com/campaign",
                "title": "Campaign report",
            },
        ],
        access_date="2026-08-15",
    )

    assert [claim["claim"] for claim in profile["claimAttribution"]["claims"]] == [
        "Remote access",
        "Injected Beacon payload",
        "Periodic callbacks",
        "Isolate affected hosts",
    ]
    assert profile["webSearchSources"]["primarySources"][1] == {
        "sourceId": "S2",
        "url": "https://example.com/campaign",
        "title": "Campaign report",
        "domain": "example.com",
        "accessDate": "2026-08-15",
        "relevanceScore": "Unknown",
        "contentType": "Web source",
        "keyFindings": "No separate finding summary recorded",
    }
    assert claim_attribution_status(profile) == (ClaimAttributionStatus.ATTRIBUTED, "3")
    assert_claim_attribution_consistent(profile)

    profile["claimAttribution"]["claims"][0]["claimField"] = "behavioralIndicators"
    with pytest.raises(SourceLedgerError, match="selector is invalid"):
        materialize_claim_attribution(profile)


def test_source_ledger_refuses_to_finalize_a_divergent_reference_list():
    profile, sources = canonicalize_profile_sources(source_profile())
    profile["referencesAndIntelligenceSharing"]["sources"][0][
        "url"
    ] = "https://different.example/report"

    with pytest.raises(SourceLedgerError, match="references diverge"):
        assert_source_ledger_consistent(profile, sources)


def test_rendered_source_subsections_must_match_the_evidence_rail():
    profile, sources = canonicalize_profile_sources(source_profile())
    markdown = generate_markdown(profile)

    assert_markdown_source_ledger_consistent(markdown, sources)
    tampered = markdown.replace(
        "[https://example.com/report](https://example.com/report)",
        "[https://different.example/report](https://different.example/report)",
        1,
    )
    with pytest.raises(SourceLedgerError, match="Primary Sources diverges"):
        assert_markdown_source_ledger_consistent(tampered, sources)


def test_review_readiness_separates_generation_evaluation_and_analyst_attention():
    assert (
        derive_review_status(
            report_status=ReportStatus.COMPLETED,
            evaluation_status=EvaluationStatus.FAILED,
            quality_score=None,
            quality_assessment=None,
            source_count=1,
        )
        is ReviewStatus.NEEDS_EVALUATION
    )
    assert (
        derive_review_status(
            report_status=ReportStatus.COMPLETED,
            evaluation_status=EvaluationStatus.COMPLETED,
            quality_score=4.2,
            quality_assessment={
                "summary": {"passed_sections": 7, "failed_sections": 0, "unavailable_sections": 0},
                "consistency": {"inconsistencies": []},
                "critical_issues": [],
                "needs_improvement": False,
            },
            source_count=1,
            evidence_admissibility_status=EvidenceAdmissibilityStatus.PASSED,
        )
        is ReviewStatus.REVIEWABLE
    )

    assert (
        derive_review_status(
            report_status=ReportStatus.COMPLETED,
            evaluation_status=EvaluationStatus.COMPLETED,
            quality_score=4.2,
            quality_assessment={"summary": {"passed_sections": 7}},
            source_count=1,
            evidence_admissibility_status=EvidenceAdmissibilityStatus.UNASSESSED,
        )
        is ReviewStatus.NEEDS_ATTENTION
    )
    assert (
        derive_review_status(
            report_status=ReportStatus.COMPLETED,
            evaluation_status=EvaluationStatus.COMPLETED,
            quality_score=4.2,
            quality_assessment={"summary": {"passed_sections": 7}, "critical_issues": []},
            source_count=0,
        )
        is ReviewStatus.NEEDS_ATTENTION
    )


def test_judgment_eligibility_is_derived_from_the_complete_evaluation_lifecycle():
    assert is_judgment_eligible(
        report_status=ReportStatus.COMPLETED,
        evaluation_status=EvaluationStatus.COMPLETED,
        quality_score=4.2,
    )
    assert not is_judgment_eligible(
        report_status=ReportStatus.FAILED,
        evaluation_status=EvaluationStatus.COMPLETED,
        quality_score=4.2,
    )
    assert not is_judgment_eligible(
        report_status=ReportStatus.COMPLETED,
        evaluation_status=EvaluationStatus.FAILED,
        quality_score=None,
    )
    assert is_reuse_eligible(
        report_status=ReportStatus.COMPLETED,
        evaluation_status=EvaluationStatus.COMPLETED,
        quality_score=4.2,
        evidence_admissibility_status=EvidenceAdmissibilityStatus.PASSED,
    )
    assert not is_reuse_eligible(
        report_status=ReportStatus.COMPLETED,
        evaluation_status=EvaluationStatus.COMPLETED,
        quality_score=4.2,
        evidence_admissibility_status=EvidenceAdmissibilityStatus.UNASSESSED,
    )


def test_conflict_count_uses_only_explicit_cross_section_inconsistencies():
    assert (
        evaluation_conflict_count(
            {"consistency": {"inconsistencies": ["Timeline mismatch.", "", "Header mismatch."]}}
        )
        == 2
    )
    assert evaluation_conflict_count({"recommendations": ["Investigate further."]}) == 0


def test_generation_route_scope_never_promotes_a_legacy_aggregate_to_synthesis():
    assert (
        derive_generation_route_scope(
            synthesis_route={"used_fallback": False},
            generation_route={"used_fallback": True},
        )
        is GenerationRouteScope.SYNTHESIS
    )
    assert (
        derive_generation_route_scope(
            synthesis_route=None,
            generation_route={"used_fallback": True},
        )
        is GenerationRouteScope.LEGACY_AGGREGATE
    )
    assert (
        derive_generation_route_scope(synthesis_route=None, generation_route=None)
        is GenerationRouteScope.UNRECORDED
    )


def test_nested_generated_classification_and_saved_preview_survive_storage_projection():
    service = ReportStorageService.__new__(ReportStorageService)
    category, threat_type = service.categorize_tool("SocGholish", source_profile())
    report = Report(
        id="5ad0aabb-5dbf-4fd9-840f-da9c3db78455",
        tool_name="SocGholish",
        created_at=datetime(2026, 8, 14, tzinfo=timezone.utc),
        category=category,
        threat_type=threat_type,
        threat_data=source_profile(),
    )

    assert (category, threat_type) == ("malware", "loader")
    assert report.to_dict()["content_preview"].startswith("A source-backed description")


def test_evaluation_prompt_names_the_current_date_boundary_explicitly():
    prompt = build_section_evaluation_prompt(
        "webSearchSources",
        {"primarySources": []},
        SECTION_CRITERIA["webSearchSources"],
        current_date="2026-08-14",
    )

    assert "Current UTC date: 2026-08-14" in prompt
    assert "never as future dates" in prompt
    assert "Current UTC date: Unknown" not in prompt

    with pytest.raises(ValueError, match="host-owned current UTC date"):
        build_section_evaluation_prompt(
            "webSearchSources",
            {"primarySources": []},
            SECTION_CRITERIA["webSearchSources"],
            current_date="",
        )


def test_consistency_request_carries_the_current_utc_date(monkeypatch):
    captured: dict = {}

    class FixedDateTime:
        @classmethod
        def now(cls, _timezone):
            return datetime(2026, 8, 14, tzinfo=timezone.utc)

    validator = SectionValidator(client=None)

    def request_model(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(
            parsed=ConsistencyEvaluation(
                consistency_score=4.0,
                inconsistencies=[],
                recommendations=[],
            )
        )

    monkeypatch.setattr(section_validator_module, "datetime", FixedDateTime)
    monkeypatch.setattr(validator, "_request_model", request_model)

    result = validator._check_consistency({"toolOverview": {"description": "Example"}})

    assert result["was_evaluated"] is True
    assert "Current UTC date: 2026-08-14" in captured["messages"][0]["content"]
