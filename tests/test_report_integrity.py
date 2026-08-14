from datetime import datetime, timezone

import pytest

from src.core.source_ledger import (
    SourceLedgerError,
    assert_markdown_source_ledger_consistent,
    assert_source_ledger_consistent,
    canonicalize_profile_sources,
)
from src.core.validation_criteria import SECTION_CRITERIA, build_section_evaluation_prompt
from src.core.markdown_generator import generate_markdown
from src.domain.reports import EvaluationStatus, ReportStatus, ReviewStatus, derive_review_status
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
        )
        is ReviewStatus.REVIEWABLE
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
