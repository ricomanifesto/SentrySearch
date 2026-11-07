"""The detail response projects the same evidence from rows as from the record."""

from copy import deepcopy

import pytest

from src.api import main as api_main
from src.storage.profile_rows import profile_rows
from src.storage.report_service import ReportStorageService
from tests.conftest import build_threat_profile_data

ASSESSMENT = {
    "schemaVersion": "1",
    "status": "passed",
    "sourceObservations": [
        {
            "sourceId": "S1",
            "title": "Example report",
            "url": "https://research.vendor-security.com/report",
            "domain": "research.vendor-security.com",
            "purpose": "operational",
            "disposition": "admitted",
            "reason": "Captured source content passed deterministic checks.",
            "ruleId": "source.captured-operational-content",
            "snapshotStatus": "captured",
            "snapshotSha256": "a" * 64,
            "snapshotCapturedAt": "2026-08-15T12:00:00+00:00",
            "pageAge": "2026-08-14",
        },
        {
            "sourceId": "S2",
            "title": "Tabletop scenario",
            "url": "https://training.example.org/tabletop/",
            "domain": "training.example.org",
            "purpose": "excluded_non_operational",
            "disposition": "excluded",
            "reason": "Training material is not operational evidence.",
            "ruleId": "source.training-scenario",
            "snapshotStatus": "unavailable",
        },
    ],
    "indicatorObservations": [
        {
            "claimField": "filenames",
            "claimIndex": 0,
            "value": "example.exe",
            "disposition": "admitted",
            "reason": "Indicator type has no deterministic reserved-value rule.",
            "ruleId": "indicator.source-coverage-only",
        }
    ],
    "blockingFindings": [],
    "summary": {"operationalSources": 1, "excludedSources": 1, "safetyFindings": 0},
}


def _report_with_rows() -> dict:
    profile = build_threat_profile_data("https://research.vendor-security.com/report")
    profile["evidenceAdmissibility"] = deepcopy(ASSESSMENT)
    rows = profile_rows(profile, profile["webSearchSources"]["primarySources"], ASSESSMENT)
    report = {
        "id": "report",
        "tool_name": "Example",
        "created_at": "2026-08-15T12:00:00+00:00",
        "threat_data": profile,
        "web_sources": profile["webSearchSources"]["primarySources"],
        "evidence_admissibility": deepcopy(ASSESSMENT),
        "claim_attribution_status": "attributed",
        "claim_attribution_version": "5",
    }
    rows_view = {
        "sources": list(rows.sources),
        "claims": list(rows.claims),
        "claim_support": list(rows.claim_support),
        "indicator_observations": list(rows.indicator_observations),
        "source_observations": list(rows.source_observations),
        "findings": list(rows.findings),
    }
    return {**report, "_rows": rows_view}


def test_source_rail_from_rows_matches_the_record():
    report = _report_with_rows()

    assert api_main.detail_report_sources(report) == api_main.get_report_sources(report)


def test_claim_links_from_rows_match_the_record():
    report = _report_with_rows()

    from_rows = api_main.detail_claim_attributions(report)

    assert from_rows == api_main.get_claim_attributions(report)
    assert len(from_rows) == 10


@pytest.mark.parametrize("schema_version", ["2", "3", "4"])
def test_retained_source_links_without_excerpts_survive_the_row_projection(schema_version):
    profile = build_threat_profile_data("https://research.vendor-security.com/report")
    profile["claimAttribution"]["schemaVersion"] = schema_version
    for record in profile["claimAttribution"]["claims"]:
        record.pop("supportingEvidence", None)
    rows = profile_rows(profile, profile["webSearchSources"]["primarySources"], ASSESSMENT)
    report = {
        **_report_with_rows(),
        "threat_data": profile,
        "claim_attribution_version": schema_version,
    }
    report["_rows"] = {**report["_rows"], "claims": list(rows.claims), "claim_support": []}

    from_rows = api_main.detail_claim_attributions(report)

    assert from_rows == api_main.get_claim_attributions(report)
    assert any(entry.source_ids == ["S1"] for entry in from_rows)
    assert all(entry.supporting_evidence == [] for entry in from_rows)


def test_evidence_audit_from_rows_matches_the_record():
    report = _report_with_rows()

    assert api_main.detail_evidence_admissibility(
        report
    ) == api_main.get_validated_evidence_admissibility(report)


def test_reports_without_rows_keep_the_record_projection():
    report = _report_with_rows()
    report.pop("_rows")

    assert api_main.detail_report_sources(report)
    assert len(api_main.detail_claim_attributions(report)) == 10


def test_unattributed_reports_never_expose_claim_links_from_rows():
    report = _report_with_rows()
    report["claim_attribution_status"] = "legacy"

    assert api_main.detail_claim_attributions(report) == []


def test_stored_reader_state_is_read_instead_of_recomputed():
    report = {
        "id": "report",
        "tool_name": "Example",
        "created_at": "2026-08-15T12:00:00+00:00",
        "status": "completed",
        "reader_state_version": 1,
        # Deliberately unlike what the inputs would derive: the stored value wins.
        "review_status": "needs_attention",
        "eligible_for_judgment": True,
        "eligible_for_acceptance": True,
        "eligible_for_handoff": True,
    }

    fields = api_main.report_response_fields(report)

    assert fields["review_status"] == "needs_attention"
    assert fields["eligible_for_handoff"] is True


def test_collection_policy_withholds_markdown_without_an_allowed_decision():
    allowed = {"_markdown_s3_key": "a.md", "_markdown_policy_status": "allowed"}

    assert api_main.markdown_policy_allows({}) is True
    assert api_main.markdown_policy_allows(allowed) is True
    for status in ("excluded", "unknown", None):
        assert api_main.markdown_policy_allows({**allowed, "_markdown_policy_status": status}) is (
            False
        )


def test_tags_mirror_search_tags_without_duplicates():
    from src.storage.models import Report

    report = Report(id="r", tool_name="t")

    ReportStorageService._write_tags(
        report, ["Cobalt Strike", " ", "cobalt strike", "Cobalt Strike"]
    )

    assert [tag.tag for tag in report.tags] == ["Cobalt Strike", "cobalt strike"]


def test_markdown_renderer_places_each_claim_citation_beside_its_claim():
    from src.core.markdown_generator import generate_markdown

    markdown = generate_markdown(build_threat_profile_data())

    assert "- Remote access [S1](#source-S1)" in markdown
    assert "- `example.exe` [S1](#source-S1)" in markdown
    assert "- Application control **General practice**" in markdown
    assert markdown.count("](#source-S1)") == 8


def test_markdown_renderer_never_cites_an_inconsistent_or_legacy_ledger():
    from src.core.markdown_generator import generate_markdown

    legacy = build_threat_profile_data()
    legacy.pop("claimAttribution")
    tampered = build_threat_profile_data()
    tampered["claimAttribution"]["claims"][0]["claim"] = "Different text"

    for profile in (legacy, tampered):
        markdown = generate_markdown(profile)
        assert "#source-" not in markdown
        assert "General practice" not in markdown


def test_source_rail_keeps_sources_the_rows_cannot_key():
    report = _report_with_rows()
    sources = report["threat_data"]["webSearchSources"]["primarySources"]
    unkeyed = {key: value for key, value in deepcopy(sources[0]).items() if key != "sourceId"}
    unkeyed["url"] = "https://second.vendor-security.com/analysis"
    sources.append(unkeyed)
    report["web_sources"] = sources

    detail = api_main.detail_report_sources(report)

    assert detail == api_main.get_report_sources(report)
    assert [source.source_id for source in detail] == ["S1", None]


def test_claim_links_for_schema_two_records_without_selectors_use_the_record():
    report = _report_with_rows()
    attribution = report["threat_data"]["claimAttribution"]
    attribution["schemaVersion"] = "2"
    for record in attribution["claims"]:
        record.pop("claimField", None)
        record.pop("claimIndex", None)
        record.pop("supportingEvidence", None)
    report["claim_attribution_version"] = "2"

    from_detail = api_main.detail_claim_attributions(report)

    assert from_detail == api_main.get_claim_attributions(report)
    assert any(entry.source_ids == ["S1"] for entry in from_detail)


def test_claim_links_for_schema_three_with_an_unattributed_claim_use_the_record():
    report = _report_with_rows()
    attribution = report["threat_data"]["claimAttribution"]
    attribution["schemaVersion"] = "3"
    attribution["claims"] = attribution["claims"][1:]
    report["claim_attribution_version"] = "3"

    from_detail = api_main.detail_claim_attributions(report)

    assert from_detail == api_main.get_claim_attributions(report)
    assert len(from_detail) == 9
