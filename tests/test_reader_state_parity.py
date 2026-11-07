"""Stored reader state must equal the read-time projection for retained shapes."""

from copy import deepcopy
from datetime import datetime, timezone

import pytest

from src.api import main as api_main
from src.storage.models import Report
from src.storage.report_service import ReportStorageService
from tests.conftest import build_threat_profile_data

PASSING_ASSESSMENT = {"overall_score": 4.5, "summary": {"passed_sections": 3, "failed_sections": 0}}


def _record() -> dict:
    profile = build_threat_profile_data("https://research.vendor-security.com/report")
    return {
        "id": "00000000-0000-0000-0000-000000000001",
        "tool_name": "Example",
        "status": "completed",
        "created_at": datetime(2026, 8, 15, tzinfo=timezone.utc),
        "threat_data": profile,
        "web_sources": deepcopy(profile["webSearchSources"]["primarySources"]),
        "evaluation_status": "completed",
        "quality_score": 4.5,
        "quality_assessment": deepcopy(PASSING_ASSESSMENT),
        "evidence_admissibility_status": "passed",
        "evidence_admissibility": {"schemaVersion": "1", "status": "passed"},
        "claim_attribution_status": "attributed",
        "claim_attribution_version": "5",
    }


def _profile_owned_assessment(record):
    record["threat_data"]["_quality_assessment"] = record.pop("quality_assessment")


def _profile_owned_evidence_status(record):
    record.pop("evidence_admissibility_status")
    record.pop("evidence_admissibility")
    record["threat_data"]["evidenceAdmissibility"] = {"schemaVersion": "1", "status": "passed"}


def _unknown_evidence_status(record):
    record["evidence_admissibility_status"] = "not-a-status"


def _older_attribution_with_passed_evidence(record):
    record["claim_attribution_version"] = "4"


def _evaluation_status_from_score(record):
    record.pop("evaluation_status")


def _invalid_sources_are_not_counted(record):
    record["web_sources"] = [{"url": "ftp://example.org/file"}, "not a source"]


@pytest.mark.parametrize(
    "variant",
    [
        lambda record: None,
        _profile_owned_assessment,
        _profile_owned_evidence_status,
        _unknown_evidence_status,
        _older_attribution_with_passed_evidence,
        _evaluation_status_from_score,
        _invalid_sources_are_not_counted,
    ],
)
def test_stored_reader_state_matches_the_read_projection(variant):
    record = _record()
    variant(record)
    report = Report(**{key: value for key, value in record.items() if key != "created_at"})

    ReportStorageService._refresh_review_status(report)
    expected = api_main.report_response_fields(record)

    assert (
        report.review_status,
        report.eligible_for_judgment,
        report.eligible_for_acceptance,
        report.eligible_for_handoff,
    ) == (
        expected["review_status"].value,
        expected["eligible_for_judgment"],
        expected["eligible_for_acceptance"],
        expected["eligible_for_handoff"],
    )
