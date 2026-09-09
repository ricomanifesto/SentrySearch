"""Pure whole-record eligibility and explicit reader-safe projections."""

from copy import deepcopy
from typing import Any, Callable

from src.core.evidence_admissibility import (
    ContentPolicyExclusion,
    contains_virtual_event_promotion,
    reader_evidence_admissibility,
)

PUBLIC_FIELDS = frozenset(
    {
        "id",
        "tool_name",
        "category",
        "threat_type",
        "classification_status",
        "claim_attribution_status",
        "claim_attribution_version",
        "claim_attributions",
        "evidence_admissibility_status",
        "evidence_admissibility_version",
        "evidence_admissibility",
        "quality_score",
        "created_at",
        "processing_time_ms",
        "status",
        "generation_stage",
        "generation_failure_stage",
        "generation_error_code",
        "generation_retryable",
        "generation_failure",
        "evaluation_status",
        "evaluation_error_code",
        "evaluation_attempts",
        "evaluated_at",
        "review_status",
        "analyst_disposition",
        "content_preview",
        "markdown_content",
        "threat_data",
        "web_sources",
        "search_tags",
        "generation_route",
        "research_route",
        "synthesis_route",
        "evaluation_route",
        "quality_assessment",
        "current_disposition",
        "disposition_history",
    }
)


def reader_safe_threat_data(report: dict[str, Any]) -> dict[str, Any] | None:
    profile = report.get("threat_data")
    if not isinstance(profile, dict):
        return None
    public = {
        key: deepcopy(value)
        for key, value in profile.items()
        if not key.startswith("_") and key != "comprehensiveWebSearchSources"
    }
    audit = public.get("evidenceAdmissibility")
    if isinstance(audit, dict):
        public["evidenceAdmissibility"] = reader_evidence_admissibility(audit)
    if contains_virtual_event_promotion(public):
        raise ContentPolicyExclusion("Report profile contains an excluded virtual-event promotion")
    return public


def public_report_content(report: dict[str, Any]) -> dict[str, Any]:
    public = {key: deepcopy(value) for key, value in report.items() if key in PUBLIC_FIELDS}
    public["threat_data"] = reader_safe_threat_data(report)
    audit = report.get("evidence_admissibility")
    if isinstance(audit, dict):
        public["evidence_admissibility"] = reader_evidence_admissibility(audit)
    profile = report.get("threat_data")
    if not isinstance(public.get("quality_assessment"), dict) and isinstance(profile, dict):
        public["quality_assessment"] = deepcopy(profile.get("_quality_assessment"))
    if contains_virtual_event_promotion(public):
        raise ContentPolicyExclusion("Report contains an excluded virtual-event promotion")
    return public


def assert_report_content_allowed(report: dict[str, Any]) -> None:
    public_report_content(report)
    if report.get("_markdown_s3_key") and report.get("markdown_content") is None:
        raise RuntimeError("Retained report content has not been loaded")


def load_checked_report(report: dict[str, Any], load: Callable[[str], str]) -> dict[str, Any]:
    """Load a snapshot outside locks; retain originals separately from projection."""
    public_report_content(report)
    snapshot = dict(report)
    key = snapshot.get("_markdown_s3_key")
    if snapshot.get("markdown_content") is None and key:
        snapshot["markdown_content"] = load(key)
    assert_report_content_allowed(snapshot)
    return snapshot
