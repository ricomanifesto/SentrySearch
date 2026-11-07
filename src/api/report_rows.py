"""Project the detail response's evidence surfaces from stored rows.

``threat_data`` stays a rendered artifact for the inspection panel; the source
rail, claim links, and evidence observations come from the flat relations.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from src.api.contracts import ClaimAttributionEntry, ReportSource


def _value(row: Mapping[str, Any], name: str, default: str = "") -> str:
    value = row.get(name)
    return str(value) if value is not None and str(value).strip() else default


def report_sources_from_rows(rows: Sequence[Mapping[str, Any]]) -> list[ReportSource]:
    return [
        ReportSource(
            source_id=row.get("source_id"),
            title=_value(row, "title", _value(row, "domain")),
            url=str(row["url"]),
            domain=_value(row, "domain"),
            access_date=_value(row, "access_date", "Unknown"),
            relevance_score=_value(row, "relevance_score", "Unknown"),
            content_type=_value(row, "content_type", "Unknown"),
            key_findings=_value(row, "key_findings", "No findings recorded"),
            evidence_purpose=row.get("purpose"),
            evidence_disposition=row.get("disposition"),
            evidence_reason=row.get("reason"),
            evidence_rule_id=row.get("rule_id"),
            evidence_snapshot_status=row.get("snapshot_status"),
            evidence_snapshot_sha256=row.get("snapshot_sha256"),
            evidence_snapshot_captured_at=row.get("snapshot_captured_at"),
            evidence_snapshot_final_url=row.get("snapshot_final_url"),
            evidence_page_age=row.get("page_age"),
        )
        for row in sorted(rows, key=lambda row: row["position"])
    ]


def claim_attributions_from_rows(
    claims: Sequence[Mapping[str, Any]],
    support: Sequence[Mapping[str, Any]],
) -> list[ClaimAttributionEntry]:
    by_claim: dict[str, list[Mapping[str, Any]]] = {}
    for row in sorted(support, key=lambda row: row["position"]):
        by_claim.setdefault(row["claim_id"], []).append(row)
    entries = []
    for claim in sorted(claims, key=lambda row: row["position"]):
        supports = by_claim.get(claim["claim_id"], [])
        entries.append(
            ClaimAttributionEntry(
                claim_class=claim["claim_class"],
                claim=claim["value"],
                evidence_role=claim.get("evidence_role"),
                source_ids=[row["source_id"] for row in supports],
                supporting_evidence=[
                    {
                        "source_id": row["source_id"],
                        "excerpt": row["excerpt"],
                        "snapshot_sha256": row.get("snapshot_sha256") or "",
                    }
                    for row in supports
                ],
            )
        )
    return entries


def _without_none(record: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if value is not None}


def evidence_admissibility_from_rows(
    assessment: Mapping[str, Any],
    source_observations: Sequence[Mapping[str, Any]],
    indicator_observations: Sequence[Mapping[str, Any]],
    findings: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """The audit record with its observations and findings read from rows.

    The schema version, status, and summary counts stay on the stored record.
    """

    return {
        "schemaVersion": assessment.get("schemaVersion"),
        "status": assessment.get("status"),
        "sourceObservations": [
            _without_none(
                {
                    "sourceId": row.get("source_id"),
                    "title": row.get("title"),
                    "url": row.get("url"),
                    "domain": row.get("domain"),
                    "purpose": row.get("purpose"),
                    "disposition": row.get("disposition"),
                    "reason": row.get("reason"),
                    "ruleId": row.get("rule_id"),
                    "snapshotStatus": row.get("snapshot_status"),
                    "snapshotSha256": row.get("snapshot_sha256"),
                    "snapshotCapturedAt": row.get("snapshot_captured_at"),
                    "snapshotFinalUrl": row.get("snapshot_final_url"),
                    "pageAge": row.get("page_age"),
                }
            )
            for row in sorted(source_observations, key=lambda row: row["position"])
        ],
        "indicatorObservations": [
            _without_none(
                {
                    "claimField": row.get("field"),
                    "claimIndex": row.get("ordinal"),
                    "value": row.get("value"),
                    "disposition": row.get("disposition"),
                    "reason": row.get("reason"),
                    "ruleId": row.get("rule_id"),
                }
            )
            for row in sorted(indicator_observations, key=lambda row: row["position"])
        ],
        "blockingFindings": [
            row["message"] for row in sorted(findings, key=lambda row: row["position"])
        ],
        "summary": dict(assessment.get("summary") or {}),
    }
