"""Project a stored profile into flat storage rows, and rows back into the profile.

Both the writers (dual-write) and the release backfill use ``profile_rows``.
It parses the profile through the same ``flatten`` the evidence gate uses and
never infers evidence that the stored record does not carry: retained schema-4
support has unknown verification state, not a fabricated one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any, Mapping

from src.core.profile_tables import (
    CLAIM_FIELD_PATHS,
    CLAIM_FIELDS,
    INDICATOR_FIELDS,
    flatten,
    item_text,
)
from src.core.source_ledger import CLAIM_ATTRIBUTION_SCHEMA_VERSION

_CONTENT_ADDRESSED_KEY = re.compile(r"/artifacts/([0-9a-f]{64})\.(?:md|json)$")


@dataclass(frozen=True)
class ProfileRows:
    """Plain column dictionaries for every flat evidence relation."""

    sources: tuple[dict[str, Any], ...] = ()
    claims: tuple[dict[str, Any], ...] = ()
    claim_support: tuple[dict[str, Any], ...] = ()
    indicator_observations: tuple[dict[str, Any], ...] = ()
    source_observations: tuple[dict[str, Any], ...] = ()
    findings: tuple[dict[str, Any], ...] = field(default_factory=tuple)


def _text(value: Any) -> str | None:
    text = str(value).strip() if value is not None else ""
    return text or None


def content_address(s3_key: str | None) -> str | None:
    """The SHA-256 a content-addressed artifact key carries, when it has one."""

    match = _CONTENT_ADDRESSED_KEY.search(s3_key or "")
    return match.group(1) if match else None


def profile_rows(
    threat_data: Mapping[str, Any] | None,
    web_sources: Any = None,
    evidence_admissibility: Mapping[str, Any] | None = None,
) -> ProfileRows:
    """Rows for one stored report. Absent inputs produce no rows."""

    tables = flatten(threat_data if isinstance(threat_data, Mapping) else {})
    schema_five = tables.schema_version == CLAIM_ATTRIBUTION_SCHEMA_VERSION

    roles: dict[str, str] = {}
    owners: dict[str, str] = {}
    for record in tables.attributions:
        if record.claim_id is None or record.claim_id in roles:
            continue
        roles[record.claim_id] = record.evidence_role or ""
        owners[record.attribution_id] = record.claim_id

    claims = tuple(
        {
            "claim_id": row.claim_id,
            "position": position,
            "claim_class": row.claim_class,
            "claim_field": row.claim_field,
            "ordinal": row.ordinal,
            "value": item_text(row.raw),
            "evidence_role": roles.get(row.claim_id) or None,
        }
        for position, row in enumerate(
            row
            for _, claim_field, _ in CLAIM_FIELDS
            for row in tables.field_rows(claim_field)
            if item_text(row.raw)
        )
    )
    claim_support = tuple(
        {
            "claim_id": owners[support.owner_id],
            "position": support.position,
            "source_id": support.source_id,
            "excerpt": support.excerpt,
            # Only schema 5 persists support after exact-substring verification.
            "verified": True if schema_five and support.snapshot_sha256 else None,
            "anchor_ok": True if schema_five and support.snapshot_sha256 else None,
            "snapshot_sha256": support.snapshot_sha256 or None,
        }
        for support in tables.claim_support
        if support.owner_id in owners and support.source_id and support.excerpt
    )

    primary = web_sources if isinstance(web_sources, list) else []
    if not primary:
        block = tables.document.get("webSearchSources")
        candidate = block.get("primarySources") if isinstance(block, Mapping) else None
        primary = candidate if isinstance(candidate, list) else []
    seen_sources: set[str] = set()
    sources: list[dict[str, Any]] = []
    for source in primary:
        if not isinstance(source, Mapping):
            continue
        source_id = _text(source.get("sourceId"))
        url = _text(source.get("url"))
        if not source_id or not url or source_id in seen_sources:
            continue
        seen_sources.add(source_id)
        sources.append(
            {
                "source_id": source_id,
                "position": len(sources),
                "url": url,
                "domain": _text(source.get("domain")),
                "title": _text(source.get("title")),
                "snapshot_status": _text(source.get("evidenceSnapshotStatus")),
                "snapshot_sha256": _text(source.get("evidenceSnapshotSha256")),
                "page_age": _text(source.get("evidencePageAge")),
                "purpose": _text(source.get("evidencePurpose")),
                "disposition": _text(source.get("evidenceDisposition")),
                "rule_id": _text(source.get("evidenceRuleId")),
                "reason": _text(source.get("evidenceReason")),
            }
        )

    assessment = evidence_admissibility
    if not isinstance(assessment, Mapping):
        stored = tables.document.get("evidenceAdmissibility")
        assessment = stored if isinstance(stored, Mapping) else {}

    claim_ids = {
        (row.claim_field, row.ordinal): row.claim_id
        for row in tables.claims
        if row.claim_field in INDICATOR_FIELDS
    }
    indicator_observations = tuple(
        {
            "position": position,
            "claim_id": (
                claim_ids.get((str(item.get("claimField")), item.get("claimIndex")))
                if str(item.get("claimField")) in CLAIM_FIELD_PATHS
                and item.get("disposition") != "excluded"
                else None
            ),
            "field": str(item.get("claimField") or ""),
            "ordinal": item.get("claimIndex") if isinstance(item.get("claimIndex"), int) else None,
            "value": str(item.get("value") or ""),
            "disposition": str(item.get("disposition") or ""),
            "rule_id": _text(item.get("ruleId")),
            "reason": _text(item.get("reason")),
        }
        for position, item in enumerate(
            item
            for item in assessment.get("indicatorObservations") or []
            if isinstance(item, Mapping)
        )
    )
    source_observations = tuple(
        {
            "position": position,
            "source_id": _text(item.get("sourceId")),
            "title": _text(item.get("title")),
            "url": _text(item.get("url")),
            "domain": _text(item.get("domain")),
            "purpose": _text(item.get("purpose")),
            "disposition": _text(item.get("disposition")),
            "rule_id": _text(item.get("ruleId")),
            "reason": _text(item.get("reason")),
            "snapshot_status": _text(item.get("snapshotStatus")),
            "snapshot_sha256": _text(item.get("snapshotSha256")),
            "page_age": _text(item.get("pageAge")),
        }
        for position, item in enumerate(
            item for item in assessment.get("sourceObservations") or [] if isinstance(item, Mapping)
        )
    )
    # Safety findings are always listed first; the summary says how many.
    summary = assessment.get("summary")
    safety_count = summary.get("safetyFindings") if isinstance(summary, Mapping) else 0
    safety_count = safety_count if isinstance(safety_count, int) else 0
    findings = tuple(
        {
            "position": position,
            "kind": "safety" if position < safety_count else "coverage",
            "rule_id": None,
            "selector": None,
            "message": message,
        }
        for position, message in enumerate(
            str(item) for item in assessment.get("blockingFindings") or [] if str(item).strip()
        )
    )
    return ProfileRows(
        sources=tuple(sources),
        claims=claims,
        claim_support=claim_support,
        indicator_observations=indicator_observations,
        source_observations=source_observations,
        findings=findings,
    )


def render_claims(
    threat_data: Mapping[str, Any],
    claims: Any,
    claim_support: Any,
    *,
    schema_version: str = CLAIM_ATTRIBUTION_SCHEMA_VERSION,
    generation_shape: str | None = None,
) -> dict[str, Any]:
    """Rebuild the high-risk claim lists and schema-5 attribution from rows.

    ``claims`` and ``claim_support`` are row dictionaries (or objects with the
    same attributes). Everything else in ``threat_data`` is kept as stored.
    """

    def value(row: Any, name: str) -> Any:
        return row.get(name) if isinstance(row, Mapping) else getattr(row, name)

    from copy import deepcopy

    rendered = deepcopy(dict(threat_data))
    ordered = sorted(claims, key=lambda row: value(row, "position"))
    support_by_claim: dict[str, list[Any]] = {}
    for row in sorted(claim_support, key=lambda row: value(row, "position")):
        support_by_claim.setdefault(value(row, "claim_id"), []).append(row)

    for _, claim_field, path in CLAIM_FIELDS:
        parent: Any = rendered
        for key in path[:-1]:
            parent = parent.get(key) if isinstance(parent, dict) else None
        if not isinstance(parent, dict) or not isinstance(parent.get(path[-1]), list):
            continue
        parent[path[-1]] = [
            value(row, "value")
            for row in sorted(
                (row for row in ordered if value(row, "claim_field") == claim_field),
                key=lambda row: value(row, "ordinal"),
            )
        ]

    records = []
    for row in ordered:
        supports = support_by_claim.get(value(row, "claim_id"), [])
        records.append(
            {
                "claimClass": value(row, "claim_class"),
                "claim": value(row, "value"),
                "claimField": value(row, "claim_field"),
                "claimIndex": value(row, "ordinal"),
                "evidenceRole": value(row, "evidence_role"),
                "sourceIds": [value(support, "source_id") for support in supports],
                "supportingEvidence": [
                    {
                        "sourceId": value(support, "source_id"),
                        "excerpt": value(support, "excerpt"),
                        "snapshotSha256": value(support, "snapshot_sha256"),
                    }
                    for support in supports
                ],
            }
        )
    attribution: dict[str, Any] = {"schemaVersion": schema_version}
    if generation_shape:
        attribution["generationShape"] = generation_shape
    attribution["claims"] = records
    rendered["claimAttribution"] = attribution
    return rendered
