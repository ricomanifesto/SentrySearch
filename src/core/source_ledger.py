"""Canonical source-ledger projection and persist-time consistency gate."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import json
import logging
import re
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

from src.core.generation_failures import EvidenceCoverageError
from src.core.profile_tables import (
    CLAIM_FIELDS,
    AttributionRow,
    ClaimRow,
    ClaimSupportRow,
    ProfileTables,
    flatten,
    item_text,
    render,
    resolve_selector,
    with_attribution,
    with_claims,
    write_back,
)
from src.core.source_urls import canonical_source_url
from src.domain.reports import (
    ClaimAttributionStatus,
    EvidenceAdmissibilityStatus,
    GenerationErrorCode,
)

logger = logging.getLogger(__name__)


class SourceLedgerError(ValueError):
    """Raised when a report cannot attest one coherent reader-visible source ledger."""

    generation_error_code = GenerationErrorCode.EVIDENCE_UNATTESTED
    retryable = False


CLAIM_ATTRIBUTION_SCHEMA_VERSION = "5"
CLAIM_ATTRIBUTION_GENERATION_SHAPE = "embedded_evidence_items"
SUPPORTED_CLAIM_ATTRIBUTION_VERSIONS = frozenset({"2", "3", "4", CLAIM_ATTRIBUTION_SCHEMA_VERSION})
HIGH_RISK_CLAIM_CLASSES = frozenset(
    {
        "threat_activity",
        "forensic_artifact",
        "detection_indicator",
        "mitigation_action",
    }
)
CLAIM_CLASS_SECTIONS = {
    "threat_activity": "threatIntelligence",
    "forensic_artifact": "forensicArtifacts",
    "detection_indicator": "detectionAndMitigation",
    "mitigation_action": "mitigationAndResponse",
}
# Derived from the single claim-field table so every consumer shares one order.
CLAIM_CLASS_SELECTORS: dict[str, dict[str, tuple[str, ...]]] = {}
for _claim_class, _claim_field, _field_path in CLAIM_FIELDS:
    CLAIM_CLASS_SELECTORS.setdefault(_claim_class, {})[_claim_field] = _field_path


_MARKDOWN_LINK = re.compile(r"\]\((https?://[^)\s]+)\)")
_SUPPORT_TOKEN = re.compile(r"[a-z0-9][a-z0-9._/-]{2,}")
MAX_PERSISTED_SUPPORT_EXCERPT = 600
_SUPPORT_STOPWORDS = frozenset(
    {
        "and",
        "are",
        "for",
        "from",
        "into",
        "that",
        "the",
        "this",
        "through",
        "using",
        "with",
    }
)


def _support_has_claim_anchor(claim: str, excerpt: str) -> bool:
    claim_tokens = {
        token
        for token in _SUPPORT_TOKEN.findall(claim.casefold())
        if token not in _SUPPORT_STOPWORDS
    }
    excerpt_tokens = {
        token
        for token in _SUPPORT_TOKEN.findall(excerpt.casefold())
        if token not in _SUPPORT_STOPWORDS
    }
    return bool(claim_tokens & excerpt_tokens)


def _bounded_support_excerpt(claim: str, excerpt: str) -> str:
    """Keep one exact source window around the strongest claim token."""

    if len(excerpt) <= MAX_PERSISTED_SUPPORT_EXCERPT:
        return excerpt
    claim_tokens = sorted(
        {
            token
            for token in _SUPPORT_TOKEN.findall(claim.casefold())
            if token not in _SUPPORT_STOPWORDS
        },
        key=len,
        reverse=True,
    )
    excerpt_casefolded = excerpt.casefold()
    anchor = next(
        (
            (excerpt_casefolded.index(token), len(token))
            for token in claim_tokens
            if token in excerpt_casefolded
        ),
        None,
    )
    if anchor is None:
        return excerpt[:MAX_PERSISTED_SUPPORT_EXCERPT].strip()
    anchor_start, anchor_length = anchor
    context = max(0, (MAX_PERSISTED_SUPPORT_EXCERPT - anchor_length) // 2)
    start = max(0, anchor_start - context)
    end = min(len(excerpt), start + MAX_PERSISTED_SUPPORT_EXCERPT)
    start = max(0, end - MAX_PERSISTED_SUPPORT_EXCERPT)
    return excerpt[start:end].strip()


def _normalized_http_url(value: object) -> str:
    url = canonical_source_url(value)
    if not url:
        raise SourceLedgerError("Source ledger contains a non-HTTP URL")
    return url


def canonical_source_urls(sources: Iterable[Mapping[str, Any]]) -> tuple[str, ...]:
    """Return normalized, ordered, unique URLs for one source collection."""

    urls: list[str] = []
    seen: set[str] = set()
    for source in sources:
        url = _normalized_http_url(source.get("url"))
        if url in seen:
            continue
        seen.add(url)
        urls.append(url)
    return tuple(urls)


def attach_source_ids(sources: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Assign stable request-local source IDs before synthesis and attestation."""

    identified: list[dict[str, Any]] = []
    seen: set[str] = set()
    for source in sources:
        item = dict(source)
        url = _normalized_http_url(item.get("url"))
        if url in seen:
            continue
        seen.add(url)
        item["url"] = url
        item["sourceId"] = f"S{len(identified) + 1}"
        identified.append(item)
    return identified


def _selected_claim_text(tables: ProfileTables, record: AttributionRow) -> str:
    row = resolve_selector(tables, record.claim_class, record.claim_field, record.claim_index)
    if row is None:
        raise SourceLedgerError("Current claim attribution selector is invalid")
    claim_text = item_text(row.raw)
    if not claim_text:
        raise SourceLedgerError("Current claim attribution selector is invalid")
    return claim_text


# -- table transforms ---------------------------------------------------------


def attribute_claim_text(tables: ProfileTables) -> ProfileTables:
    """Copy each selected structured value into its attribution record."""

    if not tables.has_attribution_mapping or tables.schema_version not in {"3", "4", "5"}:
        return tables
    if not tables.attribution_listed:
        raise SourceLedgerError("Current claim attribution selector is invalid")
    attributions = []
    for record in tables.attributions:
        if not record.valid:
            raise SourceLedgerError("Current claim attribution selector is invalid")
        raw = dict(record.raw)
        raw["claim"] = _selected_claim_text(tables, record)
        attributions.append(replace(record, raw=raw))
    return replace(tables, attributions=tuple(attributions))


def derive_embedded_attribution(
    tables: ProfileTables,
    *,
    require_complete_classes: bool = False,
) -> tuple[ProfileTables, EvidenceCoverageError | None]:
    """Derive schema-5 attribution and verify support against captured snapshots.

    Returns the gated tables and, when coverage is incomplete, the typed error
    the caller raises. Surviving claims keep their ``claim_id``; ``ordinal``
    becomes their position in the surviving list.
    """

    snapshots_by_id = {
        source.source_id: source.captured_snapshot
        for source in tables.sources
        if source.source_id and source.captured_snapshot is not None
    }
    embedded_count = sum(1 for row in tables.claims if row.embedded)
    if embedded_count == 0 and tables.has_attribution_mapping:
        # Retained test and compatibility payloads can still supply the legacy
        # parallel ledger during the bounded migration window above.
        return tables, None

    kept: list[ClaimRow] = []
    records: list[tuple[str | None, dict[str, Any]]] = []
    support_rows: list[ClaimSupportRow] = []
    discarded_findings: list[str] = []
    discarded_count = 0
    for claim_class, claim_field, _ in CLAIM_FIELDS:
        if claim_field not in tables.present_fields:
            continue
        surviving = 0
        for row in tables.field_rows(claim_field):
            claim_index = row.ordinal
            if not row.embedded:
                value = item_text(row.raw)
                if value:
                    if embedded_count:
                        discarded_findings.append(
                            f"{claim_field}[{claim_index}] uses a legacy string without embedded evidence."
                        )
                        discarded_count += 1
                    else:
                        kept.append(replace(row, raw=value))
                        surviving += 1
                continue
            value = row.value
            role = row.evidence_role
            source_ids = list(row.source_ids)
            raw_support = row.raw.get("supportingEvidence")
            supports = raw_support if isinstance(raw_support, list) else []
            verified_support: list[dict[str, str]] = []
            support_ids: list[str] = []
            item_findings: list[str] = []
            for support in supports:
                if not isinstance(support, Mapping):
                    item_findings.append(
                        f"{claim_field}[{claim_index}] contains an invalid support record."
                    )
                    continue
                source_id = str(support.get("sourceId") or "").strip()
                excerpt = str(support.get("excerpt") or "").strip()
                snapshot = snapshots_by_id.get(source_id)
                if not source_id or not excerpt or snapshot is None:
                    item_findings.append(
                        f"{claim_field}[{claim_index}] support is not tied to a captured source."
                    )
                    continue
                snapshot_text, snapshot_sha256 = snapshot
                if excerpt not in snapshot_text:
                    item_findings.append(
                        f"{claim_field}[{claim_index}] support excerpt is not verbatim in {source_id}."
                    )
                    continue
                persisted_excerpt = _bounded_support_excerpt(value, excerpt)
                if not _support_has_claim_anchor(value, persisted_excerpt):
                    item_findings.append(
                        f"{claim_field}[{claim_index}] support excerpt in {source_id} has no lexical claim anchor."
                    )
                    continue
                support_ids.append(source_id)
                verified_support.append(
                    {
                        "sourceId": source_id,
                        "excerpt": persisted_excerpt,
                        "snapshotSha256": snapshot_sha256,
                    }
                )
            if not value:
                item_findings.append(f"{claim_field}[{claim_index}] has no reader-visible value.")
            if role == "direct_evidence" and (not source_ids or source_ids != support_ids):
                item_findings.append(
                    f"{claim_field}[{claim_index}] lacks verified captured support for every source."
                )
            elif role == "general_practice" and (
                claim_class != "mitigation_action" or source_ids or supports
            ):
                item_findings.append(
                    f"{claim_field}[{claim_index}] uses general practice outside uncited mitigation guidance."
                )
            elif role not in {"direct_evidence", "general_practice"}:
                item_findings.append(f"{claim_field}[{claim_index}] has no valid evidence role.")

            if item_findings:
                discarded_findings.extend(item_findings)
                discarded_count += 1
                continue
            kept.append(replace(row, raw=value))
            surviving += 1
            attribution_id = f"A{len(records) + 1}"
            support_rows.extend(
                ClaimSupportRow(
                    owner_id=attribution_id,
                    position=position,
                    source_id=support["sourceId"],
                    excerpt=support["excerpt"],
                    snapshot_sha256=support["snapshotSha256"],
                    verified=True,
                    anchor_ok=True,
                )
                for position, support in enumerate(verified_support)
            )
            records.append(
                (
                    row.claim_id,
                    {
                        "claimClass": claim_class,
                        "claim": value,
                        "claimField": claim_field,
                        "claimIndex": surviving - 1,
                        "evidenceRole": role,
                        "sourceIds": source_ids,
                        "supportingEvidence": verified_support,
                    },
                )
            )

    gated = with_claims(tables, kept)
    findings: list[str] = []
    if not records:
        findings.append("No high-risk item carried embedded evidence.")
    if discarded_findings or require_complete_classes:
        observed_classes = {record["claimClass"] for _, record in records}
        missing_classes = sorted(HIGH_RISK_CLAIM_CLASSES - observed_classes)
        if missing_classes:
            findings.extend(discarded_findings)
            findings.append(
                "Embedded evidence is missing required claim classes: " + ", ".join(missing_classes)
            )
        elif discarded_findings:
            logger.warning(
                "Discarded %d unsupported embedded claim(s) while preserving complete schema-5 coverage",
                discarded_count,
            )

    if findings:
        assessment = {
            "schemaVersion": "1",
            "status": EvidenceAdmissibilityStatus.UNASSESSED.value,
            "sourceObservations": [],
            "indicatorObservations": [],
            "blockingFindings": findings,
            "summary": {"safetyFindings": 0, "coverageFindings": len(findings)},
        }
        document = dict(gated.document)
        document["evidenceAdmissibility"] = assessment
        return gated.with_document(document), EvidenceCoverageError(
            "Generated report has incomplete embedded high-risk evidence",
            findings=findings,
            assessment=assessment,
        )

    return (
        with_attribution(
            gated,
            {
                "schemaVersion": CLAIM_ATTRIBUTION_SCHEMA_VERSION,
                "generationShape": CLAIM_ATTRIBUTION_GENERATION_SHAPE,
            },
            records,
            support_rows,
        ),
        None,
    )


def cite_sources(tables: ProfileTables, *, access_date: str) -> ProfileTables:
    """Build every reader-visible source surface from cited attested evidence."""

    document = deepcopy(tables.document)
    web = document.get("webSearchSources")
    if not isinstance(web, dict) or not tables.has_attribution_mapping:
        raise SourceLedgerError("Current claim attribution source ledger is invalid")
    if not isinstance(web.get("primarySources"), list) or not tables.attribution_listed:
        raise SourceLedgerError("Current claim attribution source ledger is invalid")

    cited_ids: list[str] = []
    for record in tables.attributions:
        if not record.valid:
            continue
        for source_id in record.get("sourceIds") or []:
            normalized_id = str(source_id).strip()
            if normalized_id and normalized_id not in cited_ids:
                cited_ids.append(normalized_id)

    cited_set = set(cited_ids)
    primary_sources: list[dict[str, Any]] = []
    for source in tables.sources:
        if source.source_id not in cited_set:
            continue
        url = _normalized_http_url(source.url)
        hostname = (urlsplit(url).hostname or "").lower()
        source_record: dict[str, Any] = {
            "sourceId": source.source_id,
            "url": url,
            "title": str(source.title or hostname or "Unknown source"),
            "domain": hostname,
            "accessDate": str(source.access_date or access_date),
            "relevanceScore": str(source.relevance_score or "Unknown"),
            "contentType": str(source.content_type or "Web source"),
            "keyFindings": str(source.key_findings or "No separate finding summary recorded"),
        }
        snapshot = source.record.get("contentSnapshot")
        snapshot = snapshot if isinstance(snapshot, Mapping) else {}
        optional_snapshot_fields = {
            "evidenceSnapshotStatus": snapshot.get("status"),
            "evidenceSnapshotSha256": snapshot.get("sha256"),
            "evidenceSnapshotCapturedAt": snapshot.get("capturedAt"),
            "evidenceSnapshotFinalUrl": snapshot.get("finalUrl"),
            "evidencePageAge": source.evidence_page_age,
        }
        source_record.update(
            {
                key: value
                for key, value in optional_snapshot_fields.items()
                if value is not None and str(value).strip()
            }
        )
        primary_sources.append(source_record)

    web["primarySources"] = primary_sources
    references = document.get("referencesAndIntelligenceSharing")
    if not isinstance(references, dict):
        raise SourceLedgerError("Current references source ledger is invalid")
    references["sources"] = [
        {
            "title": source["title"],
            "url": source["url"],
            "date": source["accessDate"],
            "relevanceScore": source["relevanceScore"],
        }
        for source in primary_sources
    ]
    operations = document.get("operationalGuidance")
    if isinstance(operations, dict):
        operations["communityResources"] = [
            {
                "resourceType": source["contentType"],
                "name": source["title"],
                "url": source["url"],
                "focus": source["keyFindings"],
            }
            for source in primary_sources
        ]
    return tables.with_document(document)


def attribution_status(
    tables: ProfileTables,
) -> tuple[ClaimAttributionStatus, str | None]:
    """Classify attribution over the flat relations."""

    if not tables.attribution_key_present:
        return ClaimAttributionStatus.LEGACY, None
    if not tables.has_attribution_mapping:
        return ClaimAttributionStatus.UNATTRIBUTED, None
    version = str(tables.schema_version or "").strip() or None
    sources = tables.document.get("webSearchSources")
    primary_sources = sources.get("primarySources") if isinstance(sources, Mapping) else None
    if version not in SUPPORTED_CLAIM_ATTRIBUTION_VERSIONS:
        return ClaimAttributionStatus.UNATTRIBUTED, version
    if not isinstance(primary_sources, list) or not tables.attribution_listed:
        return ClaimAttributionStatus.UNATTRIBUTED, version
    known_ids = {
        str(source.get("sourceId") or "").strip()
        for source in primary_sources
        if isinstance(source, Mapping) and str(source.get("sourceId") or "").strip()
    }
    known_snapshot_hashes = {
        str(source.get("sourceId") or "")
        .strip(): str(source.get("evidenceSnapshotSha256") or "")
        .strip()
        for source in primary_sources
        if isinstance(source, Mapping) and str(source.get("sourceId") or "").strip()
    }
    observed_classes: set[str] = set()
    observed_selectors: list[tuple[str, str, int]] = []
    for record in tables.attributions:
        if not record.valid:
            return ClaimAttributionStatus.UNATTRIBUTED, version
        claim_text = record.claim_text
        source_ids = record.source_ids
        if not claim_text or source_ids is None:
            return ClaimAttributionStatus.UNATTRIBUTED, version
        evidence_role = record.evidence_role
        claim_class = record.claim_class
        if version in {"4", "5"}:
            if evidence_role == "direct_evidence" and not source_ids:
                return ClaimAttributionStatus.UNATTRIBUTED, version
            if evidence_role == "general_practice" and (
                record.get("claimClass") != "mitigation_action" or source_ids
            ):
                return ClaimAttributionStatus.UNATTRIBUTED, version
            if evidence_role not in {"direct_evidence", "general_practice"}:
                return ClaimAttributionStatus.UNATTRIBUTED, version
        elif not source_ids:
            return ClaimAttributionStatus.UNATTRIBUTED, version
        if any(source_id not in known_ids for source_id in source_ids):
            return ClaimAttributionStatus.UNATTRIBUTED, version
        if version == "5":
            supports = record.supports
            if supports is None:
                return ClaimAttributionStatus.UNATTRIBUTED, version
            support_ids = [
                str(support.get("sourceId") or "").strip()
                for support in supports
                if isinstance(support, Mapping)
                and str(support.get("sourceId") or "").strip()
                and str(support.get("excerpt") or "").strip()
                and str(support.get("snapshotSha256") or "").strip()
            ]
            if any(
                not isinstance(support, Mapping)
                or str(support.get("snapshotSha256") or "").strip()
                != known_snapshot_hashes.get(str(support.get("sourceId") or "").strip())
                for support in supports
            ):
                return ClaimAttributionStatus.UNATTRIBUTED, version
            if evidence_role == "direct_evidence" and support_ids != list(source_ids):
                return ClaimAttributionStatus.UNATTRIBUTED, version
            if evidence_role == "general_practice" and supports:
                return ClaimAttributionStatus.UNATTRIBUTED, version
        if version in {"3", "4", CLAIM_ATTRIBUTION_SCHEMA_VERSION}:
            try:
                selected_claim = _selected_claim_text(tables, record)
            except SourceLedgerError:
                return ClaimAttributionStatus.UNATTRIBUTED, version
            if claim_text != selected_claim:
                return ClaimAttributionStatus.UNATTRIBUTED, version
            observed_selectors.append((claim_class, record.claim_field, int(record.claim_index)))
        else:
            section_name = CLAIM_CLASS_SECTIONS.get(claim_class)
            section = render(tables).get(section_name) if section_name else None
            if not isinstance(section, Mapping):
                return ClaimAttributionStatus.UNATTRIBUTED, version
            section_text = json.dumps(section, sort_keys=True).casefold()
            if claim_text.casefold() not in section_text:
                return ClaimAttributionStatus.UNATTRIBUTED, version
        observed_classes.add(claim_class)
    if not HIGH_RISK_CLAIM_CLASSES.issubset(observed_classes):
        return ClaimAttributionStatus.UNATTRIBUTED, version
    if version in {"4", CLAIM_ATTRIBUTION_SCHEMA_VERSION}:
        expected_selectors = [
            (row.claim_class, row.claim_field, row.ordinal)
            for row in tables.claims
            if item_text(row.raw)
        ]
        if sorted(observed_selectors) != sorted(expected_selectors):
            return ClaimAttributionStatus.UNATTRIBUTED, version
    return ClaimAttributionStatus.ATTRIBUTED, version


def require_consistent_attribution(tables: ProfileTables) -> None:
    """Fail closed when a new profile lacks the versioned high-risk evidence map."""

    status, _ = attribution_status(tables)
    if status is not ClaimAttributionStatus.ATTRIBUTED:
        raise SourceLedgerError("Report claim attribution is inconsistent")


# -- dictionary adapters ------------------------------------------------------


def materialize_claim_attribution(profile: dict[str, Any]) -> None:
    """Copy model-selected structured values into the reader-visible claim map."""

    write_back(profile, render(attribute_claim_text(flatten(profile))))


def materialize_embedded_claim_evidence(
    profile: dict[str, Any],
    evidence_sources: Iterable[Mapping[str, Any]] = (),
    *,
    require_complete_classes: bool = False,
) -> None:
    """Derive schema-5 attribution and verify support against captured source text."""

    tables, error = derive_embedded_attribution(
        flatten(profile, evidence_sources),
        require_complete_classes=require_complete_classes,
    )
    write_back(profile, render(tables))
    if error is not None:
        raise error


def materialize_cited_sources(
    profile: dict[str, Any],
    evidence_sources: Iterable[Mapping[str, Any]],
    *,
    access_date: str,
) -> None:
    """Build every reader-visible source surface from cited attested evidence."""

    write_back(
        profile,
        render(cite_sources(flatten(profile, evidence_sources), access_date=access_date)),
    )


def claim_attribution_status(
    profile: Mapping[str, Any] | None,
) -> tuple[ClaimAttributionStatus, str | None]:
    """Classify attribution without inventing claim links for legacy records."""

    if not isinstance(profile, Mapping):
        return ClaimAttributionStatus.LEGACY, None
    return attribution_status(flatten(profile))


def assert_claim_attribution_consistent(profile: Mapping[str, Any]) -> None:
    """Fail closed when a new profile lacks the versioned high-risk evidence map."""

    require_consistent_attribution(flatten(profile))


def canonicalize_profile_sources(profile: Mapping[str, Any]) -> tuple[dict[str, Any], list[dict]]:
    """Make primary sources the only ledger used by references and reader surfaces."""

    normalized = deepcopy(dict(profile))
    web = normalized.get("webSearchSources")
    if not isinstance(web, dict):
        raise SourceLedgerError("Profile has no structured source ledger")
    raw_sources = web.get("primarySources")
    if not isinstance(raw_sources, list) or not raw_sources:
        raise SourceLedgerError("Profile source ledger is empty")

    sources: list[dict] = []
    seen: set[str] = set()
    for raw in raw_sources:
        if not isinstance(raw, Mapping):
            raise SourceLedgerError("Profile source ledger contains an invalid record")
        source = dict(raw)
        url = _normalized_http_url(source.get("url"))
        if url in seen:
            continue
        seen.add(url)
        source["url"] = url
        source["domain"] = urlsplit(url).netloc
        sources.append(source)

    if not sources:
        raise SourceLedgerError("Profile source ledger is empty")
    web["primarySources"] = sources

    references = normalized.setdefault("referencesAndIntelligenceSharing", {})
    if not isinstance(references, dict):
        raise SourceLedgerError("Profile references section is invalid")
    references["sources"] = [
        {
            "title": source.get("title") or source["domain"],
            "url": source["url"],
            "date": source.get("accessDate") or "Unknown",
            "relevanceScore": source.get("relevanceScore") or "Unknown",
        }
        for source in sources
    ]

    operations = normalized.setdefault("operationalGuidance", {})
    if isinstance(operations, dict):
        operations["communityResources"] = [
            {
                "resourceType": source.get("contentType") or "Source",
                "name": source.get("title") or source["domain"],
                "url": source["url"],
                "focus": source.get("keyFindings") or "Supporting evidence",
            }
            for source in sources
        ]

    # The legacy analysis summarized a broader transient search collection and
    # routinely disagreed with the persisted evidence rail. One ledger is clearer.
    normalized.pop("comprehensiveWebSearchSources", None)
    return normalized, sources


def assert_source_ledger_consistent(
    profile: Mapping[str, Any],
    persisted_sources: Iterable[Mapping[str, Any]],
) -> None:
    """Fail closed when any persisted reader source surface diverges."""

    web = profile.get("webSearchSources")
    references = profile.get("referencesAndIntelligenceSharing")
    if not isinstance(web, Mapping) or not isinstance(references, Mapping):
        raise SourceLedgerError("Profile source surfaces are incomplete")

    primary = web.get("primarySources")
    reference_sources = references.get("sources")
    if not isinstance(primary, list) or not isinstance(reference_sources, list):
        raise SourceLedgerError("Profile source surfaces are incomplete")

    expected = canonical_source_urls(primary)
    if not expected:
        raise SourceLedgerError("Profile source ledger is empty")
    if canonical_source_urls(reference_sources) != expected:
        raise SourceLedgerError("Profile references diverge from the source ledger")
    if canonical_source_urls(persisted_sources) != expected:
        raise SourceLedgerError("Persisted source evidence diverges from the source ledger")
    if "comprehensiveWebSearchSources" in profile:
        raise SourceLedgerError("Legacy competing source analysis must not be persisted")


def _markdown_subsection_urls(markdown: str, heading: str) -> tuple[str, ...]:
    lines = markdown.splitlines()
    try:
        start = lines.index(heading) + 1
    except ValueError as exc:
        raise SourceLedgerError(f"Markdown is missing {heading}") from exc

    urls: list[str] = []
    for line in lines[start:]:
        if line.startswith("## ") or line.startswith("### "):
            break
        urls.extend(_normalized_http_url(match) for match in _MARKDOWN_LINK.findall(line))
    return tuple(dict.fromkeys(urls))


def assert_markdown_source_ledger_consistent(
    markdown: str,
    persisted_sources: Iterable[Mapping[str, Any]],
) -> None:
    """Fail closed when rendered source subsections disagree with the evidence rail."""

    expected = canonical_source_urls(persisted_sources)
    if not expected:
        raise SourceLedgerError("Persisted source evidence is empty")
    subsection_headings = (
        "### Primary Sources",
        "### Sources",
        "### Community Resources",
    )
    for heading in subsection_headings:
        if _markdown_subsection_urls(markdown, heading) != expected:
            raise SourceLedgerError(f"Markdown {heading} diverges from the source ledger")
