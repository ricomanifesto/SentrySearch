"""Canonical source-ledger projection and persist-time consistency gate."""

from __future__ import annotations

from copy import deepcopy
import json
import re
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit, urlunsplit

from src.core.generation_failures import EvidenceCoverageError
from src.domain.reports import (
    ClaimAttributionStatus,
    EvidenceAdmissibilityStatus,
    GenerationErrorCode,
)


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
CLAIM_CLASS_SELECTORS = {
    "threat_activity": {
        "riskFactors": ("threatIntelligence", "riskAssessment", "riskFactors"),
    },
    "forensic_artifact": {
        "fileSystemArtifacts": ("forensicArtifacts", "fileSystemArtifacts"),
        "registryArtifacts": ("forensicArtifacts", "registryArtifacts"),
        "networkArtifacts": ("forensicArtifacts", "networkArtifacts"),
        "memoryArtifacts": ("forensicArtifacts", "memoryArtifacts"),
        "logArtifacts": ("forensicArtifacts", "logArtifacts"),
    },
    "detection_indicator": {
        "hashes": ("detectionAndMitigation", "iocs", "hashes"),
        "domains": ("detectionAndMitigation", "iocs", "domains"),
        "ips": ("detectionAndMitigation", "iocs", "ips"),
        "urls": ("detectionAndMitigation", "iocs", "urls"),
        "filenames": ("detectionAndMitigation", "iocs", "filenames"),
        "behavioralIndicators": ("detectionAndMitigation", "behavioralIndicators"),
    },
    "mitigation_action": {
        "preventiveMeasures": ("mitigationAndResponse", "preventiveMeasures"),
        "detectionMethods": ("mitigationAndResponse", "detectionMethods"),
        "responseActions": ("mitigationAndResponse", "responseActions"),
        "recoveryGuidance": ("mitigationAndResponse", "recoveryGuidance"),
    },
}


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
    candidate = str(value or "").strip()
    parsed = urlsplit(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise SourceLedgerError("Source ledger contains a non-HTTP URL")
    return urlunsplit(
        (parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "", parsed.query, "")
    )


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


def _selected_claim_value(profile: Mapping[str, Any], claim: Mapping[str, Any]) -> str:
    claim_class = str(claim.get("claimClass") or "")
    claim_field = str(claim.get("claimField") or "")
    claim_index = claim.get("claimIndex")
    field_path = CLAIM_CLASS_SELECTORS.get(claim_class, {}).get(claim_field)
    if field_path is None or isinstance(claim_index, bool) or not isinstance(claim_index, int):
        raise SourceLedgerError("Current claim attribution selector is invalid")

    selected: Any = profile
    for field_name in field_path:
        if not isinstance(selected, Mapping):
            raise SourceLedgerError("Current claim attribution selector is invalid")
        selected = selected.get(field_name)
    if not isinstance(selected, list) or claim_index < 0 or claim_index >= len(selected):
        raise SourceLedgerError("Current claim attribution selector is invalid")
    claim_text = str(selected[claim_index] or "").strip()
    if not claim_text:
        raise SourceLedgerError("Current claim attribution selector is invalid")
    return claim_text


def materialize_claim_attribution(profile: dict[str, Any]) -> None:
    """Copy model-selected structured values into the reader-visible claim map."""

    attribution = profile.get("claimAttribution")
    if not isinstance(attribution, dict) or attribution.get("schemaVersion") not in {"3", "4", "5"}:
        return
    claims = attribution.get("claims")
    if not isinstance(claims, list):
        raise SourceLedgerError("Current claim attribution selector is invalid")
    for claim in claims:
        if not isinstance(claim, dict):
            raise SourceLedgerError("Current claim attribution selector is invalid")
        claim["claim"] = _selected_claim_value(profile, claim)


def materialize_embedded_claim_evidence(
    profile: dict[str, Any],
    evidence_sources: Iterable[Mapping[str, Any]] = (),
) -> None:
    """Derive schema-5 attribution and verify support against captured source text."""

    claims: list[dict[str, Any]] = []
    embedded_count = 0
    string_count = 0
    findings: list[str] = []
    selected_lists: list[tuple[str, str, list[Any]]] = []
    snapshots_by_id: dict[str, tuple[str, str]] = {}
    for source in evidence_sources:
        source_id = str(source.get("sourceId") or "").strip()
        snapshot = source.get("contentSnapshot")
        if not source_id or not isinstance(snapshot, Mapping):
            continue
        snapshot_text = str(snapshot.get("text") or "")
        snapshot_sha256 = str(snapshot.get("sha256") or "").strip()
        if snapshot.get("status") == "captured" and snapshot_text and snapshot_sha256:
            snapshots_by_id[source_id] = (snapshot_text, snapshot_sha256)

    for claim_class, fields in CLAIM_CLASS_SELECTORS.items():
        for claim_field, field_path in fields.items():
            selected: Any = profile
            for field_name in field_path:
                if not isinstance(selected, Mapping):
                    selected = None
                    break
                selected = selected.get(field_name)
            if not isinstance(selected, list):
                continue
            selected_lists.append((claim_class, claim_field, selected))
            for item in selected:
                if isinstance(item, Mapping):
                    embedded_count += 1
                elif str(item or "").strip():
                    string_count += 1

    if embedded_count == 0 and isinstance(profile.get("claimAttribution"), Mapping):
        # Retained test and compatibility payloads can still supply the legacy
        # parallel ledger during the bounded migration window above.
        return
    if embedded_count and string_count:
        findings.append("High-risk fields mix embedded evidence items with legacy string values.")

    for claim_class, claim_field, values in selected_lists:
        normalized_values: list[str] = []
        for claim_index, item in enumerate(values):
            if not isinstance(item, Mapping):
                value = str(item or "").strip()
                if value:
                    normalized_values.append(value)
                continue
            value = str(item.get("value") or "").strip()
            role = str(item.get("evidenceRole") or "").strip()
            raw_source_ids = item.get("sourceIds")
            source_ids = (
                [str(source_id).strip() for source_id in raw_source_ids if str(source_id).strip()]
                if isinstance(raw_source_ids, list)
                else []
            )
            raw_support = item.get("supportingEvidence")
            supports = raw_support if isinstance(raw_support, list) else []
            verified_support: list[dict[str, str]] = []
            support_ids: list[str] = []
            for support in supports:
                if not isinstance(support, Mapping):
                    findings.append(
                        f"{claim_field}[{claim_index}] contains an invalid support record."
                    )
                    continue
                source_id = str(support.get("sourceId") or "").strip()
                excerpt = str(support.get("excerpt") or "").strip()
                snapshot = snapshots_by_id.get(source_id)
                if not source_id or not excerpt or snapshot is None:
                    findings.append(
                        f"{claim_field}[{claim_index}] support is not tied to a captured source."
                    )
                    continue
                snapshot_text, snapshot_sha256 = snapshot
                if excerpt not in snapshot_text:
                    findings.append(
                        f"{claim_field}[{claim_index}] support excerpt is not verbatim in {source_id}."
                    )
                    continue
                persisted_excerpt = _bounded_support_excerpt(value, excerpt)
                if not _support_has_claim_anchor(value, persisted_excerpt):
                    findings.append(
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
                findings.append(f"{claim_field}[{claim_index}] has no reader-visible value.")
                continue
            if role == "direct_evidence" and (not source_ids or source_ids != support_ids):
                findings.append(
                    f"{claim_field}[{claim_index}] lacks verified captured support for every source."
                )
            elif role == "general_practice" and (
                claim_class != "mitigation_action" or source_ids or supports
            ):
                findings.append(
                    f"{claim_field}[{claim_index}] uses general practice outside uncited mitigation guidance."
                )
            elif role not in {"direct_evidence", "general_practice"}:
                findings.append(f"{claim_field}[{claim_index}] has no valid evidence role.")
            normalized_values.append(value)
            claims.append(
                {
                    "claimClass": claim_class,
                    "claim": value,
                    "claimField": claim_field,
                    "claimIndex": len(normalized_values) - 1,
                    "evidenceRole": role,
                    "sourceIds": source_ids,
                    "supportingEvidence": verified_support,
                }
            )
        values[:] = normalized_values

    if not claims:
        findings.append("No high-risk item carried embedded evidence.")

    if findings:
        assessment = {
            "schemaVersion": "1",
            "status": EvidenceAdmissibilityStatus.UNASSESSED.value,
            "sourceObservations": [],
            "indicatorObservations": [],
            "blockingFindings": findings,
            "summary": {"safetyFindings": 0, "coverageFindings": len(findings)},
        }
        profile["evidenceAdmissibility"] = assessment
        raise EvidenceCoverageError(
            "Generated report has incomplete embedded high-risk evidence",
            findings=findings,
            assessment=assessment,
        )

    profile["claimAttribution"] = {
        "schemaVersion": CLAIM_ATTRIBUTION_SCHEMA_VERSION,
        "generationShape": CLAIM_ATTRIBUTION_GENERATION_SHAPE,
        "claims": claims,
    }


def materialize_cited_sources(
    profile: dict[str, Any],
    evidence_sources: Iterable[Mapping[str, Any]],
    *,
    access_date: str,
) -> None:
    """Add explicitly cited attested sources to the one reader-visible ledger."""

    web = profile.get("webSearchSources")
    attribution = profile.get("claimAttribution")
    if not isinstance(web, dict) or not isinstance(attribution, Mapping):
        raise SourceLedgerError("Current claim attribution source ledger is invalid")
    primary_sources = web.get("primarySources")
    claims = attribution.get("claims")
    if not isinstance(primary_sources, list) or not isinstance(claims, list):
        raise SourceLedgerError("Current claim attribution source ledger is invalid")

    evidence_by_id = {
        str(source.get("sourceId") or "").strip(): source
        for source in evidence_sources
        if str(source.get("sourceId") or "").strip()
    }
    visible_ids = {
        str(source.get("sourceId") or "").strip()
        for source in primary_sources
        if isinstance(source, Mapping) and str(source.get("sourceId") or "").strip()
    }
    cited_ids: list[str] = []
    for claim in claims:
        if not isinstance(claim, Mapping):
            continue
        for source_id in claim.get("sourceIds") or []:
            normalized_id = str(source_id).strip()
            if normalized_id and normalized_id not in cited_ids:
                cited_ids.append(normalized_id)

    for source_id in cited_ids:
        if source_id in visible_ids:
            continue
        evidence = evidence_by_id.get(source_id)
        if evidence is None:
            continue
        url = _normalized_http_url(evidence.get("url"))
        hostname = (urlsplit(url).hostname or "").lower()
        primary_sources.append(
            {
                "sourceId": source_id,
                "url": url,
                "title": str(evidence.get("title") or hostname or "Unknown source"),
                "domain": hostname,
                "accessDate": access_date,
                "relevanceScore": "Unknown",
                "contentType": "Web source",
                "keyFindings": "No separate finding summary recorded",
            }
        )
        visible_ids.add(source_id)


def claim_attribution_status(
    profile: Mapping[str, Any] | None,
) -> tuple[ClaimAttributionStatus, str | None]:
    """Classify attribution without inventing claim links for legacy records."""

    if not isinstance(profile, Mapping) or "claimAttribution" not in profile:
        return ClaimAttributionStatus.LEGACY, None
    attribution = profile.get("claimAttribution")
    if not isinstance(attribution, Mapping):
        return ClaimAttributionStatus.UNATTRIBUTED, None
    version = str(attribution.get("schemaVersion") or "").strip() or None
    sources = profile.get("webSearchSources")
    primary_sources = sources.get("primarySources") if isinstance(sources, Mapping) else None
    claims = attribution.get("claims")
    if version not in SUPPORTED_CLAIM_ATTRIBUTION_VERSIONS:
        return ClaimAttributionStatus.UNATTRIBUTED, version
    if not isinstance(primary_sources, list) or not isinstance(claims, list):
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
    for claim in claims:
        if not isinstance(claim, Mapping):
            return ClaimAttributionStatus.UNATTRIBUTED, version
        claim_text = str(claim.get("claim") or "").strip()
        source_ids = claim.get("sourceIds")
        if not claim_text or not isinstance(source_ids, list):
            return ClaimAttributionStatus.UNATTRIBUTED, version
        evidence_role = str(claim.get("evidenceRole") or "")
        if version in {"4", "5"}:
            if evidence_role == "direct_evidence" and not source_ids:
                return ClaimAttributionStatus.UNATTRIBUTED, version
            if evidence_role == "general_practice" and (
                claim.get("claimClass") != "mitigation_action" or source_ids
            ):
                return ClaimAttributionStatus.UNATTRIBUTED, version
            if evidence_role not in {"direct_evidence", "general_practice"}:
                return ClaimAttributionStatus.UNATTRIBUTED, version
        elif not source_ids:
            return ClaimAttributionStatus.UNATTRIBUTED, version
        if any(str(source_id) not in known_ids for source_id in source_ids):
            return ClaimAttributionStatus.UNATTRIBUTED, version
        claim_class = str(claim.get("claimClass") or "")
        if version == "5":
            supports = claim.get("supportingEvidence")
            if not isinstance(supports, list):
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
            if evidence_role == "direct_evidence" and support_ids != [
                str(source_id) for source_id in source_ids
            ]:
                return ClaimAttributionStatus.UNATTRIBUTED, version
            if evidence_role == "general_practice" and supports:
                return ClaimAttributionStatus.UNATTRIBUTED, version
        if version in {"3", "4", CLAIM_ATTRIBUTION_SCHEMA_VERSION}:
            try:
                selected_claim = _selected_claim_value(profile, claim)
            except SourceLedgerError:
                return ClaimAttributionStatus.UNATTRIBUTED, version
            if claim_text != selected_claim:
                return ClaimAttributionStatus.UNATTRIBUTED, version
            observed_selectors.append(
                (
                    claim_class,
                    str(claim.get("claimField") or ""),
                    int(claim.get("claimIndex")),
                )
            )
        else:
            section_name = CLAIM_CLASS_SECTIONS.get(claim_class)
            section = profile.get(section_name) if section_name else None
            if not isinstance(section, Mapping):
                return ClaimAttributionStatus.UNATTRIBUTED, version
            section_text = json.dumps(section, sort_keys=True).casefold()
            if claim_text.casefold() not in section_text:
                return ClaimAttributionStatus.UNATTRIBUTED, version
        observed_classes.add(claim_class)
    if not HIGH_RISK_CLAIM_CLASSES.issubset(observed_classes):
        return ClaimAttributionStatus.UNATTRIBUTED, version
    if version in {"4", CLAIM_ATTRIBUTION_SCHEMA_VERSION}:
        expected_selectors: list[tuple[str, str, int]] = []
        for expected_class, fields in CLAIM_CLASS_SELECTORS.items():
            for field_name, field_path in fields.items():
                selected: Any = profile
                for path_item in field_path:
                    if not isinstance(selected, Mapping):
                        selected = None
                        break
                    selected = selected.get(path_item)
                if not isinstance(selected, list):
                    continue
                expected_selectors.extend(
                    (expected_class, field_name, index)
                    for index, value in enumerate(selected)
                    if str(value or "").strip()
                )
        if sorted(observed_selectors) != sorted(expected_selectors):
            return ClaimAttributionStatus.UNATTRIBUTED, version
    return ClaimAttributionStatus.ATTRIBUTED, version


def assert_claim_attribution_consistent(profile: Mapping[str, Any]) -> None:
    """Fail closed when a new profile lacks the versioned high-risk evidence map."""

    status, _ = claim_attribution_status(profile)
    if status is not ClaimAttributionStatus.ATTRIBUTED:
        raise SourceLedgerError("Report claim attribution is inconsistent")


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
