"""Canonical source-ledger projection and persist-time consistency gate."""

from __future__ import annotations

from copy import deepcopy
import json
import re
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit, urlunsplit

from src.domain.reports import ClaimAttributionStatus, GenerationErrorCode


class SourceLedgerError(ValueError):
    """Raised when a report cannot attest one coherent reader-visible source ledger."""

    generation_error_code = GenerationErrorCode.EVIDENCE_UNATTESTED
    retryable = False


CLAIM_ATTRIBUTION_SCHEMA_VERSION = "4"
SUPPORTED_CLAIM_ATTRIBUTION_VERSIONS = frozenset({"2", "3", CLAIM_ATTRIBUTION_SCHEMA_VERSION})
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
    if not isinstance(attribution, dict) or attribution.get("schemaVersion") not in {"3", "4"}:
        return
    claims = attribution.get("claims")
    if not isinstance(claims, list):
        raise SourceLedgerError("Current claim attribution selector is invalid")
    for claim in claims:
        if not isinstance(claim, dict):
            raise SourceLedgerError("Current claim attribution selector is invalid")
        claim["claim"] = _selected_claim_value(profile, claim)


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
        if version == "4":
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
        if version in {"3", CLAIM_ATTRIBUTION_SCHEMA_VERSION}:
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
    if version == CLAIM_ATTRIBUTION_SCHEMA_VERSION:
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
