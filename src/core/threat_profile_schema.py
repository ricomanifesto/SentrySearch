"""Structured output contract for generated threat intelligence profiles."""

from __future__ import annotations

import json
import logging
import re
from copy import deepcopy
from typing import Any, Literal
from urllib.parse import parse_qsl, urlencode, urlsplit

from json_repair import repair_json
from pydantic import BaseModel, ConfigDict, Field, model_validator

logger = logging.getLogger(__name__)

_INVALID_JSON_ESCAPE = re.compile(r'\\(?!["\\/bfnrt]|u[0-9a-fA-F]{4})')

_EMBEDDED_EVIDENCE_PATHS = (
    ("threatIntelligence", "riskAssessment", "riskFactors"),
    ("forensicArtifacts", "fileSystemArtifacts"),
    ("forensicArtifacts", "registryArtifacts"),
    ("forensicArtifacts", "networkArtifacts"),
    ("forensicArtifacts", "memoryArtifacts"),
    ("forensicArtifacts", "logArtifacts"),
    ("detectionAndMitigation", "iocs", "hashes"),
    ("detectionAndMitigation", "iocs", "domains"),
    ("detectionAndMitigation", "iocs", "ips"),
    ("detectionAndMitigation", "iocs", "urls"),
    ("detectionAndMitigation", "iocs", "filenames"),
    ("detectionAndMitigation", "behavioralIndicators"),
    ("mitigationAndResponse", "preventiveMeasures"),
    ("mitigationAndResponse", "detectionMethods"),
    ("mitigationAndResponse", "responseActions"),
    ("mitigationAndResponse", "recoveryGuidance"),
)

_PLAIN_STRING_LIST_PATHS = (
    ("toolOverview", "knownAliases"),
    ("technicalDetails", "operatingSystems"),
    ("technicalDetails", "dependencies"),
    ("technicalDetails", "persistence"),
    ("technicalDetails", "capabilities"),
    ("commandAndControl", "beaconingPatterns", "*", "indicators"),
    ("commandAndControl", "commonCommands"),
    ("threatIntelligence", "entities", "campaigns", "*", "targetSectors"),
    ("referencesAndIntelligenceSharing", "additionalReferences"),
    ("integration", "threatHuntingQueries"),
    ("lineage", "variants"),
    ("lineage", "relationships"),
    ("operationalGuidance", "validationCriteria"),
)

_EVIDENCE_WRAPPER_KEYS = {
    "value",
    "evidenceRole",
    "sourceIds",
    "supportingEvidence",
}


def _lists_at_path(value: Any, path: tuple[str, ...]) -> list[list[Any]]:
    """Resolve plain-list paths, including list-item wildcards."""

    values = [value]
    for key in path:
        resolved: list[Any] = []
        for candidate in values:
            if key == "*" and isinstance(candidate, list):
                resolved.extend(candidate)
            elif isinstance(candidate, dict) and key in candidate:
                resolved.append(candidate[key])
        values = resolved
    return [candidate for candidate in values if isinstance(candidate, list)]


def _unwrap_evidence_objects_from_plain_lists(profile: dict[str, Any]) -> int:
    """Restore non-claim string arrays when a model over-applies evidence wrappers."""

    unwrapped = 0
    for path in _PLAIN_STRING_LIST_PATHS:
        for values in _lists_at_path(profile, path):
            for index, item in enumerate(values):
                if (
                    isinstance(item, dict)
                    and set(item).issubset(_EVIDENCE_WRAPPER_KEYS)
                    and isinstance(item.get("value"), str)
                ):
                    values[index] = item["value"]
                    unwrapped += 1
    return unwrapped


def _drop_incomplete_campaigns(profile: dict[str, Any]) -> int:
    """Discard incomplete descriptive campaign records without inventing fields."""

    entities = profile.get("threatIntelligence")
    entities = entities.get("entities") if isinstance(entities, dict) else None
    campaigns = entities.get("campaigns") if isinstance(entities, dict) else None
    if not isinstance(campaigns, list):
        return 0
    required = {"name", "timeframe", "targetSectors", "geographicFocus"}
    retained = [
        campaign
        for campaign in campaigns
        if isinstance(campaign, dict) and required.issubset(campaign)
    ]
    dropped = len(campaigns) - len(retained)
    campaigns[:] = retained
    return dropped


def _load_model_json(text: str) -> dict[str, Any]:
    """Parse model JSON and repair syntax before the complete domain validation."""

    try:
        payload = json.loads(text)
    except json.JSONDecodeError as error:
        repair_input = text
        if "Invalid \\escape" in error.msg:
            repaired, repair_count = _INVALID_JSON_ESCAPE.subn(lambda _: r"\\", text)
            if repair_count:
                logger.warning("Escaped %d invalid JSON backslash sequence(s)", repair_count)
                repair_input = repaired
                try:
                    payload = json.loads(repair_input)
                except json.JSONDecodeError as repaired_error:
                    error = repaired_error
                else:
                    if not isinstance(payload, dict):
                        raise ValueError("Model response threat profile JSON must be an object")
                    return payload
        payload = repair_json(
            repair_input,
            return_objects=True,
            skip_json_loads=True,
        )
        logger.warning(
            "Repaired malformed model JSON after parser error at line %d column %d",
            error.lineno,
            error.colno,
        )
    if not isinstance(payload, dict):
        raise ValueError("Model response threat profile JSON must be an object")
    return payload


def _drop_incomplete_embedded_evidence(profile: dict[str, Any]) -> int:
    """Remove model claims that lack the complete evidence identity they assert."""

    dropped = 0
    for path in _EMBEDDED_EVIDENCE_PATHS:
        value: Any = profile
        for key in path:
            if not isinstance(value, dict):
                value = None
                break
            value = value.get(key)
        if not isinstance(value, list):
            continue

        retained: list[Any] = []
        for item in value:
            if not isinstance(item, dict):
                retained.append(item)
                continue
            role = item.get("evidenceRole")
            source_ids = item.get("sourceIds")
            support = item.get("supportingEvidence")
            if role == "direct_evidence":
                support_ids = (
                    [entry.get("sourceId") for entry in support]
                    if isinstance(support, list)
                    and all(isinstance(entry, dict) for entry in support)
                    else []
                )
                excerpts_complete = isinstance(support, list) and all(
                    str(entry.get("excerpt") or "").strip()
                    for entry in support
                    if isinstance(entry, dict)
                )
                complete = (
                    isinstance(source_ids, list)
                    and bool(source_ids)
                    and support_ids == source_ids
                    and excerpts_complete
                )
                if not complete:
                    dropped += 1
                    continue
            elif role == "general_practice" and (source_ids or support):
                dropped += 1
                continue
            retained.append(item)
        value[:] = retained
    return dropped


class StrictModel(BaseModel):
    """Base model that keeps the provider structured-output schema closed."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class CoreMetadata(StrictModel):
    name: str
    version: str
    category: str
    profile_id: str = Field(alias="profileId")
    profile_author: str = Field(alias="profileAuthor")
    created_date: str = Field(alias="createdDate")
    last_updated: str = Field(alias="lastUpdated")
    profile_version: str = Field(alias="profileVersion")


class PrimarySource(StrictModel):
    source_id: str = Field(alias="sourceId", min_length=1)
    url: str
    title: str
    domain: str
    access_date: str = Field(alias="accessDate")
    relevance_score: str = Field(alias="relevanceScore")
    content_type: str = Field(alias="contentType")
    key_findings: str = Field(alias="keyFindings")
    evidence_snapshot_status: Literal["captured", "unavailable"] | None = Field(
        default=None, alias="evidenceSnapshotStatus"
    )
    evidence_snapshot_sha256: str | None = Field(default=None, alias="evidenceSnapshotSha256")
    evidence_snapshot_captured_at: str | None = Field(
        default=None, alias="evidenceSnapshotCapturedAt"
    )
    evidence_snapshot_final_url: str | None = Field(default=None, alias="evidenceSnapshotFinalUrl")
    evidence_page_age: str | None = Field(default=None, alias="evidencePageAge")


class EvidenceSupport(StrictModel):
    """Verbatim captured text that supports one claim at one named source."""

    source_id: str = Field(alias="sourceId", min_length=1)
    # Gemini sometimes returns a complete source paragraph even when asked for a
    # short excerpt. Keep parsing bounded by the captured snapshot ceiling; the
    # deterministic source ledger verifies and shortens it before persistence.
    excerpt: str = Field(min_length=1, max_length=12_000)
    snapshot_sha256: str | None = Field(default=None, alias="snapshotSha256")


class ClaimAttributionEntry(StrictModel):
    claim_class: Literal[
        "threat_activity",
        "forensic_artifact",
        "detection_indicator",
        "mitigation_action",
    ] = Field(alias="claimClass")
    claim: str = ""
    claim_field: Literal[
        "riskFactors",
        "fileSystemArtifacts",
        "registryArtifacts",
        "networkArtifacts",
        "memoryArtifacts",
        "logArtifacts",
        "hashes",
        "domains",
        "ips",
        "urls",
        "filenames",
        "behavioralIndicators",
        "preventiveMeasures",
        "detectionMethods",
        "responseActions",
        "recoveryGuidance",
    ] = Field(alias="claimField")
    claim_index: int = Field(alias="claimIndex", ge=0)
    evidence_role: Literal["direct_evidence", "general_practice"] = Field(alias="evidenceRole")
    source_ids: list[str] = Field(alias="sourceIds")
    supporting_evidence: list[EvidenceSupport] = Field(alias="supportingEvidence")

    @model_validator(mode="after")
    def validate_evidence_role(self) -> "ClaimAttributionEntry":
        support_ids = [support.source_id for support in self.supporting_evidence]
        if self.evidence_role == "direct_evidence" and (
            not self.source_ids or support_ids != self.source_ids
        ):
            raise ValueError("Direct evidence claims require at least one source ID")
        if self.evidence_role == "general_practice" and (
            self.claim_class != "mitigation_action" or self.source_ids or self.supporting_evidence
        ):
            raise ValueError("General practice is only valid for uncited mitigation guidance")
        return self


class ClaimAttribution(StrictModel):
    schema_version: Literal["5"] = Field(alias="schemaVersion")
    claims: list[ClaimAttributionEntry] = Field(min_length=1)


class EvidenceClaimItem(StrictModel):
    """One high-risk generated value with evidence identity attached at creation."""

    value: str = Field(min_length=1)
    evidence_role: Literal["direct_evidence", "general_practice"] = Field(alias="evidenceRole")
    source_ids: list[str] = Field(alias="sourceIds")
    supporting_evidence: list[EvidenceSupport] = Field(alias="supportingEvidence")

    @model_validator(mode="after")
    def validate_support(self) -> "EvidenceClaimItem":
        support_ids = [support.source_id for support in self.supporting_evidence]
        if self.evidence_role == "direct_evidence" and (
            not self.source_ids or support_ids != self.source_ids
        ):
            raise ValueError("Direct evidence items require one verbatim excerpt per source ID")
        if self.evidence_role == "general_practice" and (
            self.source_ids or self.supporting_evidence
        ):
            raise ValueError("General-practice items cannot claim captured source support")
        return self


class EmbeddedCorrectionClaimItem(StrictModel):
    """One bounded correction claim whose source IDs are derived from support."""

    value: str = Field(min_length=1)
    evidence_role: Literal["direct_evidence", "general_practice"] = Field(alias="evidenceRole")
    supporting_evidence: list[EvidenceSupport] = Field(alias="supportingEvidence")

    @model_validator(mode="after")
    def validate_support(self) -> "EmbeddedCorrectionClaimItem":
        if self.evidence_role == "direct_evidence" and not self.supporting_evidence:
            raise ValueError("Direct evidence corrections require a verbatim excerpt")
        if self.evidence_role == "general_practice" and self.supporting_evidence:
            raise ValueError("General-practice corrections cannot claim captured support")
        return self


class EmbeddedForensicCorrectionItem(EmbeddedCorrectionClaimItem):
    """One forensic artifact plus its destination in the complete profile."""

    claim_field: Literal[
        "fileSystemArtifacts",
        "registryArtifacts",
        "networkArtifacts",
        "memoryArtifacts",
        "logArtifacts",
    ] = Field(alias="claimField")


class EmbeddedIndicatorCorrectionItem(EmbeddedCorrectionClaimItem):
    """One detection indicator plus its destination in the complete profile."""

    claim_field: Literal[
        "hashes",
        "domains",
        "ips",
        "urls",
        "filenames",
        "behavioralIndicators",
    ] = Field(alias="claimField")


class EmbeddedMitigationCorrectionItem(EmbeddedCorrectionClaimItem):
    """One mitigation action plus its destination in the complete profile."""

    claim_field: Literal[
        "preventiveMeasures",
        "detectionMethods",
        "responseActions",
        "recoveryGuidance",
    ] = Field(alias="claimField")


class EmbeddedEvidenceCorrection(StrictModel):
    """Small correction artifact for high-risk fields only."""

    risk_factor: EmbeddedCorrectionClaimItem = Field(alias="riskFactor")
    forensic_artifact: EmbeddedForensicCorrectionItem = Field(alias="forensicArtifact")
    detection_indicator: EmbeddedIndicatorCorrectionItem = Field(alias="detectionIndicator")
    mitigation_action: EmbeddedMitigationCorrectionItem = Field(alias="mitigationAction")

    @model_validator(mode="after")
    def require_direct_non_mitigation_evidence(self) -> "EmbeddedEvidenceCorrection":
        items = (
            self.risk_factor,
            self.forensic_artifact,
            self.detection_indicator,
        )
        if any(item.evidence_role != "direct_evidence" for item in items):
            raise ValueError("Risk, forensic, and detection corrections require direct evidence")
        return self


# TODO(embedded-evidence-v1): Remove string-valued generation compatibility after
# three successful production canaries persist schema-5 snapshot-verified evidence.
EvidenceClaimValue = EvidenceClaimItem | str


class WebSearchSources(StrictModel):
    search_queries_used: list[str] = Field(alias="searchQueriesUsed", min_length=1)
    primary_sources: list[PrimarySource] = Field(alias="primarySources", min_length=1)
    search_strategy: str = Field(alias="searchStrategy")
    data_freshness: str = Field(alias="dataFreshness")
    source_reliability: str = Field(alias="sourceReliability")


class ToolOverview(StrictModel):
    description: str
    primary_purpose: str = Field(alias="primaryPurpose")
    target_audience: str = Field(alias="targetAudience")
    known_aliases: list[str] = Field(alias="knownAliases")
    first_seen: str = Field(alias="firstSeen")
    last_updated: str = Field(alias="lastUpdated")
    current_status: str = Field(alias="currentStatus")


class TechnicalDetails(StrictModel):
    architecture: str
    operating_systems: list[str] = Field(alias="operatingSystems")
    dependencies: list[str]
    encryption: str
    obfuscation: str
    persistence: list[str]
    capabilities: list[str]


class CommandProtocol(StrictModel):
    protocol_name: str = Field(alias="protocolName")
    encoding: str
    encryption: str
    detection_notes: str = Field(alias="detectionNotes")


class BeaconingPattern(StrictModel):
    pattern: str
    frequency: str
    indicators: list[str]


class CommandAndControl(StrictModel):
    communication_methods: str = Field(alias="communicationMethods")
    command_protocols: list[CommandProtocol] = Field(alias="commandProtocols")
    beaconing_patterns: list[BeaconingPattern] = Field(alias="beaconingPatterns")
    common_commands: list[str] = Field(alias="commonCommands")


class ThreatActor(StrictModel):
    name: str
    attribution: str
    activity_timeframe: str = Field(alias="activityTimeframe")


class Campaign(StrictModel):
    name: str
    timeframe: str
    target_sectors: list[str] = Field(alias="targetSectors")
    geographic_focus: str = Field(alias="geographicFocus")


class ThreatEntities(StrictModel):
    threat_actors: list[ThreatActor] = Field(alias="threatActors")
    campaigns: list[Campaign]


class RiskAssessment(StrictModel):
    overall_risk: str = Field(alias="overallRisk")
    impact_rating: str = Field(alias="impactRating")
    likelihood_rating: str = Field(alias="likelihoodRating")
    risk_factors: list[EvidenceClaimValue] = Field(alias="riskFactors")


class ThreatIntelligence(StrictModel):
    entities: ThreatEntities
    risk_assessment: RiskAssessment = Field(alias="riskAssessment")


class ForensicArtifacts(StrictModel):
    file_system_artifacts: list[EvidenceClaimValue] = Field(alias="fileSystemArtifacts")
    registry_artifacts: list[EvidenceClaimValue] = Field(alias="registryArtifacts")
    network_artifacts: list[EvidenceClaimValue] = Field(alias="networkArtifacts")
    memory_artifacts: list[EvidenceClaimValue] = Field(alias="memoryArtifacts")
    log_artifacts: list[EvidenceClaimValue] = Field(alias="logArtifacts")


class IndicatorsOfCompromise(StrictModel):
    hashes: list[EvidenceClaimValue]
    domains: list[EvidenceClaimValue]
    ips: list[EvidenceClaimValue]
    urls: list[EvidenceClaimValue]
    filenames: list[EvidenceClaimValue]


class DetectionAndMitigation(StrictModel):
    iocs: IndicatorsOfCompromise
    behavioral_indicators: list[EvidenceClaimValue] = Field(alias="behavioralIndicators")


class MitigationAndResponse(StrictModel):
    preventive_measures: list[EvidenceClaimValue] = Field(alias="preventiveMeasures")
    detection_methods: list[EvidenceClaimValue] = Field(alias="detectionMethods")
    response_actions: list[EvidenceClaimValue] = Field(alias="responseActions")
    recovery_guidance: list[EvidenceClaimValue] = Field(alias="recoveryGuidance")


class ReferenceSource(StrictModel):
    title: str
    url: str
    date: str
    relevance_score: str = Field(alias="relevanceScore")


class ReferencesAndIntelligenceSharing(StrictModel):
    sources: list[ReferenceSource] = Field(min_length=1)
    mitre_attack_mapping: str = Field(alias="mitreAttackMapping")
    cve_references: str = Field(alias="cveReferences")
    additional_references: list[str] = Field(alias="additionalReferences")


class Integration(StrictModel):
    siem_integration: str = Field(alias="siemIntegration")
    threat_hunting_queries: list[str] = Field(alias="threatHuntingQueries")
    automated_response: str = Field(alias="automatedResponse")


class Lineage(StrictModel):
    variants: list[str]
    evolution: str
    relationships: list[str]


class UsageContexts(StrictModel):
    legitimate_use: str = Field(alias="legitimateUse")
    malicious_use: str = Field(alias="maliciousUse")
    dual_use_considerations: str = Field(alias="dualUseConsiderations")


class TrendAnalysis(StrictModel):
    industry_impact: str = Field(alias="industryImpact")
    future_outlook: str = Field(alias="futureOutlook")
    adoption_trend: str = Field(alias="adoptionTrend")


class ContextualAnalysis(StrictModel):
    usage_contexts: UsageContexts = Field(alias="usageContexts")
    trend_analysis: TrendAnalysis = Field(alias="trendAnalysis")


class CommunityResource(StrictModel):
    resource_type: str = Field(alias="resourceType")
    name: str
    url: str
    focus: str


class OperationalGuidance(StrictModel):
    validation_criteria: list[str] = Field(alias="validationCriteria")
    community_resources: list[CommunityResource] = Field(alias="communityResources")


class ThreatProfile(StrictModel):
    """The stable profile artifact generated before validation and enrichment."""

    core_metadata: CoreMetadata = Field(alias="coreMetadata")
    web_search_sources: WebSearchSources = Field(alias="webSearchSources")
    claim_attribution: ClaimAttribution | None = Field(default=None, alias="claimAttribution")
    tool_overview: ToolOverview = Field(alias="toolOverview")
    technical_details: TechnicalDetails = Field(alias="technicalDetails")
    command_and_control: CommandAndControl = Field(alias="commandAndControl")
    threat_intelligence: ThreatIntelligence = Field(alias="threatIntelligence")
    forensic_artifacts: ForensicArtifacts = Field(alias="forensicArtifacts")
    detection_and_mitigation: DetectionAndMitigation = Field(alias="detectionAndMitigation")
    mitigation_and_response: MitigationAndResponse = Field(alias="mitigationAndResponse")
    references_and_intelligence_sharing: ReferencesAndIntelligenceSharing = Field(
        alias="referencesAndIntelligenceSharing"
    )
    integration: Integration
    lineage: Lineage
    contextual_analysis: ContextualAnalysis = Field(alias="contextualAnalysis")
    operational_guidance: OperationalGuidance = Field(alias="operationalGuidance")


EVIDENCE_ENHANCEMENT_MODELS: dict[str, type[StrictModel]] = {
    "technicalDetails": TechnicalDetails,
    "commandAndControl": CommandAndControl,
    "threatIntelligence": ThreatIntelligence,
    "forensicArtifacts": ForensicArtifacts,
    "detectionAndMitigation": DetectionAndMitigation,
    "mitigationAndResponse": MitigationAndResponse,
}


def parse_threat_profile_response(response: Any) -> dict[str, Any]:
    """Return a validated profile from parsed or deferred JSON output."""

    parsed = getattr(response, "parsed", None)
    if isinstance(parsed, ThreatProfile):
        profile = parsed
        return profile.model_dump(mode="json", by_alias=True)
    if isinstance(parsed, dict):
        payload = deepcopy(parsed)
    else:
        text_parts = [
            str(getattr(part, "text", ""))
            for part in (getattr(response, "content", None) or [])
            if getattr(part, "type", None) == "text" and str(getattr(part, "text", "")).strip()
        ]
        if not text_parts:
            raise ValueError("Model response did not include threat profile JSON")
        payload = _load_model_json("\n".join(text_parts))
    dropped_campaigns = _drop_incomplete_campaigns(payload)
    if dropped_campaigns:
        logger.warning(
            "Discarded %d incomplete descriptive campaign record(s)",
            dropped_campaigns,
        )
    unwrapped = _unwrap_evidence_objects_from_plain_lists(payload)
    if unwrapped:
        logger.warning(
            "Unwrapped %d evidence object(s) from non-claim string arrays before profile validation",
            unwrapped,
        )
    dropped = _drop_incomplete_embedded_evidence(payload)
    if dropped:
        logger.warning(
            "Discarded %d incomplete embedded evidence item(s) before profile validation",
            dropped,
        )
    profile = ThreatProfile.model_validate(payload)
    return profile.model_dump(mode="json", by_alias=True)


def parse_embedded_evidence_correction(response: Any) -> dict[str, Any]:
    """Return one locally validated high-risk evidence correction."""

    parsed = getattr(response, "parsed", None)
    if isinstance(parsed, EmbeddedEvidenceCorrection):
        correction = parsed
    elif isinstance(parsed, dict):
        correction = EmbeddedEvidenceCorrection.model_validate(deepcopy(parsed))
    else:
        text_parts = [
            str(getattr(part, "text", ""))
            for part in (getattr(response, "content", None) or [])
            if getattr(part, "type", None) == "text" and str(getattr(part, "text", "")).strip()
        ]
        if not text_parts:
            raise ValueError("Model response did not include embedded evidence JSON")
        correction = EmbeddedEvidenceCorrection.model_validate(
            _load_model_json("\n".join(text_parts))
        )
    return correction.model_dump(mode="json", by_alias=True)


def attest_profile_sources(
    profile: dict[str, Any], web_search_sources: list[dict[str, Any]]
) -> None:
    """Reject profile URLs that were not returned by the hosted web-search tool."""

    evidence_url_pairs = [
        (str(source.get("url", "")).strip(), normalized)
        for source in web_search_sources
        if (normalized := _normalize_url(str(source.get("url", ""))))
    ]
    evidence_urls = {normalized for _, normalized in evidence_url_pairs}
    if not evidence_urls:
        raise ValueError("OpenRouter web search returned no source evidence")

    claimed_sources = _prune_unavailable_source_records(
        profile["webSearchSources"]["primarySources"]
    )
    claimed_references = _prune_unavailable_source_records(
        profile["referencesAndIntelligenceSharing"]["sources"]
    )
    claimed_community_resources = _prune_unavailable_source_records(
        profile["operationalGuidance"]["communityResources"]
    )
    profile["webSearchSources"]["primarySources"] = claimed_sources
    profile["referencesAndIntelligenceSharing"]["sources"] = claimed_references
    profile["operationalGuidance"]["communityResources"] = claimed_community_resources

    if not claimed_sources:
        raise ValueError("Threat profile requires at least one attested primary source")
    if not claimed_references:
        raise ValueError("Threat profile requires at least one attested reference source")
    claimed_urls: set[str] = set()
    for source in [
        *claimed_sources,
        *claimed_references,
        *claimed_community_resources,
    ]:
        raw_url = str(source.get("url", ""))
        normalized = _normalize_url(raw_url)
        if not normalized:
            raise ValueError(f"Threat profile included an invalid source URL: {raw_url!r}")
        if normalized not in evidence_urls:
            replacement = _resolve_unique_attested_descendant(raw_url, evidence_url_pairs)
            if replacement:
                source["url"] = replacement
                normalized = _normalize_url(replacement)
        claimed_urls.add(normalized)

    unattested = sorted(claimed_urls - evidence_urls)
    if unattested:
        raise ValueError(
            "Threat profile included URLs that were not returned by OpenRouter web search: "
            + ", ".join(unattested)
        )

    for source in claimed_sources:
        hostname = (urlsplit(str(source["url"])).hostname or "").lower()
        declared_domain = str(source.get("domain", "")).strip().lower()
        domain_matches = declared_domain == hostname or hostname.endswith(f".{declared_domain}")
        if not domain_matches:
            raise ValueError(
                "Threat profile source domain does not match its URL: "
                f"{declared_domain!r} != {hostname!r}"
            )

    evidence_ids_by_url = {
        normalized: str(source.get("sourceId") or "").strip()
        for source in web_search_sources
        if (normalized := _normalize_url(str(source.get("url", ""))))
    }
    for source in claimed_sources:
        normalized = _normalize_url(str(source.get("url", "")))
        canonical_source_id = evidence_ids_by_url.get(normalized)
        if not canonical_source_id:
            raise ValueError("Threat profile source ID does not match its attested URL")
        source["sourceId"] = canonical_source_id

    source_ids = [str(source.get("sourceId") or "").strip() for source in claimed_sources]
    if any(not source_id for source_id in source_ids) or len(set(source_ids)) != len(source_ids):
        raise ValueError("Threat profile primary source IDs must be non-empty and unique")

    attribution = profile.get("claimAttribution")
    claims = attribution.get("claims") if isinstance(attribution, dict) else None
    if not isinstance(attribution, dict) or attribution.get("schemaVersion") != "5":
        raise ValueError("Threat profile claim attribution must use schema version 5")
    if not isinstance(claims, list):
        raise ValueError("Threat profile claim attribution is incomplete")
    required_classes = {
        "threat_activity",
        "forensic_artifact",
        "detection_indicator",
        "mitigation_action",
    }
    observed_classes: set[str] = set()
    known_source_ids = set(source_ids)
    for claim in claims:
        if not isinstance(claim, dict):
            raise ValueError("Threat profile claim attribution contains an invalid claim")
        observed_classes.add(str(claim.get("claimClass") or ""))
        cited_ids = claim.get("sourceIds")
        supporting_evidence = claim.get("supportingEvidence")
        evidence_role = claim.get("evidenceRole")
        if not isinstance(cited_ids, list):
            raise ValueError("Threat profile claim attribution contains invalid source IDs")
        if evidence_role == "direct_evidence" and not cited_ids:
            raise ValueError("Threat profile claim attribution contains an uncited claim")
        if evidence_role == "direct_evidence" and (
            not isinstance(supporting_evidence, list)
            or [support.get("sourceId") for support in supporting_evidence] != cited_ids
        ):
            raise ValueError("Threat profile claim attribution lacks verified support excerpts")
        if evidence_role == "general_practice" and (
            claim.get("claimClass") != "mitigation_action" or cited_ids or supporting_evidence
        ):
            raise ValueError("Threat profile general-practice attribution is invalid")
        if any(str(source_id) not in known_source_ids for source_id in cited_ids):
            raise ValueError("Threat profile claim attribution references an unknown source ID")
    if not required_classes.issubset(observed_classes):
        raise ValueError("Threat profile claim attribution is missing a high-risk claim class")


def _prune_unavailable_source_records(sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Treat the explicit no-evidence sentinel as absence, never as a URL."""

    sentinel = "no verified information found in the attested research"
    return [
        source
        for source in sources
        if not str(source.get("url", "")).strip().casefold().startswith(sentinel)
    ]


def _resolve_unique_attested_descendant(
    claimed_url: str, evidence_url_pairs: list[tuple[str, str]]
) -> str:
    """Expand one shortened source URL only when one attested URL can match it."""

    claimed = urlsplit(claimed_url.strip())
    if claimed.scheme not in {"http", "https"} or not claimed.hostname or claimed.query:
        return ""
    claimed_path = claimed.path.rstrip("/") or "/"
    matches = []
    for evidence_url, _ in evidence_url_pairs:
        evidence = urlsplit(evidence_url)
        evidence_path = evidence.path.rstrip("/") or "/"
        same_host = (evidence.hostname or "").lower() == claimed.hostname.lower()
        is_descendant = evidence_path.startswith(f"{claimed_path}/")
        if same_host and is_descendant:
            matches.append(evidence_url)
    return matches[0] if len(matches) == 1 else ""


def _normalize_url(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    parts = urlsplit(value)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        return ""
    path = parts.path.rstrip("/") or "/"
    query = urlencode(
        sorted(
            (key, item)
            for key, item in parse_qsl(parts.query, keep_blank_values=True)
            if not key.lower().startswith("utm_") and key.lower() not in {"fbclid", "gclid"}
        )
    )
    suffix = f"?{query}" if query else ""
    return f"{parts.netloc.lower()}{path}{suffix}"
