"""Structured output contract for generated threat intelligence profiles."""

from __future__ import annotations

from typing import Any, Literal
from urllib.parse import parse_qsl, urlencode, urlsplit

from pydantic import BaseModel, ConfigDict, Field


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
    tlp_classification: str = Field(alias="tlpClassification")
    trust_score: str = Field(alias="trustScore")


class PrimarySource(StrictModel):
    source_id: str = Field(alias="sourceId", min_length=1)
    url: str
    title: str
    domain: str
    access_date: str = Field(alias="accessDate")
    relevance_score: str = Field(alias="relevanceScore")
    content_type: str = Field(alias="contentType")
    key_findings: str = Field(alias="keyFindings")


class ClaimAttributionEntry(StrictModel):
    claim_class: Literal[
        "threat_activity",
        "forensic_artifact",
        "detection_indicator",
        "mitigation_action",
    ] = Field(alias="claimClass")
    claim: str = Field(min_length=1)
    source_ids: list[str] = Field(alias="sourceIds", min_length=1)


class ClaimAttribution(StrictModel):
    schema_version: Literal["2"] = Field(alias="schemaVersion")
    claims: list[ClaimAttributionEntry] = Field(min_length=4)


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
    risk_factors: list[str] = Field(alias="riskFactors")


class ThreatIntelligence(StrictModel):
    entities: ThreatEntities
    risk_assessment: RiskAssessment = Field(alias="riskAssessment")


class ForensicArtifacts(StrictModel):
    file_system_artifacts: list[str] = Field(alias="fileSystemArtifacts")
    registry_artifacts: list[str] = Field(alias="registryArtifacts")
    network_artifacts: list[str] = Field(alias="networkArtifacts")
    memory_artifacts: list[str] = Field(alias="memoryArtifacts")
    log_artifacts: list[str] = Field(alias="logArtifacts")


class IndicatorsOfCompromise(StrictModel):
    hashes: list[str]
    domains: list[str]
    ips: list[str]
    urls: list[str]
    filenames: list[str]


class DetectionAndMitigation(StrictModel):
    iocs: IndicatorsOfCompromise
    behavioral_indicators: list[str] = Field(alias="behavioralIndicators")


class MitigationAndResponse(StrictModel):
    preventive_measures: list[str] = Field(alias="preventiveMeasures")
    detection_methods: list[str] = Field(alias="detectionMethods")
    response_actions: list[str] = Field(alias="responseActions")
    recovery_guidance: list[str] = Field(alias="recoveryGuidance")


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
    claim_attribution: ClaimAttribution = Field(alias="claimAttribution")
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
    """Return a validated profile from the model client's parsed payload."""

    parsed = getattr(response, "parsed", None)
    if parsed is None:
        raise ValueError("Model response did not include a parsed threat profile")

    profile = parsed if isinstance(parsed, ThreatProfile) else ThreatProfile.model_validate(parsed)
    return profile.model_dump(mode="json", by_alias=True)


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

    source_ids = [str(source.get("sourceId") or "").strip() for source in claimed_sources]
    if any(not source_id for source_id in source_ids) or len(set(source_ids)) != len(source_ids):
        raise ValueError("Threat profile primary source IDs must be non-empty and unique")
    evidence_ids_by_url = {
        normalized: str(source.get("sourceId") or "").strip()
        for source in web_search_sources
        if (normalized := _normalize_url(str(source.get("url", ""))))
    }
    for source in claimed_sources:
        normalized = _normalize_url(str(source.get("url", "")))
        if evidence_ids_by_url.get(normalized) != source.get("sourceId"):
            raise ValueError("Threat profile source ID does not match its attested URL")

    attribution = profile.get("claimAttribution")
    claims = attribution.get("claims") if isinstance(attribution, dict) else None
    if not isinstance(attribution, dict) or attribution.get("schemaVersion") != "2":
        raise ValueError("Threat profile claim attribution must use schema version 2")
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
        if not isinstance(cited_ids, list) or not cited_ids:
            raise ValueError("Threat profile claim attribution contains an uncited claim")
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
