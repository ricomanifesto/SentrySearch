"""Deterministic evidence-purpose and operational-indicator safety gates."""

from __future__ import annotations

from copy import deepcopy
from enum import StrEnum
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network
import re
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

from src.core.generation_failures import (
    EvidenceAdmissibilityError,
    EvidenceCoverageError,
    EvidenceGateError,
)
from src.core.source_ledger import CLAIM_CLASS_SELECTORS
from src.domain.reports import EvidenceAdmissibilityStatus

EVIDENCE_ADMISSIBILITY_SCHEMA_VERSION = "1"


class SourcePurpose(StrEnum):
    """How one researched source may participate in the operational report."""

    OPERATIONAL = "operational"
    CONTEXT_ONLY = "context_only"
    EXCLUDED_NON_OPERATIONAL = "excluded_non_operational"


class EvidenceDisposition(StrEnum):
    """Application-owned disposition for a source or indicator."""

    ADMITTED = "admitted"
    CONTEXT_REQUIRED = "context_required"
    EXCLUDED = "excluded"
    REJECTED = "rejected"


_TRAINING_URL_MARKERS = (
    "/scenario-cards/",
    "/tabletop/",
    "/training/",
    "/simulation/",
    "incident-response-exercise",
    "cyber-range",
)
_TRAINING_TEXT_MARKERS = (
    "tabletop exercise",
    "training exercise",
    "training guide",
    "scenario card",
    "scenario facilitator",
    "fictional scenario",
    "simulation exercise",
    "game-based security education",
    "malware and monsters",
)
_CONTEXT_URL_MARKERS = (
    "rfc-editor.org/rfc/rfc5737",
    "rfc-editor.org/rfc/rfc3849",
    "iana.org/assignments/iana-ipv4-special-registry",
    "iana.org/assignments/iana-ipv6-special-registry",
)
_OPERATIONAL_TEXT_MARKERS = (
    "adversary",
    "attack",
    "command and control",
    "cve-",
    "cybersecurity",
    "detection",
    "exploit",
    "forensic",
    "incident response",
    "indicator",
    "intrusion",
    "malware",
    "mitigation",
    "security advisory",
    "threat",
    "vulnerability",
)
_RESERVED_EXAMPLE_HOSTS = frozenset(
    {
        "example",
        "example.com",
        "example.net",
        "example.org",
        "invalid",
        "localhost",
        "test",
    }
)

_DOCUMENTATION_NETWORKS: tuple[IPv4Network | IPv6Network, ...] = (
    ip_network("192.0.2.0/24"),
    ip_network("198.51.100.0/24"),
    ip_network("203.0.113.0/24"),
    ip_network("2001:db8::/32"),
)
_PRIVATE_NETWORKS: tuple[IPv4Network | IPv6Network, ...] = (
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("fc00::/7"),
)
_SPECIAL_USE_NETWORKS: tuple[IPv4Network | IPv6Network, ...] = (
    ip_network("0.0.0.0/8"),
    ip_network("100.64.0.0/10"),
    ip_network("127.0.0.0/8"),
    ip_network("169.254.0.0/16"),
    ip_network("192.0.0.0/24"),
    ip_network("192.88.99.0/24"),
    ip_network("198.18.0.0/15"),
    ip_network("224.0.0.0/4"),
    ip_network("240.0.0.0/4"),
    ip_network("::/128"),
    ip_network("::1/128"),
    ip_network("100::/64"),
    ip_network("fe80::/10"),
    ip_network("ff00::/8"),
)
_IPV4_TOKEN = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?")
_DOMAIN_TOKEN = re.compile(
    r"(?<![A-Za-z0-9-])(?:\*\.)?(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}"
)
_HEX_HASH = re.compile(r"^[0-9a-fA-F]+$")


def _host_is_reserved_example(hostname: str) -> bool:
    host = hostname.strip().strip(".").casefold()
    return any(host == value or host.endswith(f".{value}") for value in _RESERVED_EXAMPLE_HOSTS)


def _source_observation(source: Mapping[str, Any]) -> dict[str, Any]:
    url = str(source.get("url") or "").strip()
    title = str(source.get("title") or "Unknown source").strip()
    parsed = urlsplit(url)
    hostname = (parsed.hostname or "").casefold()
    url_text = url.casefold()
    title_text = title.casefold()
    snapshot = source.get("contentSnapshot")
    snapshot = snapshot if isinstance(snapshot, Mapping) else {}
    snapshot_status = str(snapshot.get("status") or "unavailable").strip()
    snapshot_text = str(snapshot.get("text") or "").casefold()
    snapshot_sha256 = str(snapshot.get("sha256") or "").strip() or None
    page_age = str(snapshot.get("pageAge") or source.get("page_age") or "").strip() or None
    operational_markers = {
        marker for marker in _OPERATIONAL_TEXT_MARKERS if marker in f"{title_text} {snapshot_text}"
    }

    if _host_is_reserved_example(hostname):
        purpose = SourcePurpose.EXCLUDED_NON_OPERATIONAL
        disposition = EvidenceDisposition.EXCLUDED
        rule_id = "source.reserved-example-host"
        reason = "Reserved example infrastructure cannot support operational intelligence."
    elif any(marker in url_text for marker in _TRAINING_URL_MARKERS) or any(
        marker in f"{title_text} {snapshot_text}" for marker in _TRAINING_TEXT_MARKERS
    ):
        purpose = SourcePurpose.EXCLUDED_NON_OPERATIONAL
        disposition = EvidenceDisposition.EXCLUDED
        rule_id = "source.training-scenario"
        reason = "Training, tabletop, or fictional scenario material is not operational evidence."
    elif any(marker in url_text for marker in _CONTEXT_URL_MARKERS):
        purpose = SourcePurpose.CONTEXT_ONLY
        disposition = EvidenceDisposition.CONTEXT_REQUIRED
        rule_id = "source.special-use-reference"
        reason = "Special-use address documentation provides context, not threat-specific evidence."
    elif snapshot_status != "captured" or not snapshot_text or not snapshot_sha256:
        purpose = SourcePurpose.CONTEXT_ONLY
        disposition = EvidenceDisposition.CONTEXT_REQUIRED
        rule_id = "source.intent-unverified"
        reason = "Source content was not captured, so its operational intent could not be verified."
    elif len(operational_markers) < 2:
        purpose = SourcePurpose.CONTEXT_ONLY
        disposition = EvidenceDisposition.CONTEXT_REQUIRED
        rule_id = "source.intent-ambiguous"
        reason = "Captured content did not establish enough operational security context."
    else:
        purpose = SourcePurpose.OPERATIONAL
        disposition = EvidenceDisposition.ADMITTED
        rule_id = "source.captured-operational-content"
        reason = "Captured source content passed deterministic non-operational intent checks."

    return {
        "sourceId": str(source.get("sourceId") or source.get("source_id") or "").strip(),
        "title": title,
        "url": url,
        "domain": hostname,
        "purpose": purpose.value,
        "disposition": disposition.value,
        "reason": reason,
        "ruleId": rule_id,
        "snapshotStatus": snapshot_status,
        "snapshotSha256": snapshot_sha256,
        "snapshotCapturedAt": snapshot.get("capturedAt"),
        "snapshotFinalUrl": snapshot.get("finalUrl"),
        "pageAge": page_age,
    }


def classify_research_sources(
    sources: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Annotate the attested catalog before synthesis without trusting model judgment."""

    classified: list[dict[str, Any]] = []
    for source in sources:
        item = deepcopy(dict(source))
        observation = _source_observation(item)
        item.update(
            {
                "evidencePurpose": observation["purpose"],
                "evidenceDisposition": observation["disposition"],
                "evidenceReason": observation["reason"],
                "evidenceRuleId": observation["ruleId"],
                "evidenceSnapshotStatus": observation["snapshotStatus"],
                "evidenceSnapshotSha256": observation["snapshotSha256"],
                "evidenceSnapshotCapturedAt": observation["snapshotCapturedAt"],
                "evidenceSnapshotFinalUrl": observation["snapshotFinalUrl"],
                "evidencePageAge": observation["pageAge"],
            }
        )
        classified.append(item)
    return classified


def research_source_observations(
    sources: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Publish the deterministic source-intent record without model inference."""

    return [_source_observation(source) for source in sources]


def _network_candidates(value: str) -> list[IPv4Network | IPv6Network]:
    tokens = _IPV4_TOKEN.findall(value)
    if ":" in value:
        tokens.extend(token.strip("[](),.;") for token in value.split() if ":" in token)
    networks: list[IPv4Network | IPv6Network] = []
    for token in dict.fromkeys(tokens):
        try:
            networks.append(ip_network(token, strict=False))
        except ValueError:
            continue
    return networks


def _network_in(candidate: IPv4Network | IPv6Network, networks: tuple) -> bool:
    return any(
        candidate.version == expected.version and candidate.subnet_of(expected)
        for expected in networks
    )


def _classify_ip(value: str) -> tuple[EvidenceDisposition, str, str]:
    networks = _network_candidates(value)
    if not networks:
        return (
            EvidenceDisposition.REJECTED,
            "Indicator is not a valid IP address or network.",
            "indicator.ip-invalid",
        )
    if any(_network_in(network, _DOCUMENTATION_NETWORKS) for network in networks):
        return (
            EvidenceDisposition.REJECTED,
            "Documentation-only address space cannot be promoted as a malicious indicator.",
            "indicator.ip-documentation",
        )
    if any(_network_in(network, _SPECIAL_USE_NETWORKS) for network in networks):
        return (
            EvidenceDisposition.REJECTED,
            "Special-use address space cannot be promoted as an operational indicator.",
            "indicator.ip-special-use",
        )
    if any(_network_in(network, _PRIVATE_NETWORKS) for network in networks):
        return (
            EvidenceDisposition.CONTEXT_REQUIRED,
            "Private addressing is admissible only as victim-environment context.",
            "indicator.ip-private-context",
        )
    if any(not ip_address(network.network_address).is_global for network in networks):
        return (
            EvidenceDisposition.REJECTED,
            "Non-global address space requires an explicit application rule before operational use.",
            "indicator.ip-non-global",
        )
    return (
        EvidenceDisposition.ADMITTED,
        "Publicly routable address passed deterministic special-use checks.",
        "indicator.ip-public",
    )


def _domain_from_value(value: str) -> str:
    candidate = value.strip().casefold()
    if "://" in candidate:
        return (urlsplit(candidate).hostname or "").casefold()
    return candidate.removeprefix("*.").split(":", 1)[0].strip(".")


def _classify_domain(value: str) -> tuple[EvidenceDisposition, str, str]:
    hostname = _domain_from_value(value)
    if not hostname or not _DOMAIN_TOKEN.fullmatch(hostname):
        return (
            EvidenceDisposition.REJECTED,
            "Indicator is not a valid domain name.",
            "indicator.domain-invalid",
        )
    if _host_is_reserved_example(hostname):
        return (
            EvidenceDisposition.REJECTED,
            "Reserved example domains cannot be promoted as malicious indicators.",
            "indicator.domain-reserved-example",
        )
    return (
        EvidenceDisposition.ADMITTED,
        "Domain passed deterministic reserved-name checks.",
        "indicator.domain-admitted",
    )


def _classify_url(value: str) -> tuple[EvidenceDisposition, str, str]:
    parsed = urlsplit(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return (
            EvidenceDisposition.REJECTED,
            "Indicator is not a valid HTTP or HTTPS URL.",
            "indicator.url-invalid",
        )
    disposition, reason, rule_id = _classify_domain(parsed.hostname)
    return disposition, reason, rule_id.replace("indicator.domain", "indicator.url-host")


def _classify_hash(value: str) -> tuple[EvidenceDisposition, str, str]:
    candidate = value.strip()
    if ":" in candidate:
        prefix, remainder = candidate.split(":", 1)
        if prefix.strip().casefold() in {"md5", "sha1", "sha-1", "sha256", "sha-256"}:
            candidate = remainder.strip()
    if len(candidate) not in {32, 40, 64} or not _HEX_HASH.fullmatch(candidate):
        return (
            EvidenceDisposition.REJECTED,
            "Indicator is not a complete MD5, SHA-1, or SHA-256 value.",
            "indicator.hash-invalid",
        )
    return (
        EvidenceDisposition.ADMITTED,
        "Hash passed deterministic length and encoding checks.",
        "indicator.hash-admitted",
    )


def _classify_indicator(
    claim_field: str,
    value: str,
) -> tuple[EvidenceDisposition, str, str]:
    if claim_field == "ips":
        return _classify_ip(value)
    if claim_field == "domains":
        return _classify_domain(value)
    if claim_field == "urls":
        return _classify_url(value)
    if claim_field == "hashes":
        return _classify_hash(value)
    return (
        EvidenceDisposition.ADMITTED,
        "Indicator type has no deterministic reserved-value rule.",
        "indicator.source-coverage-only",
    )


def quarantine_rejected_indicator_items(profile: dict[str, Any]) -> list[dict[str, Any]]:
    """Remove malformed or reserved IOC values before they enter the operational ledger."""

    detection = profile.get("detectionAndMitigation")
    iocs = detection.get("iocs") if isinstance(detection, dict) else None
    if not isinstance(iocs, dict):
        return []

    observations: list[dict[str, Any]] = []
    for claim_field in ("hashes", "domains", "ips", "urls", "filenames"):
        values = iocs.get(claim_field)
        if not isinstance(values, list):
            continue
        retained: list[Any] = []
        for claim_index, item in enumerate(values):
            value = str(item.get("value") if isinstance(item, Mapping) else item or "").strip()
            disposition, reason, rule_id = _classify_indicator(claim_field, value)
            if disposition is not EvidenceDisposition.REJECTED:
                retained.append(item)
                continue
            observations.append(
                {
                    "claimField": claim_field,
                    "claimIndex": claim_index,
                    "value": value,
                    "disposition": EvidenceDisposition.EXCLUDED.value,
                    "reason": f"Removed before operational reuse. {reason}",
                    "ruleId": rule_id,
                }
            )
        values[:] = retained
    return observations


def _selected_values(profile: Mapping[str, Any]) -> list[tuple[str, str, int, str]]:
    selected_values: list[tuple[str, str, int, str]] = []
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
            for claim_index, raw_value in enumerate(selected):
                value = str(raw_value or "").strip()
                if value:
                    selected_values.append((claim_class, claim_field, claim_index, value))
    return selected_values


def _unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def _profile_strings(
    value: Any,
    path: str = "profile",
) -> Iterable[tuple[str, str]]:
    """Yield reader-visible profile strings without rescanning source metadata."""

    if isinstance(value, Mapping):
        for key, child in value.items():
            if path == "profile" and key in {
                "claimAttribution",
                "evidenceAdmissibility",
                "references",
                "webSearchSources",
            }:
                continue
            yield from _profile_strings(child, f"{path}.{key}")
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            yield from _profile_strings(child, f"{path}[{index}]")
        return
    if isinstance(value, str) and value.strip():
        yield path, value


def assess_profile_evidence(
    profile: dict[str, Any],
    research_sources: Iterable[Mapping[str, Any]],
    *,
    excluded_indicator_observations: Iterable[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Attach an application-owned safety record and fail closed on unsafe evidence."""

    classified_sources = classify_research_sources(research_sources)
    source_observations = research_source_observations(classified_sources)
    sources_by_id = {
        observation["sourceId"]: observation
        for observation in source_observations
        if observation["sourceId"]
    }
    coverage_findings: list[str] = []
    safety_findings: list[str] = []

    attribution = profile.get("claimAttribution")
    claims = attribution.get("claims") if isinstance(attribution, Mapping) else None
    if not isinstance(attribution, Mapping) or attribution.get("schemaVersion") != "5":
        coverage_findings.append("Operational claim coverage does not use attribution schema 5.")
        claims = []
    if not isinstance(claims, list):
        coverage_findings.append("Operational claim coverage is missing.")
        claims = []

    expected_values = _selected_values(profile)
    claims_by_selector: dict[tuple[str, str, int], list[Mapping[str, Any]]] = {}
    for claim in claims:
        if not isinstance(claim, Mapping):
            coverage_findings.append("Operational claim coverage contains an invalid record.")
            continue
        selector = (
            str(claim.get("claimClass") or ""),
            str(claim.get("claimField") or ""),
            int(claim.get("claimIndex")) if isinstance(claim.get("claimIndex"), int) else -1,
        )
        claims_by_selector.setdefault(selector, []).append(claim)

        role = str(claim.get("evidenceRole") or "")
        source_ids = [str(value) for value in claim.get("sourceIds") or []]
        supports = claim.get("supportingEvidence")
        if role == "general_practice":
            if selector[0] != "mitigation_action" or source_ids:
                coverage_findings.append(
                    "General-practice attribution is only valid for uncited mitigation guidance."
                )
            continue
        if role != "direct_evidence" or not source_ids:
            coverage_findings.append("An operational claim lacks direct evidence.")
            continue
        if (
            not isinstance(supports, list)
            or [
                str(support.get("sourceId") or "")
                for support in supports
                if isinstance(support, Mapping)
            ]
            != source_ids
        ):
            coverage_findings.append("An operational claim lacks verified support excerpts.")
            continue
        for source_id in source_ids:
            observation = sources_by_id.get(source_id)
            if observation is None:
                coverage_findings.append(
                    f"Operational claim cites unknown source {source_id or 'without an ID'}."
                )
            elif observation["purpose"] != SourcePurpose.OPERATIONAL.value:
                safety_findings.append(
                    f"Operational claim cites {source_id}, which is {observation['purpose']}."
                )

    for claim_class, claim_field, claim_index, _ in expected_values:
        selector = (claim_class, claim_field, claim_index)
        matches = claims_by_selector.get(selector, [])
        if len(matches) != 1:
            coverage_findings.append(
                f"{claim_field}[{claim_index}] requires exactly one schema-5 attribution record."
            )

    expected_selectors = {
        (claim_class, claim_field, claim_index)
        for claim_class, claim_field, claim_index, _ in expected_values
    }
    for selector in claims_by_selector:
        if selector not in expected_selectors:
            coverage_findings.append(
                f"Claim attribution selector {selector[1]}[{selector[2]}] has no stored value."
            )

    if excluded_indicator_observations is None:
        previous = profile.get("evidenceAdmissibility")
        previous_observations = (
            previous.get("indicatorObservations") if isinstance(previous, Mapping) else []
        )
        excluded_indicator_observations = [
            observation
            for observation in previous_observations or []
            if isinstance(observation, Mapping)
            and observation.get("disposition") == EvidenceDisposition.EXCLUDED.value
        ]
    indicator_observations: list[dict[str, Any]] = [
        dict(observation) for observation in excluded_indicator_observations
    ]
    indicator_fields = {"hashes", "domains", "ips", "urls", "filenames"}
    for _, claim_field, claim_index, value in expected_values:
        if claim_field not in indicator_fields:
            continue
        disposition, reason, rule_id = _classify_indicator(claim_field, value)
        observation = {
            "claimField": claim_field,
            "claimIndex": claim_index,
            "value": value,
            "disposition": disposition.value,
            "reason": reason,
            "ruleId": rule_id,
        }
        indicator_observations.append(observation)
        if disposition is EvidenceDisposition.REJECTED:
            safety_findings.append(f"{claim_field}[{claim_index}] was rejected: {reason}")

    observed_indicator_keys = {
        (observation["value"], observation["ruleId"]) for observation in indicator_observations
    }
    for path, text in _profile_strings(profile):
        for value in _IPV4_TOKEN.findall(text):
            disposition, reason, rule_id = _classify_ip(value)
            observation_key = (value, rule_id)
            if (
                disposition is EvidenceDisposition.ADMITTED
                or observation_key in observed_indicator_keys
            ):
                continue
            observed_indicator_keys.add(observation_key)
            indicator_observations.append(
                {
                    "claimField": path.removeprefix("profile."),
                    "claimIndex": 0,
                    "value": value,
                    "disposition": disposition.value,
                    "reason": reason,
                    "ruleId": rule_id,
                }
            )
            if disposition is EvidenceDisposition.REJECTED:
                safety_findings.append(
                    f"{path.removeprefix('profile.')} contains rejected infrastructure "
                    f"{value}: {reason}"
                )

    web = profile.get("webSearchSources")
    primary_sources = web.get("primarySources") if isinstance(web, dict) else None
    if isinstance(primary_sources, list):
        for source in primary_sources:
            if not isinstance(source, dict):
                continue
            observation = sources_by_id.get(str(source.get("sourceId") or ""))
            if observation is None:
                continue
            source["evidencePurpose"] = observation["purpose"]
            source["evidenceDisposition"] = observation["disposition"]
            source["evidenceReason"] = observation["reason"]
            source["evidenceRuleId"] = observation["ruleId"]
            source["evidenceSnapshotStatus"] = observation["snapshotStatus"]
            source["evidenceSnapshotSha256"] = observation["snapshotSha256"]
            source["evidenceSnapshotCapturedAt"] = observation["snapshotCapturedAt"]
            source["evidenceSnapshotFinalUrl"] = observation["snapshotFinalUrl"]
            source["evidencePageAge"] = observation["pageAge"]
            if observation["purpose"] != SourcePurpose.OPERATIONAL.value:
                safety_findings.append(
                    f"Primary source {observation['sourceId']} is not operational evidence."
                )

    coverage_findings = _unique(coverage_findings)
    safety_findings = _unique(safety_findings)
    blocking_findings = [*safety_findings, *coverage_findings]
    assessment = {
        "schemaVersion": EVIDENCE_ADMISSIBILITY_SCHEMA_VERSION,
        "status": (
            EvidenceAdmissibilityStatus.BLOCKED.value
            if safety_findings
            else (
                EvidenceAdmissibilityStatus.UNASSESSED.value
                if coverage_findings
                else EvidenceAdmissibilityStatus.PASSED.value
            )
        ),
        "sourceObservations": source_observations,
        "indicatorObservations": indicator_observations,
        "blockingFindings": blocking_findings,
        "summary": {
            "operationalSources": sum(
                observation["purpose"] == SourcePurpose.OPERATIONAL.value
                for observation in source_observations
            ),
            "contextSources": sum(
                observation["purpose"] == SourcePurpose.CONTEXT_ONLY.value
                for observation in source_observations
            ),
            "excludedSources": sum(
                observation["purpose"] == SourcePurpose.EXCLUDED_NON_OPERATIONAL.value
                for observation in source_observations
            ),
            "admittedIndicators": sum(
                observation["disposition"] == EvidenceDisposition.ADMITTED.value
                for observation in indicator_observations
            ),
            "contextIndicators": sum(
                observation["disposition"] == EvidenceDisposition.CONTEXT_REQUIRED.value
                for observation in indicator_observations
            ),
            "rejectedIndicators": sum(
                observation["disposition"] == EvidenceDisposition.REJECTED.value
                for observation in indicator_observations
            ),
            "excludedIndicators": sum(
                observation["disposition"] == EvidenceDisposition.EXCLUDED.value
                for observation in indicator_observations
            ),
            "coveredOperationalClaims": len(expected_values),
            "safetyFindings": len(safety_findings),
            "coverageFindings": len(coverage_findings),
        },
    }
    profile["evidenceAdmissibility"] = assessment
    if safety_findings:
        raise EvidenceAdmissibilityError(
            "Generated report contains evidence that is unsafe for operational use",
            findings=blocking_findings,
            assessment=assessment,
        )
    if coverage_findings:
        raise EvidenceCoverageError(
            "Generated report has incomplete high-risk claim coverage",
            findings=coverage_findings,
            assessment=assessment,
        )
    return assessment


def evidence_correction_prompt(error: EvidenceGateError) -> str:
    """Give one bounded correction attempt the deterministic failures verbatim."""

    findings = "\n".join(f"- {finding}" for finding in error.findings[:12])
    return f"""CORRECTION ATTEMPT AFTER A FAILED EVIDENCE GATE:
The previous response contained inadmissible evidence or incomplete embedded
high-risk evidence. Return a complete corrected JSON object.

Deterministic findings:
{findings}

- Remove documentation, reserved, special-use, training, tabletop, and fictional
  infrastructure from operational indicators and target-specific actions.
- Do not include or cite sources marked context_only or excluded_non_operational
  in any high-risk operational claim.
- Every high-risk array item MUST carry value, evidenceRole, sourceIds, and
  supportingEvidence; do
  not emit a parallel claimAttribution map.
- Use evidenceRole direct_evidence with exact source IDs for supported items.
- For every direct source ID, copy one short verbatim excerpt from that source's
  captured content into supportingEvidence. Never paraphrase an excerpt.
- Use evidenceRole general_practice with no source IDs only for generic mitigation
  guidance that does not assert a target-specific fact; supportingEvidence must
  also be empty.
- Do not replace rejected values with invented alternatives.
"""
