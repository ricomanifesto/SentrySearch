"""Deterministic evidence-purpose and operational-indicator safety gates."""

from __future__ import annotations

from copy import deepcopy
from enum import StrEnum
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network
import re
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

from src.core.generation_failures import EvidenceAdmissibilityError
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
    "scenario card",
    "fictional scenario",
    "simulation exercise",
)
_CONTEXT_URL_MARKERS = (
    "rfc-editor.org/rfc/rfc5737",
    "rfc-editor.org/rfc/rfc3849",
    "iana.org/assignments/iana-ipv4-special-registry",
    "iana.org/assignments/iana-ipv6-special-registry",
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

    if _host_is_reserved_example(hostname):
        purpose = SourcePurpose.EXCLUDED_NON_OPERATIONAL
        disposition = EvidenceDisposition.EXCLUDED
        rule_id = "source.reserved-example-host"
        reason = "Reserved example infrastructure cannot support operational intelligence."
    elif any(marker in url_text for marker in _TRAINING_URL_MARKERS) or any(
        marker in title_text for marker in _TRAINING_TEXT_MARKERS
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
    else:
        purpose = SourcePurpose.OPERATIONAL
        disposition = EvidenceDisposition.ADMITTED
        rule_id = "source.no-non-operational-marker"
        reason = "No deterministic non-operational source marker was detected."

    return {
        "sourceId": str(source.get("sourceId") or source.get("source_id") or "").strip(),
        "title": title,
        "url": url,
        "domain": hostname,
        "purpose": purpose.value,
        "disposition": disposition.value,
        "reason": reason,
        "ruleId": rule_id,
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
            }
        )
        classified.append(item)
    return classified


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
) -> dict[str, Any]:
    """Attach an application-owned safety record and fail closed on unsafe evidence."""

    classified_sources = classify_research_sources(research_sources)
    source_observations = [_source_observation(source) for source in classified_sources]
    sources_by_id = {
        observation["sourceId"]: observation
        for observation in source_observations
        if observation["sourceId"]
    }
    blocking_findings: list[str] = []

    attribution = profile.get("claimAttribution")
    claims = attribution.get("claims") if isinstance(attribution, Mapping) else None
    if not isinstance(attribution, Mapping) or attribution.get("schemaVersion") != "4":
        blocking_findings.append("Operational claim coverage does not use attribution schema 4.")
        claims = []
    if not isinstance(claims, list):
        blocking_findings.append("Operational claim coverage is missing.")
        claims = []

    expected_values = _selected_values(profile)
    claims_by_selector: dict[tuple[str, str, int], list[Mapping[str, Any]]] = {}
    for claim in claims:
        if not isinstance(claim, Mapping):
            blocking_findings.append("Operational claim coverage contains an invalid record.")
            continue
        selector = (
            str(claim.get("claimClass") or ""),
            str(claim.get("claimField") or ""),
            int(claim.get("claimIndex")) if isinstance(claim.get("claimIndex"), int) else -1,
        )
        claims_by_selector.setdefault(selector, []).append(claim)

        role = str(claim.get("evidenceRole") or "")
        source_ids = [str(value) for value in claim.get("sourceIds") or []]
        if role == "general_practice":
            if selector[0] != "mitigation_action" or source_ids:
                blocking_findings.append(
                    "General-practice attribution is only valid for uncited mitigation guidance."
                )
            continue
        if role != "direct_evidence" or not source_ids:
            blocking_findings.append("An operational claim lacks direct evidence.")
            continue
        for source_id in source_ids:
            observation = sources_by_id.get(source_id)
            if observation is None:
                blocking_findings.append(
                    f"Operational claim cites unknown source {source_id or 'without an ID'}."
                )
            elif observation["purpose"] != SourcePurpose.OPERATIONAL.value:
                blocking_findings.append(
                    f"Operational claim cites {source_id}, which is {observation['purpose']}."
                )

    for claim_class, claim_field, claim_index, _ in expected_values:
        selector = (claim_class, claim_field, claim_index)
        matches = claims_by_selector.get(selector, [])
        if len(matches) != 1:
            blocking_findings.append(
                f"{claim_field}[{claim_index}] requires exactly one schema-4 attribution record."
            )

    expected_selectors = {
        (claim_class, claim_field, claim_index)
        for claim_class, claim_field, claim_index, _ in expected_values
    }
    for selector in claims_by_selector:
        if selector not in expected_selectors:
            blocking_findings.append(
                f"Claim attribution selector {selector[1]}[{selector[2]}] has no stored value."
            )

    indicator_observations: list[dict[str, Any]] = []
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
            blocking_findings.append(f"{claim_field}[{claim_index}] was rejected: {reason}")

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
                blocking_findings.append(
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
            if observation["purpose"] != SourcePurpose.OPERATIONAL.value:
                blocking_findings.append(
                    f"Primary source {observation['sourceId']} is not operational evidence."
                )

    blocking_findings = _unique(blocking_findings)
    assessment = {
        "schemaVersion": EVIDENCE_ADMISSIBILITY_SCHEMA_VERSION,
        "status": (
            EvidenceAdmissibilityStatus.BLOCKED.value
            if blocking_findings
            else EvidenceAdmissibilityStatus.PASSED.value
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
            "coveredOperationalClaims": len(expected_values),
        },
    }
    profile["evidenceAdmissibility"] = assessment
    if blocking_findings:
        raise EvidenceAdmissibilityError(
            "Generated report contains evidence that is unsafe for operational use",
            findings=blocking_findings,
            assessment=assessment,
        )
    return assessment


def evidence_correction_prompt(error: EvidenceAdmissibilityError) -> str:
    """Give one bounded correction attempt the deterministic failures verbatim."""

    findings = "\n".join(f"- {finding}" for finding in error.findings[:12])
    return f"""CORRECTION ATTEMPT AFTER A FAILED OPERATIONAL EVIDENCE GATE:
The previous response contained inadmissible evidence or incomplete schema-4
coverage. Return a complete corrected JSON object.

Deterministic findings:
{findings}

- Remove documentation, reserved, special-use, training, tabletop, and fictional
  infrastructure from operational indicators and target-specific actions.
- Do not include or cite sources marked context_only or excluded_non_operational
  in any high-risk operational claim.
- claimAttribution schemaVersion 4 MUST cover every non-empty item in every
  allowed claim field exactly once.
- Use evidenceRole direct_evidence with exact source IDs for supported claims.
- Use evidenceRole general_practice with no source IDs only for generic mitigation
  guidance that does not assert a target-specific fact.
- Do not replace rejected values with invented alternatives.
"""
