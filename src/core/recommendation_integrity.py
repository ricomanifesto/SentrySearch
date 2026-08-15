"""Deterministic checks for evaluator recommendations that assert source content."""

from __future__ import annotations

from ipaddress import ip_address
import re
from typing import Any, Iterable, Mapping

_IP = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])")
_HASH = re.compile(
    r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})(?![0-9a-fA-F])"
)
_URL = re.compile(r"https?://[^\s<>()\[\]{}]+", re.IGNORECASE)
_DOMAIN = re.compile(
    r"(?<![A-Za-z0-9-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}"
)
_IOC_FIELD_PATTERNS = {
    "ips": re.compile(r"\b(?:ips?|ip addresses?)\b", re.IGNORECASE),
    "domains": re.compile(r"\bdomains?\b", re.IGNORECASE),
    "urls": re.compile(r"\burls?\b", re.IGNORECASE),
    "hashes": re.compile(r"\b(?:hashes?|sha-?256|sha-?1|md5)\b", re.IGNORECASE),
}


def _operational_snapshot_text(
    sources: Iterable[Mapping[str, Any]],
    profile: Mapping[str, Any] | None,
) -> str:
    parts: list[str] = []
    for source in sources:
        if source.get("evidencePurpose") != "operational":
            continue
        snapshot = source.get("contentSnapshot")
        if not isinstance(snapshot, Mapping) or snapshot.get("status") != "captured":
            continue
        text = str(snapshot.get("text") or "").strip()
        if text:
            parts.append(text)
    if isinstance(profile, Mapping):
        source_block = profile.get("webSearchSources")
        primary_sources = (
            source_block.get("primarySources") if isinstance(source_block, Mapping) else []
        )
        admitted_ids = {
            str(source.get("sourceId") or "")
            for source in primary_sources or []
            if isinstance(source, Mapping)
            and source.get("evidencePurpose") == "operational"
            and source.get("evidenceSnapshotStatus") == "captured"
        }
        attribution = profile.get("claimAttribution")
        claims = attribution.get("claims") if isinstance(attribution, Mapping) else []
        for claim in claims or []:
            if not isinstance(claim, Mapping):
                continue
            for support in claim.get("supportingEvidence") or []:
                if not isinstance(support, Mapping):
                    continue
                if str(support.get("sourceId") or "") not in admitted_ids:
                    continue
                excerpt = str(support.get("excerpt") or "").strip()
                if excerpt:
                    parts.append(excerpt)
    return "\n".join(parts)


def _candidate_values(field: str, text: str) -> list[str]:
    if field == "ips":
        candidates: list[str] = []
        for value in _IP.findall(text):
            try:
                if ip_address(value).is_global:
                    candidates.append(value)
            except ValueError:
                continue
        return list(dict.fromkeys(candidates))
    if field == "domains":
        return list(dict.fromkeys(_DOMAIN.findall(text)))
    if field == "urls":
        return list(dict.fromkeys(value.rstrip(".,;") for value in _URL.findall(text)))
    if field == "hashes":
        return list(dict.fromkeys(_HASH.findall(text)))
    return []


def _requested_ioc_fields(recommendation: str) -> list[str]:
    return [
        field for field, pattern in _IOC_FIELD_PATTERNS.items() if pattern.search(recommendation)
    ]


def validate_quality_recommendations(
    assessment: dict[str, Any],
    research_sources: Iterable[Mapping[str, Any]],
    profile: Mapping[str, Any] | None = None,
) -> None:
    """Separate source-checkable IOC advice from unsupported evaluator prose."""

    snapshot_text = _operational_snapshot_text(research_sources, profile)
    unverified: list[dict[str, str]] = []
    evidence: list[dict[str, Any]] = []
    recommendation_containers: list[dict[str, Any]] = [assessment]
    consistency = assessment.get("consistency")
    if isinstance(consistency, dict):
        recommendation_containers.append(consistency)
    for container in recommendation_containers:
        recommendations = container.get("recommendations")
        if not isinstance(recommendations, list):
            continue
        verified: list[str] = []
        for raw_recommendation in recommendations:
            recommendation = str(raw_recommendation or "").strip()
            if not recommendation:
                continue
            requested_fields = _requested_ioc_fields(recommendation)
            if not requested_fields:
                verified.append(recommendation)
                continue
            snapshot_candidates = {
                field: _candidate_values(field, snapshot_text) for field in requested_fields
            }
            candidates = {
                field: [
                    value
                    for value in _candidate_values(field, recommendation)
                    if value in snapshot_candidates[field]
                ]
                for field in requested_fields
            }
            missing = [field for field, values in candidates.items() if not values]
            if missing:
                unverified.append(
                    {
                        "recommendation": recommendation,
                        "reason": (
                            "The suggestion does not name a concrete admitted source-backed "
                            + ", ".join(missing)
                            + " value."
                        ),
                    }
                )
                continue
            verified.append(recommendation)
            evidence.append(
                {
                    "recommendation": recommendation,
                    "candidateValues": {field: values[:5] for field, values in candidates.items()},
                }
            )
        container["recommendations"] = verified
    assessment["recommendation_evidence"] = evidence
    assessment["unverified_recommendations"] = unverified
    if unverified:
        assessment["needs_improvement"] = True
