"""Canonical source-ledger projection and persist-time consistency gate."""

from __future__ import annotations

from copy import deepcopy
import re
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit, urlunsplit


class SourceLedgerError(ValueError):
    """Raised when a report cannot attest one coherent reader-visible source ledger."""


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
