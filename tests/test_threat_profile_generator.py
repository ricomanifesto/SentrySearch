from copy import deepcopy
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from src.core.section_validator import SectionValidator
from src.core.threat_profile_schema import (
    ThreatProfile,
    attest_profile_sources,
    parse_threat_profile_response,
)


def test_threat_profile_schema_preserves_public_field_names(threat_profile_data):
    profile = ThreatProfile.model_validate(threat_profile_data)

    dumped = profile.model_dump(mode="json", by_alias=True)

    assert dumped == threat_profile_data
    assert "coreMetadata" in dumped
    assert "core_metadata" not in dumped


def test_threat_profile_schema_requires_source_backed_sections(threat_profile_data):
    invalid = deepcopy(threat_profile_data)
    invalid["webSearchSources"]["primarySources"] = []

    with pytest.raises(ValidationError):
        ThreatProfile.model_validate(invalid)


def test_parse_threat_profile_response_requires_sdk_parsed_payload(threat_profile_data):
    response = SimpleNamespace(parsed=ThreatProfile.model_validate(threat_profile_data))

    assert parse_threat_profile_response(response) == threat_profile_data

    with pytest.raises(ValueError, match="parsed threat profile"):
        parse_threat_profile_response(SimpleNamespace(parsed=None))


def test_attest_profile_sources_accepts_only_hosted_search_evidence(threat_profile_data):
    attest_profile_sources(
        threat_profile_data,
        [{"url": "https://example.com/report", "title": "Example report"}],
    )

    invalid = deepcopy(threat_profile_data)
    invalid["referencesAndIntelligenceSharing"]["sources"][0][
        "url"
    ] = "https://unverified.example/report"

    with pytest.raises(ValueError, match="not returned by OpenRouter web search"):
        attest_profile_sources(
            invalid,
            [{"url": "https://example.com/report", "title": "Example report"}],
        )

    wrong_domain = deepcopy(threat_profile_data)
    wrong_domain["webSearchSources"]["primarySources"][0]["domain"] = "other.example"
    with pytest.raises(ValueError, match="domain does not match"):
        attest_profile_sources(
            wrong_domain,
            [{"url": "https://example.com/report", "title": "Example report"}],
        )

    unverified_resource = deepcopy(threat_profile_data)
    unverified_resource["operationalGuidance"]["communityResources"][0][
        "url"
    ] = "https://community.example/resource"
    with pytest.raises(ValueError, match="not returned by OpenRouter web search"):
        attest_profile_sources(
            unverified_resource,
            [{"url": "https://example.com/report?utm_source=search"}],
        )


def test_source_attestation_ignores_scheme_and_query_variants(threat_profile_data):
    attest_profile_sources(
        threat_profile_data,
        [{"url": "http://example.com/report?utm_source=search"}],
    )

    with pytest.raises(ValueError, match="not returned by OpenRouter web search"):
        attest_profile_sources(
            threat_profile_data,
            [{"url": "https://example.com/report?id=other"}],
        )


def test_section_validator_consumes_normalized_sdk_sources():
    validator = SectionValidator(client=None)
    response = SimpleNamespace(
        web_search_sources=[
            {
                "url": "https://example.com/report",
                "title": "Example report",
                "page_age": "2026-08-10",
                "origin": "url_citation",
            }
        ]
    )

    sources = validator._extract_web_search_sources_from_response(
        response, "initial_research", "Example Threat"
    )

    assert sources[0]["url"] == "https://example.com/report"
    assert sources[0]["publishedDate"] == "2026-08-10"
    assert sources[0]["evidenceOrigin"] == "url_citation"
