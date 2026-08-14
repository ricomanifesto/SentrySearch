from copy import deepcopy
import json
from threading import Barrier
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from src.core.section_validator import SectionValidator
from src.core.parallel_section_validator import ParallelSectionValidator
from src.core.markdown_generator import generate_markdown
from src.core.threat_profile_generator import ThreatProfileGenerator
from src.domain.reports import GenerationProgress, GenerationStage
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


def test_generated_markdown_contains_each_primary_source_as_a_link(threat_profile_data):
    markdown = generate_markdown(threat_profile_data)

    assert "## Web Search Sources & Research Methodology" in markdown
    for source in threat_profile_data["webSearchSources"]["primarySources"]:
        url = source["url"]
        assert f"[{url}]({url})" in markdown


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


def test_source_attestation_prunes_explicit_unavailable_optional_urls(
    threat_profile_data,
):
    unavailable = deepcopy(threat_profile_data)
    unavailable["operationalGuidance"]["communityResources"][0][
        "url"
    ] = "No verified information found in the attested research"

    attest_profile_sources(
        unavailable,
        [{"url": "https://example.com/report", "title": "Example report"}],
    )

    assert unavailable["operationalGuidance"]["communityResources"] == []


def test_source_attestation_does_not_prune_required_source_placeholders(
    threat_profile_data,
):
    unavailable = deepcopy(threat_profile_data)
    unavailable["webSearchSources"]["primarySources"][0][
        "url"
    ] = "No verified information found in the attested research"

    with pytest.raises(ValueError, match="requires at least one attested primary source"):
        attest_profile_sources(
            unavailable,
            [{"url": "https://example.com/report", "title": "Example report"}],
        )


def test_source_attestation_accepts_declared_parent_domain(threat_profile_data):
    subdomain_source = deepcopy(threat_profile_data)
    subdomain_source["webSearchSources"]["primarySources"][0][
        "url"
    ] = "https://blog.example.com/report"

    attest_profile_sources(
        subdomain_source,
        [
            {"url": "https://blog.example.com/report", "title": "Example report"},
            {"url": "https://example.com/report", "title": "Example root report"},
        ],
    )

    lookalike_source = deepcopy(subdomain_source)
    lookalike_source["webSearchSources"]["primarySources"][0][
        "url"
    ] = "https://notexample.com/report"
    with pytest.raises(ValueError, match="domain does not match"):
        attest_profile_sources(
            lookalike_source,
            [
                {"url": "https://notexample.com/report", "title": "Lookalike report"},
                {"url": "https://example.com/report", "title": "Example root report"},
            ],
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


def test_source_attestation_resolves_one_unambiguous_parent_url(threat_profile_data):
    shortened = deepcopy(threat_profile_data)
    shortened["referencesAndIntelligenceSharing"]["sources"][0][
        "url"
    ] = "https://example.com/reports"

    attest_profile_sources(
        shortened,
        [
            {"url": "https://example.com/report"},
            {"url": "https://example.com/reports/vendor-analysis"},
        ],
    )

    assert shortened["referencesAndIntelligenceSharing"]["sources"][0]["url"] == (
        "https://example.com/reports/vendor-analysis"
    )


def test_source_attestation_rejects_an_ambiguous_parent_url(threat_profile_data):
    shortened = deepcopy(threat_profile_data)
    shortened["webSearchSources"]["primarySources"][0]["url"] = "https://example.com/reports"
    shortened["referencesAndIntelligenceSharing"]["sources"][0][
        "url"
    ] = "https://example.com/reports"

    with pytest.raises(ValueError, match="not returned by OpenRouter web search"):
        attest_profile_sources(
            shortened,
            [
                {"url": "https://example.com/report"},
                {"url": "https://example.com/reports/one"},
                {"url": "https://example.com/reports/two"},
            ],
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


def test_threat_profile_generator_uses_bounded_parallel_quality_validation(monkeypatch):
    monkeypatch.setattr(
        "src.core.threat_profile_generator.create_model_client",
        lambda: SimpleNamespace(messages=SimpleNamespace()),
    )

    generator = ThreatProfileGenerator(enable_tracing=False, enable_metrics=False)

    assert isinstance(generator.validator, ParallelSectionValidator)


def test_generation_separates_web_research_from_structured_synthesis(
    monkeypatch, threat_profile_data
):
    class Messages:
        def __init__(self):
            self.requests: list[dict] = []
            self.responses: list[SimpleNamespace] = []
            self.research_barrier = Barrier(3)

        def create(self, **kwargs):
            self.requests.append(kwargs)
            if kwargs.get("tools"):
                self.research_barrier.wait(timeout=1)
                response = SimpleNamespace(
                    content=[
                        SimpleNamespace(
                            type="text",
                            text=(
                                "Example Threat uses remote access capabilities. "
                                "Source: https://example.com/report"
                            ),
                        )
                    ],
                    parsed=None,
                    web_search_sources=[
                        {
                            "url": "https://example.com/report",
                            "title": "Example report",
                            "page_age": "2026-08-11",
                            "origin": "url_citation",
                        }
                    ],
                    tool_events=[
                        {
                            "type": "web_search_call",
                            "id": "",
                            "status": "completed",
                            "action_type": "openrouter:web_search",
                            "source_count": 1,
                        }
                    ],
                    response_id="research-response",
                    model="google/gemma-4-26b-a4b-it:free",
                    provider="TestProvider",
                    usage=SimpleNamespace(
                        input_tokens=10,
                        output_tokens=20,
                        cached_tokens=0,
                        cache_write_tokens=0,
                        reasoning_tokens=0,
                        web_search_calls=1,
                        total_tokens=30,
                    ),
                )

            else:
                response = SimpleNamespace(
                    content=[SimpleNamespace(type="text", text=json.dumps(threat_profile_data))],
                    parsed=ThreatProfile.model_validate(threat_profile_data),
                    web_search_sources=[],
                    tool_events=[],
                    response_id="synthesis-response",
                    model="google/gemma-4-26b-a4b-it:free",
                    provider="TestProvider",
                    usage=SimpleNamespace(
                        input_tokens=30,
                        output_tokens=40,
                        cached_tokens=0,
                        cache_write_tokens=0,
                        reasoning_tokens=0,
                        web_search_calls=0,
                        total_tokens=70,
                    ),
                )
            self.responses.append(response)
            return response

    messages = Messages()
    monkeypatch.setattr(
        "src.core.threat_profile_generator.create_model_client",
        lambda: SimpleNamespace(messages=messages),
    )
    generator = ThreatProfileGenerator(enable_tracing=False, enable_metrics=False)
    generator.enable_quality_control = False

    progress_updates: list[GenerationProgress] = []
    result = generator.get_threat_intelligence(
        "Example Threat", progress_callback=progress_updates.append
    )

    assert result == threat_profile_data
    assert len(messages.requests) == 4
    research_requests = [request for request in messages.requests if request.get("tools")]
    synthesis_request = next(
        request for request in messages.requests if request.get("response_format") is ThreatProfile
    )
    assert len(research_requests) == 3
    assert all(request["tools"] == [{"type": "web_search"}] for request in research_requests)
    assert all(
        request["provider"] == {"only": ["google-ai-studio"], "allow_fallbacks": False}
        for request in research_requests
    )
    assert all(request["models"] == ["google/gemma-4-26b-a4b-it"] for request in research_requests)
    assert all("response_format" not in request for request in research_requests)
    research_prompts = "\n".join(request["messages"][0]["content"] for request in research_requests)
    assert "architecture" in research_prompts
    assert "detection" in research_prompts
    assert "threat actor" in research_prompts
    assert synthesis_request["response_format"] is ThreatProfile
    assert synthesis_request["provider"] == {
        "only": ["google-ai-studio"],
        "allow_fallbacks": False,
    }
    assert synthesis_request["models"] == ["google/gemma-4-26b-a4b-it"]
    assert "tools" not in synthesis_request
    assert "https://example.com/report" in synthesis_request["messages"][0]["content"]
    assert "Example Threat uses remote access capabilities" in (
        synthesis_request["messages"][0]["content"]
    )
    synthesis_response = next(response for response in messages.responses if response.parsed)
    assert synthesis_response.usage.input_tokens == 60
    assert synthesis_response.usage.output_tokens == 100
    assert synthesis_response.usage.web_search_calls == 3
    assert synthesis_response.usage.total_tokens == 160
    assert all(isinstance(update, GenerationProgress) for update in progress_updates)
    assert [update.stage for update in progress_updates] == [
        GenerationStage.QUEUED,
        GenerationStage.RESEARCHING,
        GenerationStage.SYNTHESIZING,
        GenerationStage.VALIDATING,
        GenerationStage.FINALIZING,
    ]
