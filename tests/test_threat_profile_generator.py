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
        [{"sourceId": "S1", "url": "https://example.com/report", "title": "Example report"}],
    )

    invalid = deepcopy(threat_profile_data)
    invalid["referencesAndIntelligenceSharing"]["sources"][0][
        "url"
    ] = "https://unverified.example/report"

    with pytest.raises(ValueError, match="not returned by OpenRouter web search"):
        attest_profile_sources(
            invalid,
            [{"sourceId": "S1", "url": "https://example.com/report", "title": "Example report"}],
        )

    wrong_domain = deepcopy(threat_profile_data)
    wrong_domain["webSearchSources"]["primarySources"][0]["domain"] = "other.example"
    with pytest.raises(ValueError, match="domain does not match"):
        attest_profile_sources(
            wrong_domain,
            [{"sourceId": "S1", "url": "https://example.com/report", "title": "Example report"}],
        )

    unverified_resource = deepcopy(threat_profile_data)
    unverified_resource["operationalGuidance"]["communityResources"][0][
        "url"
    ] = "https://community.example/resource"
    with pytest.raises(ValueError, match="not returned by OpenRouter web search"):
        attest_profile_sources(
            unverified_resource,
            [{"sourceId": "S1", "url": "https://example.com/report?utm_source=search"}],
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
        [{"sourceId": "S1", "url": "https://example.com/report", "title": "Example report"}],
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
            [{"sourceId": "S1", "url": "https://example.com/report", "title": "Example report"}],
        )


def test_source_attestation_accepts_declared_parent_domain(threat_profile_data):
    subdomain_source = deepcopy(threat_profile_data)
    subdomain_source["webSearchSources"]["primarySources"][0][
        "url"
    ] = "https://blog.example.com/report"

    attest_profile_sources(
        subdomain_source,
        [
            {"sourceId": "S1", "url": "https://blog.example.com/report", "title": "Example report"},
            {"sourceId": "S2", "url": "https://example.com/report", "title": "Example root report"},
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
                {
                    "sourceId": "S1",
                    "url": "https://notexample.com/report",
                    "title": "Lookalike report",
                },
                {
                    "sourceId": "S2",
                    "url": "https://example.com/report",
                    "title": "Example root report",
                },
            ],
        )


def test_source_attestation_ignores_scheme_and_query_variants(threat_profile_data):
    attest_profile_sources(
        threat_profile_data,
        [{"sourceId": "S1", "url": "http://example.com/report?utm_source=search"}],
    )

    with pytest.raises(ValueError, match="not returned by OpenRouter web search"):
        attest_profile_sources(
            threat_profile_data,
            [{"sourceId": "S1", "url": "https://example.com/report?id=other"}],
        )


def test_source_attestation_resolves_one_unambiguous_parent_url(threat_profile_data):
    shortened = deepcopy(threat_profile_data)
    shortened["referencesAndIntelligenceSharing"]["sources"][0][
        "url"
    ] = "https://example.com/reports"

    attest_profile_sources(
        shortened,
        [
            {"sourceId": "S1", "url": "https://example.com/report"},
            {"sourceId": "S2", "url": "https://example.com/reports/vendor-analysis"},
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
                {"sourceId": "S1", "url": "https://example.com/report"},
                {"sourceId": "S2", "url": "https://example.com/reports/one"},
                {"sourceId": "S3", "url": "https://example.com/reports/two"},
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
    monkeypatch.setattr(
        "src.core.threat_profile_generator.assess_profile_evidence",
        lambda _profile, _sources: {},
    )

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
                    model="google/gemini-2.5-flash",
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

    assert {
        key: value for key, value in result.items() if not key.startswith("_")
    } == threat_profile_data
    assert result["_research_route"] == {
        "requested_models": ["google/gemma-4-26b-a4b-it:free"],
        "requested_providers": ["google-ai-studio"],
        "selected_models": [],
        "actual_models": [],
        "providers": [],
        "used_fallback": False,
        "request_count": 0,
        "attempts": [],
    }
    assert result["_synthesis_route"] == {
        "requested_models": ["google/gemini-2.5-flash"],
        "requested_providers": ["google-ai-studio"],
        "selected_models": [],
        "actual_models": [],
        "providers": [],
        "used_fallback": False,
        "request_count": 0,
        "attempts": [],
    }
    assert "_generation_route" not in result
    assert result["_evaluation_route"]["requested_models"] == ["google/gemma-4-31b-it:free"]
    assert result["_evaluation_route"]["requested_providers"] == ["google-ai-studio"]
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
    assert all(
        request["fallback_models"] == ["google/gemma-4-26b-a4b-it"] for request in research_requests
    )
    assert all(request["route_purpose"] == "research" for request in research_requests)
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
    assert synthesis_request["model"] == "google/gemini-2.5-flash"
    assert "fallback_models" not in synthesis_request
    assert synthesis_request["route_purpose"] == "synthesis"
    assert synthesis_request["max_tokens"] == 32768
    assert synthesis_request["session_id"].startswith("sentrysearch-synthesis-")
    assert synthesis_request["strict_response_schema"] is False
    assert "tools" not in synthesis_request
    synthesis_content = synthesis_request["messages"][0]["content"]
    assert synthesis_content[0]["cache_control"] == {"type": "ephemeral"}
    synthesis_prompt = "".join(block["text"] for block in synthesis_content)
    assert "https://example.com/report" in synthesis_prompt
    assert "Example Threat uses remote access capabilities" in synthesis_prompt
    assert '"sourceId": "S1"' in synthesis_prompt
    assert '"claimAttribution"' in synthesis_prompt
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


@pytest.mark.parametrize("invalid_attribution", ["unknown_source", "claim_selector"])
def test_generation_retries_one_invalid_claim_map_without_weakening_attestation(
    monkeypatch, threat_profile_data, invalid_attribution
):
    monkeypatch.setattr(
        "src.core.threat_profile_generator.assess_profile_evidence",
        lambda _profile, _sources: {},
    )
    monkeypatch.setattr(
        "src.core.threat_profile_generator.create_model_client",
        lambda: SimpleNamespace(),
    )
    generator = ThreatProfileGenerator(enable_tracing=False, enable_metrics=False)
    generator.enable_quality_control = False

    research_response = SimpleNamespace(
        content=[
            SimpleNamespace(
                type="text",
                text="Example evidence from https://example.com/report",
            )
        ],
        web_search_sources=[
            {
                "url": "https://example.com/report",
                "title": "Example report",
            }
        ],
        tool_events=[],
        response_id="research-response",
        usage=SimpleNamespace(
            input_tokens=3,
            output_tokens=4,
            cached_tokens=0,
            cache_write_tokens=0,
            reasoning_tokens=0,
            web_search_calls=1,
            total_tokens=7,
        ),
    )
    monkeypatch.setattr(generator, "_research_evidence", lambda _tool_name: research_response)

    invalid_profile = deepcopy(threat_profile_data)
    if invalid_attribution == "unknown_source":
        invalid_profile["claimAttribution"]["claims"][0]["sourceIds"] = ["S99"]
    else:
        invalid_profile["claimAttribution"]["claims"][0]["claimField"] = "behavioralIndicators"
    profiles = [invalid_profile, threat_profile_data]
    requests: list[dict] = []
    synthesis_responses: list[SimpleNamespace] = []

    def request_model(**kwargs):
        requests.append(kwargs)
        profile = profiles[len(requests) - 1]
        response = SimpleNamespace(
            content=[SimpleNamespace(type="text", text=json.dumps(profile))],
            parsed=ThreatProfile.model_validate(profile),
            web_search_sources=[],
            tool_events=[],
            response_id=f"synthesis-{len(requests)}",
            model="google/gemini-2.5-flash",
            provider="TestProvider",
            usage=SimpleNamespace(
                input_tokens=10,
                output_tokens=20,
                cached_tokens=0,
                cache_write_tokens=0,
                reasoning_tokens=0,
                web_search_calls=0,
                total_tokens=30,
            ),
        )
        synthesis_responses.append(response)
        return response

    monkeypatch.setattr(generator, "_request_model", request_model)
    progress_updates: list[GenerationProgress] = []

    result = generator.get_threat_intelligence(
        "Example Threat", progress_callback=progress_updates.append
    )

    assert {
        key: value for key, value in result.items() if not key.startswith("_")
    } == threat_profile_data
    assert len(requests) == 2
    initial_content = requests[0]["messages"][0]["content"]
    correction_content = requests[1]["messages"][0]["content"]
    assert correction_content[0] == initial_content[0]
    assert correction_content[0]["cache_control"] == {"type": "ephemeral"}
    correction_text = correction_content[1]["text"]
    assert "CORRECTION ATTEMPT AFTER A FAILED EVIDENCE CONTRACT" in correction_text
    assert "Every claimAttribution sourceId MUST appear" in correction_text
    assert "claimField and claimIndex MUST select" in correction_text
    assert requests[1]["provider"] == requests[0]["provider"]
    assert "fallback_models" not in requests[0]
    assert "fallback_models" not in requests[1]
    assert requests[0]["model"] == "google/gemini-2.5-flash"
    assert requests[1]["model"] == "google/gemini-2.5-flash"
    assert requests[0]["session_id"] == requests[1]["session_id"]
    assert requests[0]["session_id"].startswith("sentrysearch-synthesis-")
    assert requests[0]["strict_response_schema"] is False
    assert requests[1]["strict_response_schema"] is False
    assert progress_updates[-3].message == ("Reconciling claim evidence with the source ledger...")
    assert progress_updates[-1].stage is GenerationStage.FINALIZING
    assert requests[0]["response_format"] is ThreatProfile
    assert requests[1]["response_format"] is ThreatProfile
    assert requests[0]["retry_policy"].max_attempts == 1
    assert requests[1]["retry_policy"].max_attempts == 1
    assert synthesis_responses[-1].usage.input_tokens == 23
    assert synthesis_responses[-1].usage.output_tokens == 44
    assert synthesis_responses[-1].usage.web_search_calls == 1
    assert synthesis_responses[-1].usage.total_tokens == 67


def test_quality_enhancement_never_rewrites_claim_bound_sections(monkeypatch, threat_profile_data):
    validator = ParallelSectionValidator(client=None)
    enhanced_sections: list[str] = []

    def enhance(section_name, section_content, tool_name, evidence_text):
        enhanced_sections.append(section_name)
        return {**section_content, "enhancementMarker": tool_name}

    monkeypatch.setattr(validator, "_enhance_section_from_attested_evidence", enhance)
    monkeypatch.setattr(
        validator,
        "validate_section",
        lambda _section_name, _content: {"scores": {"overall": 5.0}},
    )
    results = {
        "section_validations": {
            "threatIntelligence": {"scores": {"overall": 0.0}},
            "technicalDetails": {"scores": {"overall": 0.0}},
        }
    }

    enhancements = validator._enhance_sections_parallel(
        results,
        deepcopy(threat_profile_data),
        "Example Threat",
        evidence_text="Attested evidence",
    )

    assert enhanced_sections == ["technicalDetails"]
    assert set(enhancements) == {"technicalDetails"}
