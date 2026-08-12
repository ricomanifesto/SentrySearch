from copy import deepcopy
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from src.core.markdown_generator import render_quality_assessment
from src.core.parallel_section_validator import ParallelSectionValidator, SectionEnhancement
from src.core.section_validator import SectionValidator
from src.core.validation_criteria import (
    ConsistencyEvaluation,
    SectionEvaluation,
    parse_section_evaluation_response,
    select_profile_sections,
)


def evaluation_payload(*, overall_dimensions: float = 4.0, recommendation: str = "PASS") -> dict:
    return {
        "scores": {
            "completeness": overall_dimensions,
            "technical_accuracy": overall_dimensions,
            "source_quality": overall_dimensions,
            "actionability": overall_dimensions,
            "relevance": overall_dimensions,
        },
        "missing_information": [],
        "weak_areas": [],
        "technical_issues": [],
        "specific_improvements": [],
        "recommendation": recommendation,
        "reasoning": "The section meets the rubric.",
    }


def test_section_evaluation_rejects_out_of_range_scores():
    payload = evaluation_payload()
    payload["scores"]["technical_accuracy"] = 5.1

    with pytest.raises(ValidationError):
        SectionEvaluation.model_validate(payload)


def test_parsed_section_evaluation_calculates_its_own_overall_score():
    payload = evaluation_payload()
    payload["scores"].update(
        {
            "completeness": 1,
            "technical_accuracy": 2,
            "source_quality": 3,
            "actionability": 4,
            "relevance": 5,
        }
    )
    response = SimpleNamespace(parsed=SectionEvaluation.model_validate(payload))

    parsed = parse_section_evaluation_response(response, minimum_score=3.0)

    assert parsed["scores"]["overall"] == 3.0


def test_parsed_section_evaluation_rejects_a_pass_below_the_rubric_minimum():
    response = SimpleNamespace(
        parsed=SectionEvaluation.model_validate(
            evaluation_payload(overall_dimensions=3.5, recommendation="PASS")
        )
    )

    parsed = parse_section_evaluation_response(response, minimum_score=4.0)

    assert parsed["recommendation"] == "ENHANCE"


def test_select_profile_sections_reports_sections_without_a_rubric():
    profile = {
        "coreMetadata": {"name": "Example"},
        "technicalDetails": {"architecture": "client-server"},
        "toolOverview": {"description": "Example tool"},
        "detectionAndMitigation": {"iocs": {}},
        "mlGuidance": {"enabled": True},
        "_quality_assessment": {"overall_score": 4.0},
    }

    selected, skipped = select_profile_sections(profile)

    assert list(selected) == ["technicalDetails", "detectionAndMitigation"]
    assert skipped == ["toolOverview", "mlGuidance"]


def test_validate_section_uses_the_structured_evaluation_contract():
    class Messages:
        def __init__(self):
            self.request: dict | None = None

        def create(self, **kwargs):
            self.request = kwargs
            return SimpleNamespace(parsed=SectionEvaluation.model_validate(evaluation_payload()))

    messages = Messages()
    validator = SectionValidator(SimpleNamespace(messages=messages))

    result = validator.validate_section("technicalDetails", {"architecture": "client-server"})

    assert messages.request is not None
    assert messages.request["response_format"] is SectionEvaluation
    assert result["scores"]["overall"] == 4.0
    assert result["section_name"] == "technicalDetails"
    assert result["is_critical"] is True
    assert result["timestamp"].endswith("+00:00")


def test_consistency_check_uses_structured_output_and_section_content():
    class Messages:
        def __init__(self):
            self.request: dict | None = None

        def create(self, **kwargs):
            self.request = kwargs
            return SimpleNamespace(
                parsed=ConsistencyEvaluation(
                    consistency_score=4.5,
                    inconsistencies=[],
                    recommendations=[],
                )
            )

    messages = Messages()
    validator = SectionValidator(SimpleNamespace(messages=messages))

    result = validator._check_consistency({"technicalDetails": {"architecture": "client-server"}})

    assert messages.request is not None
    assert messages.request["response_format"] is ConsistencyEvaluation
    assert "client-server" in messages.request["messages"][0]["content"]
    assert result == {
        "consistency_score": 4.5,
        "inconsistencies": [],
        "recommendations": [],
        "was_evaluated": True,
    }


def test_sequential_validation_recomputes_critical_issues_after_enhancement():
    class ImprovingValidator(SectionValidator):
        def __init__(self):
            super().__init__(client=None)
            self.validation_count = 0

        def validate_section(self, section_name, content):
            self.validation_count += 1
            recommendation = "RETRY" if self.validation_count == 1 else "PASS"
            score = 2.0 if recommendation == "RETRY" else 4.5
            result = evaluation_payload(overall_dimensions=score, recommendation=recommendation)
            result["scores"]["overall"] = score
            result["missing_information"] = (
                ["Architecture details"] if recommendation == "RETRY" else []
            )
            result["section_name"] = section_name
            result["is_critical"] = True
            return result

        def _enhance_section_with_web_search(self, section_name, content, tool_name):
            return {**content, "capabilities": ["Example capability"]}

        def _check_consistency(self, profile):
            return {
                "consistency_score": 5.0,
                "inconsistencies": [],
                "recommendations": [],
                "was_evaluated": True,
            }

    validator = ImprovingValidator()

    result = validator.validate_complete_profile(
        {"technicalDetails": {"architecture": "client-server"}},
        tool_name="Example",
    )

    assert result["critical_issues"] == []
    assert result["needs_improvement"] is False


def test_recommendations_include_sections_below_their_rubric_minimum():
    validator = SectionValidator(client=None)
    results = {
        "critical_issues": [],
        "section_validations": {
            "technicalDetails": {
                "scores": {"overall": 3.5},
                "recommendation": "ENHANCE",
                "specific_improvements": ["Add dependency versions."],
            }
        },
        "consistency": {"inconsistencies": []},
    }

    recommendations = validator._generate_recommendations(results)

    assert recommendations == ["Improve technicalDetails: Add dependency versions."]


def test_parallel_enhancement_returns_changes_without_mutating_the_profile():
    class ImprovingParallelValidator(ParallelSectionValidator):
        def _enhance_section_with_web_search(self, section_name, content, tool_name):
            return {**content, "enhanced": True}

        def validate_section(self, section_name, content):
            result = evaluation_payload(overall_dimensions=4.5)
            result["scores"]["overall"] = 4.5
            result["section_name"] = section_name
            result["is_critical"] = False
            return result

    validator = ImprovingParallelValidator(client=None, max_concurrent_enhancements=2)
    profile = {
        "threatIntelligence": {"value": "original"},
        "forensicArtifacts": {"value": "original"},
    }
    original_profile = deepcopy(profile)
    validation_results = {
        "section_validations": {
            name: {
                **evaluation_payload(overall_dimensions=2.5, recommendation="ENHANCE"),
                "scores": {**evaluation_payload()["scores"], "overall": 2.5},
            }
            for name in profile
        },
        "validation_attempts": {name: 1 for name in profile},
    }

    enhancements = validator._enhance_sections_parallel(validation_results, profile, "Example")

    assert profile == original_profile
    assert list(enhancements) == list(profile)
    assert all(isinstance(result, SectionEnhancement) for result in enhancements.values())
    assert all(result.content["enhanced"] is True for result in enhancements.values())


def test_parallel_metrics_report_observations_without_estimated_speedups():
    class DeterministicParallelValidator(ParallelSectionValidator):
        def _validate_sections_parallel(self, sections, progress_callback=None):
            return {
                name: {
                    **evaluation_payload(),
                    "scores": {**evaluation_payload()["scores"], "overall": 4.0},
                    "section_name": name,
                    "is_critical": False,
                }
                for name in sections
            }

        def _check_consistency(self, profile):
            return {
                "consistency_score": 4.0,
                "inconsistencies": [],
                "recommendations": [],
                "was_evaluated": True,
            }

    validator = DeterministicParallelValidator(client=None)

    result = validator.validate_complete_profile_parallel(
        {"threatIntelligence": {"entities": {}, "riskAssessment": {}}}
    )

    metrics = result["parallel_metrics"]
    assert metrics["sections_processed"] == 1
    assert metrics["sections_enhanced"] == 0
    assert metrics["max_concurrent_validations"] == 4
    assert "estimated_sequential_time" not in metrics
    assert "speedup_factor" not in metrics
    assert "time_saved_seconds" not in metrics


def test_quality_summary_counts_enhancements_and_sorts_section_rows():
    quality = {
        "overall_score": 3.8,
        "summary": {
            "total_sections": 3,
            "passed_sections": 1,
            "enhance_sections": 1,
            "failed_sections": 1,
        },
        "section_validations": {
            "technicalDetails": {
                "scores": {"overall": 4.2},
                "recommendation": "PASS",
            },
            "detectionAndMitigation": {
                "scores": {"overall": 2.8},
                "recommendation": "RETRY",
            },
            "forensicArtifacts": {
                "scores": {"overall": 3.4},
                "recommendation": "ENHANCE",
            },
        },
        "recommendations": ["Add source context."],
        "skipped_sections": ["toolOverview"],
        "consistency": {
            "consistency_score": 4.0,
            "inconsistencies": [],
            "was_evaluated": True,
        },
    }

    markdown = render_quality_assessment(quality)

    assert "- **Sections to Enhance**: 1" in markdown
    assert "### Sections Not Scored\n\n- Tool Overview" in markdown
    assert markdown.index("Detection And Mitigation") < markdown.index("Forensic Artifacts")
    assert markdown.index("Forensic Artifacts") < markdown.index("Technical Details")
