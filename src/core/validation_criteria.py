"""Evaluation rubrics and structured output contracts for threat profile sections."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from statistics import fmean
from types import MappingProxyType
from typing import Annotated, Any, Mapping

from pydantic import BaseModel, ConfigDict, Field


class StrictEvaluationModel(BaseModel):
    """Keep model-generated evaluation payloads closed and finite."""

    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class EvaluationRecommendation(StrEnum):
    """Actions the evaluation pipeline can take for a section."""

    PASS = "PASS"
    ENHANCE = "ENHANCE"
    RETRY = "RETRY"


class EvaluationScores(StrictEvaluationModel):
    """The five independently scored dimensions in the evaluation rubric."""

    completeness: float = Field(ge=0, le=5)
    technical_accuracy: float = Field(ge=0, le=5)
    source_quality: float = Field(ge=0, le=5)
    actionability: float = Field(ge=0, le=5)
    relevance: float = Field(ge=0, le=5)

    def average(self) -> float:
        """Calculate the aggregate score in application code, not in the model."""

        return round(
            fmean(
                (
                    self.completeness,
                    self.technical_accuracy,
                    self.source_quality,
                    self.actionability,
                    self.relevance,
                )
            ),
            2,
        )


EvaluationNote = Annotated[str, Field(min_length=1, max_length=240)]


class SectionEvaluation(StrictEvaluationModel):
    """Validated output returned by the section evaluator."""

    scores: EvaluationScores
    missing_information: list[EvaluationNote] = Field(max_length=3)
    weak_areas: list[EvaluationNote] = Field(max_length=3)
    technical_issues: list[EvaluationNote] = Field(max_length=3)
    specific_improvements: list[EvaluationNote] = Field(max_length=3)
    recommendation: EvaluationRecommendation
    reasoning: str = Field(min_length=1, max_length=480)


class ConsistencyEvaluation(StrictEvaluationModel):
    """Validated output returned by the cross-section consistency evaluator."""

    consistency_score: float = Field(ge=0, le=5)
    inconsistencies: list[EvaluationNote] = Field(max_length=5)
    recommendations: list[EvaluationNote] = Field(max_length=3)


@dataclass(frozen=True)
class SectionCriteria:
    """Static rubric configuration for one eligible profile section."""

    required_fields: tuple[str, ...]
    quality_checks: tuple[str, ...]
    minimum_score: float
    is_critical: bool


SECTION_CRITERIA: Mapping[str, SectionCriteria] = MappingProxyType(
    {
        "webSearchSources": SectionCriteria(
            required_fields=("searchQueriesUsed", "primarySources", "searchStrategy"),
            quality_checks=(
                "Search queries are specific and varied",
                "Primary sources include authoritative domains",
                "Each source includes a URL, title, and key findings",
                "Source access dates are recent",
                "The section uses multiple source types",
            ),
            minimum_score=3.5,
            is_critical=True,
        ),
        "technicalDetails": SectionCriteria(
            required_fields=("architecture", "operatingSystems", "capabilities", "dependencies"),
            quality_checks=(
                "The architecture description is technical rather than generic",
                "Operating system versions are included when known",
                "Capabilities are specific and actionable",
                "Dependencies include versions when known",
                "Implementation details support the technical claims",
            ),
            minimum_score=4.0,
            is_critical=True,
        ),
        "commandAndControl": SectionCriteria(
            required_fields=("communicationMethods", "commonCommands"),
            quality_checks=(
                "Communication methods include ports and protocols",
                "Command protocols describe encoding or encryption when known",
                "Beaconing patterns include timing information",
                "The section includes detection guidance for command-and-control traffic",
                "Common commands use the correct syntax",
            ),
            minimum_score=3.5,
            is_critical=True,
        ),
        "detectionAndMitigation": SectionCriteria(
            required_fields=("iocs", "behavioralIndicators"),
            quality_checks=(
                "Indicators of compromise are well formed",
                "Both network and host indicators are included when available",
                "Behavioral indicators are specific",
                "Indicators include enough context to explain their relevance",
                "Detection guidance is actionable",
            ),
            minimum_score=4.0,
            is_critical=True,
        ),
        "threatIntelligence": SectionCriteria(
            required_fields=("entities", "riskAssessment"),
            quality_checks=(
                "Threat actor attributions include confidence",
                "Campaigns include timeframes",
                "Risk ratings include supporting reasons",
                "Known tactics and techniques are linked when possible",
            ),
            minimum_score=3.0,
            is_critical=False,
        ),
        "forensicArtifacts": SectionCriteria(
            required_fields=("fileSystemArtifacts", "registryArtifacts", "networkArtifacts"),
            quality_checks=(
                "Artifacts use specific file paths, registry keys, or network values",
                "Each artifact explains what it reveals",
                "The section covers multiple artifact types",
                "Memory artifacts include concrete search patterns when available",
            ),
            minimum_score=3.5,
            is_critical=False,
        ),
        "mitigationAndResponse": SectionCriteria(
            required_fields=("preventiveMeasures", "detectionMethods", "responseActions"),
            quality_checks=(
                "Measures are specific and actionable",
                "Mitigations are prioritized by effectiveness",
                "Response actions follow incident-response practice",
                "The section includes technical and procedural measures",
            ),
            minimum_score=3.5,
            is_critical=True,
        ),
    }
)

PROFILE_METADATA_FIELDS = frozenset(
    {"coreMetadata", "evidenceAdmissibility", "_quality_assessment"}
)


SECTION_EVALUATION_PROMPT = """You are a cybersecurity expert evaluating one section of a threat intelligence profile.

Current UTC date: {current_date}
Treat dates on or before this date as historical or current, never as future dates.

Section name: {section_name}
Section content:
{content}

Score these dimensions from 0 to 5:
1. Completeness: required fields are populated with meaningful content.
2. Technical accuracy: claims are accurate and meet the section checks.
3. Source quality: technical claims use credible, appropriate sources.
4. Actionability: a security team can act on the information.
5. Relevance: content is specific to the threat or tool and avoids filler.

Required fields:
- {required_fields}

Section checks:
- {quality_checks}

Attested profile source context:
{source_context}

Use this profile-level source context when scoring source quality and checking whether section claims are supported. The deterministicEvidenceAdmissibility block is application-owned ground truth: do not override an exclusion or rejected indicator. Any rejected evidence that survives in operational content requires RETRY. Do not assume that lack of inline citations inside this isolated section means the profile lacks sources.

Identify only the most important missing information, weak areas, technical issues, and concrete improvements.
Keep each list to at most 3 concise one-sentence items. Keep reasoning to at most 2 concise sentences.
Choose one recommendation:
- PASS: every dimension is at least {minimum_score} and no critical issue remains.
- ENHANCE: some dimensions are below {minimum_score}, but the content is usable.
- RETRY: critical information is missing or major technical issues make the content unsafe to use.

Return one evaluation object that matches the provided response schema. Do not calculate an overall score; the application calculates it from the five dimensions."""


CONSISTENCY_PROMPT = """Evaluate consistency across these threat profile sections.

Current UTC date: {current_date}
Treat dates on or before this date as historical or current, never as future dates.

{sections}

Check technical claims, timelines, source use, and terminology. Treat evidenceAdmissibility as application-owned ground truth and never override a rejected indicator or excluded source. Score consistency from 0 to 5 using the same five-point scale as the section evaluations; this is not a 0 to 1 probability. Return at most 5 concise inconsistencies and 3 concise recommendations. Return one consistency evaluation that matches the provided response schema."""


def build_section_evaluation_prompt(
    section_name: str,
    content: Mapping[str, Any],
    criteria: SectionCriteria,
    *,
    current_date: str,
    source_context: Mapping[str, Any] | None = None,
) -> str:
    """Render the model prompt from one explicit rubric."""

    if not current_date.strip():
        raise ValueError("Evaluation prompts require the host-owned current UTC date")

    return SECTION_EVALUATION_PROMPT.format(
        section_name=section_name,
        content=json.dumps(content, indent=2),
        required_fields="\n- ".join(criteria.required_fields),
        quality_checks="\n- ".join(criteria.quality_checks),
        source_context=json.dumps(source_context or {}, indent=2),
        minimum_score=criteria.minimum_score,
        current_date=current_date,
    )


def select_profile_sections(
    profile: Mapping[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    """Split a profile into rubric-backed sections and transparent skips."""

    selected = {name: content for name, content in profile.items() if name in SECTION_CRITERIA}
    skipped = [
        name
        for name in profile
        if name not in SECTION_CRITERIA and name not in PROFILE_METADATA_FIELDS
    ]
    return selected, skipped


def parse_section_evaluation_response(response: Any, *, minimum_score: float) -> dict[str, Any]:
    """Return a validated evaluation with host-owned aggregate decisions."""

    parsed = getattr(response, "parsed", None)
    if parsed is None:
        raise ValueError("Model response did not include a parsed section evaluation")

    evaluation = (
        parsed
        if isinstance(parsed, SectionEvaluation)
        else SectionEvaluation.model_validate(parsed)
    )
    result = evaluation.model_dump(mode="json")
    result["scores"]["overall"] = evaluation.scores.average()
    result["was_evaluated"] = True
    dimension_scores = evaluation.scores.model_dump().values()
    pass_requirements_met = (
        all(score >= minimum_score for score in dimension_scores)
        and not evaluation.missing_information
        and not evaluation.technical_issues
    )
    if evaluation.recommendation == EvaluationRecommendation.PASS and not pass_requirements_met:
        result["recommendation"] = EvaluationRecommendation.ENHANCE.value
    return result


def parse_consistency_evaluation_response(response: Any) -> dict[str, Any]:
    """Return a validated consistency evaluation from structured model output."""

    parsed = getattr(response, "parsed", None)
    if parsed is None:
        raise ValueError("Model response did not include a parsed consistency evaluation")

    evaluation = (
        parsed
        if isinstance(parsed, ConsistencyEvaluation)
        else ConsistencyEvaluation.model_validate(parsed)
    )
    return {**evaluation.model_dump(mode="json"), "was_evaluated": True}
