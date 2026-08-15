"""Evaluator-only retry path for an already researched and synthesized report."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Mapping

from src.core.openrouter_client import create_model_client, evaluation_request_options
from src.core.parallel_section_validator import ParallelSectionValidator
from src.core.recommendation_integrity import validate_quality_recommendations
from src.domain.model_routes import ModelRouteProvenance, ModelRoutePurpose


@dataclass(frozen=True, slots=True)
class SavedReportEvaluation:
    """One evaluator-only attempt and the route that actually handled it."""

    profile: dict[str, Any]
    quality_assessment: dict[str, Any]
    evaluation_route: dict[str, Any]

    @property
    def succeeded(self) -> bool:
        return isinstance(self.quality_assessment.get("overall_score"), (int, float))


def _evaluation_route(client: object) -> dict[str, Any]:
    options = evaluation_request_options()
    provider = options.get("provider")
    requested = provider.get("only") if isinstance(provider, Mapping) else ()
    requested_providers = tuple(str(value) for value in requested or ())
    summarize = getattr(client, "route_provenance", None)
    if callable(summarize):
        return summarize(
            ModelRoutePurpose.EVALUATION,
            requested_model=str(options["model"]),
            requested_providers=requested_providers,
        ).to_dict()
    return ModelRouteProvenance.summarize(
        (),
        requested_model=str(options["model"]),
        requested_providers=requested_providers,
    ).to_dict()


def evaluate_saved_report(profile: Mapping[str, Any]) -> SavedReportEvaluation:
    """Re-evaluate stored evidence without repeating web research or synthesis."""

    clean_profile = deepcopy(dict(profile))
    for key in tuple(clean_profile):
        if key.startswith("_"):
            clean_profile.pop(key, None)
    clean_profile.pop("comprehensiveWebSearchSources", None)

    client = create_model_client()
    validator = ParallelSectionValidator(client)
    assessment = validator.validate_complete_profile(
        clean_profile,
        tool_name=None,
        evidence_text=None,
    )
    source_block = clean_profile.get("webSearchSources")
    primary_sources = (
        source_block.get("primarySources") if isinstance(source_block, Mapping) else []
    )
    validate_quality_recommendations(
        assessment,
        primary_sources if isinstance(primary_sources, list) else [],
        clean_profile,
    )
    clean_profile["_quality_assessment"] = assessment
    return SavedReportEvaluation(
        profile=clean_profile,
        quality_assessment=assessment,
        evaluation_route=_evaluation_route(client),
    )
