"""Domain vocabulary for stored threat-intelligence reports."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any, Iterable, Mapping


class ReportStatus(StrEnum):
    """Lifecycle states persisted for a report."""

    GENERATING = "generating"
    COMPLETED = "completed"
    FAILED = "failed"


class EvaluationStatus(StrEnum):
    """Lifecycle states for the independently recoverable quality evaluation."""

    UNRECORDED = "unrecorded"
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"


class ReviewStatus(StrEnum):
    """Reader-facing readiness derived from generation, evaluation, and evidence."""

    GENERATING = "generating"
    GENERATION_FAILED = "generation_failed"
    EVALUATION_PENDING = "evaluation_pending"
    NEEDS_EVALUATION = "needs_evaluation"
    NEEDS_ATTENTION = "needs_attention"
    REVIEWABLE = "reviewable"


class AnalystDisposition(StrEnum):
    """Latest analyst judgment for one evaluation vintage."""

    UNREVIEWED = "unreviewed"
    ACCEPTED = "accepted"
    NEEDS_REVISION = "needs_revision"
    REJECTED = "rejected"


class ClassificationStatus(StrEnum):
    """Provenance of the reader-facing category and threat-family fields."""

    RECORDED = "recorded"
    RECONCILED = "reconciled"
    UNMAPPED = "unmapped"
    UNRECORDED = "unrecorded"


class ClaimAttributionStatus(StrEnum):
    """Whether claim-level source identity exists for a saved report."""

    ATTRIBUTED = "attributed"
    UNATTRIBUTED = "unattributed"
    LEGACY = "legacy"


class EvidenceAdmissibilityStatus(StrEnum):
    """Deterministic safety posture for operational evidence in a saved report."""

    UNASSESSED = "unassessed"
    PASSED = "passed"
    BLOCKED = "blocked"


class GenerationErrorCode(StrEnum):
    """Reader-safe, queryable reasons a generation run did not finish."""

    PROVIDER_RATE_LIMITED = "provider_rate_limited"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    PROVIDER_TIMEOUT = "provider_timeout"
    MODEL_REQUEST_REJECTED = "model_request_rejected"
    MODEL_OUTPUT_INVALID = "model_output_invalid"
    EVIDENCE_UNAVAILABLE = "evidence_unavailable"
    EVIDENCE_UNATTESTED = "evidence_unattested"
    EVIDENCE_INADMISSIBLE = "evidence_inadmissible"
    PERSISTENCE_FAILED = "persistence_failed"
    UNKNOWN = "unknown"


class GenerationStage(StrEnum):
    """Reader-visible stages emitted by the generation pipeline."""

    QUEUED = "queued"
    RESEARCHING = "researching"
    SYNTHESIZING = "synthesizing"
    VALIDATING = "validating"
    FINALIZING = "finalizing"
    COMPLETED = "completed"
    FAILED = "failed"


class GenerationRouteScope(StrEnum):
    """Precision available for analytics attribution of the authoring route."""

    SYNTHESIS = "synthesis"
    LEGACY_AGGREGATE = "legacy_aggregate"
    UNRECORDED = "unrecorded"


@dataclass(frozen=True, slots=True)
class GenerationProgress:
    """Typed progress emitted by the report-generation pipeline."""

    progress: float
    stage: GenerationStage
    message: str

    def __post_init__(self) -> None:
        if not 0 <= self.progress <= 1:
            raise ValueError("Generation progress must be between 0 and 1")
        object.__setattr__(self, "stage", GenerationStage(self.stage))
        if not self.message.strip():
            raise ValueError("Generation progress must include reader-facing detail")


class ReportSortField(StrEnum):
    """Report fields exposed as stable sort keys."""

    CREATED_AT = "created_at"
    QUALITY_SCORE = "quality_score"
    TOOL_NAME = "tool_name"
    PROCESSING_TIME = "processing_time_ms"


class SortOrder(StrEnum):
    """Supported report sort directions."""

    ASCENDING = "asc"
    DESCENDING = "desc"


def _as_tuple(values: Iterable[str] | None) -> tuple[str, ...]:
    return tuple(values or ())


@dataclass(frozen=True, slots=True)
class ReportFilters:
    """Immutable filter and ordering values for one report query."""

    category: str | None = None
    threat_type: str | None = None
    threat_types: tuple[str, ...] = ()
    min_quality_score: float | None = None
    search_query: str | None = None
    tags: tuple[str, ...] = ()
    statuses: tuple[ReportStatus, ...] = ()
    review_statuses: tuple[ReviewStatus, ...] = ()
    analyst_dispositions: tuple[AnalystDisposition, ...] = ()
    requires_action: bool = False
    created_after: datetime | None = None
    user_id: str | None = None
    sort_by: ReportSortField = ReportSortField.CREATED_AT
    sort_order: SortOrder = SortOrder.DESCENDING

    def __post_init__(self) -> None:
        object.__setattr__(self, "threat_types", _as_tuple(self.threat_types))
        object.__setattr__(self, "tags", _as_tuple(self.tags))
        object.__setattr__(
            self,
            "statuses",
            tuple(ReportStatus(value) for value in self.statuses),
        )
        object.__setattr__(
            self,
            "review_statuses",
            tuple(ReviewStatus(value) for value in self.review_statuses),
        )
        object.__setattr__(
            self,
            "analyst_dispositions",
            tuple(AnalystDisposition(value) for value in self.analyst_dispositions),
        )
        object.__setattr__(self, "sort_by", ReportSortField(self.sort_by))
        object.__setattr__(self, "sort_order", SortOrder(self.sort_order))


@dataclass(frozen=True, slots=True)
class ReportAnalyticsRecord:
    """Minimal persisted fields needed to derive report analytics."""

    created_at: datetime
    quality_score: float | None
    processing_time_ms: int | None
    status: ReportStatus
    threat_type: str | None
    generation_used_fallback: bool | None = None
    generation_route_scope: GenerationRouteScope = GenerationRouteScope.UNRECORDED
    evaluation_status: EvaluationStatus = EvaluationStatus.UNRECORDED
    quality_assessment: Mapping[str, Any] | None = None
    source_count: int = 0
    evidence_admissibility_status: EvidenceAdmissibilityStatus = (
        EvidenceAdmissibilityStatus.UNASSESSED
    )
    generation_error_code: GenerationErrorCode | None = None
    generation_failure_stage: GenerationStage | None = None


def derive_generation_route_scope(
    *, synthesis_route: object, generation_route: object
) -> GenerationRouteScope:
    """Name the most precise authoring-route provenance retained by a report."""

    if isinstance(synthesis_route, Mapping) and synthesis_route:
        return GenerationRouteScope.SYNTHESIS
    if isinstance(generation_route, Mapping) and generation_route:
        return GenerationRouteScope.LEGACY_AGGREGATE
    return GenerationRouteScope.UNRECORDED


def coerce_evaluation_status(
    value: str | EvaluationStatus | None,
    *,
    quality_score: float | None = None,
) -> EvaluationStatus:
    """Keep legacy scored reports useful while leaving unknown history explicit."""

    if value:
        try:
            return EvaluationStatus(value)
        except ValueError:
            pass
    return EvaluationStatus.COMPLETED if quality_score is not None else EvaluationStatus.UNRECORDED


def is_judgment_eligible(
    *,
    report_status: ReportStatus | str,
    evaluation_status: EvaluationStatus | str | None,
    quality_score: float | None,
) -> bool:
    """Return whether the current evaluation vintage can receive analyst judgment."""

    status = ReportStatus(report_status)
    evaluator = coerce_evaluation_status(evaluation_status, quality_score=quality_score)
    return (
        status is ReportStatus.COMPLETED
        and evaluator is EvaluationStatus.COMPLETED
        and quality_score is not None
    )


def is_reuse_eligible(
    *,
    report_status: ReportStatus | str,
    evaluation_status: EvaluationStatus | str | None,
    quality_score: float | None,
    evidence_admissibility_status: EvidenceAdmissibilityStatus | str,
) -> bool:
    """Return whether an analyst may accept the current vintage for reuse."""

    return is_judgment_eligible(
        report_status=report_status,
        evaluation_status=evaluation_status,
        quality_score=quality_score,
    ) and (
        EvidenceAdmissibilityStatus(evidence_admissibility_status)
        is EvidenceAdmissibilityStatus.PASSED
    )


def evaluation_conflict_count(quality_assessment: Mapping[str, Any] | None) -> int:
    """Count explicit cross-section conflicts without inferring legacy evidence."""

    assessment = quality_assessment or {}
    consistency = assessment.get("consistency")
    if not isinstance(consistency, Mapping):
        return 0
    inconsistencies = consistency.get("inconsistencies")
    if not isinstance(inconsistencies, list):
        return 0
    return sum(isinstance(value, str) and bool(value.strip()) for value in inconsistencies)


def derive_review_status(
    *,
    report_status: ReportStatus | str,
    evaluation_status: EvaluationStatus | str | None,
    quality_score: float | None,
    quality_assessment: Mapping[str, Any] | None,
    source_count: int,
    evidence_admissibility_status: EvidenceAdmissibilityStatus | str = (
        EvidenceAdmissibilityStatus.UNASSESSED
    ),
) -> ReviewStatus:
    """Derive one honest review state without overloading generation completion."""

    status = ReportStatus(report_status)
    if status is ReportStatus.GENERATING:
        return ReviewStatus.GENERATING
    if status is ReportStatus.FAILED:
        return ReviewStatus.GENERATION_FAILED

    evaluator = coerce_evaluation_status(evaluation_status, quality_score=quality_score)
    if evaluator is EvaluationStatus.PENDING:
        return ReviewStatus.EVALUATION_PENDING
    if evaluator is not EvaluationStatus.COMPLETED or quality_score is None:
        return ReviewStatus.NEEDS_EVALUATION
    if source_count < 1:
        return ReviewStatus.NEEDS_ATTENTION
    if (
        EvidenceAdmissibilityStatus(evidence_admissibility_status)
        is not EvidenceAdmissibilityStatus.PASSED
    ):
        return ReviewStatus.NEEDS_ATTENTION

    assessment = quality_assessment or {}
    summary = assessment.get("summary")
    summary = summary if isinstance(summary, Mapping) else {}
    if assessment.get("critical_issues") or assessment.get("needs_improvement") is True:
        return ReviewStatus.NEEDS_ATTENTION
    if int(summary.get("passed_sections") or 0) == 0:
        return ReviewStatus.NEEDS_ATTENTION
    if int(summary.get("failed_sections") or 0) > 0:
        return ReviewStatus.NEEDS_ATTENTION
    if int(summary.get("unavailable_sections") or 0) > 0:
        return ReviewStatus.NEEDS_ATTENTION

    consistency = assessment.get("consistency")
    if isinstance(consistency, Mapping) and consistency.get("inconsistencies"):
        return ReviewStatus.NEEDS_ATTENTION
    return ReviewStatus.REVIEWABLE
