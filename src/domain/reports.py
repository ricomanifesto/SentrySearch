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


class GenerationErrorCode(StrEnum):
    """Reader-safe, queryable reasons a generation run did not finish."""

    PROVIDER_RATE_LIMITED = "provider_rate_limited"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    PROVIDER_TIMEOUT = "provider_timeout"
    MODEL_OUTPUT_INVALID = "model_output_invalid"
    EVIDENCE_UNAVAILABLE = "evidence_unavailable"
    EVIDENCE_UNATTESTED = "evidence_unattested"
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
    evaluation_status: EvaluationStatus = EvaluationStatus.UNRECORDED
    quality_assessment: Mapping[str, Any] | None = None
    source_count: int = 0
    generation_error_code: GenerationErrorCode | None = None
    generation_failure_stage: GenerationStage | None = None


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


def derive_review_status(
    *,
    report_status: ReportStatus | str,
    evaluation_status: EvaluationStatus | str | None,
    quality_score: float | None,
    quality_assessment: Mapping[str, Any] | None,
    source_count: int,
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
