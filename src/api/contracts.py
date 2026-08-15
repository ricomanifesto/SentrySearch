"""Validated HTTP request and response contracts for the SentrySearch API."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from src.domain.reports import (
    ClaimAttributionStatus,
    ClassificationStatus,
    EvaluationStatus,
    GenerationErrorCode,
    GenerationStage,
    ReportStatus,
    ReviewStatus,
)

ReportSortKey = Literal["created_at", "quality_score", "tool_name", "processing_time_ms"]
SortDirection = Literal["asc", "desc"]


class ReportCreate(BaseModel):
    tool_name: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Target for threat intelligence analysis",
    )
    analysis_type: Literal["comprehensive", "quick", "custom"] = Field(
        default="comprehensive", description="Analysis depth"
    )

    @field_validator("tool_name", mode="before")
    @classmethod
    def normalize_tool_name(cls, value: object) -> object:
        return value.strip() if isinstance(value, str) else value


class ReportResponse(BaseModel):
    id: str
    tool_name: str
    category: str
    threat_type: str
    classification_status: ClassificationStatus = ClassificationStatus.UNRECORDED
    claim_attribution_status: ClaimAttributionStatus = ClaimAttributionStatus.LEGACY
    claim_attribution_version: str | None = None
    quality_score: float | None
    created_at: datetime
    processing_time_ms: int = 0
    status: ReportStatus = ReportStatus.COMPLETED
    generation_stage: GenerationStage = GenerationStage.COMPLETED
    generation_failure_stage: GenerationStage | None = None
    generation_error_code: GenerationErrorCode | None = None
    generation_retryable: bool | None = None
    generation_failure: dict[str, Any] | None = None
    evaluation_status: EvaluationStatus = EvaluationStatus.UNRECORDED
    evaluation_error_code: str | None = None
    evaluation_attempts: int = 0
    evaluated_at: datetime | None = None
    review_status: ReviewStatus = ReviewStatus.NEEDS_EVALUATION
    content_preview: str | None = None


class ReportSource(BaseModel):
    source_id: str | None = None
    title: str
    url: str
    domain: str
    access_date: str
    relevance_score: str
    content_type: str
    key_findings: str


class ModelRouteProvenance(BaseModel):
    requested_models: list[str] = Field(default_factory=list)
    requested_providers: list[str] = Field(default_factory=list)
    selected_models: list[str] = Field(default_factory=list)
    actual_models: list[str] = Field(default_factory=list)
    providers: list[str] = Field(default_factory=list)
    used_fallback: bool = False
    request_count: int = Field(default=0, ge=0)
    attempts: list[dict[str, Any]] = Field(default_factory=list)


class ClaimAttributionEntry(BaseModel):
    claim_class: Literal[
        "threat_activity",
        "forensic_artifact",
        "detection_indicator",
        "mitigation_action",
    ]
    claim: str
    source_ids: list[str] = Field(default_factory=list)


class ReportDetail(ReportResponse):
    markdown_content: str | None = None
    threat_data: dict[str, Any] | None = None
    web_sources: list[ReportSource] = Field(default_factory=list)
    search_tags: list[str] = Field(default_factory=list)
    generation_route: ModelRouteProvenance | None = None
    evaluation_route: ModelRouteProvenance | None = None
    quality_assessment: dict[str, Any] | None = None
    claim_attributions: list[ClaimAttributionEntry] = Field(default_factory=list)


class SearchFilters(BaseModel):
    query: str | None = Field(default=None, max_length=500)
    threat_types: list[str] = Field(default_factory=list, max_length=50)
    date_range_days: int | None = Field(default=None, ge=1, le=3650)
    min_quality_score: float | None = Field(default=None, ge=0, le=5)
    tags: list[str] = Field(default_factory=list, max_length=50)
    statuses: list[ReportStatus] = Field(default_factory=list, max_length=10)
    review_statuses: list[ReviewStatus] = Field(default_factory=list, max_length=10)


class PaginationParams(BaseModel):
    page: int = Field(default=1, ge=1)
    limit: int = Field(default=20, ge=1, le=100)
    sort_by: ReportSortKey = "created_at"
    sort_order: SortDirection = "desc"
