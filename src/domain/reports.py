"""Domain vocabulary for stored threat-intelligence reports."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Iterable


class ReportStatus(StrEnum):
    """Lifecycle states persisted for a report."""

    GENERATING = "generating"
    COMPLETED = "completed"
    FAILED = "failed"


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
    created_after: datetime | None = None
    user_id: str | None = None
    sort_by: ReportSortField = ReportSortField.CREATED_AT
    sort_order: SortOrder = SortOrder.DESCENDING

    def __post_init__(self) -> None:
        object.__setattr__(self, "threat_types", _as_tuple(self.threat_types))
        object.__setattr__(self, "tags", _as_tuple(self.tags))
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
