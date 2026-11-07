"""Plain facts recorded while one report generation runs.

The generator fills one ``GenerationRun`` as a local value: stage timestamps,
prompt and source counts, the final profile facts, and any error. Performance
metrics and trace files are projections of this record plus the run's
``list[ModelCall]``, computed once after the run ends.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import time
from typing import Any
import uuid

TRACE_STAGES = ("initialization", "web_search", "quality_validation", "completion")


@dataclass
class StageSpan:
    started_at: datetime | None = None
    ended_at: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class GenerationRun:
    """One generation's observable facts; no behavior beyond recording."""

    tool_name: str
    model: str
    prompt_type: str = "threat_intel_main"
    cache_enabled: bool = True
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    metrics_request_id: str = ""
    started_at: datetime = field(default_factory=_utc_now)
    metrics_timestamp: str = ""
    metrics_started_clock: float = 0.0
    stages: dict[str, StageSpan] = field(default_factory=dict)
    api_started_clock: float | None = None
    api_ended_clock: float | None = None
    prompt_size_chars: int = 0
    source_count: int = 0
    tool_events: list[Any] = field(default_factory=list)
    contract_valid: bool = False
    quality_metrics: dict[str, Any] | None = None
    core_metadata: dict[str, Any] | None = None
    final_guidance: str = ""
    validator_sources: list[Any] = field(default_factory=list)
    error: str | None = None
    error_at: datetime | None = None
    error_clock: float | None = None
    completed_at: datetime | None = None
    completed_clock: float | None = None
    completed_profile: bool = False

    def __post_init__(self) -> None:
        if not self.metrics_request_id:
            self.metrics_request_id = f"{self.prompt_type}_{uuid.uuid4().hex}"
        self.stages.setdefault("initialization", StageSpan(started_at=self.started_at))

    def start_metrics(self) -> None:
        self.metrics_timestamp = datetime.now().isoformat()
        self.metrics_started_clock = time.time()

    def start_stage(self, name: str) -> None:
        self.stages.setdefault(name, StageSpan()).started_at = _utc_now()

    def end_stage(self, name: str, **metadata: Any) -> None:
        span = self.stages.setdefault(name, StageSpan())
        span.ended_at = _utc_now()
        span.metadata.update(metadata)

    def fail(self, error: BaseException) -> None:
        self.error = str(error)
        self.error_at = _utc_now()
        self.error_clock = time.time()

    def complete(self, *, profile: bool) -> None:
        self.completed_at = _utc_now()
        self.completed_clock = time.time()
        self.completed_profile = profile
