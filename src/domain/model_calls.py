"""One plain record per model request attempt, and projections over a call log.

A run owns one ``list[ModelCall]``. The model client appends to it; route
provenance, usage totals, performance metrics, and traces are computed from it
after the run instead of being accumulated by stateful observers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from src.domain.model_routes import (
    ModelRouteAttemptObservation,
    ModelRouteAttemptOutcome,
    ModelRouteObservation,
    ModelRouteProvenance,
    ModelRoutePurpose,
)

USAGE_FIELDS = (
    "input_tokens",
    "output_tokens",
    "cached_tokens",
    "cache_write_tokens",
    "reasoning_tokens",
    "web_search_calls",
    "total_tokens",
)


@dataclass(frozen=True, slots=True)
class ModelCall:
    """One model request attempt: route, usage, and outcome."""

    purpose: ModelRoutePurpose | None
    requested_model: str
    selected_model: str
    outcome: ModelRouteAttemptOutcome
    started_at: float
    ended_at: float
    actual_model: str = ""
    provider: str = ""
    requested_providers: tuple[str, ...] = ()
    error_code: str = ""
    retryable: bool = False
    input_tokens: int = 0
    output_tokens: int = 0
    cached_tokens: int = 0
    cache_write_tokens: int = 0
    reasoning_tokens: int = 0
    web_search_calls: int = 0
    total_tokens: int = 0

    @property
    def succeeded(self) -> bool:
        return self.outcome is ModelRouteAttemptOutcome.SUCCEEDED

    def observation(self) -> ModelRouteObservation:
        if self.purpose is None or not self.succeeded:
            raise ValueError("Only a successful routed call has a route observation")
        return ModelRouteObservation(
            purpose=self.purpose,
            requested_model=self.requested_model,
            selected_model=self.selected_model,
            actual_model=self.actual_model,
            provider=self.provider,
            requested_providers=self.requested_providers,
        )

    def attempt(self) -> ModelRouteAttemptObservation:
        if self.purpose is None:
            raise ValueError("Only a routed call has an attempt record")
        return ModelRouteAttemptObservation(
            purpose=self.purpose,
            requested_model=self.requested_model,
            selected_model=self.selected_model,
            actual_model=self.actual_model,
            provider=self.provider,
            outcome=self.outcome,
            error_code=self.error_code,
            retryable=self.retryable,
        )


def route_provenance(
    calls: Iterable[ModelCall],
    purpose: ModelRoutePurpose | str,
    *,
    requested_model: str,
    requested_providers: tuple[str, ...] = (),
) -> ModelRouteProvenance:
    """Summarize one pipeline role from a call log."""

    normalized = ModelRoutePurpose(purpose)
    routed = [call for call in calls if call.purpose is normalized]
    return ModelRouteProvenance.summarize(
        [call.observation() for call in routed if call.succeeded],
        requested_model=requested_model,
        requested_providers=requested_providers,
        attempts=[call.attempt() for call in routed],
    )


def usage_totals(
    calls: Iterable[ModelCall],
    purposes: Iterable[ModelRoutePurpose] | None = None,
) -> dict[str, int]:
    """Sum provider-reported usage over successful calls for the given roles."""

    wanted = set(purposes) if purposes is not None else None
    totals = {field: 0 for field in USAGE_FIELDS}
    for call in calls:
        if not call.succeeded or (wanted is not None and call.purpose not in wanted):
            continue
        for field in USAGE_FIELDS:
            totals[field] += int(getattr(call, field) or 0)
    return totals
