"""Canonical provenance for model routes that contributed to a report."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Iterable


class ModelRoutePurpose(StrEnum):
    """Report pipeline roles with independently configured model routes."""

    GENERATION = "generation"
    EVALUATION = "evaluation"


class ModelRouteAttemptOutcome(StrEnum):
    """Whether one explicit application-owned route attempt returned usable output."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"


def _unique(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(value.strip() for value in values if value.strip()))


@dataclass(frozen=True, slots=True)
class ModelRouteObservation:
    """One successful model response and the application route that reached it."""

    purpose: ModelRoutePurpose
    requested_model: str
    selected_model: str
    actual_model: str
    provider: str = ""
    requested_providers: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "purpose", ModelRoutePurpose(self.purpose))
        for field_name in ("requested_model", "selected_model", "actual_model"):
            value = getattr(self, field_name).strip()
            if not value:
                raise ValueError(f"Model route {field_name} must not be empty")
            object.__setattr__(self, field_name, value)
        object.__setattr__(self, "provider", self.provider.strip())
        object.__setattr__(self, "requested_providers", _unique(self.requested_providers))

    @property
    def used_fallback(self) -> bool:
        return self.selected_model != self.requested_model


@dataclass(frozen=True, slots=True)
class ModelRouteAttemptObservation:
    """One candidate route attempt, including typed failures before a response exists."""

    purpose: ModelRoutePurpose
    requested_model: str
    selected_model: str
    outcome: ModelRouteAttemptOutcome
    provider: str = ""
    actual_model: str = ""
    error_code: str = ""
    retryable: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "purpose", ModelRoutePurpose(self.purpose))
        object.__setattr__(self, "outcome", ModelRouteAttemptOutcome(self.outcome))
        for field_name in ("requested_model", "selected_model"):
            value = getattr(self, field_name).strip()
            if not value:
                raise ValueError(f"Model route attempt {field_name} must not be empty")
            object.__setattr__(self, field_name, value)
        object.__setattr__(self, "provider", self.provider.strip())
        object.__setattr__(self, "actual_model", self.actual_model.strip())
        object.__setattr__(self, "error_code", self.error_code.strip())
        if self.outcome is ModelRouteAttemptOutcome.FAILED and not self.error_code:
            raise ValueError("Failed model route attempts require an error code")

    def to_dict(self) -> dict[str, object]:
        return {
            "requested_model": self.requested_model,
            "selected_model": self.selected_model,
            "actual_model": self.actual_model or None,
            "provider": self.provider or None,
            "outcome": self.outcome.value,
            "error_code": self.error_code or None,
            "retryable": self.retryable,
        }


@dataclass(frozen=True, slots=True)
class ModelRouteProvenance:
    """Stable report-level summary of every successful call for one pipeline role."""

    requested_models: tuple[str, ...]
    requested_providers: tuple[str, ...]
    selected_models: tuple[str, ...]
    actual_models: tuple[str, ...]
    providers: tuple[str, ...]
    used_fallback: bool
    request_count: int
    attempts: tuple[ModelRouteAttemptObservation, ...] = ()

    @classmethod
    def summarize(
        cls,
        observations: Iterable[ModelRouteObservation],
        *,
        requested_model: str,
        requested_providers: Iterable[str] = (),
        attempts: Iterable[ModelRouteAttemptObservation] = (),
    ) -> "ModelRouteProvenance":
        observed = tuple(observations)
        attempted = tuple(attempts)
        requested_models = _unique([requested_model, *(item.requested_model for item in observed)])
        return cls(
            requested_models=requested_models,
            requested_providers=_unique(
                [
                    *requested_providers,
                    *(provider for item in observed for provider in item.requested_providers),
                ]
            ),
            selected_models=_unique(item.selected_model for item in observed),
            actual_models=_unique(item.actual_model for item in observed),
            providers=_unique(item.provider for item in observed),
            used_fallback=(
                any(item.used_fallback for item in observed)
                or any(item.selected_model != item.requested_model for item in attempted)
            ),
            request_count=len(observed),
            attempts=attempted,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "requested_models": list(self.requested_models),
            "requested_providers": list(self.requested_providers),
            "selected_models": list(self.selected_models),
            "actual_models": list(self.actual_models),
            "providers": list(self.providers),
            "used_fallback": self.used_fallback,
            "request_count": self.request_count,
            "attempts": [attempt.to_dict() for attempt in self.attempts],
        }


def generation_fallback_state(route: object) -> bool | None:
    """Return a query-safe fallback classification, preserving legacy unknowns."""

    if not isinstance(route, dict):
        return None
    used_fallback = route.get("used_fallback")
    return used_fallback if isinstance(used_fallback, bool) else None
