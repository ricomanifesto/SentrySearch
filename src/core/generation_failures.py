"""Typed, reader-safe generation failure classification."""

from __future__ import annotations

from typing import Any, Mapping

from src.domain.reports import GenerationErrorCode, GenerationStage


class EvidenceUnavailableError(RuntimeError):
    """Raised when research cannot produce the minimum attested evidence set."""

    generation_error_code = GenerationErrorCode.EVIDENCE_UNAVAILABLE
    retryable = False

    def __init__(self, message: str, *, assessment: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.assessment = dict(assessment or {})


class EvidenceAttestationError(RuntimeError):
    """Raised when generated claims or sources fail the evidence contract."""

    generation_error_code = GenerationErrorCode.EVIDENCE_UNATTESTED
    retryable = False


class EvidenceGateError(RuntimeError):
    """Base error retaining application-owned evidence-gate findings."""

    def __init__(
        self,
        message: str,
        *,
        findings: list[str] | None = None,
        assessment: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.findings = tuple(findings or ())
        self.assessment = dict(assessment or {})


class EvidenceCoverageError(EvidenceGateError):
    """Raised when generated high-risk claims lack complete source coverage."""

    generation_error_code = GenerationErrorCode.EVIDENCE_INCOMPLETE
    retryable = True


class EvidenceAdmissibilityError(EvidenceGateError):
    """Raised when attested evidence is unsafe for operational use."""

    generation_error_code = GenerationErrorCode.EVIDENCE_INADMISSIBLE
    retryable = False


class ProfileOutputError(RuntimeError):
    """Raised when synthesis output cannot satisfy the structured profile contract."""

    generation_error_code = GenerationErrorCode.MODEL_OUTPUT_INVALID
    retryable = True


class PersistenceFailureError(RuntimeError):
    """Raised when a valid analysis cannot be committed as a review record."""

    generation_error_code = GenerationErrorCode.PERSISTENCE_FAILED
    retryable = True


def build_generation_failure(
    error: BaseException,
    *,
    stage: GenerationStage | str | None,
    route: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Project an internal exception into a stable record without leaking its message."""

    raw_code = getattr(error, "generation_error_code", GenerationErrorCode.UNKNOWN)
    try:
        code = GenerationErrorCode(raw_code)
    except (TypeError, ValueError):
        code = GenerationErrorCode.UNKNOWN
    try:
        normalized_stage = GenerationStage(stage) if stage is not None else None
    except (TypeError, ValueError):
        normalized_stage = None
    attempts = route.get("attempts") if isinstance(route, Mapping) else None
    failure = {
        "schema_version": 1,
        "error_code": code.value,
        "retryable": bool(getattr(error, "retryable", False)),
        "stage": normalized_stage.value if normalized_stage is not None else None,
        "route_attempts": list(attempts) if isinstance(attempts, list) else [],
        "route": dict(route) if isinstance(route, Mapping) else None,
    }
    evidence_assessment = getattr(error, "assessment", None)
    if isinstance(evidence_assessment, Mapping):
        failure["evidence_admissibility"] = dict(evidence_assessment)
    return failure
