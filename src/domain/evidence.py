"""Shared validation contract for persisted evidence assessments."""

from typing import Literal

from pydantic import BaseModel, Field

from src.domain.reports import EvidenceAdmissibilityStatus


class EvidenceSourceObservation(BaseModel):
    source_id: str | None = Field(default=None, validation_alias="sourceId")
    title: str
    url: str
    domain: str
    purpose: Literal["operational", "context_only", "excluded_non_operational"]
    disposition: Literal["admitted", "context_required", "excluded", "rejected"]
    reason: str
    rule_id: str = Field(validation_alias="ruleId")
    snapshot_status: Literal["captured", "unavailable"] = Field(
        default="unavailable", validation_alias="snapshotStatus"
    )
    snapshot_sha256: str | None = Field(default=None, validation_alias="snapshotSha256")
    snapshot_captured_at: str | None = Field(default=None, validation_alias="snapshotCapturedAt")
    snapshot_final_url: str | None = Field(default=None, validation_alias="snapshotFinalUrl")
    page_age: str | None = Field(default=None, validation_alias="pageAge")


class EvidenceIndicatorObservation(BaseModel):
    claim_field: str = Field(validation_alias="claimField")
    claim_index: int = Field(ge=0, validation_alias="claimIndex")
    value: str
    disposition: Literal["admitted", "context_required", "excluded", "rejected"]
    reason: str
    rule_id: str = Field(validation_alias="ruleId")


class EvidenceAdmissibility(BaseModel):
    schema_version: str = Field(validation_alias="schemaVersion")
    status: EvidenceAdmissibilityStatus
    source_observations: list[EvidenceSourceObservation] = Field(
        default_factory=list, validation_alias="sourceObservations"
    )
    indicator_observations: list[EvidenceIndicatorObservation] = Field(
        default_factory=list, validation_alias="indicatorObservations"
    )
    blocking_findings: list[str] = Field(default_factory=list, validation_alias="blockingFindings")
    summary: dict[str, int] = Field(default_factory=dict)
