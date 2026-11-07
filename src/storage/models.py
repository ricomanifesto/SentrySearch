"""
Database models for SentrySearch report storage using SQLAlchemy
"""

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    Numeric,
    String,
    Text,
)
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.sql import func
from datetime import datetime
import uuid
from typing import Any

Base = declarative_base()


def _optional_float(value: Any) -> float | None:
    return float(value) if value is not None else None


def _content_preview(value: Any, threat_data: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    if not isinstance(threat_data, dict):
        return None
    overview = threat_data.get("toolOverview")
    description = overview.get("description") if isinstance(overview, dict) else None
    if not isinstance(description, str) or not description.strip():
        return None
    compact = " ".join(description.split())
    return compact if len(compact) <= 240 else f"{compact[:237].rstrip()}..."


class Report(Base):
    __tablename__ = "reports"

    # Primary identifiers
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tool_name = Column(String(255), nullable=False, index=True)
    category = Column(String(100), index=True)
    threat_type = Column(String(100), index=True)
    classification_status = Column(String(30), default="unrecorded", index=True)
    claim_attribution_status = Column(String(30), default="legacy", index=True)
    claim_attribution_version = Column(String(10))
    evidence_admissibility_status = Column(String(30), default="unassessed", index=True)
    evidence_admissibility_version = Column(String(10))

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Quality metrics
    quality_score = Column(Numeric(3, 2))  # 0.00 to 5.00
    confidence_score = Column(Numeric(3, 2))  # 0.00 to 1.00
    trust_score = Column(Numeric(3, 2))  # 0.00 to 1.00

    # Performance metrics
    processing_time_ms = Column(Integer)
    api_calls_count = Column(Integer)

    # Structured data (JSON)
    threat_data = Column(JSONB)
    ml_techniques = Column(JSONB)
    quality_assessment = Column(JSONB)
    web_sources = Column(JSONB)
    evidence_admissibility = Column(JSONB)
    # TODO(route-provenance-v2): Remove generation_route after the retained-report
    # window no longer contains aggregate-only route records. Never write it for
    # successful v2 reports; research_route and synthesis_route own new provenance.
    generation_route = Column(JSONB)
    research_route = Column(JSONB)
    synthesis_route = Column(JSONB)
    evaluation_route = Column(JSONB)
    evaluation_status = Column(String(20))
    evaluation_error_code = Column(String(50))
    evaluation_attempts = Column(Integer, default=0)
    evaluated_at = Column(DateTime(timezone=True))
    evaluation_lease_id = Column(UUID(as_uuid=True))
    evaluation_lease_expires_at = Column(DateTime(timezone=True))
    evaluation_recoveries = Column(Integer, nullable=False, default=0, server_default="0")

    # Cloud storage references
    markdown_s3_key = Column(String(500))  # S3 object key for markdown content
    trace_s3_key = Column(String(500))  # S3 object key for trace data

    # User context
    api_key_hash = Column(String(64))  # Hashed API key for user association
    user_id = Column(String(100))  # Future: actual user system

    # Generation lifecycle: "generating" while a background job runs, then
    # "completed" or "failed". Defaults to "completed" so rows created before this
    # column existed are treated as finished.
    status = Column(String(20), default="completed", index=True)
    generation_stage = Column(String(20), default="completed")
    generation_failure_stage = Column(String(20))
    generation_error_code = Column(String(50))
    generation_retryable = Column(Boolean)
    generation_failure = Column(JSONB)
    review_status = Column(String(30), default="needs_evaluation", index=True)
    # Derived reader state, computed by src.domain.reports at write time inside
    # the writing transaction and filtered in SQL. Older versions are recomputed
    # by the reconciliation command.
    reader_state_version = Column(Integer)
    eligible_for_judgment = Column(Boolean)
    eligible_for_acceptance = Column(Boolean)
    eligible_for_handoff = Column(Boolean, index=True)

    # Flags and metadata
    is_flagged = Column(Boolean, default=False)
    is_favorite = Column(Boolean, default=False)
    version = Column(String(20))

    # Search optimization
    search_tags = Column(JSONB)  # Array of searchable tags
    content_preview = Column(Text)

    # Flat evidence relations projected from the profile at write time. Writers
    # assign whole collections on the already-locked row; the unit of work
    # replaces the previous rows in the same transaction.
    profile_sources = relationship(
        "ReportSourceRow",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="ReportSourceRow.position",
    )
    profile_claims = relationship(
        "ReportClaimRow",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="ReportClaimRow.position",
    )
    claim_support = relationship(
        "ReportClaimSupportRow",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="(ReportClaimSupportRow.claim_id, ReportClaimSupportRow.position)",
    )
    indicator_observations = relationship(
        "ReportIndicatorObservationRow",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="ReportIndicatorObservationRow.position",
    )
    source_observations = relationship(
        "ReportSourceObservationRow",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="ReportSourceObservationRow.position",
    )
    findings = relationship(
        "ReportFindingRow",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="ReportFindingRow.position",
    )
    artifacts = relationship(
        "ReportArtifact",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="ReportArtifact.kind",
    )
    disposition_events = relationship(
        "ReportDispositionEvent",
        viewonly=True,
        order_by="(ReportDispositionEvent.created_at, ReportDispositionEvent.id)",
    )

    def to_dict(self):
        """Convert model to dictionary for API responses"""
        return {
            "id": str(self.id),
            "tool_name": self.tool_name,
            "category": self.category,
            "threat_type": self.threat_type,
            "classification_status": self.classification_status or "unrecorded",
            "claim_attribution_status": self.claim_attribution_status or "legacy",
            "claim_attribution_version": self.claim_attribution_version,
            "evidence_admissibility_status": (self.evidence_admissibility_status or "unassessed"),
            "evidence_admissibility_version": self.evidence_admissibility_version,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "quality_score": _optional_float(self.quality_score),
            "confidence_score": _optional_float(self.confidence_score),
            "processing_time_ms": self.processing_time_ms or 0,
            "status": self.status or "completed",
            "generation_stage": self.generation_stage or self.status or "completed",
            "generation_failure_stage": self.generation_failure_stage,
            "generation_error_code": self.generation_error_code,
            "generation_retryable": self.generation_retryable,
            "generation_failure": self.generation_failure,
            "review_status": self.review_status,
            "generation_route": self.generation_route,
            "research_route": self.research_route,
            "synthesis_route": self.synthesis_route,
            "evaluation_route": self.evaluation_route,
            "evaluation_status": self.evaluation_status,
            "evaluation_error_code": self.evaluation_error_code,
            "evaluation_attempts": self.evaluation_attempts or 0,
            "evaluated_at": self.evaluated_at.isoformat() if self.evaluated_at else None,
            "quality_assessment": self.quality_assessment,
            "web_sources": self.web_sources or [],
            "search_tags": self.search_tags or [],
            "evidence_admissibility": self.evidence_admissibility,
            "threat_data": self.threat_data,
            "content_preview": _content_preview(self.content_preview, self.threat_data),
            "ml_techniques": self.ml_techniques,
            "user_id": self.user_id,
            "is_flagged": self.is_flagged,
            "is_favorite": self.is_favorite,
        }


class ReportRuntimeDispatch(Base):
    """Durable intent to submit one report to the local execution runtime."""

    __tablename__ = "report_runtime_dispatches"
    __table_args__ = (Index("ix_report_runtime_dispatches_pending", "state", "created_at"),)

    report_id = Column(
        UUID(as_uuid=True),
        ForeignKey("reports.id", ondelete="CASCADE"),
        primary_key=True,
    )
    runtime_run_id = Column(UUID(as_uuid=True))
    lease_version = Column(BigInteger, nullable=False, default=0, server_default="0")
    lease_owner = Column(Text)
    state = Column(String(20), nullable=False, default="pending")
    dispatch_attempts = Column(Integer, nullable=False, default=0)
    last_error_code = Column(String(50))
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class ReportDispositionEvent(Base):
    """Append-only analyst judgment attached to one evaluation attempt."""

    __tablename__ = "report_disposition_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    report_id = Column(
        UUID(as_uuid=True),
        ForeignKey("reports.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    reviewer_user_id = Column(String(100), nullable=False)
    disposition = Column(String(30), nullable=False, index=True)
    note = Column(Text)
    evaluation_attempt = Column(Integer, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    def to_dict(self, *, current_evaluation_attempt: int) -> dict[str, Any]:
        return {
            "id": str(self.id),
            "disposition": self.disposition,
            "note": self.note,
            "evaluation_attempt": self.evaluation_attempt,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "is_current": self.evaluation_attempt == current_evaluation_attempt,
        }


class ReportSearch(Base):
    __tablename__ = "report_searches"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(String(100))
    query = Column(Text)
    filters = Column(JSONB)
    results_count = Column(Integer)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())


class ReportTag(Base):
    __tablename__ = "report_tags"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    report_id = Column(UUID(as_uuid=True), nullable=False)
    tag = Column(String(100), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


def _report_fk() -> Column:
    return Column(
        UUID(as_uuid=True),
        ForeignKey("reports.id", ondelete="CASCADE"),
        primary_key=True,
    )


class ReportSourceRow(Base):
    """One cited primary source in the report's reader-visible ledger."""

    __tablename__ = "report_sources"

    report_id = _report_fk()
    source_id = Column(String(20), primary_key=True)
    position = Column(Integer, nullable=False)
    url = Column(Text, nullable=False)
    domain = Column(String(255))
    title = Column(Text)
    access_date = Column(Text)
    relevance_score = Column(Text)
    content_type = Column(Text)
    key_findings = Column(Text)
    snapshot_status = Column(String(20))
    snapshot_sha256 = Column(String(64))
    snapshot_captured_at = Column(Text)
    snapshot_final_url = Column(Text)
    page_age = Column(Text)
    purpose = Column(String(40))
    disposition = Column(String(30))
    rule_id = Column(String(80))
    reason = Column(Text)


class ReportClaimRow(Base):
    """One high-risk claim. ``ordinal`` is its position in the stored list."""

    __tablename__ = "report_claims"

    report_id = _report_fk()
    claim_id = Column(String(20), primary_key=True)
    position = Column(Integer, nullable=False)
    claim_class = Column(String(40), nullable=False)
    claim_field = Column(String(40), nullable=False)
    ordinal = Column(Integer, nullable=False)
    value = Column(Text, nullable=False)
    evidence_role = Column(String(30))


class ReportClaimSupportRow(Base):
    """One verbatim support excerpt for one claim."""

    __tablename__ = "report_claim_support"

    report_id = _report_fk()
    claim_id = Column(String(20), primary_key=True)
    position = Column(Integer, primary_key=True)
    source_id = Column(String(20), nullable=False)
    excerpt = Column(Text, nullable=False)
    verified = Column(Boolean)
    anchor_ok = Column(Boolean)
    snapshot_sha256 = Column(String(64))


class ReportIndicatorObservationRow(Base):
    """One deterministic infrastructure decision from the evidence assessment."""

    __tablename__ = "report_indicator_observations"

    report_id = _report_fk()
    position = Column(Integer, primary_key=True)
    claim_id = Column(String(20))
    field = Column(Text, nullable=False)
    ordinal = Column(Integer)
    value = Column(Text, nullable=False)
    disposition = Column(String(30), nullable=False)
    rule_id = Column(String(80))
    reason = Column(Text)


class ReportSourceObservationRow(Base):
    """One researched source's purpose decision, including named exclusions."""

    __tablename__ = "report_source_observations"

    report_id = _report_fk()
    position = Column(Integer, primary_key=True)
    source_id = Column(String(20))
    title = Column(Text)
    url = Column(Text)
    domain = Column(String(255))
    purpose = Column(String(40))
    disposition = Column(String(30))
    rule_id = Column(String(80))
    reason = Column(Text)
    snapshot_status = Column(String(20))
    snapshot_sha256 = Column(String(64))
    page_age = Column(Text)


class ReportFindingRow(Base):
    """One blocking gate finding; ``kind`` is ``safety`` or ``coverage``."""

    __tablename__ = "report_findings"

    report_id = _report_fk()
    position = Column(Integer, primary_key=True)
    kind = Column(String(20), nullable=False)
    rule_id = Column(String(80))
    selector = Column(Text)
    message = Column(Text, nullable=False)


class ReportArtifact(Base):
    """The current published object of one kind and its content-policy decision."""

    __tablename__ = "report_artifacts"
    __table_args__ = (Index("ix_report_artifacts_policy", "kind", "policy_status"),)

    report_id = _report_fk()
    kind = Column(String(20), primary_key=True)
    sha256 = Column(String(64))
    s3_key = Column(String(500), nullable=False)
    policy_status = Column(String(20), nullable=False)
    policy_version = Column(Integer, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
