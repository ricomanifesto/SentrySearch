"""
Database models for SentrySearch report storage using SQLAlchemy
"""

from sqlalchemy import Column, String, DateTime, Integer, Numeric, Text, Boolean, JSON
from sqlalchemy.orm import declarative_base
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
    generation_route = Column(JSONB)
    evaluation_route = Column(JSONB)
    evaluation_status = Column(String(20))
    evaluation_error_code = Column(String(50))
    evaluation_attempts = Column(Integer, default=0)
    evaluated_at = Column(DateTime(timezone=True))

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

    # Flags and metadata
    is_flagged = Column(Boolean, default=False)
    is_favorite = Column(Boolean, default=False)
    version = Column(String(20))

    # Search optimization
    search_tags = Column(JSONB)  # Array of searchable tags
    content_preview = Column(Text)

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
            "evaluation_route": self.evaluation_route,
            "evaluation_status": self.evaluation_status,
            "evaluation_error_code": self.evaluation_error_code,
            "evaluation_attempts": self.evaluation_attempts or 0,
            "evaluated_at": self.evaluated_at.isoformat() if self.evaluated_at else None,
            "quality_assessment": self.quality_assessment,
            "web_sources": self.web_sources or [],
            "threat_data": self.threat_data,
            "content_preview": _content_preview(self.content_preview, self.threat_data),
            "ml_techniques": self.ml_techniques,
            "user_id": self.user_id,
            "is_flagged": self.is_flagged,
            "is_favorite": self.is_favorite,
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
