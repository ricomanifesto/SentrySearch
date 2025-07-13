"""
Database models for SentrySearch report storage using SQLAlchemy
"""
from sqlalchemy import Column, String, DateTime, Integer, Numeric, Text, Boolean, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.sql import func
from datetime import datetime
import uuid

Base = declarative_base()

class Report(Base):
    __tablename__ = "reports"
    
    # Primary identifiers
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tool_name = Column(String(255), nullable=False, index=True)
    category = Column(String(100), index=True)
    threat_type = Column(String(100), index=True)
    
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
    
    # Cloud storage references
    markdown_s3_key = Column(String(500))  # S3 object key for markdown content
    trace_s3_key = Column(String(500))     # S3 object key for trace data
    
    # User context
    api_key_hash = Column(String(64))  # Hashed API key for user association
    user_id = Column(String(100))      # Future: actual user system
    
    # Flags and metadata
    is_flagged = Column(Boolean, default=False)
    is_favorite = Column(Boolean, default=False)
    version = Column(String(20))
    
    # Search optimization
    search_tags = Column(JSONB)  # Array of searchable tags
    
    def to_dict(self):
        """Convert model to dictionary for API responses"""
        return {
            'id': str(self.id),
            'tool_name': self.tool_name,
            'category': self.category,
            'threat_type': self.threat_type,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'quality_score': float(self.quality_score) if self.quality_score else None,
            'confidence_score': float(self.confidence_score) if self.confidence_score else None,
            'processing_time_ms': self.processing_time_ms,
            'ml_techniques': self.ml_techniques,
            'is_flagged': self.is_flagged,
            'is_favorite': self.is_favorite
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