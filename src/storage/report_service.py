"""
Report storage service combining PostgreSQL and S3 for SentrySearch
"""
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
import hashlib
import json
from sqlalchemy.orm import Session
from sqlalchemy import desc, and_, or_

from .database import db_manager
from .models import Report, ReportSearch, ReportTag
from .s3_manager import s3_manager

logger = logging.getLogger(__name__)

class ReportStorageService:
    def __init__(self):
        self.db_manager = db_manager
        self.s3_manager = s3_manager
    
    def store_report(self, report_data: Dict[str, Any], api_key: str = None) -> str:
        """Store a complete report with metadata in PostgreSQL and content in S3"""
        try:
            # Generate API key hash for user association
            api_key_hash = None
            if api_key:
                api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            
            # Upload content to S3
            report_id = report_data.get('id') or report_data.get('report_id')
            if not report_id:
                raise ValueError("Report ID is required")
            
            # Upload markdown content to S3
            markdown_s3_key = None
            if 'markdown_content' in report_data:
                markdown_s3_key = self.s3_manager.upload_markdown_report(
                    report_id, 
                    report_data['markdown_content']
                )
            
            # Upload trace data to S3 if available
            trace_s3_key = None
            if 'trace_data' in report_data:
                trace_s3_key = self.s3_manager.upload_trace_data(
                    report_id,
                    report_data['trace_data']
                )
            
            # Create database record
            with self.db_manager.get_session() as session:
                report = Report(
                    id=report_id,
                    tool_name=report_data.get('tool_name', ''),
                    category=report_data.get('category', ''),
                    threat_type=report_data.get('threat_type', ''),
                    quality_score=report_data.get('quality_score'),
                    confidence_score=report_data.get('confidence_score'),
                    trust_score=report_data.get('trust_score'),
                    processing_time_ms=report_data.get('processing_time_ms'),
                    api_calls_count=report_data.get('api_calls_count'),
                    threat_data=report_data.get('threat_data'),
                    ml_techniques=report_data.get('ml_techniques'),
                    quality_assessment=report_data.get('quality_assessment'),
                    web_sources=report_data.get('web_sources'),
                    markdown_s3_key=markdown_s3_key,
                    trace_s3_key=trace_s3_key,
                    api_key_hash=api_key_hash,
                    is_flagged=report_data.get('is_flagged', False),
                    version=report_data.get('version', '1.0'),
                    search_tags=report_data.get('search_tags', [])
                )
                
                session.add(report)
                session.commit()
                
                logger.info(f"Report stored successfully: {report_id}")
                return str(report.id)
                
        except Exception as e:
            logger.error(f"Error storing report: {e}")
            raise
    
    def get_report(self, report_id: str, include_content: bool = False) -> Optional[Dict[str, Any]]:
        """Get report by ID with optional content loading"""
        try:
            with self.db_manager.get_session() as session:
                report = session.query(Report).filter(Report.id == report_id).first()
                
                if not report:
                    return None
                
                report_dict = report.to_dict()
                
                # Load content from S3 if requested
                if include_content:
                    if report.markdown_s3_key:
                        try:
                            report_dict['markdown_content'] = self.s3_manager.download_content(
                                report.markdown_s3_key
                            )
                        except Exception as e:
                            logger.warning(f"Could not load markdown content: {e}")
                    
                    if report.trace_s3_key:
                        try:
                            trace_content = self.s3_manager.download_content(report.trace_s3_key)
                            report_dict['trace_data'] = json.loads(trace_content)
                        except Exception as e:
                            logger.warning(f"Could not load trace data: {e}")
                
                return report_dict
                
        except Exception as e:
            logger.error(f"Error getting report: {e}")
            raise
    
    def list_reports(self, 
                    limit: int = 20, 
                    offset: int = 0,
                    category: Optional[str] = None,
                    threat_type: Optional[str] = None,
                    min_quality_score: Optional[float] = None,
                    search_query: Optional[str] = None) -> List[Dict[str, Any]]:
        """List reports with filtering and pagination"""
        try:
            with self.db_manager.get_session() as session:
                query = session.query(Report)
                
                # Apply filters
                if category:
                    query = query.filter(Report.category == category)
                
                if threat_type:
                    query = query.filter(Report.threat_type == threat_type)
                
                if min_quality_score is not None:
                    query = query.filter(Report.quality_score >= min_quality_score)
                
                if search_query:
                    # Simple text search across tool name and category
                    search_filter = or_(
                        Report.tool_name.ilike(f'%{search_query}%'),
                        Report.category.ilike(f'%{search_query}%'),
                        Report.threat_type.ilike(f'%{search_query}%')
                    )
                    query = query.filter(search_filter)
                
                # Order by creation date (newest first)
                query = query.order_by(desc(Report.created_at))
                
                # Apply pagination
                query = query.offset(offset).limit(limit)
                
                reports = query.all()
                
                return [report.to_dict() for report in reports]
                
        except Exception as e:
            logger.error(f"Error listing reports: {e}")
            raise
    
    def get_report_stats(self) -> Dict[str, Any]:
        """Get basic statistics about stored reports"""
        try:
            with self.db_manager.get_session() as session:
                total_reports = session.query(Report).count()
                
                # Count by category
                category_counts = session.query(
                    Report.category, 
                    session.query(Report).filter(Report.category == Report.category).count()
                ).group_by(Report.category).all()
                
                # Average quality score
                avg_quality = session.query(
                    session.query(Report.quality_score).filter(Report.quality_score.isnot(None))
                ).scalar()
                
                return {
                    'total_reports': total_reports,
                    'category_counts': dict(category_counts) if category_counts else {},
                    'average_quality_score': float(avg_quality) if avg_quality else None
                }
                
        except Exception as e:
            logger.error(f"Error getting report stats: {e}")
            raise
    
    def delete_report(self, report_id: str) -> bool:
        """Delete a report and its associated files"""
        try:
            with self.db_manager.get_session() as session:
                report = session.query(Report).filter(Report.id == report_id).first()
                
                if not report:
                    return False
                
                # Delete S3 files
                try:
                    self.s3_manager.delete_report_files(report_id)
                except Exception as e:
                    logger.warning(f"Could not delete S3 files: {e}")
                
                # Delete database record
                session.delete(report)
                session.commit()
                
                logger.info(f"Report deleted successfully: {report_id}")
                return True
                
        except Exception as e:
            logger.error(f"Error deleting report: {e}")
            raise
    
    def get_download_url(self, report_id: str, content_type: str = 'markdown') -> Optional[str]:
        """Get presigned URL for downloading report content"""
        try:
            with self.db_manager.get_session() as session:
                report = session.query(Report).filter(Report.id == report_id).first()
                
                if not report:
                    return None
                
                s3_key = None
                if content_type == 'markdown' and report.markdown_s3_key:
                    s3_key = report.markdown_s3_key
                elif content_type == 'trace' and report.trace_s3_key:
                    s3_key = report.trace_s3_key
                
                if s3_key:
                    return self.s3_manager.get_presigned_url(s3_key)
                
                return None
                
        except Exception as e:
            logger.error(f"Error getting download URL: {e}")
            raise

# Global report storage service instance
report_service = ReportStorageService()