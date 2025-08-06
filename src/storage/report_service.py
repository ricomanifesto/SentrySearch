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
    
    def categorize_tool(self, tool_name: str, threat_data: Dict[str, Any] = None) -> tuple[str, str]:
        """
        Categorize a tool/threat into category and threat_type based on tool name and metadata.
        
        Args:
            tool_name: Name of the tool/threat to categorize
            threat_data: Optional threat intelligence data for more accurate categorization
            
        Returns:
            tuple: (category, threat_type) where:
                - category: 'malware', 'threat_group', 'legitimate_software', or 'unknown'
                - threat_type: more specific classification
        """
        if not tool_name:
            return ('unknown', 'unknown')
        
        tool_lower = tool_name.lower().strip()
        
        # Malware signatures (common malware families and indicators)
        malware_indicators = [
            'ransomware', 'trojan', 'backdoor', 'rat', 'rootkit', 'spyware', 'adware',
            'worm', 'virus', 'botnet', 'cryptominer', 'stealer', 'loader', 'dropper',
            'shadowpad', 'cobalt strike', 'meterpreter', 'empire', 'mimikatz', 'lazarus',
            'apt', 'carbanak', 'emotet', 'trickbot', 'ryuk', 'conti', 'lockbit',
            'stealc', 'bumblebee', 'redline', 'azorult', 'formbook', 'agent tesla',
            'nanocore', 'njrat', 'darkcomet', 'poison ivy', 'blackrat'
        ]
        
        # Legitimate software indicators
        legitimate_indicators = [
            'windows', 'microsoft', 'office', 'outlook', 'excel', 'word', 'powershell',
            'cmd', 'notepad', 'explorer', 'chrome', 'firefox', 'safari', 'adobe',
            'java', 'python', 'nodejs', 'git', 'docker', 'kubernetes', 'jenkins',
            'sharepoint', 'exchange', 'active directory', 'ldap', 'ssh', 'ftp', 'sftp',
            'vmware', 'virtualbox', 'hyper-v', 'citrix', 'remote desktop', 'vnc',
            'teamviewer', 'anydesk', 'logmein', 'webex', 'zoom', 'slack', 'teams',
            'sap', 'oracle', 'mysql', 'postgresql', 'mongodb', 'redis', 'elasticsearch',
            'apache', 'nginx', 'iis', 'tomcat', 'node', 'express', 'react', 'angular',
            'get-aduser', 'nltest', 'net user', 'whoami', 'ipconfig', 'netstat',
            'ping', 'tracert', 'nslookup', 'runas', 'tasklist', 'services'
        ]
        
        # Threat group indicators
        threat_group_indicators = [
            'lazarus', 'apt1', 'apt28', 'apt29', 'apt34', 'apt40', 'fancy bear',
            'cozy bear', 'carbanak', 'fin7', 'fin8', 'wizard spider', 'sandworm',
            'turla', 'equation group', 'darkhydrus', 'mustang panda', 'kimsuky'
        ]
        
        # Check for malware indicators
        for indicator in malware_indicators:
            if indicator in tool_lower:
                # Determine specific malware type
                if any(word in tool_lower for word in ['ransomware', 'ryuk', 'conti', 'lockbit']):
                    return ('malware', 'ransomware')
                elif any(word in tool_lower for word in ['rat', 'backdoor', 'remote access']):
                    return ('malware', 'remote_access_trojan')
                elif any(word in tool_lower for word in ['trojan', 'stealer', 'stealc', 'redline']):
                    return ('malware', 'trojan')
                elif any(word in tool_lower for word in ['apt', 'advanced persistent']):
                    return ('malware', 'apt_malware')
                elif any(word in tool_lower for word in ['botnet', 'bot']):
                    return ('malware', 'botnet')
                elif any(word in tool_lower for word in ['framework', 'cobalt', 'empire', 'meterpreter']):
                    return ('malware', 'post_exploitation_framework')
                else:
                    return ('malware', 'malware')
        
        # Check for threat group indicators
        for indicator in threat_group_indicators:
            if indicator in tool_lower:
                return ('threat_group', 'threat_actor')
        
        # Check for legitimate software indicators
        for indicator in legitimate_indicators:
            if indicator in tool_lower:
                # Determine specific legitimate software type
                if any(word in tool_lower for word in ['windows', 'cmd', 'powershell', 'net ', 'runas', 'nltest', 'get-aduser']):
                    return ('legitimate_software', 'system_administration')
                elif any(word in tool_lower for word in ['office', 'word', 'excel', 'outlook', 'sharepoint']):
                    return ('legitimate_software', 'productivity_software')
                elif any(word in tool_lower for word in ['chrome', 'firefox', 'safari', 'browser']):
                    return ('legitimate_software', 'web_browser')
                elif any(word in tool_lower for word in ['ssh', 'ftp', 'remote', 'vnc', 'teamviewer', 'anydesk']):
                    return ('legitimate_software', 'remote_access')
                elif any(word in tool_lower for word in ['vmware', 'docker', 'kubernetes', 'virtualization']):
                    return ('legitimate_software', 'virtualization')
                elif any(word in tool_lower for word in ['apache', 'nginx', 'iis', 'server']):
                    return ('legitimate_software', 'server_software')
                else:
                    return ('legitimate_software', 'legitimate_software')
        
        # If we have threat data, use it for better categorization
        if threat_data:
            core_metadata = threat_data.get('coreMetadata', {})
            category_from_data = core_metadata.get('category', '').lower()
            
            if category_from_data:
                category_mapping = {
                    'rat': ('malware', 'remote_access_trojan'),
                    'backdoor': ('malware', 'backdoor'), 
                    'trojan': ('malware', 'trojan'),
                    'ransomware': ('malware', 'ransomware'),
                    'botnet': ('malware', 'botnet'),
                    'apt': ('malware', 'apt_malware'),
                    'framework': ('malware', 'post_exploitation_framework'),
                    'tool': ('legitimate_software', 'security_tool'),
                    'software': ('legitimate_software', 'legitimate_software')
                }
                
                if category_from_data in category_mapping:
                    return category_mapping[category_from_data]
        
        # Default to unknown if no clear categorization
        return ('unknown', 'unknown')
    
    def update_existing_categorizations(self) -> int:
        """
        Update existing reports that have 'unknown' or empty category/threat_type.
        Returns number of reports updated.
        """
        updated_count = 0
        try:
            with self.db_manager.get_session() as session:
                # Find reports with unknown or empty categories
                reports_to_update = session.query(Report).filter(
                    or_(
                        Report.category.is_(None),
                        Report.category == '',
                        Report.category == 'unknown',
                        Report.threat_type.is_(None),
                        Report.threat_type == '',
                        Report.threat_type == 'unknown'
                    )
                ).all()
                
                # Debug: show current values
                for report in reports_to_update[:5]:
                    logger.info(f"Report to update: '{report.tool_name}' (current category: '{report.category}', threat_type: '{report.threat_type}')")
                
                logger.info(f"Found {len(reports_to_update)} reports to categorize")
                
                for report in reports_to_update:
                    # Get new categorization
                    category, threat_type = self.categorize_tool(report.tool_name)
                    
                    # Update if different from current values
                    if (report.category != category or report.threat_type != threat_type):
                        old_category = report.category
                        old_threat_type = report.threat_type
                        
                        report.category = category
                        report.threat_type = threat_type
                        updated_count += 1
                        
                        logger.info(f"Updated report '{report.tool_name}' (ID: {report.id}): "
                                  f"category '{old_category}' -> '{category}', "
                                  f"threat_type '{old_threat_type}' -> '{threat_type}'")
                
                session.commit()
                logger.info(f"Successfully updated {updated_count} report categorizations")
                return updated_count
                
        except Exception as e:
            logger.error(f"Error updating report categorizations: {e}")
            raise
    
    def store_report(self, report_data: Dict[str, Any], api_key: str = None, user_id: str = None) -> str:
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
            
            # Auto-categorize if category/threat_type are missing or 'unknown'
            tool_name = report_data.get('tool_name', '')
            current_category = report_data.get('category', '').strip()
            current_threat_type = report_data.get('threat_type', '').strip()
            
            if not current_category or current_category.lower() in ['', 'unknown']:
                category, threat_type = self.categorize_tool(tool_name, report_data.get('threat_data'))
                report_data['category'] = category
                report_data['threat_type'] = threat_type
                logger.info(f"Auto-categorized '{tool_name}' as category='{category}', threat_type='{threat_type}'")
            
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
                    user_id=user_id,
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
                    search_query: Optional[str] = None,
                    sort_by: str = "created_at",
                    sort_order: str = "desc",
                    user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List reports with filtering and pagination"""
        try:
            with self.db_manager.get_session() as session:
                query = session.query(Report)
                
                # Apply filters
                if user_id:
                    query = query.filter(Report.user_id == user_id)
                    
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
                
                # Dynamic sorting
                sort_column = getattr(Report, sort_by, Report.created_at)
                if sort_order.lower() == "asc":
                    query = query.order_by(sort_column)
                else:
                    query = query.order_by(desc(sort_column))
                
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
                from sqlalchemy import func
                
                total_reports = session.query(Report).count()
                
                # Count by category
                category_counts = session.query(
                    Report.category,
                    func.count(Report.id)
                ).group_by(Report.category).filter(
                    Report.category.isnot(None)
                ).all()
                
                # Average quality score
                avg_quality = session.query(
                    func.avg(Report.quality_score)
                ).filter(Report.quality_score.isnot(None)).scalar()
                
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
    
    def test_connection(self) -> bool:
        """Test database connection for health checks"""
        try:
            with self.db_manager.get_session() as session:
                from sqlalchemy import text
                session.execute(text("SELECT 1"))
                return True
        except Exception as e:
            logger.error(f"Database connection test failed: {e}")
            return False
    
    def count_reports(self, **filters) -> int:
        """Count total reports with optional filters"""
        try:
            with self.db_manager.get_session() as session:
                query = session.query(Report)
                
                # Apply same filters as list_reports
                if filters.get('user_id'):
                    query = query.filter(Report.user_id == filters['user_id'])
                if filters.get('category'):
                    query = query.filter(Report.category == filters['category'])
                if filters.get('threat_type'):
                    query = query.filter(Report.threat_type == filters['threat_type'])
                if filters.get('min_quality_score') is not None:
                    query = query.filter(Report.quality_score >= filters['min_quality_score'])
                if filters.get('search_query'):
                    search_filter = or_(
                        Report.tool_name.ilike(f'%{filters["search_query"]}%'),
                        Report.category.ilike(f'%{filters["search_query"]}%'),
                        Report.threat_type.ilike(f'%{filters["search_query"]}%')
                    )
                    query = query.filter(search_filter)
                if filters.get('created_after'):
                    query = query.filter(Report.created_at >= filters['created_after'])
                
                return query.count()
        except Exception as e:
            logger.error(f"Error counting reports: {e}")
            return 0
    
    def search_reports(self, **kwargs) -> List[Dict[str, Any]]:
        """Advanced search - currently uses same logic as list_reports"""
        return self.list_reports(**kwargs)
    
    def count_search_results(self, **filters) -> int:
        """Count search results - currently uses same logic as count_reports"""
        return self.count_reports(**filters)
    
    def get_unique_threat_types(self) -> List[str]:
        """Get list of unique threat types"""
        try:
            with self.db_manager.get_session() as session:
                results = session.query(Report.threat_type).distinct().filter(
                    Report.threat_type.isnot(None),
                    Report.threat_type != ''
                ).all()
                return [r[0] for r in results if r[0]]
        except Exception as e:
            logger.error(f"Error getting threat types: {e}")
            return []
    
    def get_unique_categories(self) -> List[str]:
        """Get list of unique categories"""
        try:
            with self.db_manager.get_session() as session:
                results = session.query(Report.category).distinct().filter(
                    Report.category.isnot(None),
                    Report.category != ''
                ).all()
                return [r[0] for r in results if r[0]]
        except Exception as e:
            logger.error(f"Error getting categories: {e}")
            return []
    
    def get_popular_tags(self, limit: int = 50) -> List[str]:
        """Get most popular tags"""
        try:
            with self.db_manager.get_session() as session:
                # For now, return unique values from search_tags arrays
                # In a production system, you'd want proper tag frequency counting
                results = session.query(Report.search_tags).filter(
                    Report.search_tags.isnot(None)
                ).all()
                
                all_tags = []
                for result in results:
                    if result[0]:  # search_tags is a list
                        all_tags.extend(result[0])
                
                # Count frequency and return most popular
                from collections import Counter
                tag_counts = Counter(all_tags)
                return [tag for tag, count in tag_counts.most_common(limit)]
                
        except Exception as e:
            logger.error(f"Error getting popular tags: {e}")
            return []
    
    def get_threat_type_stats(self) -> Dict[str, int]:
        """Get threat type distribution"""
        try:
            with self.db_manager.get_session() as session:
                from sqlalchemy import func
                results = session.query(
                    Report.threat_type,
                    func.count(Report.id)
                ).group_by(Report.threat_type).filter(
                    Report.threat_type.isnot(None),
                    Report.threat_type != ''
                ).all()
                
                return {threat_type: count for threat_type, count in results}
        except Exception as e:
            logger.error(f"Error getting threat type stats: {e}")
            return {}
    
    def get_quality_score_distribution(self) -> Dict[str, Any]:
        """Get quality score statistics and distribution"""
        try:
            with self.db_manager.get_session() as session:
                from sqlalchemy import func
                
                # Get average quality score
                avg_quality = session.query(func.avg(Report.quality_score)).filter(
                    Report.quality_score.isnot(None)
                ).scalar()
                
                # Get distribution buckets
                quality_scores = session.query(Report.quality_score).filter(
                    Report.quality_score.isnot(None)
                ).all()
                
                scores = [float(score[0]) for score in quality_scores if score[0] is not None]
                
                # Create distribution buckets
                buckets = {
                    "0.0-1.0": len([s for s in scores if 0.0 <= s < 1.0]),
                    "1.0-2.0": len([s for s in scores if 1.0 <= s < 2.0]),
                    "2.0-3.0": len([s for s in scores if 2.0 <= s < 3.0]),
                    "3.0-4.0": len([s for s in scores if 3.0 <= s < 4.0]),
                    "4.0-5.0": len([s for s in scores if 4.0 <= s <= 5.0])
                }
                
                return {
                    "average": float(avg_quality) if avg_quality else 0.0,
                    "distribution": buckets,
                    "total_scored": len(scores)
                }
                
        except Exception as e:
            logger.error(f"Error getting quality score distribution: {e}")
            return {"average": 0.0, "distribution": {}, "total_scored": 0}

# Global report storage service instance
report_service = ReportStorageService()