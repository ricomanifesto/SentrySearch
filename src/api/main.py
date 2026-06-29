"""SentrySearch FastAPI application."""

import logging
import os
import sys
import time
import uuid
from fastapi import FastAPI, HTTPException, Query, Depends, Header, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import uvicorn
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from storage.report_service import report_service
from storage.database import db_manager
from core.threat_profile_generator import ThreatProfileGenerator
from core.markdown_generator import generate_markdown
from auth.supabase_auth import AuthenticatedUser, verify_jwt_token

logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="SentrySearch API",
    description="Threat Intelligence Platform API",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# CORS middleware for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:3003",
        "https://sentry-search.vercel.app",
        "https://sentry-search-2k3f26n3c-michael-ricos-projects.vercel.app",
        "https://sentry-search-git-main-michael-ricos-projects.vercel.app",
        "https://sentry-search-2ftm00kao-michael-ricos-projects.vercel.app",
        "https://*.vercel.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def apply_schema_migrations() -> None:
    """Self-heal the database schema on boot (additive, idempotent migrations)."""
    try:
        db_manager.migrate_schema()
    except Exception as e:  # pragma: no cover - startup best-effort
        logger.exception("Schema migration on startup failed: %s", e)


# Pydantic models for API
class ReportCreate(BaseModel):
    tool_name: str = Field(..., description="Target for threat intelligence analysis")
    enable_ml_guidance: bool = Field(default=True, description="Enable ML-powered guidance")
    analysis_type: str = Field(default="comprehensive", description="Analysis depth")


class ReportResponse(BaseModel):
    id: str
    tool_name: str
    category: str
    threat_type: str
    quality_score: float
    created_at: datetime
    processing_time_ms: int = 0
    status: str = "completed"
    content_preview: Optional[str] = None


class ReportDetail(ReportResponse):
    markdown_content: Optional[str] = None
    threat_data: Optional[Dict[str, Any]] = None
    search_tags: List[str] = []


class SearchFilters(BaseModel):
    query: Optional[str] = None
    threat_types: List[str] = []
    date_range_days: Optional[int] = None
    min_quality_score: Optional[float] = None
    tags: List[str] = []


class PaginationParams(BaseModel):
    page: int = Field(default=1, ge=1)
    limit: int = Field(default=20, ge=1, le=100)
    sort_by: str = Field(default="created_at")
    sort_order: str = Field(default="desc")


# Helper functions
def get_pagination_params(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    sort_by: str = Query("created_at"),
    sort_order: str = Query("desc"),
) -> PaginationParams:
    return PaginationParams(page=page, limit=limit, sort_by=sort_by, sort_order=sort_order)


def internal_server_error(message: str, exc: Exception) -> HTTPException:
    """Log internal errors while returning a stable client-safe message."""
    logger.exception("%s: %s", message, exc)
    return HTTPException(status_code=500, detail=message)


def get_report_scope(user: AuthenticatedUser) -> Dict[str, str]:
    """Return report filters needed to isolate non-admin users."""
    if user.metadata.get("role") == "admin":
        return {}
    return {"user_id": user.id}


def get_quality_score(report: Dict[str, Any]) -> float:
    return report.get("quality_score") or 0.0


def get_report_label(report: Dict[str, Any], field: str) -> str:
    return report.get(field) or "unknown"


# API Routes


@app.get("/")
async def root():
    """Health check endpoint"""
    return {"message": "SentrySearch API", "status": "operational", "version": "1.0.0"}


@app.get("/api/health")
async def health_check():
    """Detailed health check for monitoring"""
    try:
        # Test database connection
        db_status = report_service.test_connection()
        return {
            "status": "healthy" if db_status else "degraded",
            "database": "connected" if db_status else "disconnected",
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        logger.exception("Health check failed: %s", e)
        return JSONResponse(
            status_code=503,
            content={"status": "unhealthy", "error": "Health check failed"},
        )


@app.get("/api/ready")
async def readiness_check():
    """Readiness check for deployment promotion."""
    try:
        db_status = report_service.test_connection()
        if not db_status:
            return JSONResponse(
                status_code=503,
                content={"status": "unready", "database": "disconnected"},
            )
        return {"status": "ready", "database": "connected"}
    except Exception as e:
        logger.exception("Readiness check failed: %s", e)
        return JSONResponse(
            status_code=503,
            content={"status": "unready", "error": "Readiness check failed"},
        )


# Report Management Endpoints


@app.get("/api/reports", response_model=Dict[str, Any])
async def list_reports(
    pagination: PaginationParams = Depends(get_pagination_params),
    user: AuthenticatedUser = Depends(verify_jwt_token),
    query: Optional[str] = Query(None, description="Search query"),
    threat_type: Optional[str] = Query(None, description="Filter by threat type"),
    min_quality: Optional[float] = Query(None, ge=0, le=5, description="Minimum quality score"),
):
    """List reports with pagination and filtering"""
    try:
        # Calculate offset
        offset = (pagination.page - 1) * pagination.limit

        # Build filters
        filters = {}
        if query:
            filters["search_query"] = query
        if threat_type:
            filters["threat_type"] = threat_type
        if min_quality:
            filters["min_quality_score"] = min_quality

        # Add user filter unless user is admin
        filters.update(get_report_scope(user))

        # Get reports
        reports = report_service.list_reports(
            limit=pagination.limit,
            offset=offset,
            sort_by=pagination.sort_by,
            sort_order=pagination.sort_order,
            **filters,
        )

        # Get total count for pagination
        total_count = report_service.count_reports(**filters)

        # Convert to response models
        report_responses = []
        for report in reports:
            report_responses.append(
                ReportResponse(
                    id=report["id"],
                    tool_name=report["tool_name"],
                    category=get_report_label(report, "category"),
                    threat_type=get_report_label(report, "threat_type"),
                    quality_score=get_quality_score(report),
                    created_at=report["created_at"],
                    processing_time_ms=report.get("processing_time_ms") or 0,
                    status=report.get("status") or "completed",
                    content_preview=(
                        report.get("markdown_content", "")[:200] + "..."
                        if report.get("markdown_content")
                        else None
                    ),
                )
            )

        return {
            "reports": report_responses,
            "pagination": {
                "page": pagination.page,
                "limit": pagination.limit,
                "total": total_count,
                "pages": (total_count + pagination.limit - 1) // pagination.limit,
            },
            "filters": filters,
        }

    except Exception as e:
        raise internal_server_error("Failed to list reports", e)


@app.get("/api/reports/{report_id}", response_model=ReportDetail)
async def get_report(
    report_id: str,
    include_content: bool = Query(True),
    user: AuthenticatedUser = Depends(verify_jwt_token),
):
    """Get specific report by ID"""
    try:
        report = report_service.get_report(report_id, include_content=include_content)

        if not report:
            raise HTTPException(status_code=404, detail="Report not found")

        # Check if user owns this report unless user is admin
        if get_report_scope(user) and report.get("user_id") != user.id:
            raise HTTPException(status_code=404, detail="Report not found")

        return ReportDetail(
            id=report["id"],
            tool_name=report["tool_name"],
            category=get_report_label(report, "category"),
            threat_type=get_report_label(report, "threat_type"),
            quality_score=get_quality_score(report),
            created_at=report["created_at"],
            processing_time_ms=report.get("processing_time_ms") or 0,
            status=report.get("status") or "completed",
            markdown_content=report.get("markdown_content") if include_content else None,
            threat_data=report.get("threat_data"),
            search_tags=report.get("search_tags", []),
        )

    except HTTPException:
        raise
    except Exception as e:
        raise internal_server_error("Failed to get report", e)


def run_report_generation(
    report_id: str,
    tool_name: str,
    enable_ml_guidance: bool,
    user_id: str,
) -> None:
    """Run a long report generation off the request path and persist the result.

    Report generation takes several minutes — far longer than a single synchronous
    HTTP request can stay open behind the platform edge. This runs as a background
    task so the request returns immediately; the client polls the report until its
    status leaves "generating". Failures are recorded on the row, never surfaced to
    the caller, so a provider error can't leak details.
    """
    start = time.monotonic()
    try:
        generator = ThreatProfileGenerator()
        generator.enable_ml_guidance = enable_ml_guidance
        profile = generator.get_threat_intelligence(tool_name=tool_name)

        if not profile or "error" in profile:
            logger.error("Generation returned no usable result for report %s", report_id)
            report_service.mark_report_failed(report_id)
            return

        # get_threat_intelligence returns the raw profile; map it onto the storage
        # schema (narrative, structured extraction, quality, tags) the way the record
        # view expects, rather than persisting the bare profile.
        quality_data = profile.get("_quality_assessment") or {}
        elapsed_ms = profile.get("_processing_time_ms") or int((time.monotonic() - start) * 1000)
        category = profile.get("category") or ""
        report_data = {
            "id": report_id,
            "tool_name": tool_name,
            "category": category,
            "threat_type": profile.get("threatType") or "",
            "quality_score": quality_data.get("overall_score"),
            "processing_time_ms": elapsed_ms,
            "threat_data": profile,
            "quality_assessment": quality_data or None,
            "markdown_content": generate_markdown(profile),
            "trace_data": profile.get("_trace_data"),
            "search_tags": [tag for tag in [tool_name.lower(), category.lower()] if tag],
        }
        report_service.finalize_report(report_id, report_data, user_id=user_id)

    except Exception as e:  # pragma: no cover - exercised via mark_report_failed test
        logger.exception("Background generation failed for report %s: %s", report_id, e)
        try:
            report_service.mark_report_failed(report_id)
        except Exception as mark_error:
            logger.exception("Could not mark report %s failed: %s", report_id, mark_error)


@app.post("/api/reports", response_model=Dict[str, str])
async def create_report(
    report_request: ReportCreate,
    background_tasks: BackgroundTasks,
    user: AuthenticatedUser = Depends(verify_jwt_token),
):
    """Start a threat intelligence report and return immediately.

    Generation runs in the background; the response carries the new report id with
    status "generating" so the client can poll the report until it completes.
    """
    try:
        report_id = str(uuid.uuid4())
        report_service.create_pending_report(
            report_id=report_id,
            tool_name=report_request.tool_name,
            user_id=user.id,
        )
    except Exception as e:
        raise internal_server_error("Failed to start report generation", e)

    background_tasks.add_task(
        run_report_generation,
        report_id,
        report_request.tool_name,
        report_request.enable_ml_guidance,
        user.id,
    )

    return {
        "report_id": report_id,
        "status": "generating",
        "message": f"Generating report for {report_request.tool_name}",
    }


@app.delete("/api/reports/{report_id}")
async def delete_report(report_id: str, user: AuthenticatedUser = Depends(verify_jwt_token)):
    """Delete specific report"""
    try:
        # First check if report exists and user owns it
        report = report_service.get_report(report_id, include_content=False)

        if not report:
            raise HTTPException(status_code=404, detail="Report not found")

        # Check if user owns this report or is admin
        if get_report_scope(user) and report.get("user_id") != user.id:
            raise HTTPException(status_code=404, detail="Report not found")

        success = report_service.delete_report(report_id)

        if not success:
            raise HTTPException(status_code=404, detail="Report not found")

        return {"message": "Report deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        raise internal_server_error("Failed to delete report", e)


# Search Endpoints


@app.post("/api/search", response_model=Dict[str, Any])
async def search_reports(
    filters: SearchFilters,
    pagination: PaginationParams = Depends(get_pagination_params),
    user: AuthenticatedUser = Depends(verify_jwt_token),
):
    """Advanced search across reports"""
    try:
        # Build search parameters
        search_params = {}

        if filters.query:
            search_params["search_query"] = filters.query
        if filters.threat_types:
            search_params["threat_types"] = filters.threat_types
        if filters.min_quality_score:
            search_params["min_quality_score"] = filters.min_quality_score
        if filters.tags:
            search_params["tags"] = filters.tags
        if filters.date_range_days:
            search_params["created_after"] = datetime.utcnow() - timedelta(
                days=filters.date_range_days
            )

        search_params.update(get_report_scope(user))

        # Calculate offset
        offset = (pagination.page - 1) * pagination.limit

        # Perform search
        reports = report_service.search_reports(
            limit=pagination.limit,
            offset=offset,
            sort_by=pagination.sort_by,
            sort_order=pagination.sort_order,
            **search_params,
        )

        # Get count
        total_count = report_service.count_search_results(**search_params)

        # Convert to response models
        report_responses = []
        for report in reports:
            report_responses.append(
                ReportResponse(
                    id=report["id"],
                    tool_name=report["tool_name"],
                    category=get_report_label(report, "category"),
                    threat_type=get_report_label(report, "threat_type"),
                    quality_score=get_quality_score(report),
                    created_at=report["created_at"],
                    processing_time_ms=report.get("processing_time_ms") or 0,
                    status=report.get("status") or "completed",
                    content_preview=(
                        report.get("markdown_content", "")[:200] + "..."
                        if report.get("markdown_content")
                        else None
                    ),
                )
            )

        return {
            "reports": report_responses,
            "pagination": {
                "page": pagination.page,
                "limit": pagination.limit,
                "total": total_count,
                "pages": (total_count + pagination.limit - 1) // pagination.limit,
            },
            "search_params": search_params,
        }

    except Exception as e:
        raise internal_server_error("Search failed", e)


@app.get("/api/search/filters")
async def get_search_filters(user: AuthenticatedUser = Depends(verify_jwt_token)):
    """Get available filter options for search"""
    try:
        report_scope = get_report_scope(user)

        # Get unique values for filtering
        threat_types = report_service.get_unique_threat_types(**report_scope)
        categories = report_service.get_unique_categories(**report_scope)
        tags = report_service.get_popular_tags(limit=50, **report_scope)

        return {
            "threat_types": threat_types,
            "categories": categories,
            "tags": tags,
            "quality_range": {"min": 0.0, "max": 5.0},
            "date_range_options": [
                {"label": "Last 7 days", "days": 7},
                {"label": "Last 30 days", "days": 30},
                {"label": "Last 90 days", "days": 90},
                {"label": "Last year", "days": 365},
            ],
        }

    except Exception as e:
        raise internal_server_error("Failed to get filters", e)


# Admin Endpoints


@app.post("/api/admin/update-categorizations")
async def update_categorizations(user: AuthenticatedUser = Depends(verify_jwt_token)):
    """Admin endpoint to update report categorizations"""
    if user.metadata.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")

    try:
        updated_count = report_service.update_existing_categorizations()

        # Get updated stats
        threat_stats = report_service.get_threat_type_stats()

        return {
            "message": f"Successfully updated {updated_count} reports",
            "updated_count": updated_count,
            "new_distribution": threat_stats,
        }

    except Exception as e:
        raise internal_server_error("Failed to update categorizations", e)


# Analytics Endpoints


@app.get("/api/analytics")
async def get_analytics(
    time_range: str = "30d",
    user: AuthenticatedUser = Depends(verify_jwt_token),
):
    """Get comprehensive analytics data"""
    try:
        # Parse time range
        days_map = {"7d": 7, "30d": 30, "90d": 90}
        days = days_map.get(time_range, 30)

        # Date calculations
        now = datetime.utcnow()
        start_date = now - timedelta(days=days)
        yesterday = now - timedelta(days=1)
        week_ago = now - timedelta(days=7)
        report_scope = get_report_scope(user)

        # Overview metrics
        total_reports = report_service.count_reports(**report_scope)
        reports_24h = report_service.count_reports(created_after=yesterday, **report_scope)
        reports_7d = report_service.count_reports(created_after=week_ago, **report_scope)
        reports_period = report_service.count_reports(created_after=start_date, **report_scope)

        # Get average quality score and processing time
        quality_stats = report_service.get_quality_score_distribution(**report_scope)
        avg_quality = quality_stats.get("average", 0.0)

        # Get processing time stats (simulate for now)
        avg_processing_time = 45000  # 45 seconds average

        # Most common threat type
        threat_stats = report_service.get_threat_type_stats(**report_scope)
        most_common_threat = (
            max(threat_stats.items(), key=lambda x: x[1])[0] if threat_stats else "unknown"
        )

        # Success rate (simulate)
        success_rate = 0.95

        # Daily trends (simulate with basic data)
        daily_reports = []
        for i in range(min(days, 30)):  # Last 30 days max
            date = now - timedelta(days=i)
            count = max(0, int(reports_period / days) + (i % 3) - 1)  # Simulate variation
            daily_reports.append({"date": date.isoformat(), "count": count})
        daily_reports.reverse()

        # Threat type distribution
        threat_distribution = []
        total_for_percentage = sum(threat_stats.values()) if threat_stats else 1
        for threat_type, count in list(threat_stats.items())[:10]:  # Top 10
            percentage = (count / total_for_percentage) * 100
            threat_distribution.append(
                {"threat_type": threat_type, "count": count, "percentage": percentage}
            )

        # Quality score distribution
        quality_distribution = [
            {"range": "4.0-5.0", "count": int(total_reports * 0.3), "percentage": 30},
            {"range": "3.0-3.9", "count": int(total_reports * 0.4), "percentage": 40},
            {"range": "2.0-2.9", "count": int(total_reports * 0.2), "percentage": 20},
            {"range": "1.0-1.9", "count": int(total_reports * 0.1), "percentage": 10},
        ]

        # Processing time trends (simulate)
        processing_trends = []
        for i in range(min(days, 7)):  # Last 7 days
            date = now - timedelta(days=i)
            avg_time = avg_processing_time + (i * 1000)  # Simulate variation
            processing_trends.append({"date": date.isoformat(), "avg_time_ms": avg_time})
        processing_trends.reverse()

        # Recent activity
        recent_reports = report_service.list_reports(
            limit=10, sort_by="created_at", sort_order="desc", **report_scope
        )
        recent_activity = []
        for report in recent_reports:
            recent_activity.append(
                {
                    "id": report["id"],
                    "tool_name": report["tool_name"],
                    "quality_score": report.get("quality_score", 0.0),
                    "processing_time_ms": report.get("processing_time_ms", avg_processing_time),
                    "created_at": report["created_at"],
                    "threat_type": report.get("threat_type"),
                }
            )

        return {
            "overview": {
                "total_reports": total_reports,
                "reports_last_24h": reports_24h,
                "reports_last_7d": reports_7d,
                "reports_last_30d": reports_period,
                "avg_quality_score": avg_quality,
                "avg_processing_time_ms": avg_processing_time,
                "most_common_threat_type": most_common_threat,
                "success_rate": success_rate,
            },
            "trends": {
                "daily_reports": daily_reports,
                "threat_type_distribution": threat_distribution,
                "quality_score_distribution": quality_distribution,
                "processing_time_trends": processing_trends,
            },
            "recent_activity": recent_activity,
        }

    except Exception as e:
        raise internal_server_error("Failed to get analytics", e)


@app.get("/api/analytics/dashboard")
async def get_dashboard_analytics(user: AuthenticatedUser = Depends(verify_jwt_token)):
    """Get dashboard analytics data"""
    try:
        report_scope = get_report_scope(user)

        # Get basic metrics
        total_reports = report_service.count_reports(**report_scope)
        recent_reports = report_service.count_reports(
            created_after=datetime.utcnow() - timedelta(days=7), **report_scope
        )

        # Get threat type distribution
        threat_stats = report_service.get_threat_type_stats(**report_scope)

        # Get quality score distribution
        quality_stats = report_service.get_quality_score_distribution(**report_scope)

        # Get recent activity
        recent_activity = report_service.list_reports(
            limit=5, sort_by="created_at", sort_order="desc", **report_scope
        )

        return {
            "summary": {
                "total_reports": total_reports,
                "reports_this_week": recent_reports,
                "avg_quality_score": quality_stats.get("average", 0.0),
            },
            "threat_distribution": threat_stats,
            "quality_distribution": quality_stats.get("distribution", []),
            "recent_activity": [
                {
                    "id": r["id"],
                    "tool_name": r["tool_name"],
                    "created_at": r["created_at"],
                    "quality_score": r.get("quality_score", 0.0),
                }
                for r in recent_activity
            ],
        }

    except Exception as e:
        raise internal_server_error("Failed to get analytics", e)


# Development server
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
