"""SentrySearch FastAPI application."""

from contextlib import asynccontextmanager
import logging
import time
import uuid
from fastapi import FastAPI, HTTPException, Query, Depends, Header, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta, timezone
import uvicorn
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from src.storage.report_service import report_service
from src.storage.database import db_manager
from src.core.threat_profile_generator import ThreatProfileGenerator
from src.core.markdown_generator import generate_markdown
from src.auth.supabase_auth import AuthenticatedUser, verify_jwt_token
from src.api.contracts import (
    PaginationParams,
    ReportCreate,
    ReportDetail,
    ReportResponse,
    ReportSortKey,
    SearchFilters,
    SortDirection,
)
from src.domain.reports import ReportAnalyticsRecord, ReportStatus

logger = logging.getLogger(__name__)


def apply_schema_migrations() -> None:
    """Self-heal the database schema on boot (additive, idempotent migrations)."""
    try:
        db_manager.migrate_schema()
    except Exception as e:  # pragma: no cover - startup best-effort
        logger.exception("Schema migration on startup failed: %s", e)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    apply_schema_migrations()
    yield


# Initialize FastAPI app
app = FastAPI(
    title="SentrySearch API",
    description="Threat Intelligence Platform API",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan,
)

# CORS middleware for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:3003",
        "https://sentry-search.vercel.app",
    ],
    allow_origin_regex=r"https://[a-zA-Z0-9-]+\.vercel\.app",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Helper functions
def get_pagination_params(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    sort_by: ReportSortKey = Query("created_at"),
    sort_order: SortDirection = Query("desc"),
) -> PaginationParams:
    return PaginationParams(page=page, limit=limit, sort_by=sort_by, sort_order=sort_order)


def internal_server_error(message: str, exc: Exception) -> HTTPException:
    """Log internal errors while returning a stable client-safe message."""
    logger.exception("%s: %s", message, exc)
    return HTTPException(status_code=500, detail=message)


def get_report_user_id(user: AuthenticatedUser) -> str | None:
    """Return the user constraint for report reads, or none for admins."""
    if user.metadata.get("role") == "admin":
        return None
    return user.id


def get_quality_score(report: Dict[str, Any]) -> float:
    return report.get("quality_score") or 0.0


def get_report_label(report: Dict[str, Any], field: str) -> str:
    return report.get(field) or "unknown"


def get_report_status(report: Dict[str, Any]) -> ReportStatus:
    return ReportStatus(report.get("status") or ReportStatus.COMPLETED.value)


def build_analytics_trends(
    records: List[ReportAnalyticsRecord], *, start_date: datetime, days: int
) -> Dict[str, List[Dict[str, Any]]]:
    """Derive stable analytics series from persisted report observations."""

    dates = [(start_date + timedelta(days=offset)).date() for offset in range(days + 1)]
    daily_counts = {date: 0 for date in dates}
    processing_by_date: Dict[Any, List[int]] = {date: [] for date in dates}
    threat_counts: Dict[str, int] = {}
    quality_buckets = {
        "4.0-5.0": 0,
        "3.0-3.9": 0,
        "2.0-2.9": 0,
        "1.0-1.9": 0,
        "0.0-0.9": 0,
    }

    for record in records:
        report_date = record.created_at.date()
        if report_date in daily_counts:
            daily_counts[report_date] += 1
            if record.processing_time_ms is not None:
                processing_by_date[report_date].append(record.processing_time_ms)
        if record.threat_type:
            threat_counts[record.threat_type] = threat_counts.get(record.threat_type, 0) + 1
        if record.quality_score is not None:
            score = record.quality_score
            if score >= 4:
                quality_buckets["4.0-5.0"] += 1
            elif score >= 3:
                quality_buckets["3.0-3.9"] += 1
            elif score >= 2:
                quality_buckets["2.0-2.9"] += 1
            elif score >= 1:
                quality_buckets["1.0-1.9"] += 1
            else:
                quality_buckets["0.0-0.9"] += 1

    threat_total = sum(threat_counts.values())
    quality_total = sum(quality_buckets.values())
    return {
        "daily_reports": [
            {"date": date.isoformat(), "count": daily_counts[date]} for date in dates
        ],
        "threat_type_distribution": [
            {
                "threat_type": threat_type,
                "count": count,
                "percentage": (count / threat_total * 100) if threat_total else 0.0,
            }
            for threat_type, count in sorted(
                threat_counts.items(), key=lambda item: (-item[1], item[0])
            )[:10]
        ],
        "quality_score_distribution": [
            {
                "range": label,
                "count": count,
                "percentage": (count / quality_total * 100) if quality_total else 0.0,
            }
            for label, count in quality_buckets.items()
        ],
        "processing_time_trends": [
            {
                "date": date.isoformat(),
                "avg_time_ms": (
                    sum(processing_by_date[date]) / len(processing_by_date[date])
                    if processing_by_date[date]
                    else 0.0
                ),
            }
            for date in dates
        ],
    }


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
            "timestamp": datetime.now(timezone.utc).isoformat(),
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

        user_id = get_report_user_id(user)

        # Get reports
        reports = report_service.list_reports(
            limit=pagination.limit,
            offset=offset,
            sort_by=pagination.sort_by,
            sort_order=pagination.sort_order,
            search_query=query,
            threat_type=threat_type,
            min_quality_score=min_quality,
            user_id=user_id,
        )

        # Get total count for pagination
        total_count = report_service.count_reports(
            search_query=query,
            threat_type=threat_type,
            min_quality_score=min_quality,
            user_id=user_id,
        )

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
                    status=get_report_status(report),
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
            "filters": {
                "query": query,
                "threat_type": threat_type,
                "min_quality": min_quality,
            },
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
        if get_report_user_id(user) and report.get("user_id") != user.id:
            raise HTTPException(status_code=404, detail="Report not found")

        return ReportDetail(
            id=report["id"],
            tool_name=report["tool_name"],
            category=get_report_label(report, "category"),
            threat_type=get_report_label(report, "threat_type"),
            quality_score=get_quality_score(report),
            created_at=report["created_at"],
            processing_time_ms=report.get("processing_time_ms") or 0,
            status=get_report_status(report),
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
        if get_report_user_id(user) and report.get("user_id") != user.id:
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
        if filters.min_quality_score is not None:
            search_params["min_quality_score"] = filters.min_quality_score
        if filters.tags:
            search_params["tags"] = filters.tags
        if filters.date_range_days:
            search_params["created_after"] = datetime.now(timezone.utc) - timedelta(
                days=filters.date_range_days
            )

        user_id = get_report_user_id(user)
        if user_id:
            search_params["user_id"] = user_id

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
                    status=get_report_status(report),
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
        user_id = get_report_user_id(user)

        # Get unique values for filtering
        threat_types = report_service.get_unique_threat_types(user_id=user_id)
        categories = report_service.get_unique_categories(user_id=user_id)
        tags = report_service.get_popular_tags(limit=50, user_id=user_id)

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
        now = datetime.now(timezone.utc)
        start_date = now - timedelta(days=days)
        yesterday = now - timedelta(days=1)
        week_ago = now - timedelta(days=7)
        user_id = get_report_user_id(user)

        # Overview metrics
        total_reports = report_service.count_reports(user_id=user_id)
        reports_24h = report_service.count_reports(created_after=yesterday, user_id=user_id)
        reports_7d = report_service.count_reports(created_after=week_ago, user_id=user_id)
        reports_period = report_service.count_reports(created_after=start_date, user_id=user_id)

        records = report_service.list_analytics_records(created_after=start_date, user_id=user_id)
        quality_scores = [
            record.quality_score for record in records if record.quality_score is not None
        ]
        processing_times = [
            record.processing_time_ms for record in records if record.processing_time_ms is not None
        ]
        avg_quality = sum(quality_scores) / len(quality_scores) if quality_scores else 0.0
        avg_processing_time = (
            sum(processing_times) / len(processing_times) if processing_times else 0.0
        )
        trends = build_analytics_trends(records, start_date=start_date, days=days)
        threat_distribution = trends["threat_type_distribution"]
        most_common_threat = (
            threat_distribution[0]["threat_type"] if threat_distribution else "unknown"
        )
        terminal_records = [
            record
            for record in records
            if record.status in (ReportStatus.COMPLETED, ReportStatus.FAILED)
        ]
        success_rate = (
            sum(record.status is ReportStatus.COMPLETED for record in terminal_records)
            / len(terminal_records)
            if terminal_records
            else 0.0
        )

        # Recent activity
        recent_reports = report_service.list_reports(
            limit=10, sort_by="created_at", sort_order="desc", user_id=user_id
        )
        recent_activity = []
        for report in recent_reports:
            recent_activity.append(
                {
                    "id": report["id"],
                    "tool_name": report["tool_name"],
                    "quality_score": report.get("quality_score", 0.0),
                    "processing_time_ms": report.get("processing_time_ms") or 0,
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
                "daily_reports": trends["daily_reports"],
                "threat_type_distribution": threat_distribution,
                "quality_score_distribution": trends["quality_score_distribution"],
                "processing_time_trends": trends["processing_time_trends"],
            },
            "recent_activity": recent_activity,
        }

    except Exception as e:
        raise internal_server_error("Failed to get analytics", e)


@app.get("/api/analytics/dashboard")
async def get_dashboard_analytics(user: AuthenticatedUser = Depends(verify_jwt_token)):
    """Get dashboard analytics data"""
    try:
        user_id = get_report_user_id(user)

        # Get basic metrics
        total_reports = report_service.count_reports(user_id=user_id)
        recent_reports = report_service.count_reports(
            created_after=datetime.now(timezone.utc) - timedelta(days=7), user_id=user_id
        )

        # Get threat type distribution
        threat_stats = report_service.get_threat_type_stats(user_id=user_id)

        # Get quality score distribution
        quality_stats = report_service.get_quality_score_distribution(user_id=user_id)

        # Get recent activity
        recent_activity = report_service.list_reports(
            limit=5, sort_by="created_at", sort_order="desc", user_id=user_id
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
    uvicorn.run("src.api.main:app", host="0.0.0.0", port=8000, reload=True)
