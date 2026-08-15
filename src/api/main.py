"""SentrySearch FastAPI application."""

from contextlib import asynccontextmanager
import logging
import time
import uuid
from urllib.parse import urlsplit
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
from src.core.report_evaluator import evaluate_saved_report
from src.core.markdown_generator import generate_markdown
from src.core.generation_failures import (
    PersistenceFailureError,
    ProfileOutputError,
    build_generation_failure,
)
from src.core.source_ledger import (
    CLAIM_ATTRIBUTION_SCHEMA_VERSION,
    SourceLedgerError,
    canonicalize_profile_sources,
)
from src.auth.supabase_auth import AuthenticatedUser, verify_jwt_token
from src.api.contracts import (
    AnalystDispositionCreate,
    AnalystDispositionEvent,
    ClaimAttributionEntry,
    EvidenceAdmissibility,
    PaginationParams,
    ReportCreate,
    ReportDetail,
    ReportResponse,
    ReportSource,
    ReportSortKey,
    SearchFilters,
    SortDirection,
)
from src.domain.model_routes import generation_fallback_state
from src.domain.reports import (
    AnalystDisposition,
    ClaimAttributionStatus,
    ClassificationStatus,
    EvidenceAdmissibilityStatus,
    EvaluationStatus,
    GenerationErrorCode,
    GenerationProgress,
    GenerationRouteScope,
    GenerationStage,
    ReportAnalyticsRecord,
    ReportStatus,
    ReviewStatus,
    coerce_evaluation_status,
    derive_generation_route_scope,
    derive_review_status,
    is_handoff_eligible,
    is_judgment_eligible,
    is_reuse_eligible,
)

logger = logging.getLogger(__name__)


def apply_schema_migrations() -> None:
    """Self-heal the database schema on boot (additive, idempotent migrations)."""
    try:
        db_manager.migrate_schema()
        report_service.reconcile_reader_state()
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


def get_quality_score(report: Dict[str, Any]) -> float | None:
    score = report.get("quality_score")
    return float(score) if score is not None else None


def get_report_label(report: Dict[str, Any], field: str) -> str:
    return report.get(field) or "unknown"


def get_report_status(report: Dict[str, Any]) -> ReportStatus:
    return ReportStatus(report.get("status") or ReportStatus.COMPLETED.value)


def get_generation_stage(report: Dict[str, Any]) -> GenerationStage:
    raw_stage = report.get("generation_stage")
    if raw_stage:
        try:
            return GenerationStage(raw_stage)
        except ValueError:
            logger.warning("Unknown stored generation stage: %s", raw_stage)
    status = get_report_status(report)
    return (
        GenerationStage.QUEUED
        if status is ReportStatus.GENERATING
        else GenerationStage(status.value)
    )


def get_evaluation_status(report: Dict[str, Any]) -> EvaluationStatus:
    return coerce_evaluation_status(
        report.get("evaluation_status"),
        quality_score=get_quality_score(report),
    )


def get_quality_assessment(report: Dict[str, Any]) -> Dict[str, Any] | None:
    assessment = report.get("quality_assessment")
    if isinstance(assessment, dict):
        return assessment
    threat_data = report.get("threat_data")
    if isinstance(threat_data, dict) and isinstance(threat_data.get("_quality_assessment"), dict):
        return threat_data["_quality_assessment"]
    return None


def get_evidence_admissibility(report: Dict[str, Any]) -> Dict[str, Any] | None:
    """Return only an explicitly persisted or profile-owned safety assessment."""

    assessment = report.get("evidence_admissibility")
    if isinstance(assessment, dict):
        return assessment
    threat_data = report.get("threat_data")
    if isinstance(threat_data, dict) and isinstance(threat_data.get("evidenceAdmissibility"), dict):
        return threat_data["evidenceAdmissibility"]
    return None


def get_validated_evidence_admissibility(
    report: Dict[str, Any],
) -> EvidenceAdmissibility | None:
    """Validate the persisted safety record before publishing it on the API."""

    assessment = get_evidence_admissibility(report)
    return EvidenceAdmissibility.model_validate(assessment) if assessment is not None else None


def reader_safe_threat_data(report: Dict[str, Any]) -> Dict[str, Any] | None:
    """Expose analyst fields without internal trace or duplicate source-analysis metadata."""

    threat_data = report.get("threat_data")
    if not isinstance(threat_data, dict):
        return None
    return {
        key: value
        for key, value in threat_data.items()
        if not key.startswith("_") and key != "comprehensiveWebSearchSources"
    }


def report_response_fields(report: Dict[str, Any]) -> Dict[str, Any]:
    """Project one stored row through the same lifecycle contract on every surface."""

    quality_score = get_quality_score(report)
    sources = get_report_sources(report)
    evaluation_status = get_evaluation_status(report)
    assessment = get_quality_assessment(report)
    report_status = get_report_status(report)
    evidence_admissibility = get_evidence_admissibility(report)
    try:
        evidence_status = EvidenceAdmissibilityStatus(
            report.get("evidence_admissibility_status")
            or (
                evidence_admissibility.get("status") if evidence_admissibility is not None else None
            )
            or EvidenceAdmissibilityStatus.UNASSESSED.value
        )
    except ValueError:
        evidence_status = EvidenceAdmissibilityStatus.BLOCKED
    attribution_version = str(report.get("claim_attribution_version") or "").strip() or None
    if (
        evidence_status is EvidenceAdmissibilityStatus.PASSED
        and attribution_version != CLAIM_ATTRIBUTION_SCHEMA_VERSION
    ):
        evidence_status = EvidenceAdmissibilityStatus.UNASSESSED
    analyst_disposition = AnalystDisposition(
        report.get("analyst_disposition") or AnalystDisposition.UNREVIEWED.value
    )
    return {
        "id": report["id"],
        "tool_name": report["tool_name"],
        "category": get_report_label(report, "category"),
        "threat_type": get_report_label(report, "threat_type"),
        "classification_status": ClassificationStatus(
            report.get("classification_status") or ClassificationStatus.UNRECORDED.value
        ),
        "claim_attribution_status": ClaimAttributionStatus(
            report.get("claim_attribution_status") or ClaimAttributionStatus.LEGACY.value
        ),
        "claim_attribution_version": attribution_version,
        "evidence_admissibility_status": evidence_status,
        "evidence_admissibility_version": report.get("evidence_admissibility_version")
        or (
            evidence_admissibility.get("schemaVersion")
            if evidence_admissibility is not None
            else None
        ),
        "quality_score": quality_score,
        "created_at": report["created_at"],
        "processing_time_ms": report.get("processing_time_ms") or 0,
        "status": report_status,
        "generation_stage": get_generation_stage(report),
        "generation_failure_stage": report.get("generation_failure_stage"),
        "generation_error_code": report.get("generation_error_code"),
        "generation_retryable": report.get("generation_retryable"),
        "generation_failure": report.get("generation_failure"),
        "evaluation_status": evaluation_status,
        "evaluation_error_code": report.get("evaluation_error_code"),
        "evaluation_attempts": report.get("evaluation_attempts") or 0,
        "evaluated_at": report.get("evaluated_at"),
        "review_status": derive_review_status(
            report_status=get_report_status(report),
            evaluation_status=evaluation_status,
            quality_score=quality_score,
            quality_assessment=assessment,
            source_count=len(sources),
            evidence_admissibility_status=evidence_status,
        ),
        "analyst_disposition": analyst_disposition,
        "eligible_for_judgment": is_judgment_eligible(
            report_status=report_status,
            evaluation_status=evaluation_status,
            quality_score=quality_score,
        ),
        "eligible_for_acceptance": is_reuse_eligible(
            report_status=report_status,
            evaluation_status=evaluation_status,
            quality_score=quality_score,
            evidence_admissibility_status=evidence_status,
        ),
        "eligible_for_handoff": is_handoff_eligible(
            report_status=report_status,
            evaluation_status=evaluation_status,
            quality_score=quality_score,
            evidence_admissibility_status=evidence_status,
            analyst_disposition=analyst_disposition,
        ),
        "content_preview": report.get("content_preview"),
    }


def get_report_sources(report: Dict[str, Any]) -> List[ReportSource]:
    """Return a stable source-evidence contract, including for older report rows."""

    raw_sources = report.get("web_sources")
    if not isinstance(raw_sources, list) or not raw_sources:
        threat_data = report.get("threat_data")
        if isinstance(threat_data, dict):
            web_search_sources = threat_data.get("webSearchSources")
            if isinstance(web_search_sources, dict):
                raw_sources = web_search_sources.get("primarySources")

    if not isinstance(raw_sources, list):
        return []

    normalized: List[ReportSource] = []
    for source in raw_sources:
        if not isinstance(source, dict):
            continue
        url = str(source.get("url") or "").strip()
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            continue
        normalized.append(
            ReportSource(
                source_id=(
                    str(source.get("source_id") or source.get("sourceId") or "").strip() or None
                ),
                title=str(source.get("title") or parsed.netloc),
                url=url,
                domain=str(source.get("domain") or parsed.netloc),
                access_date=str(source.get("access_date") or source.get("accessDate") or "Unknown"),
                relevance_score=str(
                    source.get("relevance_score") or source.get("relevanceScore") or "Unknown"
                ),
                content_type=str(
                    source.get("content_type") or source.get("contentType") or "Unknown"
                ),
                key_findings=str(
                    source.get("key_findings")
                    or source.get("keyFindings")
                    or "No findings recorded"
                ),
                evidence_purpose=(source.get("evidence_purpose") or source.get("evidencePurpose")),
                evidence_disposition=(
                    source.get("evidence_disposition") or source.get("evidenceDisposition")
                ),
                evidence_reason=(source.get("evidence_reason") or source.get("evidenceReason")),
                evidence_rule_id=(source.get("evidence_rule_id") or source.get("evidenceRuleId")),
                evidence_snapshot_status=(
                    source.get("evidence_snapshot_status") or source.get("evidenceSnapshotStatus")
                ),
                evidence_snapshot_sha256=(
                    source.get("evidence_snapshot_sha256") or source.get("evidenceSnapshotSha256")
                ),
                evidence_snapshot_captured_at=(
                    source.get("evidence_snapshot_captured_at")
                    or source.get("evidenceSnapshotCapturedAt")
                ),
                evidence_snapshot_final_url=(
                    source.get("evidence_snapshot_final_url")
                    or source.get("evidenceSnapshotFinalUrl")
                ),
                evidence_page_age=(
                    source.get("evidence_page_age") or source.get("evidencePageAge")
                ),
            )
        )
    return normalized


def get_claim_attributions(report: Dict[str, Any]) -> List[ClaimAttributionEntry]:
    """Return only explicit versioned claim links; never infer them for legacy records."""

    if report.get("claim_attribution_status") != ClaimAttributionStatus.ATTRIBUTED.value:
        return []
    threat_data = report.get("threat_data")
    attribution = threat_data.get("claimAttribution") if isinstance(threat_data, dict) else None
    raw_claims = attribution.get("claims") if isinstance(attribution, dict) else None
    if not isinstance(raw_claims, list):
        return []
    normalized: List[ClaimAttributionEntry] = []
    for claim in raw_claims:
        if not isinstance(claim, dict):
            continue
        normalized.append(
            ClaimAttributionEntry(
                claim_class=claim.get("claimClass"),
                claim=str(claim.get("claim") or ""),
                evidence_role=claim.get("evidenceRole"),
                source_ids=[str(source_id) for source_id in claim.get("sourceIds") or []],
                supporting_evidence=[
                    {
                        "source_id": str(support.get("sourceId") or ""),
                        "excerpt": str(support.get("excerpt") or ""),
                        "snapshot_sha256": str(support.get("snapshotSha256") or ""),
                    }
                    for support in claim.get("supportingEvidence") or []
                    if isinstance(support, dict)
                ],
            )
        )
    return normalized


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


def build_route_performance(records: List[ReportAnalyticsRecord]) -> List[Dict[str, Any]]:
    """Compare reader-visible quality and latency by recorded generation route."""

    grouped: Dict[str, List[ReportAnalyticsRecord]] = {
        "primary": [],
        "fallback": [],
        "legacy_aggregate": [],
        "unrecorded": [],
    }
    for record in records:
        if record.status is not ReportStatus.COMPLETED:
            continue
        if record.generation_route_scope is GenerationRouteScope.LEGACY_AGGREGATE:
            route = "legacy_aggregate"
        elif record.generation_route_scope is GenerationRouteScope.SYNTHESIS:
            route = (
                "fallback"
                if record.generation_used_fallback is True
                else "primary" if record.generation_used_fallback is False else "unrecorded"
            )
        else:
            route = "unrecorded"
        grouped[route].append(record)

    results = []
    for route, route_records in grouped.items():
        quality_scores = [
            record.quality_score for record in route_records if record.quality_score is not None
        ]
        processing_times = [
            record.processing_time_ms
            for record in route_records
            if record.processing_time_ms is not None
        ]
        results.append(
            {
                "route": route,
                "report_count": len(route_records),
                "scored_report_count": len(quality_scores),
                "runtime_recorded_count": len(processing_times),
                "avg_quality_score": (
                    sum(quality_scores) / len(quality_scores) if quality_scores else None
                ),
                "avg_processing_time_ms": (
                    sum(processing_times) / len(processing_times) if processing_times else None
                ),
            }
        )
    return results


def build_generation_failure_breakdown(
    records: List[ReportAnalyticsRecord],
) -> List[Dict[str, Any]]:
    """Expose falsifiable failure clusters by cause, stage, route, and UTC hour."""

    grouped: Dict[str, List[ReportAnalyticsRecord]] = {}
    for record in records:
        if record.status is not ReportStatus.FAILED:
            continue
        code = (
            record.generation_error_code.value
            if record.generation_error_code is not None
            else GenerationErrorCode.UNKNOWN.value
        )
        grouped.setdefault(code, []).append(record)

    breakdown: List[Dict[str, Any]] = []
    for code, failures in sorted(grouped.items(), key=lambda item: (-len(item[1]), item[0])):
        stages: Dict[str, int] = {}
        routes = {"primary": 0, "fallback": 0, "unrecorded": 0}
        utc_hours: Dict[str, int] = {}
        for failure in failures:
            stage = (
                failure.generation_failure_stage.value
                if failure.generation_failure_stage is not None
                else "unrecorded"
            )
            stages[stage] = stages.get(stage, 0) + 1
            route = (
                "fallback"
                if failure.generation_used_fallback is True
                else "primary" if failure.generation_used_fallback is False else "unrecorded"
            )
            routes[route] += 1
            hour = f"{failure.created_at.astimezone(timezone.utc).hour:02d}:00"
            utc_hours[hour] = utc_hours.get(hour, 0) + 1
        breakdown.append(
            {
                "error_code": code,
                "report_count": len(failures),
                "stages": stages,
                "routes": routes,
                "utc_hours": utc_hours,
            }
        )
    return breakdown


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
    status: Optional[List[ReportStatus]] = Query(None, description="Filter by generation state"),
    review_status: Optional[List[ReviewStatus]] = Query(
        None, description="Filter by reader-facing review state"
    ),
    analyst_disposition: Optional[List[AnalystDisposition]] = Query(
        None, description="Filter by the latest judgment for the current evaluation"
    ),
    requires_action: bool = Query(False, description="Return unresolved analyst work"),
    eligible_for_handoff: bool = Query(False, description="Return records safe to hand off"),
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
            statuses=status,
            review_statuses=review_status,
            analyst_dispositions=analyst_disposition,
            requires_action=requires_action,
            eligible_for_handoff=eligible_for_handoff,
            user_id=user_id,
        )

        # Get total count for pagination
        total_count = report_service.count_reports(
            search_query=query,
            threat_type=threat_type,
            min_quality_score=min_quality,
            statuses=status,
            review_statuses=review_status,
            analyst_dispositions=analyst_disposition,
            requires_action=requires_action,
            eligible_for_handoff=eligible_for_handoff,
            user_id=user_id,
        )

        # Convert to response models
        report_responses = [ReportResponse(**report_response_fields(report)) for report in reports]

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
                "status": status,
                "review_status": review_status,
                "analyst_disposition": analyst_disposition,
                "requires_action": requires_action,
                "eligible_for_handoff": eligible_for_handoff,
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
            **report_response_fields(report),
            markdown_content=report.get("markdown_content") if include_content else None,
            threat_data=reader_safe_threat_data(report),
            web_sources=get_report_sources(report),
            search_tags=report.get("search_tags", []),
            generation_route=report.get("generation_route"),
            research_route=report.get("research_route"),
            synthesis_route=report.get("synthesis_route"),
            evaluation_route=report.get("evaluation_route"),
            quality_assessment=get_quality_assessment(report),
            claim_attributions=get_claim_attributions(report),
            evidence_admissibility=get_validated_evidence_admissibility(report),
            current_disposition=report.get("current_disposition"),
            disposition_history=report.get("disposition_history", []),
        )

    except HTTPException:
        raise
    except Exception as e:
        raise internal_server_error("Failed to get report", e)


@app.post(
    "/api/reports/{report_id}/dispositions",
    response_model=AnalystDispositionEvent,
)
async def append_report_disposition(
    report_id: str,
    request: AnalystDispositionCreate,
    user: AuthenticatedUser = Depends(verify_jwt_token),
):
    """Append a judgment to the current evaluation vintage."""

    try:
        event = report_service.append_report_disposition(
            report_id,
            disposition=request.disposition,
            note=request.note,
            reviewer_user_id=user.id,
            owner_user_id=get_report_user_id(user),
        )
        if event is None:
            raise HTTPException(status_code=404, detail="Report not found")
        return AnalystDispositionEvent(**event)
    except ValueError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    except HTTPException:
        raise
    except Exception as e:
        raise internal_server_error("Failed to record analyst disposition", e)


@app.post("/api/reports/{report_id}/evaluation", response_model=Dict[str, str])
async def retry_report_evaluation(
    report_id: str,
    background_tasks: BackgroundTasks,
    user: AuthenticatedUser = Depends(verify_jwt_token),
):
    """Retry a failed or unrecorded evaluator without repeating report generation."""

    try:
        report = report_service.get_report(report_id, include_content=False)
        if report is None:
            raise HTTPException(status_code=404, detail="Report not found")
        if get_report_user_id(user) and report.get("user_id") != user.id:
            raise HTTPException(status_code=404, detail="Report not found")
        owner_id = str(report.get("user_id") or user.id)
        if not report_service.begin_report_evaluation(report_id, user_id=owner_id):
            raise HTTPException(
                status_code=409,
                detail="This report is not available for evaluation retry",
            )
        background_tasks.add_task(run_report_evaluation, report_id, owner_id)
        return {
            "report_id": report_id,
            "evaluation_status": EvaluationStatus.PENDING.value,
            "message": "Evaluation retry started",
        }
    except HTTPException:
        raise
    except Exception as e:
        raise internal_server_error("Failed to retry report evaluation", e)


def run_report_generation(
    report_id: str,
    tool_name: str,
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
    generator: ThreatProfileGenerator | None = None
    last_stage: GenerationStage | None = GenerationStage.QUEUED
    try:
        generator = ThreatProfileGenerator()
        # The evidence-backed report is the core artifact. Persist it before the
        # optional judge runs so evaluator latency or failure cannot hold the
        # narrative and source ledger hostage.
        generator.enable_quality_control = False
        stage_order = {
            GenerationStage.QUEUED: 0,
            GenerationStage.RESEARCHING: 1,
            GenerationStage.SYNTHESIZING: 2,
            GenerationStage.VALIDATING: 3,
            GenerationStage.FINALIZING: 4,
        }

        def persist_progress(update: GenerationProgress) -> None:
            nonlocal last_stage
            stage = update.stage
            stage_rank = stage_order.get(stage)
            previous_rank = stage_order.get(last_stage) if last_stage is not None else None
            if stage_rank is not None and (previous_rank is None or stage_rank > previous_rank):
                report_service.update_generation_stage(report_id, stage.value)
                last_stage = stage

        raw_profile = generator.get_threat_intelligence(
            tool_name=tool_name,
            progress_callback=persist_progress,
        )

        if not raw_profile or "error" in raw_profile:
            raise ProfileOutputError("Generation returned no usable result")

        profile, web_sources = canonicalize_profile_sources(raw_profile)

        # get_threat_intelligence returns the raw profile; map it onto the storage
        # schema (narrative, structured extraction, quality, tags) the way the record
        # view expects, rather than persisting the bare profile.
        quality_data: Dict[str, Any] = {}
        elapsed_ms = profile.get("_processing_time_ms") or int((time.monotonic() - start) * 1000)
        category, threat_type = report_service.categorize_tool(tool_name, profile)
        threat_data = {
            key: value
            for key, value in profile.items()
            if not key.startswith("_") and key != "comprehensiveWebSearchSources"
        }
        preview = str(threat_data.get("toolOverview", {}).get("description") or "").strip()
        preview = " ".join(preview.split())
        if len(preview) > 240:
            preview = f"{preview[:237].rstrip()}..."
        rendered_profile = dict(threat_data)
        rendered_profile["_quality_assessment"] = quality_data
        report_data = {
            "id": report_id,
            "tool_name": tool_name,
            "category": category,
            "threat_type": threat_type,
            "quality_score": quality_data.get("overall_score"),
            "processing_time_ms": elapsed_ms,
            "threat_data": threat_data,
            "quality_assessment": quality_data or None,
            "generation_route": profile.get("_generation_route"),
            "research_route": profile.get("_research_route"),
            "synthesis_route": profile.get("_synthesis_route"),
            "evaluation_route": None,
            "evaluation_status": EvaluationStatus.PENDING.value,
            "evaluation_error_code": None,
            "evaluation_attempts": 1,
            "evaluated_at": None,
            "web_sources": web_sources,
            "evidence_admissibility": profile.get("evidenceAdmissibility"),
            "markdown_content": generate_markdown(rendered_profile),
            "trace_data": profile.get("_trace_data"),
            "content_preview": preview or None,
            "search_tags": [tag for tag in [tool_name.lower(), category.lower()] if tag],
        }
        try:
            report_service.finalize_report(report_id, report_data, user_id=user_id)
        except SourceLedgerError:
            raise
        except Exception as error:
            raise PersistenceFailureError("Generated report could not be persisted") from error

        run_report_evaluation(report_id, user_id)

    except Exception as e:  # pragma: no cover - exercised via mark_report_failed test
        logger.exception("Background generation failed for report %s: %s", report_id, e)
        try:
            summarize_route = (
                getattr(generator, "route_provenance_for_stage", None)
                if generator is not None
                else None
            )
            route = summarize_route(last_stage) if callable(summarize_route) else None
            failure = build_generation_failure(e, stage=last_stage, route=route)
            report_service.mark_report_failed(
                report_id,
                error_code=GenerationErrorCode(failure["error_code"]),
                retryable=bool(failure["retryable"]),
                failure=failure,
            )
        except Exception as mark_error:
            logger.exception("Could not mark report %s failed: %s", report_id, mark_error)


def run_report_evaluation(report_id: str, user_id: str) -> None:
    """Retry only the quality judge for an existing synthesized report."""

    evaluation_route: Dict[str, Any] | None = None
    assessment: Dict[str, Any] | None = None
    try:
        report = report_service.get_report(report_id, include_content=False)
        if report is None or report.get("user_id") != user_id:
            return
        threat_data = report.get("threat_data")
        if not isinstance(threat_data, dict):
            report_service.fail_report_evaluation(
                report_id,
                error_code="missing_report_evidence",
            )
            return

        profile, web_sources = canonicalize_profile_sources(threat_data)
        result = evaluate_saved_report(profile)
        evaluation_route = result.evaluation_route
        assessment = result.quality_assessment
        if not result.succeeded:
            report_service.fail_report_evaluation(
                report_id,
                error_code="evaluator_unavailable",
                quality_assessment=assessment,
                evaluation_route=evaluation_route,
            )
            return

        persisted_profile = {
            key: value
            for key, value in result.profile.items()
            if not key.startswith("_") and key != "comprehensiveWebSearchSources"
        }
        persisted_profile, persisted_sources = canonicalize_profile_sources(persisted_profile)
        if [source.get("url") for source in persisted_sources] != [
            source.get("url") for source in web_sources
        ]:
            raise ValueError("Evaluator retry changed the source ledger")
        rendered_profile = dict(persisted_profile)
        rendered_profile["_quality_assessment"] = assessment
        report_service.complete_report_evaluation(
            report_id,
            quality_assessment=assessment,
            evaluation_route=evaluation_route,
            threat_data=persisted_profile,
            markdown_content=generate_markdown(rendered_profile),
        )
    except Exception as exc:
        logger.exception("Evaluator retry failed for report %s: %s", report_id, exc)
        report_service.fail_report_evaluation(
            report_id,
            error_code="evaluator_unavailable",
            quality_assessment=assessment,
            evaluation_route=evaluation_route,
        )


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
        if filters.statuses:
            search_params["statuses"] = filters.statuses
        if filters.review_statuses:
            search_params["review_statuses"] = filters.review_statuses
        if filters.analyst_dispositions:
            search_params["analyst_dispositions"] = filters.analyst_dispositions
        if filters.requires_action:
            search_params["requires_action"] = True
        if filters.eligible_for_handoff:
            search_params["eligible_for_handoff"] = True
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
        report_responses = [ReportResponse(**report_response_fields(report)) for report in reports]

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
        avg_quality = sum(quality_scores) / len(quality_scores) if quality_scores else None
        avg_processing_time = (
            sum(processing_times) / len(processing_times) if processing_times else None
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
        generation_completion_rate = (
            sum(record.status is ReportStatus.COMPLETED for record in terminal_records)
            / len(terminal_records)
            if terminal_records
            else None
        )
        review_states = [
            derive_review_status(
                report_status=record.status,
                evaluation_status=record.evaluation_status,
                quality_score=record.quality_score,
                quality_assessment=record.quality_assessment,
                source_count=record.source_count,
                evidence_admissibility_status=record.evidence_admissibility_status,
            )
            for record in records
        ]

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
                    "quality_score": report.get("quality_score"),
                    "processing_time_ms": report.get("processing_time_ms"),
                    "created_at": report["created_at"],
                    "threat_type": report.get("threat_type"),
                    "generation_used_fallback": generation_fallback_state(
                        report.get("synthesis_route") or report.get("generation_route")
                    ),
                    "generation_route_scope": derive_generation_route_scope(
                        synthesis_route=report.get("synthesis_route"),
                        generation_route=report.get("generation_route"),
                    ),
                    "evaluation_status": get_evaluation_status(report),
                    "review_status": report_response_fields(report)["review_status"],
                    "analyst_disposition": report_response_fields(report)["analyst_disposition"],
                    "eligible_for_judgment": report_response_fields(report)[
                        "eligible_for_judgment"
                    ],
                    "status": get_report_status(report),
                }
            )

        return {
            "overview": {
                "total_reports": total_reports,
                "reports_last_24h": reports_24h,
                "reports_last_7d": reports_7d,
                "reports_in_period": reports_period,
                "avg_quality_score": avg_quality,
                "avg_processing_time_ms": avg_processing_time,
                "most_common_threat_type": most_common_threat,
                "generation_completion_rate": generation_completion_rate,
                "terminal_reports": len(terminal_records),
                "scored_reports": len(quality_scores),
                "unscored_reports": len(records) - len(quality_scores),
                "evaluation_failed_reports": sum(
                    record.evaluation_status is EvaluationStatus.FAILED for record in records
                ),
                "generation_failed_reports": sum(
                    record.status is ReportStatus.FAILED for record in records
                ),
                "reviewable_reports": sum(
                    state is ReviewStatus.REVIEWABLE for state in review_states
                ),
                "needs_attention_reports": sum(
                    state in (ReviewStatus.NEEDS_ATTENTION, ReviewStatus.NEEDS_EVALUATION)
                    for state in review_states
                ),
                "unresolved_reports": report_service.count_reports(
                    created_after=start_date,
                    user_id=user_id,
                    requires_action=True,
                ),
                "accepted_reports": report_service.count_reports(
                    created_after=start_date,
                    user_id=user_id,
                    analyst_dispositions=[AnalystDisposition.ACCEPTED],
                ),
            },
            "trends": {
                "daily_reports": trends["daily_reports"],
                "threat_type_distribution": threat_distribution,
                "quality_score_distribution": trends["quality_score_distribution"],
                "processing_time_trends": trends["processing_time_trends"],
            },
            "route_performance": build_route_performance(records),
            "generation_failure_breakdown": build_generation_failure_breakdown(records),
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
        week_start = datetime.now(timezone.utc) - timedelta(days=7)
        runs_this_week = report_service.count_reports(created_after=week_start, user_id=user_id)
        completed_reports_this_week = report_service.count_reports(
            created_after=week_start,
            statuses=[ReportStatus.COMPLETED],
            user_id=user_id,
        )
        failed_reports_this_week = report_service.count_reports(
            created_after=week_start,
            statuses=[ReportStatus.FAILED],
            user_id=user_id,
        )

        # Get threat type distribution
        threat_stats = report_service.get_threat_type_stats(user_id=user_id)

        # Get quality score distribution
        quality_stats = report_service.get_quality_score_distribution(user_id=user_id)

        records = report_service.list_analytics_records(
            created_after=datetime(1970, 1, 1, tzinfo=timezone.utc),
            user_id=user_id,
        )
        scored_reports = sum(record.quality_score is not None for record in records)
        review_states = [
            derive_review_status(
                report_status=record.status,
                evaluation_status=record.evaluation_status,
                quality_score=record.quality_score,
                quality_assessment=record.quality_assessment,
                source_count=record.source_count,
                evidence_admissibility_status=record.evidence_admissibility_status,
            )
            for record in records
        ]

        # Get recent activity
        recent_activity = report_service.list_reports(
            limit=5, sort_by="created_at", sort_order="desc", user_id=user_id
        )

        return {
            "summary": {
                "total_reports": total_reports,
                "runs_this_week": runs_this_week,
                "completed_reports_this_week": completed_reports_this_week,
                "failed_reports_this_week": failed_reports_this_week,
                "avg_quality_score": quality_stats.get("average"),
                "scored_reports": scored_reports,
                "needs_attention_reports": sum(
                    state in (ReviewStatus.NEEDS_ATTENTION, ReviewStatus.NEEDS_EVALUATION)
                    for state in review_states
                ),
                "unresolved_reports": report_service.count_reports(
                    user_id=user_id,
                    requires_action=True,
                ),
            },
            "threat_distribution": threat_stats,
            "quality_distribution": quality_stats.get("distribution", []),
            "recent_activity": [
                {
                    "id": r["id"],
                    "tool_name": r["tool_name"],
                    "created_at": r["created_at"],
                    "quality_score": r.get("quality_score"),
                    "evaluation_status": get_evaluation_status(r),
                    "review_status": report_response_fields(r)["review_status"],
                    "analyst_disposition": report_response_fields(r)["analyst_disposition"],
                    "eligible_for_judgment": report_response_fields(r)["eligible_for_judgment"],
                    "status": get_report_status(r),
                }
                for r in recent_activity
            ],
        }

    except Exception as e:
        raise internal_server_error("Failed to get analytics", e)


# Development server
if __name__ == "__main__":
    uvicorn.run("src.api.main:app", host="0.0.0.0", port=8000, reload=True)
    GenerationErrorCode,
