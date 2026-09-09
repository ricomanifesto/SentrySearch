"""
Report storage service combining PostgreSQL and S3 for SentrySearch
"""

import logging
from typing import Dict, Any, List, Optional, Sequence, cast
from datetime import datetime, timedelta, timezone
import hashlib
import json
import uuid
from contextlib import nullcontext
from sqlalchemy import and_, asc, desc, func, or_, select
from sqlalchemy.orm import Session

from src.domain.execution import EVALUATION_LEASE_SECONDS, GenerationLease, GenerationLeaseLost

from src.domain.reports import (
    AnalystDisposition,
    ClaimAttributionStatus,
    ClassificationStatus,
    EvidenceAdmissibilityStatus,
    EvaluationStatus,
    GenerationErrorCode,
    GenerationStage,
    ReportAnalyticsRecord,
    ReportFilters,
    ReportSortField,
    ReportStatus,
    ReviewStatus,
    SortOrder,
    coerce_evaluation_status,
    derive_generation_route_scope,
    derive_review_status,
    evaluation_conflict_count,
    is_judgment_eligible,
    is_reuse_eligible,
)
from src.core.source_ledger import (
    CLAIM_ATTRIBUTION_SCHEMA_VERSION,
    assert_claim_attribution_consistent,
    assert_markdown_source_ledger_consistent,
    assert_source_ledger_consistent,
    claim_attribution_status,
)
from src.core.evidence_admissibility import assert_no_virtual_event_promotions
from src.core.report_content_policy import load_checked_report
from src.domain.model_routes import generation_fallback_state

from .database import db_manager
from .models import Report, ReportDispositionEvent, ReportRuntimeDispatch
from .s3_manager import s3_manager

logger = logging.getLogger(__name__)


class ReportStorageService:
    def __init__(self):
        self.db_manager = db_manager
        self.s3_manager = s3_manager

    @staticmethod
    def _evidence_admissibility_fields(
        threat_data: Any,
        explicit: Any = None,
    ) -> tuple[dict[str, Any] | None, EvidenceAdmissibilityStatus, str | None]:
        assessment = explicit
        if assessment is None and isinstance(threat_data, dict):
            assessment = threat_data.get("evidenceAdmissibility")
        if not isinstance(assessment, dict):
            return None, EvidenceAdmissibilityStatus.UNASSESSED, None
        try:
            status = EvidenceAdmissibilityStatus(assessment.get("status"))
        except (TypeError, ValueError):
            status = EvidenceAdmissibilityStatus.BLOCKED
        version = str(assessment.get("schemaVersion") or "").strip() or None
        attribution = threat_data.get("claimAttribution") if isinstance(threat_data, dict) else None
        attribution_version = (
            str(attribution.get("schemaVersion") or "").strip()
            if isinstance(attribution, dict)
            else None
        )
        if (
            status is EvidenceAdmissibilityStatus.PASSED
            and attribution_version != CLAIM_ATTRIBUTION_SCHEMA_VERSION
        ):
            status = EvidenceAdmissibilityStatus.UNASSESSED
        return assessment, status, version

    @staticmethod
    def _source_count_from_values(web_sources: Any, threat_data: Any) -> int:
        if isinstance(web_sources, list) and web_sources:
            return len(web_sources)
        if isinstance(threat_data, dict):
            source_block = threat_data.get("webSearchSources")
            if isinstance(source_block, dict) and isinstance(
                source_block.get("primarySources"), list
            ):
                return len(source_block["primarySources"])
        return 0

    @classmethod
    def _source_count(cls, report: Report) -> int:
        return cls._source_count_from_values(report.web_sources, report.threat_data)

    @classmethod
    def _refresh_review_status(cls, report: Report) -> ReviewStatus:
        model = cast(Any, report)
        status = derive_review_status(
            report_status=model.status or ReportStatus.COMPLETED.value,
            evaluation_status=model.evaluation_status,
            quality_score=(float(model.quality_score) if model.quality_score is not None else None),
            quality_assessment=model.quality_assessment,
            source_count=cls._source_count(report),
            evidence_admissibility_status=(
                model.evidence_admissibility_status or EvidenceAdmissibilityStatus.UNASSESSED.value
            ),
        )
        model.review_status = status.value
        return status

    @staticmethod
    def _latest_disposition_expression():
        """Return the latest judgment for the report's current evaluation attempt."""

        return (
            select(ReportDispositionEvent.disposition)
            .where(
                ReportDispositionEvent.report_id == Report.id,
                ReportDispositionEvent.evaluation_attempt
                == func.coalesce(Report.evaluation_attempts, 0),
            )
            .order_by(
                ReportDispositionEvent.created_at.desc(),
                ReportDispositionEvent.id.desc(),
            )
            .limit(1)
            .correlate(Report)
            .scalar_subquery()
        )

    @staticmethod
    def _attach_disposition_state(
        session: Any,
        reports: Sequence[Report],
        *,
        include_history: bool = False,
    ) -> list[Dict[str, Any]]:
        """Project append-only judgments without mutating the report row."""

        if not reports:
            return []
        query = session.query(ReportDispositionEvent)
        if include_history:
            query = query.filter(
                ReportDispositionEvent.report_id.in_([report.id for report in reports])
            )
        else:
            query = query.filter(
                or_(
                    *(
                        and_(
                            ReportDispositionEvent.report_id == report.id,
                            ReportDispositionEvent.evaluation_attempt
                            == int(cast(Any, report).evaluation_attempts or 0),
                        )
                        for report in reports
                    )
                )
            )
        events = query.order_by(
            ReportDispositionEvent.created_at.asc(),
            ReportDispositionEvent.id.asc(),
        ).all()
        by_report: dict[str, list[ReportDispositionEvent]] = {}
        for event in events:
            by_report.setdefault(str(event.report_id), []).append(event)

        projected: list[Dict[str, Any]] = []
        for report in reports:
            current_attempt = int(cast(Any, report).evaluation_attempts or 0)
            history = by_report.get(str(report.id), [])
            current_events = [
                event for event in history if event.evaluation_attempt == current_attempt
            ]
            current_event = current_events[-1] if current_events else None
            report_dict = report.to_dict()
            # Policy projection needs retained content even for metadata-only reads.
            report_dict["_markdown_s3_key"] = report.markdown_s3_key
            report_dict["analyst_disposition"] = (
                current_event.disposition
                if current_event is not None
                else AnalystDisposition.UNREVIEWED.value
            )
            report_dict["current_disposition"] = (
                current_event.to_dict(current_evaluation_attempt=current_attempt)
                if current_event is not None
                else None
            )
            report_dict["disposition_history"] = (
                [event.to_dict(current_evaluation_attempt=current_attempt) for event in history]
                if include_history
                else []
            )
            projected.append(report_dict)
        return projected

    @staticmethod
    def _structured_category_value(threat_data: Optional[Dict[str, Any]]) -> str | None:
        if not isinstance(threat_data, dict):
            return None
        core_metadata = threat_data.get("coreMetadata")
        if not isinstance(core_metadata, dict):
            return None
        value = core_metadata.get("category")
        return value.strip() if isinstance(value, str) and value.strip() else None

    @classmethod
    def _categorize_structured_threat_data(
        cls, threat_data: Optional[Dict[str, Any]]
    ) -> tuple[str, str] | None:
        raw_category = cls._structured_category_value(threat_data)
        if raw_category is None:
            return None
        category_from_data = raw_category.lower()
        category_patterns = (
            (("remote access", " rat"), ("malware", "remote_access_trojan")),
            (
                ("post-exploitation", "post exploitation", "framework"),
                ("malware", "post_exploitation_framework"),
            ),
            (("ransomware",), ("malware", "ransomware")),
            (("backdoor",), ("malware", "backdoor")),
            (("trojan",), ("malware", "trojan")),
            (("botnet",), ("malware", "botnet")),
            (("downloader", "loader"), ("malware", "loader")),
            (("apt",), ("malware", "apt_malware")),
            (("malware",), ("malware", "malware")),
            (("threat actor", "threat group"), ("threat_group", "threat_actor")),
            (("security tool",), ("legitimate_software", "security_tool")),
            (
                ("software", "technology", "platform"),
                ("legitimate_software", "legitimate_software"),
            ),
        )
        for markers, classification in category_patterns:
            if any(marker in f" {category_from_data}" for marker in markers):
                return classification
        return None

    def resolve_classification(
        self,
        *,
        tool_name: str,
        threat_data: Optional[Dict[str, Any]],
        stored_category: str | None = None,
        stored_threat_type: str | None = None,
        stored_status: str | None = None,
        legacy: bool = False,
    ) -> tuple[str, str, ClassificationStatus]:
        """Resolve classification while retaining why a value is known or unknown."""

        raw_category = self._structured_category_value(threat_data)
        structured = self._categorize_structured_threat_data(threat_data)
        current = (
            stored_category or "unknown",
            stored_threat_type or "unknown",
        )
        has_current = all(value not in {"", "unknown"} for value in current)
        if structured is not None:
            status = (
                ClassificationStatus.RECONCILED
                if stored_status == ClassificationStatus.RECONCILED.value
                or legacy
                and (not has_current or current != structured)
                else ClassificationStatus.RECORDED
            )
            return (*structured, status)
        if raw_category is not None:
            return (*current, ClassificationStatus.UNMAPPED)
        if has_current:
            return (*current, ClassificationStatus.UNRECORDED)
        inferred_category, inferred_threat_type = self.categorize_tool(tool_name)
        return (
            inferred_category,
            inferred_threat_type,
            ClassificationStatus.UNRECORDED,
        )

    @staticmethod
    def _report_sort_expression(sort_by: str, sort_order: str):
        try:
            sort_field = ReportSortField(sort_by)
        except ValueError:
            sort_field = ReportSortField.CREATED_AT
        try:
            direction = SortOrder(sort_order.lower())
        except ValueError:
            direction = SortOrder.DESCENDING

        sort_column = getattr(Report, sort_field.value)

        if direction is SortOrder.ASCENDING:
            return asc(sort_column).nulls_last()

        return desc(sort_column).nulls_last()

    @staticmethod
    def _report_filter_expressions(filters: ReportFilters) -> tuple:
        """Build the shared SQL predicates used by list and count queries."""

        expressions = []
        if filters.user_id:
            expressions.append(Report.user_id == filters.user_id)
        if filters.category:
            expressions.append(Report.category == filters.category)
        if filters.threat_type:
            expressions.append(Report.threat_type == filters.threat_type)
        if filters.threat_types:
            expressions.append(Report.threat_type.in_(filters.threat_types))
        if filters.min_quality_score is not None:
            expressions.append(Report.quality_score >= filters.min_quality_score)
        if filters.search_query:
            pattern = f"%{filters.search_query}%"
            expressions.append(
                or_(
                    Report.tool_name.ilike(pattern),
                    Report.category.ilike(pattern),
                    Report.threat_type.ilike(pattern),
                )
            )
        if filters.tags:
            expressions.append(Report.search_tags.contains(list(filters.tags)))
        if filters.statuses:
            expressions.append(Report.status.in_([status.value for status in filters.statuses]))
        if filters.review_statuses:
            expressions.append(
                Report.review_status.in_([status.value for status in filters.review_statuses])
            )
        latest_disposition = ReportStorageService._latest_disposition_expression()
        if filters.analyst_dispositions:
            requested = set(filters.analyst_dispositions)
            stored = [
                disposition.value
                for disposition in requested
                if disposition is not AnalystDisposition.UNREVIEWED
            ]
            includes_unreviewed = AnalystDisposition.UNREVIEWED in requested
            if includes_unreviewed and stored:
                expressions.append(
                    or_(latest_disposition.is_(None), latest_disposition.in_(stored))
                )
            elif includes_unreviewed:
                expressions.append(latest_disposition.is_(None))
            else:
                expressions.append(latest_disposition.in_(stored))
        if filters.requires_action:
            expressions.append(
                or_(
                    Report.review_status.in_(
                        [
                            ReviewStatus.GENERATION_FAILED.value,
                            ReviewStatus.NEEDS_EVALUATION.value,
                        ]
                    ),
                    and_(
                        Report.review_status.in_(
                            [
                                ReviewStatus.NEEDS_ATTENTION.value,
                                ReviewStatus.REVIEWABLE.value,
                            ]
                        ),
                        or_(
                            latest_disposition.is_(None),
                            latest_disposition == AnalystDisposition.NEEDS_REVISION.value,
                        ),
                    ),
                )
            )
        if filters.eligible_for_handoff:
            expressions.extend(
                [
                    Report.status == ReportStatus.COMPLETED.value,
                    Report.quality_score.isnot(None),
                    or_(
                        Report.evaluation_status == EvaluationStatus.COMPLETED.value,
                        and_(
                            Report.evaluation_status.is_(None),
                            Report.quality_score.isnot(None),
                        ),
                        and_(
                            Report.evaluation_status == EvaluationStatus.UNRECORDED.value,
                            Report.quality_score.isnot(None),
                        ),
                    ),
                    Report.evidence_admissibility_status
                    == EvidenceAdmissibilityStatus.PASSED.value,
                    latest_disposition == AnalystDisposition.ACCEPTED.value,
                ]
            )
        if filters.created_after:
            expressions.append(Report.created_at >= filters.created_after)
        return tuple(expressions)

    @staticmethod
    def _coerce_report_filters(
        *,
        category: Optional[str] = None,
        threat_type: Optional[str] = None,
        threat_types: Optional[List[str]] = None,
        min_quality_score: Optional[float] = None,
        search_query: Optional[str] = None,
        tags: Optional[List[str]] = None,
        statuses: Optional[Sequence[ReportStatus | str]] = None,
        review_statuses: Optional[Sequence[ReviewStatus | str]] = None,
        analyst_dispositions: Optional[Sequence[AnalystDisposition | str]] = None,
        requires_action: bool = False,
        eligible_for_handoff: bool = False,
        created_after: Optional[datetime] = None,
        user_id: Optional[str] = None,
        sort_by: str = "created_at",
        sort_order: str = "desc",
    ) -> ReportFilters:
        """Normalize the legacy keyword surface into one immutable query value."""

        try:
            sort_field = ReportSortField(sort_by)
        except ValueError:
            sort_field = ReportSortField.CREATED_AT
        try:
            direction = SortOrder(sort_order.lower())
        except ValueError:
            direction = SortOrder.DESCENDING

        return ReportFilters(
            category=category,
            threat_type=threat_type,
            threat_types=tuple(threat_types or ()),
            min_quality_score=min_quality_score,
            search_query=search_query,
            tags=tuple(tags or ()),
            statuses=tuple(ReportStatus(value) for value in statuses or ()),
            review_statuses=tuple(ReviewStatus(value) for value in review_statuses or ()),
            analyst_dispositions=tuple(
                AnalystDisposition(value) for value in analyst_dispositions or ()
            ),
            requires_action=requires_action,
            eligible_for_handoff=eligible_for_handoff,
            created_after=created_after,
            user_id=user_id,
            sort_by=sort_field,
            sort_order=direction,
        )

    def categorize_tool(
        self, tool_name: str, threat_data: Optional[Dict[str, Any]] = None
    ) -> tuple[str, str]:
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
            return ("unknown", "unknown")

        tool_lower = tool_name.lower().strip()

        structured_classification = self._categorize_structured_threat_data(threat_data)
        if structured_classification is not None:
            return structured_classification

        # Malware signatures (common malware families and indicators)
        malware_indicators = [
            "ransomware",
            "trojan",
            "backdoor",
            "rat",
            "rootkit",
            "spyware",
            "adware",
            "worm",
            "virus",
            "botnet",
            "cryptominer",
            "stealer",
            "loader",
            "dropper",
            "shadowpad",
            "cobalt strike",
            "meterpreter",
            "empire",
            "mimikatz",
            "lazarus",
            "apt",
            "carbanak",
            "emotet",
            "trickbot",
            "ryuk",
            "conti",
            "lockbit",
            "stealc",
            "bumblebee",
            "redline",
            "azorult",
            "formbook",
            "agent tesla",
            "nanocore",
            "njrat",
            "darkcomet",
            "poison ivy",
            "blackrat",
        ]

        # Legitimate software indicators
        legitimate_indicators = [
            "windows",
            "microsoft",
            "office",
            "outlook",
            "excel",
            "word",
            "powershell",
            "cmd",
            "notepad",
            "explorer",
            "chrome",
            "firefox",
            "safari",
            "adobe",
            "java",
            "python",
            "nodejs",
            "git",
            "docker",
            "kubernetes",
            "jenkins",
            "sharepoint",
            "exchange",
            "active directory",
            "ldap",
            "ssh",
            "ftp",
            "sftp",
            "vmware",
            "virtualbox",
            "hyper-v",
            "citrix",
            "remote desktop",
            "vnc",
            "teamviewer",
            "anydesk",
            "logmein",
            "webex",
            "zoom",
            "slack",
            "teams",
            "sap",
            "oracle",
            "mysql",
            "postgresql",
            "mongodb",
            "redis",
            "elasticsearch",
            "apache",
            "nginx",
            "iis",
            "tomcat",
            "node",
            "express",
            "react",
            "angular",
            "get-aduser",
            "nltest",
            "net user",
            "whoami",
            "ipconfig",
            "netstat",
            "ping",
            "tracert",
            "nslookup",
            "runas",
            "tasklist",
            "services",
        ]

        # Threat group indicators
        threat_group_indicators = [
            "lazarus",
            "apt1",
            "apt28",
            "apt29",
            "apt34",
            "apt40",
            "fancy bear",
            "cozy bear",
            "carbanak",
            "fin7",
            "fin8",
            "wizard spider",
            "sandworm",
            "turla",
            "equation group",
            "darkhydrus",
            "mustang panda",
            "kimsuky",
        ]

        # Check for malware indicators
        for indicator in malware_indicators:
            if indicator in tool_lower:
                # Determine specific malware type
                if any(word in tool_lower for word in ["ransomware", "ryuk", "conti", "lockbit"]):
                    return ("malware", "ransomware")
                elif any(word in tool_lower for word in ["rat", "backdoor", "remote access"]):
                    return ("malware", "remote_access_trojan")
                elif any(word in tool_lower for word in ["trojan", "stealer", "stealc", "redline"]):
                    return ("malware", "trojan")
                elif any(word in tool_lower for word in ["apt", "advanced persistent"]):
                    return ("malware", "apt_malware")
                elif any(word in tool_lower for word in ["botnet", "bot"]):
                    return ("malware", "botnet")
                elif any(
                    word in tool_lower for word in ["framework", "cobalt", "empire", "meterpreter"]
                ):
                    return ("malware", "post_exploitation_framework")
                else:
                    return ("malware", "malware")

        # Check for threat group indicators
        for indicator in threat_group_indicators:
            if indicator in tool_lower:
                return ("threat_group", "threat_actor")

        # Check for legitimate software indicators
        for indicator in legitimate_indicators:
            if indicator in tool_lower:
                # Determine specific legitimate software type
                if any(
                    word in tool_lower
                    for word in [
                        "windows",
                        "cmd",
                        "powershell",
                        "net ",
                        "runas",
                        "nltest",
                        "get-aduser",
                    ]
                ):
                    return ("legitimate_software", "system_administration")
                elif any(
                    word in tool_lower
                    for word in ["office", "word", "excel", "outlook", "sharepoint"]
                ):
                    return ("legitimate_software", "productivity_software")
                elif any(word in tool_lower for word in ["chrome", "firefox", "safari", "browser"]):
                    return ("legitimate_software", "web_browser")
                elif any(
                    word in tool_lower
                    for word in ["ssh", "ftp", "remote", "vnc", "teamviewer", "anydesk"]
                ):
                    return ("legitimate_software", "remote_access")
                elif any(
                    word in tool_lower
                    for word in ["vmware", "docker", "kubernetes", "virtualization"]
                ):
                    return ("legitimate_software", "virtualization")
                elif any(word in tool_lower for word in ["apache", "nginx", "iis", "server"]):
                    return ("legitimate_software", "server_software")
                else:
                    return ("legitimate_software", "legitimate_software")

        # If we have threat data, use it for better categorization
        if threat_data:
            core_metadata = threat_data.get("coreMetadata")
            if not isinstance(core_metadata, dict):
                core_metadata = {}
            raw_category = core_metadata.get("category")
            category_from_data = raw_category.lower() if isinstance(raw_category, str) else ""

            if category_from_data:
                category_patterns = (
                    (("remote access", " rat"), ("malware", "remote_access_trojan")),
                    (
                        ("post-exploitation", "post exploitation", "framework"),
                        ("malware", "post_exploitation_framework"),
                    ),
                    (("ransomware",), ("malware", "ransomware")),
                    (("backdoor",), ("malware", "backdoor")),
                    (("trojan",), ("malware", "trojan")),
                    (("botnet",), ("malware", "botnet")),
                    (("downloader", "loader"), ("malware", "loader")),
                    (("apt",), ("malware", "apt_malware")),
                    (("malware",), ("malware", "malware")),
                    (("threat actor", "threat group"), ("threat_group", "threat_actor")),
                    (("security tool",), ("legitimate_software", "security_tool")),
                    (
                        ("software", "technology", "platform"),
                        ("legitimate_software", "legitimate_software"),
                    ),
                )
                for markers, classification in category_patterns:
                    if any(marker in f" {category_from_data}" for marker in markers):
                        return classification

        # Default to unknown if no clear categorization
        return ("unknown", "unknown")

    def reconcile_reader_state(self, *, session: Session | None = None) -> Dict[str, int]:
        """Backfill queryable review state and explicit classification provenance."""

        summary = {
            "review_updates": 0,
            "classification_updates": 0,
            "claim_attribution_updates": 0,
            "evidence_contract_updates": 0,
        }
        try:
            with (
                nullcontext(session) if session is not None else self.db_manager.get_session()
            ) as session:
                # The release transaction owns backfill and version publication.
                # Admin reconciliation remains explicit, never a startup scan.
                reports = session.query(Report).yield_per(250)
                for row_number, row in enumerate(reports, start=1):
                    # Legacy declarative models expose Column types to static
                    # checkers; ORM instances carry the corresponding values.
                    report = cast(Any, row)
                    old_classification = (
                        report.category,
                        report.threat_type,
                        report.classification_status,
                    )
                    category, threat_type, classification_status = self.resolve_classification(
                        tool_name=report.tool_name,
                        threat_data=report.threat_data,
                        stored_category=report.category,
                        stored_threat_type=report.threat_type,
                        stored_status=report.classification_status,
                        legacy=True,
                    )
                    report.category = category
                    report.threat_type = threat_type
                    report.classification_status = classification_status.value
                    if old_classification != (
                        report.category,
                        report.threat_type,
                        report.classification_status,
                    ):
                        summary["classification_updates"] += 1

                    old_attribution = (
                        report.claim_attribution_status,
                        report.claim_attribution_version,
                    )
                    attribution_status, attribution_version = claim_attribution_status(
                        report.threat_data
                    )
                    report.claim_attribution_status = attribution_status.value
                    report.claim_attribution_version = attribution_version
                    if old_attribution != (
                        report.claim_attribution_status,
                        report.claim_attribution_version,
                    ):
                        summary["claim_attribution_updates"] += 1

                    if (
                        report.evidence_admissibility_status
                        == EvidenceAdmissibilityStatus.PASSED.value
                        and attribution_version != CLAIM_ATTRIBUTION_SCHEMA_VERSION
                    ):
                        report.evidence_admissibility_status = (
                            EvidenceAdmissibilityStatus.UNASSESSED.value
                        )
                        summary["evidence_contract_updates"] += 1

                    previous_review_status = report.review_status
                    self._refresh_review_status(report)
                    if previous_review_status != report.review_status:
                        summary["review_updates"] += 1
                    if row_number % 250 == 0:
                        session.flush()

                session.flush()
            logger.info("Reader-state reconciliation complete: %s", summary)
            return summary
        except Exception:
            logger.error("Reader-state reconciliation failed")
            raise

    def update_existing_categorizations(self) -> int:
        """Compatibility wrapper for the admin categorization endpoint."""

        return self.reconcile_reader_state()["classification_updates"]

    def store_report(
        self,
        report_data: Dict[str, Any],
        api_key: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> str:
        """Store a complete report with metadata in PostgreSQL and content in S3"""
        assert_no_virtual_event_promotions(
            report_data.get("threat_data"),
            report_data.get("web_sources"),
            report_data.get("markdown_content"),
            report_data.get("tool_name"),
            report_data.get("quality_assessment"),
        )
        try:
            # Generate API key hash for user association
            api_key_hash = None
            if api_key:
                api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()

            # Upload content to S3
            report_id = report_data.get("id") or report_data.get("report_id")
            if not report_id:
                raise ValueError("Report ID is required")

            tool_name = report_data.get("tool_name", "")
            category, threat_type, classification_status = self.resolve_classification(
                tool_name=tool_name,
                threat_data=report_data.get("threat_data"),
            )
            report_data["category"] = category
            report_data["threat_type"] = threat_type
            report_data["classification_status"] = classification_status.value
            attribution_status, attribution_version = claim_attribution_status(
                report_data.get("threat_data")
            )
            report_data["claim_attribution_status"] = attribution_status.value
            report_data["claim_attribution_version"] = attribution_version
            evidence, evidence_status, evidence_version = self._evidence_admissibility_fields(
                report_data.get("threat_data"),
                report_data.get("evidence_admissibility"),
            )
            report_data["evidence_admissibility"] = evidence
            report_data["evidence_admissibility_status"] = evidence_status.value
            report_data["evidence_admissibility_version"] = evidence_version
            assert_source_ledger_consistent(
                report_data.get("threat_data") or {},
                report_data.get("web_sources") or [],
            )
            assert_markdown_source_ledger_consistent(
                report_data.get("markdown_content") or "",
                report_data.get("web_sources") or [],
            )

            # Upload markdown content to S3
            markdown_s3_key = None
            if "markdown_content" in report_data:
                markdown_s3_key = self.s3_manager.upload_markdown_report(
                    report_id, report_data["markdown_content"]
                )

            # Upload trace data to S3 if available
            trace_s3_key = None
            if "trace_data" in report_data:
                trace_s3_key = self.s3_manager.upload_trace_data(
                    report_id, report_data["trace_data"]
                )

            # Create database record
            with self.db_manager.get_session() as session:
                report = Report(
                    id=report_id,
                    tool_name=report_data.get("tool_name", ""),
                    category=report_data.get("category", ""),
                    threat_type=report_data.get("threat_type", ""),
                    classification_status=report_data.get(
                        "classification_status", ClassificationStatus.UNRECORDED.value
                    ),
                    claim_attribution_status=report_data.get(
                        "claim_attribution_status", ClaimAttributionStatus.LEGACY.value
                    ),
                    claim_attribution_version=report_data.get("claim_attribution_version"),
                    evidence_admissibility_status=report_data.get(
                        "evidence_admissibility_status",
                        EvidenceAdmissibilityStatus.UNASSESSED.value,
                    ),
                    evidence_admissibility_version=report_data.get(
                        "evidence_admissibility_version"
                    ),
                    quality_score=report_data.get("quality_score"),
                    confidence_score=report_data.get("confidence_score"),
                    trust_score=report_data.get("trust_score"),
                    processing_time_ms=report_data.get("processing_time_ms"),
                    api_calls_count=report_data.get("api_calls_count"),
                    threat_data=report_data.get("threat_data"),
                    ml_techniques=report_data.get("ml_techniques"),
                    quality_assessment=report_data.get("quality_assessment"),
                    web_sources=report_data.get("web_sources"),
                    evidence_admissibility=report_data.get("evidence_admissibility"),
                    generation_route=report_data.get("generation_route"),
                    research_route=report_data.get("research_route"),
                    synthesis_route=report_data.get("synthesis_route"),
                    evaluation_route=report_data.get("evaluation_route"),
                    evaluation_status=report_data.get("evaluation_status"),
                    evaluation_error_code=report_data.get("evaluation_error_code"),
                    evaluation_attempts=report_data.get("evaluation_attempts", 1),
                    evaluated_at=report_data.get("evaluated_at"),
                    markdown_s3_key=markdown_s3_key,
                    trace_s3_key=trace_s3_key,
                    api_key_hash=api_key_hash,
                    user_id=user_id,
                    status=report_data.get("status", ReportStatus.COMPLETED.value),
                    generation_stage=report_data.get(
                        "generation_stage", GenerationStage.COMPLETED.value
                    ),
                    is_flagged=report_data.get("is_flagged", False),
                    version=report_data.get("version", "1.0"),
                    search_tags=report_data.get("search_tags", []),
                    content_preview=report_data.get("content_preview"),
                )

                self._refresh_review_status(report)

                session.add(report)
                session.commit()

                logger.info(f"Report stored successfully: {report_id}")
                return str(report.id)

        except Exception as e:
            logger.error(f"Error storing report: {e}")
            raise

    def create_pending_report(
        self,
        report_id: str,
        tool_name: str,
        user_id: Optional[str] = None,
        *,
        runtime_dispatch: bool = False,
    ) -> str:
        """Create a placeholder report row marked 'generating' for a background job.

        The row is pre-categorized from the tool name so the review queue shows a
        meaningful target while generation runs. The background job later calls
        ``finalize_report`` (on success) or ``mark_report_failed`` (on failure).
        """
        try:
            category, threat_type, classification_status = self.resolve_classification(
                tool_name=tool_name,
                threat_data=None,
            )
            with self.db_manager.get_session() as session:
                report = Report(
                    id=report_id,
                    tool_name=tool_name,
                    category=category,
                    threat_type=threat_type,
                    classification_status=classification_status.value,
                    status=ReportStatus.GENERATING.value,
                    generation_stage=GenerationStage.QUEUED.value,
                    review_status=ReviewStatus.GENERATING.value,
                    user_id=user_id,
                    version="1.0",
                    search_tags=[],
                )
                session.add(report)
                if runtime_dispatch:
                    session.add(ReportRuntimeDispatch(report_id=report_id))
                session.commit()
                logger.info(f"Pending report created: {report_id}")
                return str(report.id)
        except Exception as e:
            logger.error(f"Error creating pending report: {e}")
            raise

    def finalize_report(
        self,
        report_id: str,
        report_data: Dict[str, Any],
        user_id: Optional[str] = None,
        *,
        generation_lease: GenerationLease | None = None,
    ) -> str:
        """Populate an existing pending report with generated content and mark it complete.

        Check ownership before upload and again when publishing references.
        """
        assert_no_virtual_event_promotions(
            report_data.get("threat_data"),
            report_data.get("web_sources"),
            report_data.get("markdown_content"),
            report_data.get("tool_name"),
            report_data.get("quality_assessment"),
        )
        try:
            with self.db_manager.get_session() as session:
                self._generation_report(session, report_id, generation_lease)
            tool_name = report_data.get("tool_name", "")
            category, threat_type, classification_status = self.resolve_classification(
                tool_name=tool_name,
                threat_data=report_data.get("threat_data"),
            )
            report_data["category"] = category
            report_data["threat_type"] = threat_type
            report_data["classification_status"] = classification_status.value
            attribution_status, attribution_version = claim_attribution_status(
                report_data.get("threat_data")
            )
            assert_claim_attribution_consistent(report_data.get("threat_data") or {})
            report_data["claim_attribution_status"] = attribution_status.value
            report_data["claim_attribution_version"] = attribution_version
            evidence, evidence_status, evidence_version = self._evidence_admissibility_fields(
                report_data.get("threat_data"),
                report_data.get("evidence_admissibility"),
            )
            if evidence_status is not EvidenceAdmissibilityStatus.PASSED:
                raise ValueError("Generated report did not pass evidence admissibility")
            report_data["evidence_admissibility"] = evidence
            report_data["evidence_admissibility_status"] = evidence_status.value
            report_data["evidence_admissibility_version"] = evidence_version
            assert_source_ledger_consistent(
                report_data.get("threat_data") or {},
                report_data.get("web_sources") or [],
            )
            assert_markdown_source_ledger_consistent(
                report_data.get("markdown_content") or "",
                report_data.get("web_sources") or [],
            )

            # Content upload is best-effort: the structured profile and metadata are
            # persisted in Postgres regardless, so a storage hiccup degrades to a
            # record without its narrative rather than failing the whole report.
            markdown_s3_key = None
            if report_data.get("markdown_content"):
                try:
                    markdown_s3_key = self.s3_manager.upload_markdown_report(
                        report_id, report_data["markdown_content"]
                    )
                except Exception as e:
                    logger.warning(f"Could not upload markdown for {report_id}: {e}")

            trace_s3_key = None
            if report_data.get("trace_data"):
                try:
                    trace_s3_key = self.s3_manager.upload_trace_data(
                        report_id, report_data["trace_data"]
                    )
                except Exception as e:
                    logger.warning(f"Could not upload trace data for {report_id}: {e}")

            with self.db_manager.get_session() as session:
                report = self._generation_report(session, report_id, generation_lease)

                if report_data.get("tool_name"):
                    report.tool_name = report_data["tool_name"]
                report.category = report_data.get("category", report.category)
                report.threat_type = report_data.get("threat_type", report.threat_type)
                report.classification_status = report_data.get(
                    "classification_status", ClassificationStatus.UNRECORDED.value
                )
                report.claim_attribution_status = report_data.get(
                    "claim_attribution_status", ClaimAttributionStatus.LEGACY.value
                )
                report.claim_attribution_version = report_data.get("claim_attribution_version")
                report.evidence_admissibility_status = report_data.get(
                    "evidence_admissibility_status",
                    EvidenceAdmissibilityStatus.UNASSESSED.value,
                )
                report.evidence_admissibility_version = report_data.get(
                    "evidence_admissibility_version"
                )
                report.quality_score = report_data.get("quality_score")
                report.confidence_score = report_data.get("confidence_score")
                report.trust_score = report_data.get("trust_score")
                report.processing_time_ms = report_data.get("processing_time_ms")
                report.api_calls_count = report_data.get("api_calls_count")
                report.threat_data = report_data.get("threat_data")
                report.ml_techniques = report_data.get("ml_techniques")
                report.quality_assessment = report_data.get("quality_assessment")
                report.web_sources = report_data.get("web_sources")
                report.evidence_admissibility = report_data.get("evidence_admissibility")
                report.generation_route = report_data.get("generation_route")
                report.research_route = report_data.get("research_route")
                report.synthesis_route = report_data.get("synthesis_route")
                report.evaluation_route = report_data.get("evaluation_route")
                report.evaluation_status = report_data.get("evaluation_status")
                report.evaluation_error_code = report_data.get("evaluation_error_code")
                report.evaluation_attempts = report_data.get("evaluation_attempts", 1)
                report.evaluated_at = report_data.get("evaluated_at")
                report.content_preview = report_data.get("content_preview")
                if markdown_s3_key:
                    report.markdown_s3_key = markdown_s3_key
                if trace_s3_key:
                    report.trace_s3_key = trace_s3_key
                report.search_tags = report_data.get("search_tags", report.search_tags or [])
                if user_id and not report.user_id:
                    report.user_id = user_id
                report.status = ReportStatus.COMPLETED.value
                report.generation_stage = GenerationStage.COMPLETED.value
                report.generation_failure_stage = None
                report.generation_error_code = None
                report.generation_retryable = None
                report.generation_failure = None
                self._refresh_review_status(report)

                session.commit()
                logger.info(f"Report finalized successfully: {report_id}")
                return str(report.id)

        except Exception as e:
            logger.error(f"Error finalizing report: {e}")
            raise

    @staticmethod
    def _locked_report(session: Session, report_id: str) -> Any:
        # Legacy Column-based models are dynamically typed at the ORM boundary.
        return session.query(Report).filter(Report.id == report_id).with_for_update().first()

    @staticmethod
    def _locked_dispatch(session: Session, report_id: str) -> Any:
        return (
            session.query(ReportRuntimeDispatch)
            .filter(ReportRuntimeDispatch.report_id == report_id)
            .with_for_update()
            .first()
        )

    def _generation_report(
        self, session: Session, report_id: str, lease: GenerationLease | None
    ) -> Any:
        # All product writers lock the report before the dispatch record. No
        # provider call or object upload runs while these locks are held.
        report = self._locked_report(session, report_id)
        if report is None or report.status != ReportStatus.GENERATING.value:
            raise GenerationLeaseLost("report is no longer generating")
        dispatch = self._locked_dispatch(session, report_id)
        if dispatch is None:
            # TODO(sentryruntime-cutover): Require a runtime intent and lease after
            # the deployed canary and rollback gates pass. Do not add new
            # unfenced generation paths.
            if lease is not None:
                raise GenerationLeaseLost("report has no runtime intent")
        elif (
            lease is None
            or str(dispatch.runtime_run_id) != lease.run_id
            or dispatch.lease_version != lease.version
            or dispatch.lease_owner != lease.owner
            or dispatch.state != "submitted"
        ):
            raise GenerationLeaseLost("generation attempt no longer owns the report")
        return report

    def begin_runtime_attempt(self, report_id: str, lease: GenerationLease) -> bool:
        """Register the product-side fence before doing any generation work."""
        with self.db_manager.get_session() as session:
            report = self._locked_report(session, report_id)
            if report is None or report.status != ReportStatus.GENERATING.value:
                return False
            dispatch = self._locked_dispatch(session, report_id)
            if dispatch is None or dispatch.state not in {"pending", "submitted"}:
                raise GenerationLeaseLost("report has no active runtime intent")
            if dispatch.runtime_run_id is not None and str(dispatch.runtime_run_id) != lease.run_id:
                raise GenerationLeaseLost("runtime run does not match the report intent")
            version = int(dispatch.lease_version or 0)
            if lease.version < version or (
                lease.version == version and lease.owner != dispatch.lease_owner
            ):
                raise GenerationLeaseLost("generation attempt was superseded")
            dispatch.runtime_run_id = uuid.UUID(lease.run_id)
            dispatch.lease_version = lease.version
            dispatch.lease_owner = lease.owner
            dispatch.state = "submitted"
            session.commit()
            return True

    def get_pending_runtime_dispatches(self, *, limit: int = 20) -> List[str]:
        """Return durable runtime intents that have not been acknowledged."""

        with self.db_manager.get_session() as session:
            dispatches = (
                session.query(ReportRuntimeDispatch)
                .filter(ReportRuntimeDispatch.state == "pending")
                .order_by(ReportRuntimeDispatch.created_at.asc())
                .limit(limit)
                .all()
            )
            return [str(dispatch.report_id) for dispatch in dispatches]

    def mark_runtime_dispatch_submitted(
        self,
        report_id: str,
        runtime_run_id: str,
    ) -> bool:
        """Record the idempotent runtime response for one dispatch intent."""

        with self.db_manager.get_session() as session:
            dispatch = (
                session.query(ReportRuntimeDispatch)
                .filter(ReportRuntimeDispatch.report_id == report_id)
                .with_for_update()
                .first()
            )
            if dispatch is None:
                return False
            if (
                dispatch.runtime_run_id is not None
                and str(dispatch.runtime_run_id) != runtime_run_id
            ):
                raise ValueError("runtime run does not match the report intent")
            dispatch.runtime_run_id = uuid.UUID(runtime_run_id)
            if dispatch.state == "pending":
                dispatch.state = "submitted"
            dispatch.dispatch_attempts = int(dispatch.dispatch_attempts or 0) + 1
            if dispatch.state == "submitted":
                dispatch.last_error_code = None
            session.commit()
            return True

    def record_runtime_dispatch_failure(self, report_id: str, error_code: str) -> bool:
        """Keep an unavailable runtime intent pending while recording its attempt."""

        with self.db_manager.get_session() as session:
            dispatch = (
                session.query(ReportRuntimeDispatch)
                .filter(ReportRuntimeDispatch.report_id == report_id)
                .with_for_update()
                .first()
            )
            if dispatch is None or dispatch.state != "pending":
                return False
            dispatch.dispatch_attempts = int(dispatch.dispatch_attempts or 0) + 1
            dispatch.last_error_code = error_code[:50]
            session.commit()
            return True

    def get_runtime_reconciliation_batch(self, *, limit: int = 20) -> list[tuple[str, str]]:
        with self.db_manager.get_session() as session:
            rows = (
                session.query(ReportRuntimeDispatch)
                .filter(
                    ReportRuntimeDispatch.state == "submitted",
                    ReportRuntimeDispatch.runtime_run_id.is_not(None),
                )
                .order_by(
                    ReportRuntimeDispatch.updated_at.asc(), ReportRuntimeDispatch.report_id.asc()
                )
                .limit(limit)
                .all()
            )
            return [(str(row.report_id), str(row.runtime_run_id)) for row in rows]

    def get_runtime_backlog(self) -> dict[str, int]:
        """Sample aggregate product state in one statement, without report payloads."""
        dispatches = select(func.count()).select_from(ReportRuntimeDispatch)
        evaluations = (
            select(func.count())
            .select_from(Report)
            .join(ReportRuntimeDispatch, ReportRuntimeDispatch.report_id == Report.id)
            .where(
                Report.status == ReportStatus.COMPLETED.value,
                Report.evaluation_status == EvaluationStatus.PENDING.value,
                Report.user_id.is_not(None),
            )
        )
        ready = or_(
            Report.evaluation_lease_expires_at.is_(None),
            Report.evaluation_lease_expires_at <= func.statement_timestamp(),
        )
        statement = select(
            dispatches.where(ReportRuntimeDispatch.state == "pending")
            .scalar_subquery()
            .label("pending_dispatches"),
            dispatches.where(ReportRuntimeDispatch.state == "submitted")
            .scalar_subquery()
            .label("submitted_dispatches"),
            evaluations.where(ready).scalar_subquery().label("ready_evaluations"),
            evaluations.where(Report.evaluation_lease_expires_at > func.statement_timestamp())
            .scalar_subquery()
            .label("active_evaluations"),
            dispatches.where(ReportRuntimeDispatch.last_error_code.is_not(None))
            .scalar_subquery()
            .label("dispatch_errors"),
        )
        with self.db_manager.get_session() as session:
            return {
                str(key): int(value)
                for key, value in session.execute(statement).mappings().one().items()
            }

    def has_runtime_dispatch(self, report_id: str) -> bool:
        """Execution ownership follows the durable intent, not the API environment."""
        with self.db_manager.get_session() as session:
            return (
                session.scalar(
                    select(ReportRuntimeDispatch.report_id).where(
                        ReportRuntimeDispatch.report_id == report_id
                    )
                )
                is not None
            )

    def record_runtime_check_error(self, report_id: str, code: str) -> None:
        with self.db_manager.get_session() as session:
            dispatch = self._locked_dispatch(session, report_id)
            if dispatch is not None and dispatch.state == "submitted":
                dispatch.last_error_code = code[:50]
                dispatch.updated_at = func.clock_timestamp()

    def apply_runtime_observation(
        self, report_id: str, run_id: str, *, state: str, lease_version: int, error_code: str | None
    ) -> bool:
        """Reconcile a terminal run without inventing or downgrading artifacts."""
        if state not in {"queued", "running", "retry_wait", "succeeded", "failed"}:
            raise ValueError("unknown runtime state")
        with self.db_manager.get_session() as session:
            report = self._locked_report(session, report_id)
            dispatch = self._locked_dispatch(session, report_id)
            if (
                report is None
                or dispatch is None
                or dispatch.state != "submitted"
                or str(dispatch.runtime_run_id) != run_id
            ):
                return False
            dispatch.updated_at = func.clock_timestamp()
            if lease_version < int(dispatch.lease_version or 0):
                dispatch.last_error_code = "stale_runtime_observation"
                return False
            dispatch.last_error_code = None
            if state not in {"succeeded", "failed"}:
                return False
            dispatch.state = state
            dispatch.lease_version = lease_version
            if report.status == ReportStatus.GENERATING.value:
                report.status = ReportStatus.FAILED.value
                report.generation_failure_stage = report.generation_stage
                report.generation_stage = GenerationStage.FAILED.value
                report.generation_retryable = False
                report.generation_error_code = (
                    GenerationErrorCode.PERSISTENCE_FAILED
                    if state == "succeeded"
                    else GenerationErrorCode.UNKNOWN
                ).value
                report.generation_failure = {
                    "error_code": report.generation_error_code,
                    "retryable": False,
                    "runtime_state": state,
                    "runtime_error_code": error_code,
                }
                if state == "succeeded":
                    dispatch.last_error_code = "runtime_result_missing"
                self._refresh_review_status(report)
            elif report.status == ReportStatus.COMPLETED.value and state == "failed":
                dispatch.last_error_code = "runtime_failed_after_publication"
            session.commit()
            return True

    def begin_report_evaluation(self, report_id: str, *, user_id: str) -> bool:
        """Atomically claim one evaluator-only retry for a completed owned report."""

        with self.db_manager.get_session() as session:
            report = (
                session.query(Report)
                .filter(Report.id == report_id, Report.user_id == user_id)
                .with_for_update()
                .first()
            )
            if report is None or report.status != ReportStatus.COMPLETED.value:
                return False
            if (
                report.evaluation_status == EvaluationStatus.PENDING.value
                and report.evaluation_lease_id is not None
            ):
                now = session.scalar(select(func.clock_timestamp()))
                if (
                    report.evaluation_lease_expires_at is not None
                    and report.evaluation_lease_expires_at > now
                ):
                    return False
            report.evaluation_status = EvaluationStatus.PENDING.value
            report.evaluation_error_code = None
            report.evaluation_attempts = int(report.evaluation_attempts or 0) + 1
            report.evaluation_lease_id = None
            report.evaluation_lease_expires_at = None
            report.evaluation_recoveries = 0
            self._refresh_review_status(report)
            session.commit()
            return True

    def get_pending_runtime_evaluations(self, *, limit: int = 20) -> list[tuple[str, str]]:
        with self.db_manager.get_session() as session:
            rows = (
                session.query(Report)
                .join(ReportRuntimeDispatch, ReportRuntimeDispatch.report_id == Report.id)
                .filter(
                    Report.status == ReportStatus.COMPLETED.value,
                    Report.evaluation_status == EvaluationStatus.PENDING.value,
                    Report.user_id.is_not(None),
                    or_(
                        Report.evaluation_lease_expires_at.is_(None),
                        Report.evaluation_lease_expires_at <= func.clock_timestamp(),
                    ),
                )
                .order_by(
                    func.coalesce(Report.evaluation_lease_expires_at, Report.created_at), Report.id
                )
                .limit(limit)
                .all()
            )
            return [(str(report.id), str(report.user_id)) for report in rows]

    def claim_report_evaluation(
        self, report_id: str, *, user_id: str, lease_seconds: int = EVALUATION_LEASE_SECONDS
    ) -> str | None:
        """Claim queued or interrupted evaluation, with two automatic recoveries."""
        if not 1 <= lease_seconds <= 3600:
            raise ValueError("evaluation lease must be between 1 and 3600 seconds")
        with self.db_manager.get_session() as session:
            report = self._locked_report(session, report_id)
            if (
                report is None
                or report.user_id != user_id
                or report.status != ReportStatus.COMPLETED.value
                or report.evaluation_status != EvaluationStatus.PENDING.value
            ):
                return None
            now = session.scalar(select(func.clock_timestamp()))
            if report.evaluation_lease_id is not None:
                if (
                    report.evaluation_lease_expires_at is not None
                    and report.evaluation_lease_expires_at > now
                ):
                    return None
                if int(report.evaluation_recoveries or 0) >= 2:
                    report.evaluation_status = EvaluationStatus.FAILED.value
                    report.evaluation_error_code = "evaluation_recovery_exhausted"
                    report.evaluated_at = now
                    report.evaluation_lease_id = None
                    report.evaluation_lease_expires_at = None
                    self._refresh_review_status(report)
                    return None
                report.evaluation_recoveries = int(report.evaluation_recoveries or 0) + 1
                report.evaluation_attempts = int(report.evaluation_attempts or 0) + 1
            else:
                report.evaluation_attempts = max(1, int(report.evaluation_attempts or 0))
            token = uuid.uuid4()
            report.evaluation_lease_id = token
            report.evaluation_lease_expires_at = now + timedelta(seconds=lease_seconds)
            report.evaluation_error_code = None
            self._refresh_review_status(report)
            session.commit()
            return str(token)

    def _evaluation_report(self, session: Session, report_id: str, token: str) -> Any:
        report = self._locked_report(session, report_id)
        if (
            report is None
            or report.status != ReportStatus.COMPLETED.value
            or report.evaluation_status != EvaluationStatus.PENDING.value
            or report.evaluation_lease_id is None
            or str(report.evaluation_lease_id) != token
        ):
            return None
        return report

    def complete_report_evaluation(
        self,
        report_id: str,
        *,
        evaluation_lease: str,
        quality_assessment: Dict[str, Any],
        evaluation_route: Dict[str, Any],
        threat_data: Dict[str, Any],
        markdown_content: str,
    ) -> bool:
        """Persist a successful evaluator retry without repeating research or synthesis."""

        assert_no_virtual_event_promotions(threat_data, markdown_content, quality_assessment)
        with self.db_manager.get_session() as session:
            if self._evaluation_report(session, report_id, evaluation_lease) is None:
                return False

        sources = (threat_data.get("webSearchSources") or {}).get("primarySources") or []
        assert_source_ledger_consistent(threat_data, sources)
        assert_markdown_source_ledger_consistent(markdown_content, sources)
        markdown_s3_key = self.s3_manager.upload_markdown_report(report_id, markdown_content)
        with self.db_manager.get_session() as session:
            report = self._evaluation_report(session, report_id, evaluation_lease)
            if report is None:
                return False
            report.quality_assessment = quality_assessment
            report.quality_score = quality_assessment.get("overall_score")
            report.evaluation_route = evaluation_route
            report.evaluation_status = EvaluationStatus.COMPLETED.value
            report.evaluation_error_code = None
            report.evaluated_at = datetime.now(timezone.utc)
            report.evaluation_lease_id = None
            report.evaluation_lease_expires_at = None
            report.threat_data = threat_data
            report.markdown_s3_key = markdown_s3_key
            self._refresh_review_status(report)
            session.commit()
            return True

    def fail_report_evaluation(
        self,
        report_id: str,
        *,
        evaluation_lease: str,
        error_code: str,
        quality_assessment: Optional[Dict[str, Any]] = None,
        evaluation_route: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Keep the narrative and record a blame-free, retryable evaluator failure."""

        with self.db_manager.get_session() as session:
            report = self._evaluation_report(session, report_id, evaluation_lease)
            if report is None:
                return False
            report.evaluation_status = EvaluationStatus.FAILED.value
            report.evaluation_error_code = error_code
            report.evaluated_at = datetime.now(timezone.utc)
            report.evaluation_lease_id = None
            report.evaluation_lease_expires_at = None
            if quality_assessment is not None:
                report.quality_assessment = quality_assessment
            if evaluation_route is not None:
                report.evaluation_route = evaluation_route
            self._refresh_review_status(report)
            session.commit()
            return True

    def update_generation_stage(
        self,
        report_id: str,
        stage: GenerationStage | str,
        *,
        generation_lease: GenerationLease | None = None,
    ) -> bool:
        """Persist an observable background-generation stage without changing status."""

        try:
            normalized_stage = GenerationStage(stage)
            with self.db_manager.get_session() as session:
                report = self._generation_report(session, report_id, generation_lease)
                report.generation_stage = normalized_stage.value
                self._refresh_review_status(report)
                session.commit()
                logger.info("Report %s generation stage: %s", report_id, normalized_stage.value)
                return True
        except GenerationLeaseLost:
            if generation_lease is not None:
                raise
            return False
        except (ValueError, TypeError):
            logger.warning("Ignored unknown generation stage for report %s: %s", report_id, stage)
            return False
        except Exception as e:
            logger.error(f"Error updating report generation stage: {e}")
            return False

    def mark_report_failed(
        self,
        report_id: str,
        *,
        error_code: GenerationErrorCode | str = GenerationErrorCode.UNKNOWN,
        retryable: bool = False,
        failure: Optional[Dict[str, Any]] = None,
        generation_lease: GenerationLease | None = None,
    ) -> bool:
        """Mark a pending report as failed so the UI can surface a retry state."""
        try:
            with self.db_manager.get_session() as session:
                report = self._generation_report(session, report_id, generation_lease)
                if report.generation_stage not in {
                    GenerationStage.FAILED.value,
                    GenerationStage.COMPLETED.value,
                }:
                    report.generation_failure_stage = report.generation_stage
                report.status = ReportStatus.FAILED.value
                report.generation_stage = GenerationStage.FAILED.value
                report.generation_error_code = GenerationErrorCode(error_code).value
                report.generation_retryable = retryable
                report.generation_failure = failure
                if isinstance(failure, dict) and isinstance(failure.get("route"), dict):
                    report.generation_route = failure["route"]
                if isinstance(failure, dict) and isinstance(
                    failure.get("evidence_admissibility"), dict
                ):
                    evidence, status, version = self._evidence_admissibility_fields(
                        None,
                        failure["evidence_admissibility"],
                    )
                    report.evidence_admissibility = evidence
                    report.evidence_admissibility_status = status.value
                    report.evidence_admissibility_version = version
                self._refresh_review_status(report)
                session.commit()
                logger.info(f"Report marked failed: {report_id}")
                return True
        except GenerationLeaseLost:
            if generation_lease is not None:
                raise
            return False
        except Exception as e:
            logger.error(f"Error marking report failed: {e}")
            return False

    def get_report(self, report_id: str, include_content: bool = False) -> Optional[Dict[str, Any]]:
        """Get report by ID with optional content loading"""
        try:
            with self.db_manager.get_session() as session:
                report = session.query(Report).filter(Report.id == report_id).first()

                if not report:
                    return None

                report_dict = self._attach_disposition_state(
                    session,
                    [report],
                    include_history=True,
                )[0]
                # Full extraction data and tags are only needed on a single-report
                # fetch (the record view), not the list, so they're added here rather
                # than in the shared, list-facing to_dict().
                report_dict["threat_data"] = report.threat_data
                report_dict["web_sources"] = report.web_sources or []
                report_dict["search_tags"] = report.search_tags or []

                # Load content from S3 if requested
                if include_content:
                    if report.markdown_s3_key:
                        try:
                            report_dict["markdown_content"] = self.s3_manager.download_content(
                                report.markdown_s3_key
                            )
                        except Exception as e:
                            logger.warning(f"Could not load markdown content: {e}")

                    if report.trace_s3_key:
                        try:
                            trace_content = self.s3_manager.download_content(report.trace_s3_key)
                            report_dict["trace_data"] = json.loads(trace_content)
                        except Exception as e:
                            logger.warning(f"Could not load trace data: {e}")

                return report_dict

        except Exception as e:
            logger.error(f"Error getting report: {e}")
            raise

    def append_report_disposition(
        self,
        report_id: str,
        *,
        disposition: AnalystDisposition | str,
        note: str | None,
        reviewer_user_id: str,
        owner_user_id: str | None,
    ) -> Dict[str, Any] | None:
        """Append an analyst judgment without overwriting earlier review history."""

        normalized = AnalystDisposition(disposition)
        if normalized is AnalystDisposition.UNREVIEWED:
            raise ValueError("Unreviewed is derived from the absence of a current judgment")
        clean_note = note.strip() if isinstance(note, str) and note.strip() else None
        if clean_note is not None and len(clean_note) > 1000:
            raise ValueError("Disposition notes must not exceed 1000 characters")

        with self.db_manager.get_session() as session:
            query = session.query(Report).filter(Report.id == report_id)
            if owner_user_id is not None:
                query = query.filter(Report.user_id == owner_user_id)
            report = query.with_for_update().first()
            if report is None:
                return None
            evaluation_status = coerce_evaluation_status(
                report.evaluation_status,
                quality_score=(
                    float(report.quality_score) if report.quality_score is not None else None
                ),
            )
            if not is_judgment_eligible(
                report_status=report.status or ReportStatus.COMPLETED.value,
                evaluation_status=evaluation_status,
                quality_score=(
                    float(report.quality_score) if report.quality_score is not None else None
                ),
            ):
                raise ValueError("Only completed, evaluated reports can be dispositioned")
            if normalized is AnalystDisposition.ACCEPTED and not is_reuse_eligible(
                report_status=report.status or ReportStatus.COMPLETED.value,
                evaluation_status=evaluation_status,
                quality_score=(
                    float(report.quality_score) if report.quality_score is not None else None
                ),
                evidence_admissibility_status=(
                    report.evidence_admissibility_status
                    or EvidenceAdmissibilityStatus.UNASSESSED.value
                ),
            ):
                raise ValueError(
                    "Only reports that passed evidence admissibility can be accepted for reuse"
                )
            if (
                normalized is AnalystDisposition.ACCEPTED
                and evaluation_conflict_count(report.quality_assessment) > 0
                and clean_note is None
            ):
                raise ValueError(
                    "Accepting a report with recorded conflicts requires an analyst note"
                )

            event = ReportDispositionEvent(
                report_id=report.id,
                reviewer_user_id=reviewer_user_id,
                disposition=normalized.value,
                note=clean_note,
                evaluation_attempt=int(report.evaluation_attempts or 0),
            )
            session.add(event)
            session.flush()
            session.refresh(event)
            payload = event.to_dict(current_evaluation_attempt=int(report.evaluation_attempts or 0))
            session.commit()
            return payload

    def list_reports(
        self,
        limit: int = 20,
        offset: int = 0,
        category: Optional[str] = None,
        threat_type: Optional[str] = None,
        threat_types: Optional[List[str]] = None,
        min_quality_score: Optional[float] = None,
        search_query: Optional[str] = None,
        tags: Optional[List[str]] = None,
        statuses: Optional[Sequence[ReportStatus | str]] = None,
        review_statuses: Optional[Sequence[ReviewStatus | str]] = None,
        analyst_dispositions: Optional[Sequence[AnalystDisposition | str]] = None,
        requires_action: bool = False,
        eligible_for_handoff: bool = False,
        created_after: Optional[datetime] = None,
        sort_by: str = "created_at",
        sort_order: str = "desc",
        user_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List reports with filtering and pagination"""
        try:
            filters = self._coerce_report_filters(
                category=category,
                threat_type=threat_type,
                threat_types=threat_types,
                min_quality_score=min_quality_score,
                search_query=search_query,
                tags=tags,
                statuses=statuses,
                review_statuses=review_statuses,
                analyst_dispositions=analyst_dispositions,
                requires_action=requires_action,
                eligible_for_handoff=eligible_for_handoff,
                created_after=created_after,
                user_id=user_id,
                sort_by=sort_by,
                sort_order=sort_order,
            )
            with self.db_manager.get_session() as session:
                query = session.query(Report)
                query = query.filter(*self._report_filter_expressions(filters))

                # Dynamic sorting
                query = query.order_by(
                    self._report_sort_expression(filters.sort_by, filters.sort_order)
                )

                # Apply pagination
                query = query.offset(offset).limit(limit)

                reports = query.all()

                return self._attach_disposition_state(session, reports)

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
                category_counts = (
                    session.query(Report.category, func.count(Report.id))
                    .group_by(Report.category)
                    .filter(Report.category.isnot(None))
                    .all()
                )

                # Average quality score
                avg_quality = (
                    session.query(func.avg(Report.quality_score))
                    .filter(Report.quality_score.isnot(None))
                    .scalar()
                )

                return {
                    "total_reports": total_reports,
                    "category_counts": dict(category_counts) if category_counts else {},
                    "average_quality_score": float(avg_quality) if avg_quality else None,
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
                session.query(ReportDispositionEvent).filter(
                    ReportDispositionEvent.report_id == report.id
                ).delete(synchronize_session=False)
                session.delete(report)
                session.commit()

                logger.info(f"Report deleted successfully: {report_id}")
                return True

        except Exception as e:
            logger.error(f"Error deleting report: {e}")
            raise

    def download_report_content(self, key: str) -> str:
        return self.s3_manager.download_content(key)

    def get_download_url(self, report_id: str, content_type: str = "markdown") -> Optional[str]:
        """Get presigned URL for downloading report content"""
        try:
            with self.db_manager.get_session() as session:
                report = session.query(Report).filter(Report.id == report_id).first()

                if not report:
                    return None
                snapshot = report.to_dict()
                snapshot["_markdown_s3_key"] = report.markdown_s3_key
                s3_key = (
                    report.markdown_s3_key
                    if content_type == "markdown"
                    else (report.trace_s3_key if content_type == "trace" else None)
                )
            if not s3_key:
                return None
            # Trace downloads are private audit access, not public Markdown exports.
            if content_type == "markdown":
                load_checked_report(snapshot, self.download_report_content)
            return self.s3_manager.get_presigned_url(s3_key)

        except Exception as e:
            logger.error(f"Error getting download URL: {e}")
            raise

    def test_connection(self) -> bool:
        """Test database connection for health checks"""
        return self.db_manager.test_connection()

    def count_reports(self, **filters) -> int:
        """Count total reports with optional filters"""
        try:
            report_filters = self._coerce_report_filters(
                category=filters.get("category"),
                threat_type=filters.get("threat_type"),
                threat_types=filters.get("threat_types"),
                min_quality_score=filters.get("min_quality_score"),
                search_query=filters.get("search_query"),
                tags=filters.get("tags"),
                statuses=filters.get("statuses"),
                review_statuses=filters.get("review_statuses"),
                analyst_dispositions=filters.get("analyst_dispositions"),
                requires_action=bool(filters.get("requires_action", False)),
                eligible_for_handoff=bool(filters.get("eligible_for_handoff", False)),
                created_after=filters.get("created_after"),
                user_id=filters.get("user_id"),
            )
            with self.db_manager.get_session() as session:
                query = session.query(Report)
                query = query.filter(*self._report_filter_expressions(report_filters))
                return query.count()
        except Exception as e:
            logger.error(f"Error counting reports: {e}")
            raise

    def list_analytics_records(
        self, *, created_after: datetime, user_id: Optional[str] = None
    ) -> List[ReportAnalyticsRecord]:
        """Return only the persisted fields required by the analytics endpoint."""

        filters = ReportFilters(created_after=created_after, user_id=user_id)
        try:
            with self.db_manager.get_session() as session:
                rows = (
                    session.query(
                        Report.created_at,
                        Report.quality_score,
                        Report.processing_time_ms,
                        Report.status,
                        Report.threat_type,
                        Report.generation_route,
                        Report.synthesis_route,
                        Report.evaluation_status,
                        Report.quality_assessment,
                        Report.web_sources,
                        Report.threat_data,
                        Report.evidence_admissibility_status,
                        Report.generation_error_code,
                        Report.generation_failure_stage,
                    )
                    .filter(*self._report_filter_expressions(filters))
                    .all()
                )
                return [
                    ReportAnalyticsRecord(
                        created_at=row.created_at,
                        quality_score=(
                            float(row.quality_score) if row.quality_score is not None else None
                        ),
                        processing_time_ms=row.processing_time_ms,
                        status=ReportStatus(row.status or ReportStatus.COMPLETED.value),
                        threat_type=row.threat_type,
                        generation_used_fallback=generation_fallback_state(
                            row.synthesis_route or row.generation_route
                        ),
                        generation_route_scope=derive_generation_route_scope(
                            synthesis_route=row.synthesis_route,
                            generation_route=row.generation_route,
                        ),
                        evaluation_status=coerce_evaluation_status(
                            row.evaluation_status,
                            quality_score=(
                                float(row.quality_score) if row.quality_score is not None else None
                            ),
                        ),
                        quality_assessment=row.quality_assessment,
                        source_count=self._source_count_from_values(
                            row.web_sources,
                            row.threat_data,
                        ),
                        evidence_admissibility_status=EvidenceAdmissibilityStatus(
                            row.evidence_admissibility_status
                            or EvidenceAdmissibilityStatus.UNASSESSED.value
                        ),
                        generation_error_code=(
                            GenerationErrorCode(row.generation_error_code)
                            if row.generation_error_code
                            else None
                        ),
                        generation_failure_stage=(
                            GenerationStage(row.generation_failure_stage)
                            if row.generation_failure_stage
                            else None
                        ),
                    )
                    for row in rows
                ]
        except Exception as e:
            logger.error(f"Error listing analytics records: {e}")
            raise

    def search_reports(self, **kwargs) -> List[Dict[str, Any]]:
        """Advanced search - currently uses same logic as list_reports"""
        return self.list_reports(**kwargs)

    def count_search_results(self, **filters) -> int:
        """Count search results - currently uses same logic as count_reports"""
        return self.count_reports(**filters)

    def get_unique_threat_types(self, user_id: Optional[str] = None) -> List[str]:
        """Get list of unique threat types"""
        try:
            with self.db_manager.get_session() as session:
                query = (
                    session.query(Report.threat_type)
                    .distinct()
                    .filter(Report.threat_type.isnot(None), Report.threat_type != "")
                )
                if user_id:
                    query = query.filter(Report.user_id == user_id)

                results = query.all()
                return [r[0] for r in results if r[0]]
        except Exception as e:
            logger.error(f"Error getting threat types: {e}")
            raise

    def get_unique_categories(self, user_id: Optional[str] = None) -> List[str]:
        """Get list of unique categories"""
        try:
            with self.db_manager.get_session() as session:
                query = (
                    session.query(Report.category)
                    .distinct()
                    .filter(Report.category.isnot(None), Report.category != "")
                )
                if user_id:
                    query = query.filter(Report.user_id == user_id)

                results = query.all()
                return [r[0] for r in results if r[0]]
        except Exception as e:
            logger.error(f"Error getting categories: {e}")
            raise

    def get_popular_tags(self, limit: int = 50, user_id: Optional[str] = None) -> List[str]:
        """Get most popular tags"""
        try:
            with self.db_manager.get_session() as session:
                # For now, return unique values from search_tags arrays
                # In a production system, you'd want proper tag frequency counting
                query = session.query(Report.search_tags).filter(Report.search_tags.isnot(None))
                if user_id:
                    query = query.filter(Report.user_id == user_id)

                results = query.all()

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
            raise

    def get_threat_type_stats(self, user_id: Optional[str] = None) -> Dict[str, int]:
        """Get threat type distribution"""
        try:
            with self.db_manager.get_session() as session:
                from sqlalchemy import func

                query = (
                    session.query(Report.threat_type, func.count(Report.id))
                    .group_by(Report.threat_type)
                    .filter(Report.threat_type.isnot(None), Report.threat_type != "")
                )
                if user_id:
                    query = query.filter(Report.user_id == user_id)

                results = query.all()

                return {threat_type: count for threat_type, count in results}
        except Exception as e:
            logger.error(f"Error getting threat type stats: {e}")
            raise

    def get_quality_score_distribution(self, user_id: Optional[str] = None) -> Dict[str, Any]:
        """Get quality score statistics and distribution"""
        try:
            with self.db_manager.get_session() as session:
                from sqlalchemy import func

                quality_filter = [Report.quality_score.isnot(None)]
                if user_id:
                    quality_filter.append(Report.user_id == user_id)

                # Get average quality score
                avg_quality = (
                    session.query(func.avg(Report.quality_score)).filter(*quality_filter).scalar()
                )

                # Get distribution buckets
                quality_scores = session.query(Report.quality_score).filter(*quality_filter).all()

                scores = [float(score[0]) for score in quality_scores if score[0] is not None]

                # Create distribution buckets
                buckets = {
                    "0.0-1.0": len([s for s in scores if 0.0 <= s < 1.0]),
                    "1.0-2.0": len([s for s in scores if 1.0 <= s < 2.0]),
                    "2.0-3.0": len([s for s in scores if 2.0 <= s < 3.0]),
                    "3.0-4.0": len([s for s in scores if 3.0 <= s < 4.0]),
                    "4.0-5.0": len([s for s in scores if 4.0 <= s <= 5.0]),
                }

                return {
                    "average": float(avg_quality) if avg_quality is not None else None,
                    "distribution": buckets,
                    "total_scored": len(scores),
                }

        except Exception as e:
            logger.error(f"Error getting quality score distribution: {e}")
            raise


# Global report storage service instance
report_service = ReportStorageService()
