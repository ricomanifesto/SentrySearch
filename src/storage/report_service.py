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
from psycopg.errors import LockNotAvailable
from sqlalchemy import and_, asc, desc, func, or_, select
from sqlalchemy.exc import OperationalError
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
    READER_STATE_VERSION,
    coerce_evaluation_status,
    derive_generation_route_scope,
    derive_reader_state,
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
from src.core.report_content_policy import (
    ARTIFACT_POLICY_ALLOWED,
    ARTIFACT_POLICY_UNKNOWN,
    ARTIFACT_POLICY_VERSION,
    artifact_policy_status,
    load_checked_report,
)
from src.domain.model_routes import generation_fallback_state
from src.domain.threat_classification import classify_category_text, classify_tool_name

from .database import db_manager
from .models import (
    Report,
    ReportArtifact,
    ReportClaimRow,
    ReportClaimSupportRow,
    ReportDispositionEvent,
    ReportFindingRow,
    ReportIndicatorObservationRow,
    ReportRuntimeDispatch,
    ReportSourceObservationRow,
    ReportSourceRow,
    ReportTag,
)
from .profile_rows import ProfileRows, content_address, profile_rows
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

    @staticmethod
    def _current_disposition(report: Report) -> AnalystDisposition:
        """The latest judgment on the report's current evaluation vintage."""

        model = cast(Any, report)
        current_attempt = int(model.evaluation_attempts or 0)
        events = [
            event
            for event in (getattr(report, "disposition_events", None) or [])
            if event.evaluation_attempt == current_attempt
        ]
        return (
            AnalystDisposition(events[-1].disposition) if events else AnalystDisposition.UNREVIEWED
        )

    @classmethod
    def _refresh_review_status(
        cls,
        report: Report,
        *,
        analyst_disposition: AnalystDisposition | None = None,
    ) -> ReviewStatus:
        """Recompute every stored reader-state column inside the writing transaction."""

        model = cast(Any, report)
        state = derive_reader_state(
            report_status=model.status or ReportStatus.COMPLETED.value,
            evaluation_status=model.evaluation_status,
            quality_score=(float(model.quality_score) if model.quality_score is not None else None),
            quality_assessment=model.quality_assessment,
            source_count=cls._source_count(report),
            evidence_admissibility_status=(
                model.evidence_admissibility_status or EvidenceAdmissibilityStatus.UNASSESSED.value
            ),
            analyst_disposition=analyst_disposition or cls._current_disposition(report),
        )
        model.review_status = state.review_status.value
        model.eligible_for_judgment = state.eligible_for_judgment
        model.eligible_for_acceptance = state.eligible_for_acceptance
        model.eligible_for_handoff = state.eligible_for_handoff
        model.reader_state_version = state.version
        return state.review_status

    @staticmethod
    def _write_profile_rows(report: Report, rows: ProfileRows) -> None:
        """Replace the report's flat evidence rows; the caller holds the row lock."""

        model = cast(Any, report)
        model.profile_sources = [ReportSourceRow(**row) for row in rows.sources]
        model.profile_claims = [ReportClaimRow(**row) for row in rows.claims]
        model.claim_support = [ReportClaimSupportRow(**row) for row in rows.claim_support]
        model.indicator_observations = [
            ReportIndicatorObservationRow(**row) for row in rows.indicator_observations
        ]
        model.source_observations = [
            ReportSourceObservationRow(**row) for row in rows.source_observations
        ]
        model.findings = [ReportFindingRow(**row) for row in rows.findings]

    @staticmethod
    def _write_tags(report: Report, search_tags: Any) -> None:
        """Keep ``report_tags`` equal to the report's search tags."""

        model = cast(Any, report)
        wanted = list(
            dict.fromkeys(
                str(tag).strip()[:100]
                for tag in (search_tags if isinstance(search_tags, list) else [])
                if str(tag).strip()
            )
        )
        current = {tag.tag: tag for tag in (model.tags or [])}
        if list(current) == wanted:
            return
        model.tags = [current.get(tag) or ReportTag(tag=tag) for tag in wanted]

    @staticmethod
    def _write_artifact(
        report: Report,
        kind: str,
        s3_key: str | None,
        content: str | None,
        *,
        policy_status: str | None = None,
    ) -> None:
        """Record the current object of one kind with its content-policy decision."""

        if not s3_key:
            return
        model = cast(Any, report)
        sha256 = content_address(s3_key) or (
            hashlib.sha256(content.encode("utf-8")).hexdigest() if content is not None else None
        )
        status = policy_status or artifact_policy_status(content)
        existing = next(
            (artifact for artifact in (model.artifacts or []) if artifact.kind == kind), None
        )
        if existing is None:
            model.artifacts.append(
                ReportArtifact(
                    kind=kind,
                    s3_key=s3_key,
                    sha256=sha256,
                    policy_status=status,
                    policy_version=ARTIFACT_POLICY_VERSION,
                )
            )
            return
        existing.s3_key = s3_key
        existing.sha256 = sha256
        existing.policy_status = status
        existing.policy_version = ARTIFACT_POLICY_VERSION

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
    ) -> list[Dict[str, Any]]:
        """Build a complete policy snapshot without mutating stored rows or judgments."""

        if not reports:
            return []
        # Historical notes remain reader-visible in detail responses, so every
        # collection and export must inspect the same history before admission.
        query = session.query(ReportDispositionEvent).filter(
            ReportDispositionEvent.report_id.in_([report.id for report in reports])
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
            # Detail and download still read the object; collections use the
            # stored artifact policy decision instead.
            report_dict["_markdown_s3_key"] = report.markdown_s3_key
            report_dict["_markdown_policy_status"] = next(
                (
                    artifact.policy_status
                    for artifact in (getattr(report, "artifacts", None) or [])
                    if artifact.kind == "markdown" and artifact.s3_key == report.markdown_s3_key
                ),
                None,
            )
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
            report_dict["disposition_history"] = [
                event.to_dict(current_evaluation_attempt=current_attempt) for event in history
            ]
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
        return classify_category_text(raw_category)

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
            # Stored at write time by the domain rules; never re-encoded here.
            expressions.append(Report.eligible_for_handoff.is_(True))
        # The stored content-policy decision replaces per-read object downloads.
        expressions.append(ReportStorageService._content_policy_allows())
        if filters.created_after:
            expressions.append(Report.created_at >= filters.created_after)
        return tuple(expressions)

    @staticmethod
    def _content_policy_allows():
        """Withhold rows whose current Markdown has no ``allowed`` policy decision.

        ``excluded``, ``unknown`` (unreadable at reconciliation), and a missing
        decision for the current key all fail closed; reconciliation re-reads
        ``unknown`` artifacts.
        """

        return or_(
            Report.markdown_s3_key.is_(None),
            select(ReportArtifact.report_id)
            .where(
                ReportArtifact.report_id == Report.id,
                ReportArtifact.kind == "markdown",
                ReportArtifact.s3_key == Report.markdown_s3_key,
                ReportArtifact.policy_status == ARTIFACT_POLICY_ALLOWED,
            )
            .correlate(Report)
            .exists(),
        )

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

        structured_classification = self._categorize_structured_threat_data(threat_data)
        if structured_classification is not None:
            return structured_classification

        # A structured category that no rule maps cannot match on a second
        # pass either, so the tool name is the only remaining signal.
        return classify_tool_name(tool_name) or ("unknown", "unknown")

    def _artifact_policy_from_storage(self, s3_key: str) -> str:
        """Read one stored object for the content policy; never fail the caller."""

        try:
            return artifact_policy_status(self.s3_manager.download_content(s3_key))
        except Exception:
            # An unavailable artifact client must not fail a release. ``unknown``
            # stays excluded from handoff and is retried by the next reconciliation.
            return ARTIFACT_POLICY_UNKNOWN

    @staticmethod
    def _stale_artifact_kinds(report: Any) -> List[tuple[str, str]]:
        """Artifact kinds whose row is missing, outdated, or ``unknown`` for the current key."""

        current = {artifact.kind: artifact for artifact in (report.artifacts or [])}
        stale = []
        for kind, key in (("markdown", report.markdown_s3_key), ("trace", report.trace_s3_key)):
            if not key:
                continue
            artifact = current.get(kind)
            if (
                artifact is not None
                and artifact.s3_key == key
                and artifact.policy_version == ARTIFACT_POLICY_VERSION
                and artifact.policy_status != ARTIFACT_POLICY_UNKNOWN
            ):
                continue
            stale.append((kind, key))
        return stale

    def _reconcile_artifacts(self, report: Any, markdown_policy: Dict[str, str]) -> int:
        """Bring artifact rows to the current policy version; returns rows changed.

        ``markdown_policy`` maps an object key to the policy read for it. A key
        without an entry, such as one published after the read, records
        ``unknown`` and is retried by the next reconciliation.
        """

        stale = self._stale_artifact_kinds(report)
        for kind, key in stale:
            status = (
                markdown_policy.get(key, ARTIFACT_POLICY_UNKNOWN)
                if kind == "markdown"
                else ARTIFACT_POLICY_UNKNOWN
            )
            self._write_artifact(report, kind, key, None, policy_status=status)
        return len(stale)

    def _read_markdown_policy(self, report: Any, *, read_artifacts: bool) -> Dict[str, str]:
        """Read the stale Markdown object, if any, for its content policy."""

        if not read_artifacts:
            return {}
        return {
            key: self._artifact_policy_from_storage(key)
            for kind, key in self._stale_artifact_kinds(report)
            if kind == "markdown"
        }

    def _reconcile_report(self, report: Any, summary: Dict[str, int]) -> None:
        """Recompute one report's derived columns and evidence rows from its stored JSONB."""

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
        attribution_status, attribution_version = claim_attribution_status(report.threat_data)
        report.claim_attribution_status = attribution_status.value
        report.claim_attribution_version = attribution_version
        if old_attribution != (
            report.claim_attribution_status,
            report.claim_attribution_version,
        ):
            summary["claim_attribution_updates"] += 1

        if (
            report.evidence_admissibility_status == EvidenceAdmissibilityStatus.PASSED.value
            and attribution_version != CLAIM_ATTRIBUTION_SCHEMA_VERSION
        ):
            report.evidence_admissibility_status = EvidenceAdmissibilityStatus.UNASSESSED.value
            summary["evidence_contract_updates"] += 1

        previous_review_status = report.review_status
        self._refresh_review_status(report)
        if previous_review_status != report.review_status:
            summary["review_updates"] += 1

        rows = profile_rows(report.threat_data, report.web_sources, report.evidence_admissibility)
        if len(report.profile_claims or []) != len(rows.claims) or len(
            report.findings or []
        ) != len(rows.findings):
            summary["profile_row_updates"] += 1
        self._write_profile_rows(report, rows)
        self._write_tags(report, report.search_tags)

    def reconcile_reader_state(
        self,
        *,
        session: Session | None = None,
        read_artifacts: bool = True,
    ) -> Dict[str, int]:
        """Backfill reader state, classification, flat evidence rows, and artifact policy.

        With ``session``, this is the release backfill: it runs inside the release
        transaction, takes no row locks, and relies on writers being drained.

        Without ``session``, this is the online reconciliation used by the admin
        endpoint while writers may be active. Each report is reread under its row
        lock and committed on its own, so a concurrent writer is either finished
        before the reread or waits for the reconciliation. A report still locked
        after the lock-wait limit is skipped and counted in ``locked_report_skips``.

        Artifact reads for the content policy never run while a row lock is held,
        and an unavailable artifact client records ``unknown`` instead of failing.
        """

        summary = {
            "review_updates": 0,
            "classification_updates": 0,
            "claim_attribution_updates": 0,
            "evidence_contract_updates": 0,
            "profile_row_updates": 0,
            "artifact_policy_updates": 0,
        }
        try:
            if session is None:
                summary["locked_report_skips"] = 0
                self._reconcile_online(summary, read_artifacts=read_artifacts)
            else:
                self._reconcile_drained(session, summary, read_artifacts=read_artifacts)
            logger.info("Reader-state reconciliation complete: %s", summary)
            return summary
        except Exception:
            logger.error("Reader-state reconciliation failed")
            raise

    def _reconcile_drained(
        self, session: Session, summary: Dict[str, int], *, read_artifacts: bool
    ) -> None:
        # The release transaction owns backfill and version publication.
        reports = session.query(Report).yield_per(250)
        for row_number, row in enumerate(reports, start=1):
            # Legacy declarative models expose Column types to static
            # checkers; ORM instances carry the corresponding values.
            report = cast(Any, row)
            self._reconcile_report(report, summary)
            summary["artifact_policy_updates"] += self._reconcile_artifacts(
                report, self._read_markdown_policy(report, read_artifacts=read_artifacts)
            )
            if row_number % 250 == 0:
                session.flush()
        session.flush()

    def _reconcile_online(self, summary: Dict[str, int], *, read_artifacts: bool) -> None:
        with self.db_manager.get_session() as session:
            report_ids = session.scalars(select(Report.id).order_by(Report.id)).all()

        for report_id in report_ids:
            # 1. Find a stale Markdown object, then read it with no session open.
            with self.db_manager.get_session() as session:
                report = session.get(Report, report_id)
                if report is None:
                    continue
                stale_keys = [
                    key
                    for kind, key in self._stale_artifact_kinds(cast(Any, report))
                    if kind == "markdown" and read_artifacts
                ]
            markdown_policy = {key: self._artifact_policy_from_storage(key) for key in stale_keys}

            # 2. Under the row lock: reread and recompute from committed data.
            try:
                with self.db_manager.get_session() as session:
                    report = self._locked_report(session, str(report_id))
                    if report is None:
                        continue
                    self._reconcile_report(report, summary)
                    summary["artifact_policy_updates"] += self._reconcile_artifacts(
                        report, markdown_policy
                    )
                    session.commit()
            except OperationalError as exc:
                if not isinstance(exc.orig, LockNotAvailable):
                    raise
                summary["locked_report_skips"] += 1
                logger.warning("Reconciliation skipped a report held by another writer")

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
                self._write_profile_rows(
                    report,
                    profile_rows(
                        report_data.get("threat_data"),
                        report_data.get("web_sources"),
                        report_data.get("evidence_admissibility"),
                    ),
                )
                self._write_artifact(
                    report, "markdown", markdown_s3_key, report_data.get("markdown_content")
                )
                self._write_artifact(
                    report,
                    "trace",
                    trace_s3_key,
                    (
                        json.dumps(report_data["trace_data"], sort_keys=True, default=str)
                        if "trace_data" in report_data
                        else None
                    ),
                )
                self._write_tags(report, report.search_tags)

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
                self._write_profile_rows(
                    report,
                    profile_rows(
                        report_data.get("threat_data"),
                        report_data.get("web_sources"),
                        report_data.get("evidence_admissibility"),
                    ),
                )
                self._write_artifact(
                    report, "markdown", markdown_s3_key, report_data.get("markdown_content")
                )
                self._write_artifact(
                    report,
                    "trace",
                    trace_s3_key,
                    (
                        json.dumps(report_data["trace_data"], sort_keys=True, default=str)
                        if report_data.get("trace_data")
                        else None
                    ),
                )
                self._write_tags(report, report.search_tags)

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
            self._write_profile_rows(
                report,
                profile_rows(threat_data, report.web_sources, report.evidence_admissibility),
            )
            self._write_artifact(report, "markdown", markdown_s3_key, markdown_content)
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
                    self._write_profile_rows(report, profile_rows(None, None, evidence))
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

                report_dict = self._attach_disposition_state(session, [report])[0]
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
        assert_no_virtual_event_promotions(clean_note)

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
            # The new judgment changes handoff eligibility in this transaction.
            self._refresh_review_status(report, analyst_disposition=normalized)
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
                snapshot = self._attach_disposition_state(session, [report])[0]
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
                        Report.review_status,
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
                        review_status=(
                            ReviewStatus(row.review_status) if row.review_status else None
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
        """Most frequent tags, counted in SQL over ``report_tags``."""
        try:
            with self.db_manager.get_session() as session:
                frequency = func.count(ReportTag.id)
                query = (
                    session.query(ReportTag.tag, frequency)
                    .join(Report, Report.id == ReportTag.report_id)
                    .filter(self._content_policy_allows())
                )
                if user_id:
                    query = query.filter(Report.user_id == user_id)
                rows = (
                    query.group_by(ReportTag.tag)
                    .order_by(frequency.desc(), ReportTag.tag.asc())
                    .limit(limit)
                    .all()
                )
                return [tag for tag, _count in rows]

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

                quality_filter = [Report.quality_score.isnot(None), self._content_policy_allows()]
                if user_id:
                    quality_filter.append(Report.user_id == user_id)

                # Get average quality score
                avg_quality = (
                    session.query(func.avg(Report.quality_score)).filter(*quality_filter).scalar()
                )

                # One aggregate row: width_bucket assigns 0-5 scores to five
                # unit buckets; 5.00 falls in the overflow bucket and joins 4-5.
                bucket = func.width_bucket(Report.quality_score, 0, 5, 5)
                counts = (
                    session.query(
                        func.count().filter(bucket == 1),
                        func.count().filter(bucket == 2),
                        func.count().filter(bucket == 3),
                        func.count().filter(bucket == 4),
                        func.count().filter(bucket.in_([5, 6])),
                        func.count(),
                    )
                    .filter(*quality_filter)
                    .all()
                )
                values = [int(value or 0) for value in counts[0]] if counts else [0] * 6
                buckets = {
                    "0.0-1.0": values[0],
                    "1.0-2.0": values[1],
                    "2.0-3.0": values[2],
                    "3.0-4.0": values[3],
                    "4.0-5.0": values[4],
                }
                total_scored = values[5]

                return {
                    "average": float(avg_quality) if avg_quality is not None else None,
                    "distribution": buckets,
                    "total_scored": total_scored,
                }

        except Exception as e:
            logger.error(f"Error getting quality score distribution: {e}")
            raise


# Global report storage service instance
report_service = ReportStorageService()
