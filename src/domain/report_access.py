"""Explicit authority for report operations addressed by ID."""

from enum import Enum


class ReportAccessScope(Enum):
    ALL = "all_reports"


def require_report_owner(owner: str | ReportAccessScope) -> str | None:
    """Only an explicit privileged scope may omit the owner predicate."""

    if owner is ReportAccessScope.ALL:
        return None
    if not isinstance(owner, str) or not owner.strip():
        raise ValueError("A report owner or explicit privileged scope is required")
    return owner
