"""Operator preflight: prove who is calling and what time it is before any release action.

One ``sts:GetCallerIdentity`` request through the isolated client. Its account,
assumed-role ARN and user id must equal the separately approved operator
identity (the manifest account, an approved role and the manifest operator as
the role-session name). Its ``Date`` header, bracketed by the Clock's own
readings, becomes the Clock's reference. Any mismatch, error or missing value
refuses the run before a journal, lock or ECS request exists. The call needs no
permission, and it cannot prove the session's remaining lifetime.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from release_aws.errors import AwsRequestRejected, classify
from release_cli.clock import MonotonicUtcClock, ReferenceSample, parse_reference_date
from release_cli.credentials import SESSION_NAME

_ROLE_ARN = re.compile(r"arn:aws:iam::([0-9]{12}):role/(?:[\w+=,.@-]+/)*([\w+=,.@-]{1,64})")
_ROLE_ID = re.compile(r"AROA[A-Z0-9]{16,128}")


class PreflightRefused(Exception):
    """The caller or its time could not be proven; the reason carries no response text."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class OperatorIdentity:
    """The approved operator: an account, an IAM role and the role-session name."""

    account_id: str
    role_arn: str
    session_name: str

    def __post_init__(self) -> None:
        match = _ROLE_ARN.fullmatch(self.role_arn)
        if match is None or match.group(1) != self.account_id:
            raise PreflightRefused("operator_role_invalid")
        if not SESSION_NAME.fullmatch(self.session_name):
            raise PreflightRefused("operator_session_name_invalid")

    @property
    def assumed_role_arn(self) -> str:
        # Assumed-role ARNs carry the role name without its IAM path.
        name = self.role_arn.rsplit("/", 1)[1]
        return f"arn:aws:sts::{self.account_id}:assumed-role/{name}/{self.session_name}"


def verify_operator(sts: Any, expected: OperatorIdentity, clock: MonotonicUtcClock) -> None:
    """Bind caller identity and the Clock's reference, or raise ``PreflightRefused``."""
    sent_at = clock.now()
    failure: str | None = None
    try:
        response = sts.get_caller_identity()
    except (BotoCoreError, ClientError) as error:
        refused = isinstance(classify("GetCallerIdentity", error), AwsRequestRejected)
        failure = "identity_refused" if refused else "identity_unavailable"
    if failure is not None:
        raise PreflightRefused(failure)
    received_at = clock.now()
    if not isinstance(response, dict):
        raise PreflightRefused("identity_malformed")
    user_id = response.get("UserId")
    if (
        response.get("Account") != expected.account_id
        or response.get("Arn") != expected.assumed_role_arn
        or not isinstance(user_id, str)
        or ":" not in user_id
        or not _ROLE_ID.fullmatch(user_id.split(":", 1)[0])
        or user_id.split(":", 1)[1] != expected.session_name
    ):
        raise PreflightRefused("identity_mismatch")
    metadata = response.get("ResponseMetadata")
    headers = metadata.get("HTTPHeaders") if isinstance(metadata, dict) else None
    date = headers.get("date") if isinstance(headers, dict) else None
    reference = parse_reference_date(date)
    clock.bind_reference(ReferenceSample(sent_at, received_at, reference))
