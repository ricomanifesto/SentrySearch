"""LogPort over an injected CloudWatch Logs client: one page per call, unchanged tokens."""

from __future__ import annotations

from typing import Any

from release.ports import AmbiguousResponse
from release_aws.errors import AwsRequestRejected, call, require_client

MAX_PAGE_EVENTS = 10_000


class LogStreamMissing(LookupError):
    """The group or stream does not exist (yet); nothing was read."""


class CloudWatchLogs:
    """GetLogEvents read forward from the stream head; the caller owns pagination.

    Every call requests ``startFromHead`` (required when following forward tokens)
    and never unmasked data. Bounds and the caller's token pass through unchanged
    and the page comes back as received: no internal paging, retry or filtering.
    """

    def __init__(self, client: Any, *, region: str) -> None:
        require_client(client, service="logs", region=region)
        self.client = client

    def get_log_events(
        self,
        log_group: str,
        log_stream: str,
        *,
        start_time_ms: int,
        end_time_ms: int,
        next_token: str | None,
        limit: int,
    ) -> dict[str, Any]:
        if not (
            log_group
            and log_stream
            and type(start_time_ms) is int
            and type(end_time_ms) is int
            and 0 <= start_time_ms <= end_time_ms
            and type(limit) is int
            and 1 <= limit <= MAX_PAGE_EVENTS
            and (next_token is None or (isinstance(next_token, str) and next_token))
        ):
            raise ValueError("GetLogEvents request outside the reader contract")
        params: dict[str, Any] = {
            "logGroupName": log_group,
            "logStreamName": log_stream,
            "startTime": start_time_ms,
            "endTime": end_time_ms,
            "limit": limit,
            "startFromHead": True,
            "unmask": False,
        }
        if next_token is not None:
            params["nextToken"] = next_token
        missing = False
        try:
            response = call(self.client, "get_log_events", **params)
        except AwsRequestRejected as error:
            if error.code != "ResourceNotFoundException":
                raise
            missing = True
        if missing:
            raise LogStreamMissing("log group or stream not found")
        events = response.get("events")
        token = response.get("nextForwardToken")
        if not isinstance(events, list) or not isinstance(token, str) or not token:
            raise AmbiguousResponse("GetLogEvents: malformed response")
        page = []
        for event in events:
            if (
                not isinstance(event, dict)
                or type(event.get("timestamp")) is not int
                or not isinstance(event.get("message"), str)
            ):
                raise AmbiguousResponse("GetLogEvents: malformed event")
            page.append({"timestamp": event["timestamp"], "message": event["message"]})
        return {"events": page, "nextForwardToken": token}
