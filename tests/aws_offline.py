"""Offline botocore clients for adapter tests.

Clients come from a session that ignores every AWS environment variable and
configuration file, use explicit fixture credentials, an explicit region, no SDK
retries and short timeouts. Requests never leave the process: botocore validates
and serializes each request against the pinned service model, then a
``before-call`` hook answers it from the in-process fakes in
``tests.release_fakes``, checking each answer against the model's output shape.
Nothing here models IAM, CloudWatch ingestion or S3 consistency.
"""

from __future__ import annotations

import copy
import io
import json
import socket
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

from botocore import configprovider
from botocore.awsrequest import AWSResponse
from botocore.config import Config
from botocore.exceptions import ReadTimeoutError
from botocore.response import StreamingBody
from botocore.session import Session
from botocore.validate import validate_parameters

from release.journal import PreconditionFailed
from release.ports import AmbiguousResponse
from release_tools.receipt import RECEIPT_MARKER
from tests.release_fakes import ACCOUNT, REGION, FakeEcs, FakeEvidence, FakeLogs, FakeStore

BUCKET = f"sentry-staging-{ACCOUNT}-control"
CLIENT_CONFIG = Config(retries={"total_max_attempts": 1}, connect_timeout=5, read_timeout=10)
# Ordinary application output that must never reach release evidence.
SENSITIVE_LINES = (
    "Traceback (most recent call last): password=fixture-secret-7Q2 token=sk-fixture-9Z1",
    "GET /api/reports/report-fixture-55aa?api_key=fixture-key-3C8 200",
    'ERROR {"user":"fixture-user@example.invalid","report_id":"report-fixture-77bb"}',
)


def isolated_session() -> Session:
    """A botocore session that reads no environment variable or configuration file."""
    variables = {
        name: (config_name, None, default, conversion)
        for name, (config_name, _env, default, conversion) in (
            configprovider.BOTOCORE_DEFAUT_SESSION_VARIABLES.items()
        )
    }
    variables["config_file"] = (None, None, "/nonexistent/sentry-release-test/config", None)
    variables["credentials_file"] = (None, None, "/nonexistent/sentry-release-test/creds", None)
    variables["ignore_configured_endpoint_urls"] = (None, None, True, None)
    return Session(session_vars=variables)


def offline_client(service: str, *, region: str = REGION, config: Config = CLIENT_CONFIG) -> Any:
    return isolated_session().create_client(
        service,
        region_name=region,
        aws_access_key_id="fixture-not-a-key",
        aws_secret_access_key="fixture-not-a-secret",
        config=config,
    )


class ServiceError(Exception):
    """An AWS error response: code and HTTP status, with a fixed message."""

    def __init__(self, code: str, status: int) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


class Transport(Exception):
    """Raised by a fake to simulate a lost connection or timeout."""


class SdkBridge:
    """Answer validated botocore requests from fake handlers, one call at a time."""

    def __init__(self) -> None:
        self.handlers: dict[tuple[str, str], Callable[[dict[str, Any]], dict[str, Any]]] = {}
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        # (service, operation) -> queued faults raised before the handler runs.
        self.faults: dict[tuple[str, str], list[Exception]] = {}

    def attach(self, client: Any) -> Any:
        service = client.meta.service_model.service_id.hyphenize()
        client.meta.events.register(f"before-parameter-build.{service}", self._remember)
        client.meta.events.register(f"before-call.{service}", self._respond)
        return client

    def fail(self, service: str, operation: str, *errors: Exception) -> None:
        self.faults.setdefault((service, operation), []).extend(errors)

    @staticmethod
    def _remember(params: dict[str, Any], context: dict[str, Any], **_: Any) -> None:
        context["sentry_api_params"] = dict(params)

    def _respond(self, model: Any, context: dict[str, Any], **_: Any) -> tuple[Any, dict]:
        service = model.service_model.service_name
        params = context["sentry_api_params"]
        self.calls.append((service, model.name, params))
        queued = self.faults.get((service, model.name))
        try:
            if queued:
                raise queued.pop(0)
            parsed = self.handlers[(service, model.name)](params)
        except (Transport, AmbiguousResponse):
            raise ReadTimeoutError(endpoint_url=f"https://{service}.{REGION}.amazonaws.com")
        except ServiceError as error:
            parsed = {
                "Error": {"Code": error.code, "Message": "fixture error"},
                "ResponseMetadata": {"HTTPStatusCode": error.status},
            }
            return AWSResponse("https://fixture.invalid", error.status, {}, None), parsed
        if model.output_shape is not None:
            validate_parameters(parsed, model.output_shape)
        parsed = {**parsed, "ResponseMetadata": {"HTTPStatusCode": 200}}
        return AWSResponse("https://fixture.invalid", 200, {}, None), parsed


def _paged(items: list[Any], params: dict[str, Any], key: str, page: int) -> dict[str, Any]:
    start = int(params.get("nextToken") or 0)
    size = min(params.get("maxResults") or page, page)
    response: dict[str, Any] = {key: items[start : start + size]}
    if start + size < len(items):
        response["nextToken"] = str(start + size)
    return response


class FakeAws:
    """Real adapters' SDK clients answered by the controller-test fakes."""

    def __init__(
        self,
        ecs: FakeEcs,
        logs: FakeLogs,
        evidence: FakeEvidence,
        store: FakeStore,
        document: dict,
    ) -> None:
        self.bridge = SdkBridge()
        self.ecs, self.logs, self.evidence, self.store = ecs, logs, evidence, store
        self.document = document
        self.list_page_size = 100
        self.job_page_size = 100
        # Extra ordinary lines written to each job stream, before its receipt.
        self.job_noise: tuple[str, ...] = SENSITIVE_LINES
        # Job id -> lines replacing the generated stream (e.g. duplicated receipts).
        self.job_streams: dict[str, list[str]] = {}
        handlers = {
            ("ecs", "RunTask"): lambda p: self.ecs.run_task(_ecs_request(p)),
            ("ecs", "DescribeTasks"): lambda p: self.ecs.describe_tasks(p["cluster"], p["tasks"]),
            ("ecs", "ListTasks"): self._list_tasks,
            ("ecs", "UpdateService"): lambda p: self.ecs.update_service(dict(p)),
            ("ecs", "DescribeServices"): lambda p: {
                "services": self.ecs.describe_services(p["cluster"], p["services"]),
                "failures": [],
            },
            ("ecs", "StopTask"): lambda p: self.ecs.stop_task(p["cluster"], p["task"], p["reason"]),
            ("logs", "GetLogEvents"): self._get_log_events,
            ("s3", "PutObject"): self._put_object,
            ("s3", "GetObject"): self._get_object,
            ("s3", "DeleteObject"): self._delete_object,
        }
        self.bridge.handlers.update(handlers)

    def client(self, service: str, **kwargs: Any) -> Any:
        return self.bridge.attach(offline_client(service, **kwargs))

    # ECS ------------------------------------------------------------------
    def _list_tasks(self, params: dict[str, Any]) -> dict[str, Any]:
        arns = self.ecs.list_tasks(
            params["cluster"],
            started_by=params.get("startedBy"),
            service_name=params.get("serviceName"),
        )
        wanted = params.get("desiredStatus", "RUNNING")
        if params.get("startedBy") is not None:
            arns = [
                arn
                for arn in arns
                if self.ecs._describe(self.ecs.tasks[arn])["desiredStatus"] == wanted
            ]
        elif wanted != "RUNNING":
            arns = []
        return _paged(arns, params, "taskArns", self.list_page_size)

    # CloudWatch Logs --------------------------------------------------------
    def _get_log_events(self, params: dict[str, Any]) -> dict[str, Any]:
        assert params["startFromHead"] is True and params["unmask"] is False
        stream = params["logStreamName"]
        if stream.startswith("worker/"):
            try:
                return self.logs.get_log_events(
                    params["logGroupName"],
                    stream,
                    start_time_ms=params["startTime"],
                    end_time_ms=params["endTime"],
                    next_token=params.get("nextToken"),
                    limit=params["limit"],
                )
            except PermissionError:
                raise ServiceError("AccessDeniedException", 400) from None
            except LookupError:
                raise ServiceError("ResourceNotFoundException", 400) from None
        lines = self._job_lines(params["logGroupName"], stream)
        start = int((params.get("nextToken") or "f/0").split("/")[1])
        page = lines[start : start + min(params["limit"], self.job_page_size)]
        events = [{"timestamp": params["startTime"], "message": line} for line in page]
        token = f"f/{start + len(page)}" if page else (params.get("nextToken") or "f/0")
        return {"events": events, "nextForwardToken": token}

    def _job_lines(self, group: str, stream: str) -> list[str]:
        prefix, container, task_id = stream.split("/")
        task = next((t for arn, t in self.ecs.tasks.items() if arn.endswith("/" + task_id)), None)
        if task is None:
            raise ServiceError("ResourceNotFoundException", 400)
        job_id = task.tags.get("sentry:job-id")
        job = next((j for j in self.document["jobs"] if j["id"] == job_id), None)
        environment = self.document["environment"]["name"]
        if (
            job_id is None
            or job is None
            or group != f"/{environment}/{job['database']}-release"
            # Terraform's awslogs prefix: <database>-release, or <database>-<kind>.
            or prefix
            != (
                f"{job['database']}-release"
                if job["phase"] == "migrate"
                else f"{job['database']}-{job['phase']}"
            )
            or container not in {c["name"] for c in job["task"]["containers"]}
        ):
            raise ServiceError("ResourceNotFoundException", 400)
        if job_id in self.job_streams:
            return list(self.job_streams[job_id])
        receipt = self.evidence.job_receipt(self.document["release_id"], job_id, task.arn)
        lines = list(self.job_noise)
        if receipt is not None:
            lines.append(f"{RECEIPT_MARKER} {json.dumps(receipt, separators=(',', ':'))}")
        return lines

    # S3 -------------------------------------------------------------------
    def _bucket(self, params: dict[str, Any]) -> None:
        assert params["Bucket"] == BUCKET and params["ExpectedBucketOwner"] == ACCOUNT

    def _put_object(self, params: dict[str, Any]) -> dict[str, Any]:
        self._bucket(params)
        body = body_bytes(params["Body"])
        try:
            if params.get("IfNoneMatch") == "*":
                etag = self.store.create(params["Key"], body)
            else:
                etag = self.store.replace(params["Key"], body, if_match=params["IfMatch"])
        except PreconditionFailed:
            raise ServiceError("PreconditionFailed", 412) from None
        return {"ETag": etag}

    def _get_object(self, params: dict[str, Any]) -> dict[str, Any]:
        self._bucket(params)
        found = self.store.read(params["Key"])
        if found is None:
            raise ServiceError("NoSuchKey", 404)
        body, etag = found
        return {
            "Body": StreamingBody(io.BytesIO(body), len(body)),
            "ContentLength": len(body),
            "ETag": etag,
        }

    def _delete_object(self, params: dict[str, Any]) -> dict[str, Any]:
        self._bucket(params)
        try:
            self.store.delete(params["Key"], if_match=params["IfMatch"])
        except PreconditionFailed:
            raise ServiceError("PreconditionFailed", 412) from None
        return {}


def body_bytes(body: Any) -> bytes:
    """botocore wraps a bytes body in a file-like object before the request hooks run."""
    if isinstance(body, bytes):
        return body
    position = body.tell()
    data = body.read()
    body.seek(position)
    return data


def _ecs_request(params: dict[str, Any]) -> dict[str, Any]:
    return copy.deepcopy(params)


@contextmanager
def network_denied() -> Iterator[list[str]]:
    """Fail and record any attempt to resolve or connect while the block runs."""
    attempts: list[str] = []
    saved = {
        "connect": socket.socket.connect,
        "connect_ex": socket.socket.connect_ex,
        "create_connection": socket.create_connection,
        "getaddrinfo": socket.getaddrinfo,
    }

    def deny(name: str) -> Callable[..., Any]:
        def blocked(*_args: Any, **_kwargs: Any) -> Any:
            attempts.append(name)
            raise OSError(f"network access denied by adapter test: {name}")

        return blocked

    setattr(socket.socket, "connect", deny("connect"))
    setattr(socket.socket, "connect_ex", deny("connect_ex"))
    setattr(socket, "create_connection", deny("create_connection"))
    setattr(socket, "getaddrinfo", deny("getaddrinfo"))
    try:
        yield attempts
    finally:
        setattr(socket.socket, "connect", saved["connect"])
        setattr(socket.socket, "connect_ex", saved["connect_ex"])
        setattr(socket, "create_connection", saved["create_connection"])
        setattr(socket, "getaddrinfo", saved["getaddrinfo"])
