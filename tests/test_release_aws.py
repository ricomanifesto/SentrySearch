"""AWS adapters against stubbed SDK responses, injected clients and denied network.

Stubber tests pin each adapter's exact SDK request and error mapping. The full
controller runs drive the real adapters and botocore request validation, answered
by the in-process fakes (tests/aws_offline.py). None of this is IAM evaluation,
CloudWatch ingestion, ECS scheduling or S3 consistency evidence.
"""

from __future__ import annotations

import ast
import copy
import io
import json
from datetime import timedelta
from pathlib import Path

import pytest
from botocore.awsrequest import AWSResponse
from botocore.config import Config
from botocore.response import StreamingBody
from botocore.stub import Stubber

from release.controller import RecoveryAuthorization, ReleaseController, ReleaseHalted
from release.journal import PreconditionFailed
from release.manifest import load_approval, load_manifest
from release.ports import AmbiguousResponse
from release_aws.ecs import EcsAdapter
from release_aws.errors import AwsRequestRejected, require_client
from release_aws.evidence import LogEvidence, job_stream
from release_aws.logs import CloudWatchLogs, LogStreamMissing
from release_aws.store import S3ObjectStore
from release_tools.receipt import RECEIPT_MARKER
from tests.aws_offline import (
    BUCKET,
    SENSITIVE_LINES,
    FakeAws,
    ServiceError,
    Transport,
    body_bytes,
    carried_text,
    exception_chain,
    network_denied,
    offline_client,
)
from tests.release_fakes import (
    ACCOUNT,
    CLUSTER,
    REGION,
    RELEASE_ID,
    FakeClock,
    FakeEcs,
    FakeEvidence,
    FakeLogs,
    FakeStore,
    SimulatedCrash,
    Tokens,
    Trace,
    approval_document,
    encode,
    manifest_document,
    sha,
)
from tests.test_release_controller import JOURNAL, LOCK, Rig, assert_held

REPO = Path(__file__).resolve().parents[1]
TASK = f"arn:aws:ecs:{REGION}:{ACCOUNT}:task/sentry-staging/" + "a" * 32


@pytest.fixture(autouse=True)
def no_network():
    with network_denied() as attempts:
        yield
    assert attempts == [], "an adapter test attempted network access"


# Injected clients -------------------------------------------------------------


def test_adapters_never_create_sessions_or_read_ambient_configuration():
    for path in sorted((REPO / "release_aws").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names |= {alias.name for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                names.add(node.module or "")
        assert not {"boto3", "botocore.session", "dotenv", "os", "socket"} & names, path.name
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                assert node.attr not in {"create_client", "get_credentials", "environ"}, path.name


@pytest.mark.parametrize(
    "config, region, message",
    [
        (Config(connect_timeout=5, read_timeout=10), REGION, "retries"),
        (Config(retries={"total_max_attempts": 2}, connect_timeout=5, read_timeout=10), REGION,
         "retries"),
        (Config(retries={"total_max_attempts": 1}), REGION, "connect_timeout"),
        (Config(retries={"total_max_attempts": 1}, connect_timeout=5, read_timeout=31), REGION,
         "read_timeout"),
        (Config(retries={"total_max_attempts": 1}, connect_timeout=5, read_timeout=10),
         "us-west-2", "region"),
        (Config(retries={"total_max_attempts": 1, "mode": "adaptive"}, connect_timeout=5,
                read_timeout=10), REGION, "mode"),
    ],
)  # fmt: skip
def test_clients_that_retry_wait_unboundedly_or_target_another_region_are_refused(
    config, region, message
):
    client = offline_client("ecs", region=region, config=config)
    with pytest.raises(ValueError, match=message):
        EcsAdapter(client, region=REGION, cluster_arn=CLUSTER)


def test_a_client_for_another_service_is_refused():
    with pytest.raises(ValueError, match="logs"):
        require_client(offline_client("ecs"), service="logs", region=REGION)


# ECS --------------------------------------------------------------------------


def launch_request(**changes) -> dict:
    request = {
        "cluster": CLUSTER,
        "taskDefinition": f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/sentry-staging-x:7",
        "count": 1,
        "launchType": "FARGATE",
        "platformVersion": "1.4.0",
        "networkConfiguration": {
            "awsvpcConfiguration": {
                "subnets": ["subnet-0a1b2c3d4e5f60718"],
                "securityGroups": ["sg-0a1b2c3d4e5f60718"],
                "assignPublicIp": "DISABLED",
            }
        },
        "enableExecuteCommand": False,
        "startedBy": "tok-0000000000000001",
        "clientToken": "tok-0000000000000001",
        "tags": [{"key": "sentry:release-id", "value": RELEASE_ID}],
    }
    request.update(changes)
    return request


def ecs_adapter() -> tuple[EcsAdapter, Stubber]:
    client = offline_client("ecs")
    return EcsAdapter(client, region=REGION, cluster_arn=CLUSTER), Stubber(client)


def test_run_task_sends_exactly_the_controller_request_once():
    adapter, stub = ecs_adapter()
    request = launch_request()
    task = {"taskArn": TASK, "startedBy": request["startedBy"]}
    stub.add_response("run_task", {"tasks": [task], "failures": []}, copy.deepcopy(request))
    with stub:
        assert adapter.run_task(request) == {"tasks": [task], "failures": []}
    stub.assert_no_pending_responses()


@pytest.mark.parametrize(
    "changes",
    [
        {"overrides": {"containerOverrides": [{"name": "app", "command": ["sh"]}]}},
        {"overrides": {"taskRoleArn": "arn:aws:iam::111122223333:role/other"}},
        {"volumeConfigurations": []},
        {"placementConstraints": []},
        {"capacityProviderStrategy": [{"capacityProvider": "FARGATE_SPOT"}]},
        {"group": "family:other"},
        {"propagateTags": "TASK_DEFINITION"},
        {"enableECSManagedTags": True},
        {"count": 2},
        {"launchType": "EC2"},
        {"enableExecuteCommand": True},
        {"startedBy": "tok-other-000000001"},
        {"cluster": f"arn:aws:ecs:{REGION}:{ACCOUNT}:cluster/other"},
        {"networkConfiguration": {"awsvpcConfiguration": {
            "subnets": ["subnet-0a1b2c3d4e5f60718"], "securityGroups": ["sg-0a1b2c3d4e5f60718"],
            "assignPublicIp": "ENABLED"}}},
    ],
)  # fmt: skip
def test_run_task_outside_the_contract_is_refused_before_any_request(changes):
    adapter, stub = ecs_adapter()
    with stub, pytest.raises(ValueError):
        adapter.run_task(launch_request(**changes))
    stub.assert_no_pending_responses()


@pytest.mark.parametrize(
    "request_",
    [
        {"cluster": CLUSTER, "service": "svc", "desiredCount": 0},
        {"cluster": CLUSTER, "service": "svc", "taskDefinition": "td:7", "desiredCount": 1,
         "forceNewDeployment": True},
    ],
)  # fmt: skip
def test_update_service_forwards_only_controller_owned_fields(request_):
    adapter, stub = ecs_adapter()
    stub.add_response("update_service", {"service": {"serviceArn": "svc"}}, dict(request_))
    with stub:
        assert adapter.update_service(request_) == {"service": {"serviceArn": "svc"}}
    stub.assert_no_pending_responses()


@pytest.mark.parametrize(
    "extra",
    [
        {"deploymentConfiguration": {"deploymentCircuitBreaker": {"enable": True, "rollback": False}}},
        {"deploymentConfiguration": {"maximumPercent": 100, "minimumHealthyPercent": 0}},
        {"enableExecuteCommand": False},
        {"networkConfiguration": {}},
        {"platformVersion": "LATEST"},
        {"capacityProviderStrategy": []},
        {"desiredCount": 2},
        {"forceNewDeployment": False},
    ],
)  # fmt: skip
def test_update_service_never_sends_terraform_owned_settings(extra):
    adapter, stub = ecs_adapter()
    request = {"cluster": CLUSTER, "service": "svc", "taskDefinition": "td:7",
               "desiredCount": 1, "forceNewDeployment": True, **extra}  # fmt: skip
    with stub, pytest.raises(ValueError):
        adapter.update_service(request)
    stub.assert_no_pending_responses()


def test_listing_follows_every_page_to_the_end():
    adapter, stub = ecs_adapter()
    arns = [f"{TASK[:-4]}{i:04x}" for i in range(5)]
    base = {
        "cluster": CLUSTER,
        "maxResults": 100,
        "desiredStatus": "RUNNING",
        "serviceName": "worker",
    }
    stub.add_response("list_tasks", {"taskArns": arns[:2], "nextToken": "t1"}, dict(base))
    stub.add_response("list_tasks", {"taskArns": arns[2:4], "nextToken": "t2"},
                      {**base, "nextToken": "t1"})  # fmt: skip
    stub.add_response("list_tasks", {"taskArns": arns[4:]}, {**base, "nextToken": "t2"})
    with stub:
        assert adapter.list_tasks(CLUSTER, service_name="worker") == arns
    stub.assert_no_pending_responses()


OTHER = TASK[:-1] + "b"
THIRD = TASK[:-1] + "c"


def stopped_listing(stub: Stubber, tasks: list[dict]) -> None:
    """The cluster-wide STOPPED listing and its complete description."""
    arns = [task["taskArn"] for task in tasks]
    stub.add_response("list_tasks", {"taskArns": arns},
                      {"cluster": CLUSTER, "maxResults": 100, "desiredStatus": "STOPPED"})  # fmt: skip
    if arns:
        stub.add_response("describe_tasks", {"tasks": tasks, "failures": []},
                          {"cluster": CLUSTER, "tasks": arns})  # fmt: skip


def test_launch_token_listing_uses_started_by_alone_and_adds_exited_launches():
    # ECS takes startedBy only as the sole filter (tasks it still intends to run);
    # a launch that already exited is found among the described stopped tasks.
    adapter, stub = ecs_adapter()
    stub.add_response("list_tasks", {"taskArns": [TASK]},
                      {"cluster": CLUSTER, "maxResults": 100, "startedBy": "tok-1"})  # fmt: skip
    stopped_listing(stub, [{"taskArn": OTHER, "startedBy": "tok-1", "lastStatus": "STOPPED"},
                           {"taskArn": THIRD, "startedBy": "tok-2", "lastStatus": "STOPPED"}])  # fmt: skip
    with stub:
        assert adapter.list_tasks(CLUSTER, started_by="tok-1") == [TASK, OTHER]
    stub.assert_no_pending_responses()


def test_cluster_listing_includes_tasks_still_stopping():
    # A requested stop flips the desired status at once; the process may run on.
    adapter, stub = ecs_adapter()
    stub.add_response("list_tasks", {"taskArns": [TASK]},
                      {"cluster": CLUSTER, "maxResults": 100, "desiredStatus": "RUNNING"})  # fmt: skip
    stopped_listing(stub, [{"taskArn": OTHER, "lastStatus": "DEPROVISIONING"},
                           {"taskArn": THIRD, "lastStatus": "STOPPED"}])  # fmt: skip
    with stub:
        assert adapter.list_tasks(CLUSTER) == [TASK, OTHER]
    stub.assert_no_pending_responses()


def test_a_stopped_task_that_cannot_be_described_is_ambiguous():
    adapter, stub = ecs_adapter()
    stub.add_response("list_tasks", {"taskArns": []})
    stub.add_response("list_tasks", {"taskArns": [OTHER]})
    stub.add_response(
        "describe_tasks", {"tasks": [], "failures": [{"arn": OTHER, "reason": "MISSING"}]}
    )
    with stub, pytest.raises(AmbiguousResponse):
        adapter.list_tasks(CLUSTER)


def test_a_listing_page_without_its_task_list_is_ambiguous():
    adapter, stub = ecs_adapter()
    stub.add_response("list_tasks", {})
    with stub, pytest.raises(AmbiguousResponse):
        adapter.list_tasks(CLUSTER, service_name="worker")


def test_descriptions_that_omit_a_requested_resource_are_ambiguous():
    adapter, stub = ecs_adapter()
    stub.add_response("describe_tasks", {"tasks": [{"taskArn": TASK}], "failures": []})
    stub.add_response("describe_services", {"services": [], "failures": []})
    with stub:
        with pytest.raises(AmbiguousResponse):
            adapter.describe_tasks(CLUSTER, [TASK, OTHER])
        with pytest.raises(AmbiguousResponse):
            adapter.describe_services(CLUSTER, ["arn:aws:ecs:us-east-1:111122223333:service/c/s"])


@pytest.mark.parametrize("code, status", [("ThrottlingException", 400), ("ServerException", 500)])
def test_a_failed_page_makes_the_listing_ambiguous_never_partial(code, status):
    adapter, stub = ecs_adapter()
    stub.add_response("list_tasks", {"taskArns": [TASK], "nextToken": "t1"})
    stub.add_client_error("list_tasks", service_error_code=code, http_status_code=status)
    with stub, pytest.raises(AmbiguousResponse):
        adapter.list_tasks(CLUSTER)


def test_an_unbounded_listing_is_ambiguous():
    adapter, stub = ecs_adapter()
    for page in range(20):
        stub.add_response("list_tasks", {"taskArns": [], "nextToken": f"t{page}"})
    with stub, pytest.raises(AmbiguousResponse, match="page bound"):
        adapter.list_tasks(CLUSTER)
    stub.assert_no_pending_responses()


def test_describe_tasks_covers_every_requested_task_in_batches():
    adapter, stub = ecs_adapter()
    arns = [f"{TASK[:-4]}{i:04x}" for i in range(205)]
    for start in (0, 100, 200):
        batch = arns[start : start + 100]
        stub.add_response(
            "describe_tasks",
            {"tasks": [{"taskArn": arn} for arn in batch[1:]],
             "failures": [{"arn": batch[0], "reason": "MISSING"}]},
            {"cluster": CLUSTER, "tasks": batch},
        )  # fmt: skip
    with stub:
        result = adapter.describe_tasks(CLUSTER, arns)
    assert len(result["tasks"]) == 202 and len(result["failures"]) == 3
    stub.assert_no_pending_responses()


@pytest.mark.parametrize(
    "code, status, expected",
    [
        ("ThrottlingException", 400, AmbiguousResponse),
        ("ServerException", 500, AmbiguousResponse),
        ("ServiceUnavailableException", 503, AmbiguousResponse),
        ("AccessDeniedException", 400, AwsRequestRejected),
        ("ClientException", 400, AwsRequestRejected),
        ("InvalidParameterException", 400, AwsRequestRejected),
    ],
)
def test_sdk_errors_are_unknown_outcomes_or_sanitized_refusals(code, status, expected):
    adapter, stub = ecs_adapter()
    secret = "arn:aws:secretsmanager:fixture-sensitive-message"
    stub.add_client_error(
        "run_task", service_error_code=code, service_message=secret, http_status_code=status
    )
    with stub, pytest.raises(expected) as error:
        adapter.run_task(launch_request())
    # Nothing chains back to the SDK error, whose message quotes the provider.
    assert exception_chain(error.value) == [error.value]
    assert secret not in carried_text(error.value)


# CloudWatch Logs ----------------------------------------------------------------


def logs_adapter() -> tuple[CloudWatchLogs, Stubber]:
    client = offline_client("logs")
    return CloudWatchLogs(client, region=REGION), Stubber(client)


def test_get_log_events_reads_forward_from_head_unmasked_never_and_passes_tokens_through():
    adapter, stub = logs_adapter()
    expected = {"logGroupName": "/g", "logStreamName": "s", "startTime": 10, "endTime": 20,
                "limit": 100, "startFromHead": True, "unmask": False}  # fmt: skip
    stub.add_response(
        "get_log_events",
        {"events": [{"timestamp": 11, "message": "m", "ingestionTime": 12}],
         "nextForwardToken": "f/opaque/1", "nextBackwardToken": "b/1"},
        dict(expected),
    )  # fmt: skip
    stub.add_response(
        "get_log_events",
        {"events": [], "nextForwardToken": "f/opaque/1"},
        {**expected, "nextToken": "f/opaque/1"},
    )
    with stub:
        first = adapter.get_log_events("/g", "s", start_time_ms=10, end_time_ms=20,
                                       next_token=None, limit=100)  # fmt: skip
        assert first == {"events": [{"timestamp": 11, "message": "m"}],
                         "nextForwardToken": "f/opaque/1"}  # fmt: skip
        second = adapter.get_log_events("/g", "s", start_time_ms=10, end_time_ms=20,
                                        next_token=first["nextForwardToken"], limit=100)  # fmt: skip
        assert second == {"events": [], "nextForwardToken": "f/opaque/1"}
    stub.assert_no_pending_responses()


@pytest.mark.parametrize(
    "code, expected",
    [
        ("ResourceNotFoundException", LogStreamMissing),
        ("AccessDeniedException", AwsRequestRejected),
        ("ThrottlingException", AmbiguousResponse),
    ],
)
def test_log_read_failures_are_classified(code, expected):
    adapter, stub = logs_adapter()
    stub.add_client_error("get_log_events", service_error_code=code, http_status_code=400)
    with stub, pytest.raises(expected):
        adapter.get_log_events("/g", "s", start_time_ms=0, end_time_ms=1, next_token=None, limit=1)


@pytest.mark.parametrize("page", [{"events": []}, {"events": [], "nextForwardToken": ""}])
def test_a_page_without_a_forward_token_is_ambiguous(page):
    # Parsed responses are not validated against the model, so answer below Stubber.
    client = offline_client("logs")
    client.meta.events.register(
        "before-call.cloudwatch-logs.GetLogEvents",
        lambda **_: (AWSResponse("https://fixture.invalid", 200, {}, None), dict(page)),
    )
    adapter = CloudWatchLogs(client, region=REGION)
    with pytest.raises(AmbiguousResponse):
        adapter.get_log_events("/g", "s", start_time_ms=0, end_time_ms=1, next_token=None, limit=1)


@pytest.mark.parametrize(
    "start, end, limit, token",
    [(5, 4, 1, None), (0, 1, 0, None), (0, 1, 10_001, None), (-1, 1, 1, None), (0, 1, 1, "")],
)
def test_reads_outside_the_reader_contract_send_nothing(start, end, limit, token):
    adapter, stub = logs_adapter()
    with stub, pytest.raises(ValueError):
        adapter.get_log_events("/g", "s", start_time_ms=start, end_time_ms=end,
                               next_token=token, limit=limit)  # fmt: skip


# Job receipts ---------------------------------------------------------------------


MANIFEST = load_manifest(encode(manifest_document())).manifest
JOBS = {job.id: job for job in MANIFEST.jobs}
RECEIPT = {"schema": "sentry.release-tools.job.v1", "release_id": RELEASE_ID,
           "job_id": "runtime-grant", "task_arn": TASK, "status": "succeeded",
           "result": {"database": "runtime_db"}}  # fmt: skip


@pytest.mark.parametrize(
    "job_id, stream",
    [
        ("runtime-migrate", ("/staging/runtime-release", "runtime-release/migration/" + "a" * 32)),
        ("product-migrate", ("/staging/product-release", "product-release/migration/" + "a" * 32)),
        ("runtime-grant", ("/staging/runtime-release", "runtime-grant/grant/" + "a" * 32)),
        ("product-proof", ("/staging/product-release", "product-proof/proof/" + "a" * 32)),
    ],
)
def test_job_receipts_come_from_the_observed_tasks_own_stream(job_id, stream):
    assert job_stream("staging", JOBS[job_id], TASK) == stream


class PagedLogs:
    """A LogPort over fixed lines, one event per page; records every request."""

    def __init__(self, lines, *, missing=False, endless=False):
        self.lines, self.missing, self.endless = list(lines), missing, endless
        self.calls: list[dict] = []

    def get_log_events(self, log_group, log_stream, **kwargs):
        self.calls.append({"group": log_group, "stream": log_stream, **kwargs})
        if self.missing:
            raise LogStreamMissing("not found")
        token = kwargs["next_token"]
        position = int(token.split("/")[1]) if token else 0
        if self.endless:
            return {"events": [], "nextForwardToken": f"f/{position + 1}"}
        page = self.lines[position : position + 1]
        events = [{"timestamp": 0, "message": line} for line in page]
        following = f"f/{position + len(page)}" if page else (token or "f/0")
        return {"events": events, "nextForwardToken": following}


def receipt_line(document: dict) -> str:
    return f"{RECEIPT_MARKER} {json.dumps(document, separators=(',', ':'))}"


def test_only_the_parsed_receipt_leaves_a_stream_full_of_application_output():
    logs = PagedLogs([*SENSITIVE_LINES, receipt_line(RECEIPT), *SENSITIVE_LINES])
    evidence = LogEvidence(logs, MANIFEST)
    receipt = evidence.job_receipt(RELEASE_ID, "runtime-grant", TASK)
    assert receipt == RECEIPT
    assert not any(line[:20] in json.dumps(receipt) for line in SENSITIVE_LINES)
    # Every page used the same fixed window bounds and followed the stream to its end.
    bounds = {(c["start_time_ms"], c["end_time_ms"]) for c in logs.calls}
    assert bounds == {
        (int(MANIFEST.window.not_before.timestamp() * 1000),
         int(MANIFEST.window.expires_at.timestamp() * 1000))
    }  # fmt: skip
    # One event per page, then the page that returns the caller's own token.
    assert len(logs.calls) == 2 * len(SENSITIVE_LINES) + 2


@pytest.mark.parametrize(
    "lines",
    [
        [receipt_line(RECEIPT), receipt_line(RECEIPT)],
        [RECEIPT_MARKER + "{not json"],
        [receipt_line({**RECEIPT, "extra": "x"})],
        [*SENSITIVE_LINES, RECEIPT_MARKER + " " + SENSITIVE_LINES[0]],
    ],
)
def test_duplicate_or_malformed_receipts_are_ambiguous_without_echoing_content(lines):
    evidence = LogEvidence(PagedLogs(lines), MANIFEST)
    with pytest.raises(AmbiguousResponse) as error:
        evidence.job_receipt(RELEASE_ID, "runtime-grant", TASK)
    # The parser's errors quote the raw line; none of them may travel with this one.
    assert exception_chain(error.value) == [error.value]
    assert all(line[:20] not in carried_text(error.value) for line in SENSITIVE_LINES)


def test_a_log_line_that_cannot_be_encoded_is_still_counted_without_raising():
    lone_surrogate = "report " + chr(0xD800) + " fixture-secret-7Q2"
    evidence = LogEvidence(PagedLogs([lone_surrogate, receipt_line(RECEIPT)]), MANIFEST)
    assert evidence.job_receipt(RELEASE_ID, "runtime-grant", TASK) == RECEIPT


def test_absent_stream_or_receipt_is_missing_evidence_not_success():
    assert (
        LogEvidence(PagedLogs([], missing=True), MANIFEST).job_receipt(
            RELEASE_ID, "runtime-grant", TASK
        )
        is None
    )
    assert (
        LogEvidence(PagedLogs(SENSITIVE_LINES), MANIFEST).job_receipt(
            RELEASE_ID, "runtime-grant", TASK
        )
        is None
    )


def test_an_unbounded_or_oversized_stream_is_incomplete_evidence():
    with pytest.raises(AmbiguousResponse, match="read bound"):
        LogEvidence(PagedLogs([], endless=True), MANIFEST).job_receipt(
            RELEASE_ID, "runtime-grant", TASK
        )
    huge = ["x" * 100_000] * 3 + [receipt_line(RECEIPT)]
    with pytest.raises(AmbiguousResponse, match="read bound"):
        LogEvidence(PagedLogs(huge), MANIFEST).job_receipt(RELEASE_ID, "runtime-grant", TASK)


def test_unimplemented_observers_stay_unproven():
    evidence = LogEvidence(PagedLogs([]), MANIFEST)
    for check in MANIFEST.operational_checks:
        assert evidence.operational_receipt(RELEASE_ID, check.id) is None
    with pytest.raises(ValueError):
        evidence.job_receipt("5e6f7a8b-1c2d-4e3f-8a9b-0c1d2e3f4a5b", "runtime-grant", TASK)


# S3 journal and lock ----------------------------------------------------------------


def store_adapter() -> tuple[S3ObjectStore, Stubber]:
    client = offline_client("s3")
    return S3ObjectStore(client, region=REGION, bucket=BUCKET, expected_owner=ACCOUNT), Stubber(
        client
    )


def put_params(**changes) -> dict:
    return {"Bucket": BUCKET, "ExpectedBucketOwner": ACCOUNT, "Key": LOCK, "Body": b"{}",
            "ContentType": "application/json", **changes}  # fmt: skip


def test_conditional_writes_name_the_owner_and_exact_precondition():
    store, stub = store_adapter()
    stub.add_response("put_object", {"ETag": '"e1"'}, put_params(IfNoneMatch="*"))
    stub.add_response("put_object", {"ETag": '"e2"'}, put_params(IfMatch='"e1"'))
    stub.add_response(
        "delete_object",
        {},
        {"Bucket": BUCKET, "ExpectedBucketOwner": ACCOUNT, "Key": LOCK, "IfMatch": '"e2"'},
    )
    with stub:
        assert store.create(LOCK, b"{}") == '"e1"'
        assert store.replace(LOCK, b"{}", if_match='"e1"') == '"e2"'
        store.delete(LOCK, if_match='"e2"')
    stub.assert_no_pending_responses()


@pytest.mark.parametrize(
    "operation, code, status",
    [
        ("create", "PreconditionFailed", 412),
        ("create", "ConditionalRequestConflict", 409),
        ("replace", "PreconditionFailed", 412),
        ("replace", "NoSuchKey", 404),
        ("replace", "ConditionalRequestConflict", 409),
        ("delete", "PreconditionFailed", 412),
        ("delete", "NoSuchKey", 404),
    ],
)
def test_a_lost_conditional_race_is_a_precondition_failure(operation, code, status):
    """A replaced or deleted object no longer matches: the race was lost, cleanly."""
    store, stub = store_adapter()
    method = "delete_object" if operation == "delete" else "put_object"
    stub.add_client_error(method, service_error_code=code, http_status_code=status)
    with stub, pytest.raises(PreconditionFailed):
        {
            "create": lambda: store.create(LOCK, b"{}"),
            "replace": lambda: store.replace(LOCK, b"{}", if_match='"e1"'),
            "delete": lambda: store.delete(LOCK, if_match='"e1"'),
        }[operation]()


@pytest.mark.parametrize(
    "code, status, expected",
    [
        ("InternalError", 500, AmbiguousResponse),
        ("SlowDown", 503, AmbiguousResponse),
        ("AccessDenied", 403, AwsRequestRejected),
        # A missing bucket is a refusal, not a lost race on the object.
        ("NoSuchBucket", 404, AwsRequestRejected),
    ],
)
def test_a_write_with_unknown_outcome_is_ambiguous_not_a_lost_race(code, status, expected):
    store, stub = store_adapter()
    stub.add_client_error("put_object", service_error_code=code, http_status_code=status,
                          service_message="journal for report-fixture-55aa")  # fmt: skip
    with stub, pytest.raises(expected) as error:
        store.replace(JOURNAL, b"{}", if_match='"e1"')
    assert exception_chain(error.value) == [error.value]
    assert "report-fixture" not in carried_text(error.value)


def test_reads_distinguish_absent_from_refused():
    store, stub = store_adapter()
    stub.add_client_error("get_object", service_error_code="NoSuchKey", http_status_code=404)
    stub.add_client_error("get_object", service_error_code="AccessDenied", http_status_code=403)
    stub.add_response(
        "get_object",
        {"Body": StreamingBody(_bytes(b'{"a":1}'), 7), "ContentLength": 7, "ETag": '"e9"'},
        {"Bucket": BUCKET, "ExpectedBucketOwner": ACCOUNT, "Key": JOURNAL},
    )
    stub.add_response(
        "get_object",
        {"Body": StreamingBody(_bytes(b'{"a"'), 4), "ContentLength": 7, "ETag": '"e9"'},
    )
    with stub:
        assert store.read(LOCK) is None
        with pytest.raises(AwsRequestRejected):
            store.read(LOCK)
        assert store.read(JOURNAL) == (b'{"a":1}', '"e9"')
        with pytest.raises(AmbiguousResponse):
            store.read(JOURNAL)


def test_only_journal_and_lock_keys_are_written():
    store, stub = store_adapter()
    for key in ("state/releases.tfstate", "releases/x/journal.json", "locks/../state.json"):
        with stub, pytest.raises(ValueError):
            store.create(key, b"{}")
    stub.assert_no_pending_responses()


def _bytes(data: bytes) -> io.BytesIO:
    return io.BytesIO(data)


# Whole releases through the adapters ---------------------------------------------------


def aws_rig(*, checks: str = "all") -> tuple[Rig, FakeAws]:
    document = manifest_document()
    if checks == "worker":
        document["operational_checks"] = [
            check for check in document["operational_checks"] if check["id"] == "worker-readiness"
        ]
    loaded = load_manifest(encode(document))
    clock, trace = FakeClock(), Trace()
    store, ecs = FakeStore(trace), FakeEcs(clock, trace)
    ecs.configure(document)
    r = Rig(
        document=document,
        clock=clock,
        trace=trace,
        store=store,
        ecs=ecs,
        evidence=FakeEvidence(ecs, document),
        logs=FakeLogs(ecs, document),
        tokens=Tokens(),
        approval_raw=encode(approval_document(loaded.sha256)),
    )
    return r, FakeAws(r.ecs, r.logs, r.evidence, r.store, document)


def adapted(r: Rig, aws: FakeAws, session: str = "session-a") -> ReleaseController:
    loaded = load_manifest(encode(r.document))
    logs = CloudWatchLogs(aws.client("logs"), region=REGION)
    return ReleaseController(
        loaded,
        load_approval(r.approval_raw),
        store=S3ObjectStore(aws.client("s3"), region=REGION, bucket=BUCKET, expected_owner=ACCOUNT),
        ecs=EcsAdapter(aws.client("ecs"), region=REGION, cluster_arn=CLUSTER),
        evidence=LogEvidence(logs, loaded.manifest),
        logs=logs,
        clock=r.clock,
        tokens=r.tokens,
        session_id=session,
    )


def journal_bytes(r: Rig) -> str:
    return "\n".join(body.decode() for body, _ in r.store.objects.values()) + json.dumps(
        [entry[2] for entry in r.trace if entry[0] == "store"]
    )


def assert_no_application_output(r: Rig) -> None:
    text = journal_bytes(r)
    for line in SENSITIVE_LINES:
        for fragment in ("fixture-secret", "fixture-key", "report-fixture", "fixture-user"):
            if fragment in line:
                assert fragment not in text


def test_a_release_with_every_required_producer_finishes_held_paused_through_the_sdk():
    r, aws = aws_rig(checks="worker")
    outcome = adapted(r, aws).run()
    assert outcome.state == "held_paused", outcome
    assert LOCK not in r.store.objects
    operations = {(service, operation) for service, operation, _ in aws.bridge.calls}
    assert {("ecs", "RunTask"), ("ecs", "UpdateService"), ("logs", "GetLogEvents"),
            ("s3", "PutObject"), ("s3", "DeleteObject")} <= operations  # fmt: skip
    assert_no_application_output(r)


def test_unimplemented_runtime_and_api_observers_hold_after_worker_readiness_passes():
    r, aws = aws_rig()
    outcome = adapted(r, aws).run()
    assert_held(r, outcome, "operational_evidence_missing", "services_started")
    assert r.events("observation", subject="worker-readiness", result="operational_passed")
    assert_no_application_output(r)


def test_throttled_service_observation_holds():
    r, aws = aws_rig(checks="worker")
    aws.bridge.fail("ecs", "DescribeServices", ServiceError("ThrottlingException", 400))
    outcome = adapted(r, aws).run()
    assert_held(r, outcome, "observation_ambiguous", "locked")
    assert not [call for call in aws.bridge.calls if call[1] == "RunTask"]


@pytest.mark.parametrize(
    "interruption, applied",
    [("transport", False), ("transport", True), ("crash", False), ("crash", True)],
)
def test_reconciling_a_lost_deploy_through_the_sdk_never_proceeds_under_drift(
    interruption, applied
):
    # The first forward UpdateService for Runtime is lost (connection timeout or
    # controller crash), before or after ECS applied it, while its circuit
    # breaker rollback is turned on. Recovery holds before any further deploy.
    r, aws = aws_rig(checks="worker")
    runtime_arn = r.document["environment"]["services"]["runtime"]
    runtime = r.ecs.services[runtime_arn]
    original = aws.bridge.handlers[("ecs", "UpdateService")]
    forward: list[dict] = []

    def lose_first_deploy(params):
        if params["service"] != runtime_arn or params["desiredCount"] != 1:
            return original(params)
        forward.append(params)
        if len(forward) > 1:
            return original(params)
        if applied:
            original(params)
        runtime.settings["deploymentConfiguration"]["deploymentCircuitBreaker"]["rollback"] = True
        if interruption == "crash":
            raise SimulatedCrash("controller lost after the forward intent")
        raise Transport("forward UpdateService response lost")

    aws.bridge.handlers[("ecs", "UpdateService")] = lose_first_deploy
    if interruption == "crash":
        with pytest.raises(SimulatedCrash):
            adapted(r, aws).run()
        recovering = adapted(r, aws, session="session-b")
        recovering.recover(
            RecoveryAuthorization(
                prior_session_id="session-a",
                lock_etag=r.store.objects[LOCK][1],
                fence_evidence_sha256=sha("prior session process confirmed terminated"),
                authorized_by="fixture-operator",
            )
        )
        outcome = recovering.run()
    else:
        outcome = adapted(r, aws).run()
    assert_held(r, outcome, "service_settings_drift", "grants_verified")
    assert len(forward) == 1, "no forward resend under observed drift"
    assert not r.events("observation", subject="runtime", result="service_deployed")
    assert runtime.desired == (1 if applied else 0)


@pytest.mark.parametrize("where, sends", [("run_task_before", 2), ("run_task_after", 1)])
def test_a_lost_run_task_is_found_by_its_token_or_resent_identically(where, sends):
    # Lost before ECS applied it: nothing carries the token, so the identical
    # request is resent. Lost after: the token listing finds the one launch.
    r, aws = aws_rig(checks="worker")
    r.ecs.ambiguous[where] = 1
    outcome = adapted(r, aws).run()
    assert outcome.state == "held_paused", outcome
    launches = [p for s, op, p in aws.bridge.calls if op == "RunTask"
                and p["tags"][1]["value"] == "runtime-migrate"]  # fmt: skip
    assert len(launches) == sends and all(call == launches[0] for call in launches)
    assert len(r.job_tasks("runtime-migrate")) == 1


def test_a_competing_journal_write_halts_without_forking():
    r, aws = aws_rig(checks="worker")

    def competitor(key, body):
        if key == JOURNAL and json.loads(body)["events"][-1].get("action") == "run_task":
            r.store.before_replace = None
            current, _ = r.store.objects[key]
            r.store.objects[key] = (current, '"etag-competitor"')

    r.store.before_replace = competitor
    with pytest.raises(ReleaseHalted) as error:
        adapted(r, aws).run()
    assert error.value.code == "journal_conflict"
    assert not [call for call in aws.bridge.calls if call[1] == "RunTask"]


def test_an_intent_write_with_unknown_outcome_never_runs_its_side_effect():
    r, aws = aws_rig(checks="worker")
    original = aws.bridge.handlers[("s3", "PutObject")]
    lost: list[str] = []

    def lose_intent_response(params):
        response = original(params)
        event = (json.loads(body_bytes(params["Body"])).get("events") or [{}])[-1]
        if event.get("action") == "run_task" and not lost:
            lost.append(event["subject"])
            raise Transport("response lost after the write landed")
        return response

    aws.bridge.handlers[("s3", "PutObject")] = lose_intent_response
    with pytest.raises(ReleaseHalted) as error:
        adapted(r, aws).run()
    # The hold could not be journaled over the landed intent: fail closed.
    assert error.value.code == "journal_conflict"
    assert not [call for call in aws.bridge.calls if call[1] == "RunTask"]
    assert r.events("intent", action="run_task", subject="runtime-migrate")
    # A recovered session reconciles that intent and launches it exactly once.
    aws.bridge.handlers[("s3", "PutObject")] = original
    recovering = adapted(r, aws, session="session-b")
    recovering.recover(
        RecoveryAuthorization(
            prior_session_id="session-a",
            lock_etag=r.store.objects[LOCK][1],
            fence_evidence_sha256=sha("prior session process confirmed terminated"),
            authorized_by="fixture-operator",
        )
    )
    assert recovering.run().state == "held_paused"
    assert lost == ["runtime-migrate"]
    assert len(r.job_tasks("runtime-migrate")) == 1


def test_another_sessions_lock_holds_without_any_ecs_mutation():
    r, aws = aws_rig(checks="worker")
    r.store.create(LOCK, b'{"release_id":"other","session_id":"other"}')
    outcome = adapted(r, aws).run()
    assert outcome.state == "hold" and outcome.reason == "environment_locked"
    assert not [c for c in aws.bridge.calls if c[1] in {"RunTask", "UpdateService", "StopTask"}]


def test_duplicate_job_receipts_hold_as_ambiguous():
    r, aws = aws_rig(checks="worker")
    original = aws._job_lines

    def doubled(group, stream):
        lines = original(group, stream)
        return lines + [line for line in lines if line.startswith(RECEIPT_MARKER)]

    setattr(aws, "_job_lines", doubled)
    outcome = adapted(r, aws).run()
    assert_held(r, outcome, "observation_ambiguous", "quiesced")


# Readiness through the log adapter ----------------------------------------------------


def gate(r: Rig, result: str) -> list[dict]:
    return r.events("observation", subject="worker-readiness", result=result)


@pytest.mark.parametrize(
    "configure, last_reason",
    [
        (lambda r, aws: setattr(r.logs, "denied", True), "readiness_logs_unavailable"),
        (lambda r, aws: setattr(r.logs, "missing", True), "readiness_logs_unavailable"),
        (lambda r, aws: setattr(r.logs, "endless", True), "readiness_logs_incomplete"),
        # Receipts arriving 40 s late are older than the 30 s freshness bound.
        (lambda r, aws: setattr(r.logs, "delay", 40.0), None),
    ],
)
def test_unproven_readiness_through_the_adapter_holds_at_the_fixed_deadline(configure, last_reason):
    r, aws = aws_rig(checks="worker")
    configure(r, aws)
    outcome = adapted(r, aws).run()
    assert_held(r, outcome, "worker_readiness_not_proven", "services_started")
    [started] = gate(r, "readiness_observing")
    [missed] = gate(r, "readiness_not_proven")
    if last_reason is not None:
        assert missed["last_reason"] == last_reason
    assert missed["at"] >= started["deadline_at"]


def test_empty_pages_with_new_tokens_do_not_end_the_stream():
    r, aws = aws_rig(checks="worker")
    r.logs.empty_pages = 3
    assert adapted(r, aws).run().state == "held_paused"


def test_throttled_and_slow_reads_clear_stability_then_recover_a_full_window():
    r, aws = aws_rig(checks="worker")
    reads = {"n": 0}
    original = aws.bridge.handlers[("logs", "GetLogEvents")]

    def slow_then_throttled(params):
        if not params["logStreamName"].startswith("worker/"):
            return original(params)
        reads["n"] += 1
        if reads["n"] == 6:
            r.clock.advance(seconds=25)  # a slow read: visibility lost until it returns
        if 6 <= reads["n"] <= 8:
            raise ServiceError("ThrottlingException", 400)
        return original(params)

    aws.bridge.handlers[("logs", "GetLogEvents")] = slow_then_throttled
    outcome = adapted(r, aws).run()
    assert outcome.state == "held_paused", outcome
    [passed] = gate(r, "operational_passed")
    assert passed["last_reset"] == "readiness_logs_unavailable"


class ControllerClock:
    """The controller's clock only; ECS and log fakes keep their own time."""

    def __init__(self, base: FakeClock) -> None:
        self.base, self.offset = base, timedelta(0)

    def now(self):
        return self.base.now() + self.offset

    def sleep(self, seconds: float) -> None:
        self.base.sleep(seconds)


def test_controller_clock_regression_during_the_gate_holds():
    r, aws = aws_rig(checks="worker")
    clock = ControllerClock(r.clock)
    original = aws.bridge.handlers[("logs", "GetLogEvents")]
    reads: list[int] = []

    def regress(params):
        if not params["logStreamName"].startswith("worker/"):
            return original(params)
        reads.append(1)
        if len(reads) == 4:
            clock.offset = -timedelta(seconds=30)
        return original(params)

    aws.bridge.handlers[("logs", "GetLogEvents")] = regress
    controller = adapted(r, aws)
    controller.clock = clock
    outcome = controller.run()
    assert_held(r, outcome, "controller_clock_rollback", "services_started")
    assert not gate(r, "operational_passed")


def test_quiesce_waits_for_a_writer_whose_stop_is_still_in_progress():
    r, aws = aws_rig(checks="worker")
    writer = r.ecs.standalone(r.document["services"]["worker"]["task_definition"])
    writer.stopped_at = r.clock.now() + timedelta(seconds=110)
    writer.stop_code = "UserInitiated"
    launches: list = []
    original = aws.bridge.handlers[("ecs", "RunTask")]

    def record(params):
        launches.append(r.ecs._status(writer))
        return original(params)

    aws.bridge.handlers[("ecs", "RunTask")] = record
    outcome = adapted(r, aws).run()
    assert outcome.state == "held_paused", outcome
    assert launches and set(launches) == {"STOPPED"}, "a job ran beside a live writer"


def test_a_writer_ecs_still_intends_to_run_holds_quiesce():
    r, aws = aws_rig(checks="worker")
    r.ecs.standalone(r.document["services"]["worker"]["task_definition"])
    outcome = adapted(r, aws).run()
    assert_held(r, outcome, "standalone_writer_present", "locked")


def test_no_exception_escaping_a_release_carries_application_output():
    # A malformed receipt quoting a sensitive line makes the grant ambiguous; a
    # competing journal writer then makes the hold itself fail to journal.
    r, aws = aws_rig(checks="worker")
    aws.job_streams["runtime-grant"] = [*SENSITIVE_LINES, RECEIPT_MARKER + " " + SENSITIVE_LINES[0]]

    def competitor(key, body):
        if key == JOURNAL and json.loads(body)["events"][-1].get("to") == "hold":
            r.store.before_replace = None
            current, _ = r.store.objects[key]
            r.store.objects[key] = (current, '"etag-competitor"')

    r.store.before_replace = competitor
    with pytest.raises(ReleaseHalted) as error:
        adapted(r, aws).run()
    assert error.value.code == "journal_conflict"
    text = carried_text(error.value)
    for fragment in ("fixture-secret", "fixture-key", "report-fixture", "fixture-user"):
        assert fragment not in text
