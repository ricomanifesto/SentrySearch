from __future__ import annotations

import json
import threading
from typing import Any

import httpx
import pytest

from src.core.generation_failures import EvidenceAttestationError
from src.execution.dispatcher import dispatch_pending_reports
from src.execution.runtime_client import RuntimeClient, RuntimeRun, RuntimeUnavailable
from src.execution.worker import DurableGenerationWorker


def test_runtime_client_submits_and_claims_the_versioned_report_workflow():
    requests: list[tuple[str, str, dict[str, Any]]] = []

    def handle(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        requests.append((request.method, request.url.path, body))
        if request.url.path == "/v1/runs":
            return httpx.Response(
                201,
                json={
                    "run_id": "11111111-1111-1111-1111-111111111111",
                    "state": "queued",
                    "attempt": 0,
                    "lease_version": 0,
                    "input_ref": {"report_id": "report-1"},
                },
            )
        return httpx.Response(
            200,
            json={
                "run_id": "11111111-1111-1111-1111-111111111111",
                "state": "running",
                "attempt": 1,
                "lease_owner": "worker-1",
                "lease_version": 1,
                "input_ref": {"report_id": "report-1"},
            },
        )

    transport = httpx.MockTransport(handle)
    with httpx.Client(transport=transport) as http_client:
        client = RuntimeClient("http://127.0.0.1:8080", http_client=http_client)
        submitted = client.submit_report("report-1")
        claimed = client.claim("worker-1", lease_seconds=60)

    assert submitted.run_id == "11111111-1111-1111-1111-111111111111"
    assert claimed is not None
    assert requests == [
        (
            "POST",
            "/v1/runs",
            {
                "product": "sentrysearch",
                "workflow_name": "generate_report",
                "workflow_version": "v1",
                "idempotency_key": "report-1",
                "input_ref": {"report_id": "report-1"},
                "max_attempts": 3,
            },
        ),
        (
            "POST",
            "/v1/worker/claims",
            {
                "product": "sentrysearch",
                "workflow_name": "generate_report",
                "workflow_version": "v1",
                "lease_owner": "worker-1",
                "lease_duration_seconds": 60,
            },
        ),
    ]


@pytest.mark.parametrize(
    "runtime_url",
    [
        "https://runtime.example.com",
        "http://10.0.0.4:8080",
        "http://127.0.0.1:8080/unexpected-base-path",
        "file:///tmp/runtime.sock",
    ],
)
def test_runtime_client_rejects_non_loopback_urls(runtime_url: str):
    with pytest.raises(ValueError, match="loopback"):
        RuntimeClient(runtime_url)


def test_worker_acknowledges_completed_report_replay_without_regeneration():
    run = RuntimeRun(
        run_id="11111111-1111-1111-1111-111111111111",
        state="running",
        attempt=2,
        lease_owner="worker-1",
        lease_version=2,
        input_ref={"report_id": "report-1"},
    )

    class Runtime:
        completed: list[tuple[str, str, int, dict[str, Any]]] = []

        def claim(self, worker_id: str, *, lease_seconds: int) -> RuntimeRun:
            assert worker_id == "worker-1"
            assert lease_seconds == 60
            return run

        def complete(
            self,
            run_id: str,
            lease_owner: str,
            lease_version: int,
            output_ref: dict[str, Any],
        ) -> RuntimeRun:
            self.completed.append((run_id, lease_owner, lease_version, output_ref))
            return RuntimeRun(
                run_id=run_id,
                state="succeeded",
                attempt=2,
                lease_owner="",
                lease_version=lease_version,
                input_ref=run.input_ref,
            )

        def heartbeat(self, *_args: Any, **_kwargs: Any) -> RuntimeRun:
            raise AssertionError("completed replay must not heartbeat")

        def fail(self, *_args: Any, **_kwargs: Any) -> RuntimeRun:
            raise AssertionError("completed replay must not fail")

    class Reports:
        def get_report(self, report_id: str, include_content: bool = False):
            assert report_id == "report-1"
            assert include_content is False
            return {
                "id": report_id,
                "status": "completed",
                "tool_name": "Cobalt Strike",
                "user_id": "analyst-user",
            }

        def mark_report_failed(self, *_args: Any, **_kwargs: Any) -> bool:
            raise AssertionError("completed replay must not mark failure")

    def generate(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("completed report must not be regenerated")

    runtime = Runtime()
    worker = DurableGenerationWorker(
        runtime=runtime,
        reports=Reports(),
        generate=generate,
        worker_id="worker-1",
        lease_seconds=60,
    )

    assert worker.run_once() is True
    assert runtime.completed == [
        (
            run.run_id,
            "worker-1",
            2,
            {"report_id": "report-1", "status": "completed"},
        )
    ]


def test_dispatcher_marks_intent_submitted_after_idempotent_runtime_response():
    run = RuntimeRun(
        run_id="11111111-1111-1111-1111-111111111111",
        state="queued",
        attempt=0,
        lease_owner="",
        lease_version=0,
        input_ref={"report_id": "report-1"},
    )

    class Runtime:
        def submit_report(self, report_id: str) -> RuntimeRun:
            assert report_id == "report-1"
            return run

    class Reports:
        submitted: list[tuple[str, str]] = []

        def get_pending_runtime_dispatches(self, *, limit: int) -> list[str]:
            assert limit == 20
            return ["report-1"]

        def mark_runtime_dispatch_submitted(self, report_id: str, runtime_run_id: str) -> bool:
            self.submitted.append((report_id, runtime_run_id))
            return True

        def record_runtime_dispatch_failure(self, *_args: Any, **_kwargs: Any) -> bool:
            raise AssertionError("successful dispatch must not record failure")

    reports = Reports()

    assert dispatch_pending_reports(Runtime(), reports) == 1
    assert reports.submitted == [("report-1", run.run_id)]


def test_dispatcher_keeps_intent_pending_when_runtime_is_unavailable():
    class Runtime:
        def submit_report(self, report_id: str) -> RuntimeRun:
            raise RuntimeUnavailable("runtime unavailable")

    class Reports:
        failures: list[tuple[str, str]] = []

        def get_pending_runtime_dispatches(self, *, limit: int) -> list[str]:
            return ["report-1"]

        def mark_runtime_dispatch_submitted(self, *_args: Any, **_kwargs: Any) -> bool:
            raise AssertionError("failed dispatch must stay pending")

        def record_runtime_dispatch_failure(self, report_id: str, error_code: str) -> bool:
            self.failures.append((report_id, error_code))
            return True

    reports = Reports()

    assert dispatch_pending_reports(Runtime(), reports) == 0
    assert reports.failures == [("report-1", "runtime_unavailable")]


def test_worker_heartbeats_while_generation_is_running():
    heartbeat_seen = threading.Event()
    report_status = {"value": "generating"}
    run = RuntimeRun(
        run_id="11111111-1111-1111-1111-111111111111",
        state="running",
        attempt=1,
        lease_owner="worker-1",
        lease_version=1,
        input_ref={"report_id": "report-1"},
    )

    class Runtime:
        completed = False

        def claim(self, worker_id: str, *, lease_seconds: int) -> RuntimeRun:
            return run

        def heartbeat(
            self,
            run_id: str,
            lease_owner: str,
            lease_version: int,
            *,
            lease_seconds: int,
        ) -> RuntimeRun:
            assert (run_id, lease_owner, lease_version) == (
                run.run_id,
                run.lease_owner,
                run.lease_version,
            )
            heartbeat_seen.set()
            return run

        def complete(self, *_args: Any, **_kwargs: Any) -> RuntimeRun:
            self.completed = True
            return run

        def fail(self, *_args: Any, **_kwargs: Any) -> RuntimeRun:
            raise AssertionError("successful generation must not fail the run")

    class Reports:
        def get_report(self, *_args: Any, **_kwargs: Any):
            return {
                "id": "report-1",
                "status": report_status["value"],
                "tool_name": "Cobalt Strike",
                "user_id": "analyst-user",
            }

        def mark_report_failed(self, *_args: Any, **_kwargs: Any) -> bool:
            raise AssertionError("successful generation must not mark the report failed")

    def generate(*_args: Any) -> None:
        assert heartbeat_seen.wait(timeout=1)
        report_status["value"] = "completed"

    runtime = Runtime()
    worker = DurableGenerationWorker(
        runtime=runtime,
        reports=Reports(),
        generate=generate,
        worker_id="worker-1",
        lease_seconds=3,
        heartbeat_interval_seconds=0.01,
    )

    assert worker.run_once() is True
    assert runtime.completed is True


def test_worker_leaves_retryable_report_nonterminal_when_runtime_schedules_retry():
    run = RuntimeRun(
        run_id="11111111-1111-1111-1111-111111111111",
        state="running",
        attempt=1,
        lease_owner="worker-1",
        lease_version=1,
        input_ref={"report_id": "report-1"},
    )

    class Runtime:
        failures: list[dict[str, Any]] = []

        def claim(self, worker_id: str, *, lease_seconds: int) -> RuntimeRun:
            return run

        def heartbeat(self, *_args: Any, **_kwargs: Any) -> RuntimeRun:
            return run

        def complete(self, *_args: Any, **_kwargs: Any) -> RuntimeRun:
            raise AssertionError("failed generation must not complete")

        def fail(self, *_args: Any, **kwargs: Any) -> RuntimeRun:
            self.failures.append(kwargs)
            return RuntimeRun(
                run_id=run.run_id,
                state="retry_wait",
                attempt=1,
                lease_owner="",
                lease_version=1,
                input_ref=run.input_ref,
            )

    class Reports:
        marked_failed = False

        def get_report(self, *_args: Any, **_kwargs: Any):
            return {
                "id": "report-1",
                "status": "generating",
                "tool_name": "Cobalt Strike",
                "user_id": "analyst-user",
            }

        def mark_report_failed(self, *_args: Any, **_kwargs: Any) -> bool:
            self.marked_failed = True
            return True

    def generate(*_args: Any) -> None:
        raise TimeoutError("provider detail must not cross the runtime boundary")

    runtime = Runtime()
    reports = Reports()
    worker = DurableGenerationWorker(
        runtime=runtime,
        reports=reports,
        generate=generate,
        worker_id="worker-1",
        lease_seconds=3,
        heartbeat_interval_seconds=1,
    )

    assert worker.run_once() is True
    assert runtime.failures == [
        {"error_code": "dependency_timeout", "error_summary": "report generation failed"}
    ]
    assert reports.marked_failed is False


def test_worker_maps_nonretryable_result_failure_to_terminal_runtime_category():
    run = RuntimeRun(
        run_id="11111111-1111-1111-1111-111111111111",
        state="running",
        attempt=1,
        lease_owner="worker-1",
        lease_version=1,
        input_ref={"report_id": "report-1"},
    )

    class Runtime:
        error_code = ""

        def claim(self, worker_id: str, *, lease_seconds: int) -> RuntimeRun:
            return run

        def heartbeat(self, *_args: Any, **_kwargs: Any) -> RuntimeRun:
            return run

        def complete(self, *_args: Any, **_kwargs: Any) -> RuntimeRun:
            raise AssertionError("failed generation must not complete")

        def fail(self, *_args: Any, **kwargs: Any) -> RuntimeRun:
            self.error_code = kwargs["error_code"]
            return RuntimeRun(
                run_id=run.run_id,
                state="failed",
                attempt=1,
                lease_owner="",
                lease_version=1,
                input_ref=run.input_ref,
            )

    class Reports:
        failure: dict[str, Any] | None = None

        def get_report(self, *_args: Any, **_kwargs: Any):
            return {
                "id": "report-1",
                "status": "generating",
                "tool_name": "Cobalt Strike",
                "user_id": "analyst-user",
            }

        def mark_report_failed(self, report_id: str, **failure: Any) -> bool:
            self.failure = failure
            return True

    def generate(*_args: Any) -> None:
        raise EvidenceAttestationError("private evidence detail")

    runtime = Runtime()
    reports = Reports()
    worker = DurableGenerationWorker(
        runtime=runtime,
        reports=reports,
        generate=generate,
        worker_id="worker-1",
        lease_seconds=3,
        heartbeat_interval_seconds=1,
    )

    assert worker.run_once() is True
    assert runtime.error_code == "invalid_result"
    assert reports.failure is not None
    assert reports.failure["error_code"] == "evidence_unattested"
    assert reports.failure["retryable"] is False


def test_worker_fails_missing_product_record_as_invalid_input():
    run = RuntimeRun(
        run_id="11111111-1111-1111-1111-111111111111",
        state="running",
        attempt=1,
        lease_owner="worker-1",
        lease_version=1,
        input_ref={"report_id": "missing-report"},
    )

    class Runtime:
        error_code = ""

        def claim(self, worker_id: str, *, lease_seconds: int) -> RuntimeRun:
            return run

        def heartbeat(self, *_args: Any, **_kwargs: Any) -> RuntimeRun:
            raise AssertionError("invalid work must not heartbeat")

        def complete(self, *_args: Any, **_kwargs: Any) -> RuntimeRun:
            raise AssertionError("invalid work must not complete")

        def fail(self, *_args: Any, **kwargs: Any) -> RuntimeRun:
            self.error_code = kwargs["error_code"]
            return run

    class Reports:
        def get_report(self, *_args: Any, **_kwargs: Any):
            return None

        def mark_report_failed(self, *_args: Any, **_kwargs: Any) -> bool:
            raise AssertionError("missing report cannot be marked")

    runtime = Runtime()
    worker = DurableGenerationWorker(
        runtime=runtime,
        reports=Reports(),
        generate=lambda *_args: None,
        worker_id="worker-1",
        lease_seconds=3,
    )

    assert worker.run_once() is True
    assert runtime.error_code == "invalid_input"
