from dataclasses import replace
import threading
from typing import Any

import httpx
import pytest

from src.domain.execution import GenerationLease, GenerationLeaseLost
from src.execution.reconciler import reconcile_runtime_reports
from src.execution.runtime_client import (
    RuntimeAccessDenied,
    RuntimeClient,
    RuntimeLeaseFenced,
    RuntimeRun,
    RuntimeRunMissing,
    RuntimeUnavailable,
)
from src.execution.worker import DurableGenerationWorker, LeaseHeartbeat

RUN = RuntimeRun(
    "11111111-1111-1111-1111-111111111111",
    "running",
    1,
    "worker",
    1,
    {"report_id": "report-1"},
)


class Runtime:
    def __init__(self, *, error=None, run=RUN):
        self.error = error
        self.run = run
        self.heartbeat_seen = threading.Event()

    def get_run(self, run_id: str) -> RuntimeRun:
        if self.error:
            raise self.error
        return self.run

    def claim(self, worker_id: str, *, lease_seconds: int) -> RuntimeRun:
        return self.run

    def heartbeat(self, *_args: Any, **_kwargs: Any) -> RuntimeRun:
        self.heartbeat_seen.set()
        if self.error:
            raise self.error
        return self.run

    def complete(self, *_args: Any, **_kwargs: Any) -> RuntimeRun:
        raise AssertionError("a fenced execution must not acknowledge completion")

    def fail(self, *_args: Any, **_kwargs: Any) -> RuntimeRun:
        raise AssertionError("fencing and auth errors are not generation failures")


class Reports:
    def __init__(self):
        self.errors = []
        self.observations = []

    def get_report(self, report_id: str, include_content: bool = False):
        return {"status": "generating", "tool_name": "Example", "user_id": "owner"}

    def begin_runtime_attempt(self, report_id: str, lease: GenerationLease) -> bool:
        assert lease == GenerationLease(RUN.run_id, RUN.lease_owner, RUN.lease_version)
        return True

    def mark_report_failed(self, *_args: Any, **_kwargs: Any) -> bool:
        raise AssertionError("a fenced execution cannot change the report")

    def get_runtime_reconciliation_batch(self, *, limit: int) -> list[tuple[str, str]]:
        return [("report-1", RUN.run_id)]

    def record_runtime_check_error(self, report_id: str, code: str) -> None:
        self.errors.append((report_id, code))

    def apply_runtime_observation(self, report_id: str, run_id: str, **kwargs: Any) -> bool:
        self.observations.append((report_id, run_id, kwargs))
        return True


@pytest.mark.parametrize(
    "error,code",
    [(RuntimeUnavailable(), "runtime_unavailable"), (RuntimeRunMissing(), "runtime_run_missing")],
)
def test_reconciler_preserves_intents_when_the_runtime_cannot_be_read(error, code):
    reports = Reports()
    assert reconcile_runtime_reports(Runtime(error=error), reports) == 0
    assert reports.errors == [("report-1", code)]
    assert reports.observations == []


def test_reconciler_auth_failure_requires_operator_correction():
    reports = Reports()
    with pytest.raises(RuntimeAccessDenied):
        reconcile_runtime_reports(Runtime(error=RuntimeAccessDenied()), reports)
    assert reports.errors == []
    assert reports.observations == []


@pytest.mark.parametrize(
    "run", [replace(RUN, run_id="wrong-run"), replace(RUN, input_ref={"report_id": "other"})]
)
def test_reconciler_rejects_mismatched_references(run):
    reports = Reports()
    assert reconcile_runtime_reports(Runtime(run=run), reports) == 0
    assert reports.errors == [("report-1", "runtime_reference_mismatch")]
    assert reports.observations == []


def test_reconciler_passes_terminal_evidence_to_the_product_store():
    reports = Reports()
    assert (
        reconcile_runtime_reports(
            Runtime(run=replace(RUN, state="failed", error_code="worker_lost")), reports
        )
        == 1
    )
    assert reports.observations == [
        (
            "report-1",
            RUN.run_id,
            {"state": "failed", "lease_version": 1, "error_code": "worker_lost"},
        )
    ]


@pytest.mark.parametrize("error", [GenerationLeaseLost(), RuntimeLeaseFenced()])
def test_worker_does_not_classify_a_fence_as_a_generation_failure(error):
    def generate(*_args):
        raise error

    worker = DurableGenerationWorker(
        runtime=Runtime(), reports=Reports(), generate=generate, worker_id="worker", lease_seconds=3
    )
    assert worker.run_once()


@pytest.mark.parametrize("error", [RuntimeAccessDenied(), RuntimeLeaseFenced()])
def test_heartbeat_failure_is_propagated_and_thread_stopped(error):
    runtime = Runtime(error=error)
    heartbeat = LeaseHeartbeat(runtime, RUN, lease_seconds=3, interval_seconds=0.01)
    with pytest.raises(type(error)):
        with heartbeat:
            assert runtime.heartbeat_seen.wait(1)
    assert not heartbeat._thread.is_alive()


@pytest.mark.parametrize("interval", [0, -1, 3, 4])
def test_worker_rejects_unsafe_heartbeat_intervals(interval):
    with pytest.raises(ValueError, match="heartbeat interval"):
        DurableGenerationWorker(
            runtime=Runtime(),
            reports=Reports(),
            generate=lambda *_args: None,
            worker_id="worker",
            lease_seconds=3,
            heartbeat_interval_seconds=interval,
        )


def test_runtime_client_reads_run_with_producer_auth_and_preserves_error_code():
    def handle(request):
        assert request.method == "GET"
        assert request.url.path == f"/v1/runs/{RUN.run_id}"
        assert request.headers["Authorization"] == "Bearer " + "p" * 40
        return httpx.Response(
            200,
            json={
                "run_id": RUN.run_id,
                "state": "failed",
                "attempt": 3,
                "lease_version": 3,
                "input_ref": RUN.input_ref,
                "error_code": "worker_lost",
            },
        )

    with httpx.Client(transport=httpx.MockTransport(handle)) as transport:
        client = RuntimeClient(
            "http://127.0.0.1:8080", bearer_token="p" * 40, http_client=transport
        )
        assert client.get_run(RUN.run_id).error_code == "worker_lost"


@pytest.mark.parametrize(
    "status,body,error",
    [
        (404, {}, RuntimeRunMissing),
        (409, {"code": "lease_fenced"}, RuntimeLeaseFenced),
        (409, {"code": "different_conflict"}, httpx.HTTPStatusError),
    ],
)
def test_runtime_client_distinguishes_missing_fenced_and_other_conflicts(status, body, error):
    with httpx.Client(
        transport=httpx.MockTransport(lambda _req: httpx.Response(status, json=body))
    ) as transport:
        client = RuntimeClient("http://127.0.0.1:8080", http_client=transport)
        with pytest.raises(error):
            client.get_run(RUN.run_id)
