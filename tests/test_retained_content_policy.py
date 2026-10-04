import asyncio
from copy import deepcopy
from threading import Event, Lock
from time import sleep
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest
from fastapi import HTTPException

from dev import run_runtime_worker as runner
from src.api import main as api
from src.auth.supabase_auth import AuthenticatedUser
from src.core.evidence_admissibility import ContentPolicyExclusion
from src.execution.runtime_client import RuntimeRun
from src.execution.supervisor import WorkerSettings
from src.execution.worker import DurableGenerationWorker
from src.storage.models import Report, ReportDispositionEvent
from src.storage.report_service import ReportStorageService
from tests.test_virtual_event_promotions import MARKERS, collection_report


@pytest.mark.parametrize("field", ["blockingFindings", "value", "reason", "claimField"])
def test_every_public_audit_field_is_checked_without_mutating_private_original(field):
    audit = {
        "schemaVersion": "1",
        "status": "passed",
        "sourceObservations": [],
        "indicatorObservations": [],
        "blockingFindings": [],
        "summary": {},
    }
    if field == "blockingFindings":
        audit[field] = ["[Virtual Event] Register now"]
    else:
        observation = {
            "claimField": "indicators",
            "claimIndex": 0,
            "value": "192.0.2.1",
            "disposition": "excluded",
            "reason": "Context",
            "ruleId": "indicator.context",
        }
        observation[field] = "[Virtual Event] Register now"
        audit["indicatorObservations"] = [observation]
    report = {**collection_report("retained"), "evidence_admissibility": audit}
    original = deepcopy(report)
    with pytest.raises(ContentPolicyExclusion):
        api.report_response_fields(report)
    assert report == original


@pytest.mark.parametrize("blocked", [True, False])
@pytest.mark.parametrize("field", ["tool_name", "search_tags"])
def test_retained_download_checks_stored_policy_fields_before_signing(blocked, field):
    service = ReportStorageService.__new__(ReportStorageService)
    service.db_manager = MagicMock()
    session = service.db_manager.get_session.return_value.__enter__.return_value
    report = Report(id="retained", tool_name="Security events", markdown_s3_key="retained.md")
    value = "[Virtual Event] Briefing" if blocked else "Security events"
    setattr(report, field, [value] if field == "search_tags" else value)
    session.query.return_value.filter.return_value.first.return_value = report
    service.s3_manager = Mock()
    service.s3_manager.download_content.return_value = "Security analysis"
    if blocked:
        with pytest.raises(ContentPolicyExclusion):
            service.get_download_url("retained")
        service.s3_manager.get_presigned_url.assert_not_called()
    else:
        service.get_download_url("retained")
        service.s3_manager.get_presigned_url.assert_called_once()
    session.commit.assert_not_called()


@pytest.mark.parametrize("blocked", [True, False])
def test_durable_replay_rejects_policy_before_product_transition_or_generator(blocked):
    run = RuntimeRun(
        run_id="11111111-1111-1111-1111-111111111111",
        state="running",
        attempt=1,
        lease_owner="worker",
        lease_version=1,
        input_ref={"report_id": "retained"},
    )
    runtime = Mock()
    runtime.claim.return_value = run
    reports = Mock()
    row = {
        "id": "retained",
        "user_id": "owner",
        "status": "generating",
        "tool_name": "[Virtual Event] Briefing" if blocked else "Security events",
    }
    original = deepcopy(row)
    reports.get_report.return_value = row
    reports.begin_runtime_attempt.return_value = True
    generate = Mock(side_effect=lambda *_: row.update(status="completed"))
    worker = DurableGenerationWorker(
        runtime=runtime, reports=reports, generate=generate, worker_id="worker", lease_seconds=60
    )
    worker.run_once()
    if blocked:
        generate.assert_not_called()
        reports.begin_runtime_attempt.assert_not_called()
        reports.mark_report_failed.assert_not_called()
        assert runtime.fail.call_args.kwargs["error_code"] == "invalid_input"
        assert row == original
    else:
        generate.assert_called_once()
        runtime.complete.assert_called_once()


def test_object_reader_deadline_does_not_release_running_capacity():
    from src.storage.retained_content import RetainedContentReader, RetainedContentUnavailable

    release = Event()
    entered = Event()
    calls = []

    def load(key):
        calls.append(key)
        entered.set()
        release.wait(2)
        return "Security analysis"

    reader = RetainedContentReader(max_workers=1, timeout_seconds=0.05)

    async def scenario():
        with pytest.raises(RetainedContentUnavailable):
            await reader.read_many(["one"], load)
        assert entered.is_set()
        with pytest.raises(RetainedContentUnavailable):
            await reader.read_many(["two"], load)
        assert calls == ["one"]
        release.set()
        await asyncio.sleep(0.02)
        assert await reader.read_many(["three", "three"], load) == {"three": "Security analysis"}

    try:
        asyncio.run(scenario())
    finally:
        release.set()
        reader.close()


def test_object_reader_is_concurrent_global_and_nonblocking():
    from src.storage.retained_content import RetainedContentReader

    active = peak = 0
    lock = Lock()
    release = Event()
    reader = RetainedContentReader(max_workers=3, timeout_seconds=1)

    def load(key):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        release.wait(1)
        with lock:
            active -= 1
        return key

    async def scenario():
        jobs = [
            asyncio.create_task(reader.read_many([str(i) for i in range(10)], load))
            for _ in range(2)
        ]
        await asyncio.sleep(0.03)
        assert peak == 3
        release.set()
        results = await asyncio.gather(*jobs)
        assert all(list(result) == [str(i) for i in range(10)] for result in results)
        assert peak == 3

    try:
        asyncio.run(scenario())
    finally:
        release.set()
        reader.close()


def test_maximum_page_of_healthy_retained_reads_completes():
    from src.storage.retained_content import RetainedContentReader

    reader = RetainedContentReader()
    keys = [f"{index}.md" for index in range(100)]
    active = peak = 0
    lock = Lock()

    def load(key):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            sleep(0.25)
            return f"content:{key}"
        finally:
            with lock:
                active -= 1

    try:
        result = asyncio.run(reader.read_many(keys + keys, load))
        assert list(result.items()) == [(key, f"content:{key}") for key in keys]
        assert peak == 4
    finally:
        reader.close()


@pytest.mark.parametrize("occupied", [False, True])
def test_large_batch_keeps_individual_read_and_admission_timeouts(occupied):
    from src.storage.retained_content import RetainedContentReader, RetainedContentUnavailable

    reader = RetainedContentReader(max_workers=1, timeout_seconds=0.05)
    release = Event()
    entered = Event()
    calls = []

    def load(key):
        calls.append(key)
        entered.set()
        release.wait(2)
        return key

    async def scenario():
        if occupied:
            with pytest.raises(RetainedContentUnavailable):
                await reader.read_many(["occupied"], load)
        # A larger page must not grant a stalled read or saturated admission
        # the entire multi-wave batch budget.
        with pytest.raises(RetainedContentUnavailable):
            await asyncio.wait_for(reader.read_many([str(i) for i in range(100)], load), 0.5)
        assert entered.is_set()
        assert calls == (["occupied"] if occupied else ["0"])

    try:
        asyncio.run(scenario())
    finally:
        release.set()
        reader.close()


def test_private_trace_access_preserves_the_original_audit():
    service = ReportStorageService.__new__(ReportStorageService)
    service.db_manager = MagicMock()
    session = service.db_manager.get_session.return_value.__enter__.return_value
    report = Report(
        id="retained",
        tool_name="[Virtual Event] Briefing",
        markdown_s3_key="report.md",
        trace_s3_key="private.json",
        threat_data={"evidenceAdmissibility": {"private": "[Virtual Event] audit"}},
    )
    session.query.return_value.filter.return_value.first.return_value = report
    service.s3_manager = Mock()
    original = deepcopy(report.to_dict())
    service.get_download_url("retained", "trace")
    service.s3_manager.get_presigned_url.assert_called_once_with("private.json")
    service.s3_manager.download_content.assert_not_called()
    assert report.to_dict() == original


def test_cancelled_request_keeps_capacity_until_sdk_completion():
    from src.storage.retained_content import RetainedContentReader, RetainedContentUnavailable

    reader = RetainedContentReader(max_workers=1, timeout_seconds=0.05)
    release = Event()
    entered = Event()
    calls = []

    def load(key):
        calls.append(key)
        entered.set()
        release.wait(2)
        return key

    async def scenario():
        task = asyncio.create_task(reader.read_many(["one", "queued"], load))
        while not entered.is_set():
            await asyncio.sleep(0.001)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        with pytest.raises(RetainedContentUnavailable):
            await reader.read_many(["another"], load)
        assert calls == ["one"]
        release.set()

    try:
        asyncio.run(scenario())
    finally:
        release.set()
        reader.close()


def test_expired_request_never_submits_even_when_capacity_is_free(monkeypatch):
    from src.storage.retained_content import RetainedContentReader, RetainedContentUnavailable

    reader = RetainedContentReader(max_workers=1, timeout_seconds=0.01)
    submit = Mock(wraps=reader._executor.submit)
    monkeypatch.setattr(reader._executor, "submit", submit)

    async def scenario():
        task = asyncio.create_task(reader.read_many(["expired"], lambda key: key))
        # The parent establishes its deadline, then the child runs after it.
        await asyncio.sleep(0)
        sleep(0.02)
        with pytest.raises(RetainedContentUnavailable):
            await task
        submit.assert_not_called()

    try:
        asyncio.run(scenario())
    finally:
        reader.close()


def test_collection_object_reads_are_bounded_nonblocking_and_keep_order(monkeypatch):
    from src.storage.retained_content import RetainedContentReader

    reader = RetainedContentReader(max_workers=4, timeout_seconds=2)
    monkeypatch.setattr(api, "retained_content_reader", reader)
    service = Mock()
    rows = [{**collection_report(str(i)), "_markdown_s3_key": f"{i // 2}.md"} for i in range(100)]
    calls = []

    def load(key):
        calls.append(key)
        sleep(0.01)
        return "[Virtual Event] Briefing" if key == "2.md" else "Security events"

    service.s3_manager.download_content.side_effect = load
    monkeypatch.setattr(api, "report_service", service)
    original = deepcopy(rows)

    async def scenario():
        task = asyncio.create_task(api.report_collection_fields(rows))
        await asyncio.sleep(0.03)
        assert not task.done()
        projected, excluded = await task
        assert excluded == 2
        assert [fields["id"] for _, fields in projected] == [
            str(i) for i in range(100) if i not in {4, 5}
        ]

    try:
        asyncio.run(scenario())
    finally:
        reader.close()
    assert len(calls) == 50
    assert rows == original


@pytest.mark.parametrize("failure", ["missing", "timeout", "audit", "profile_audit"])
@pytest.mark.parametrize("status", ["generating", "completed"])
def test_invalid_retained_job_does_not_terminate_worker_loop(monkeypatch, failure, status):
    stop = Event()
    runtime = Mock()
    reports = Mock()
    rows: dict[str, dict[str, Any]] = {
        key: {
            "id": key,
            "user_id": "owner",
            "status": "generating",
            "tool_name": "Security analysis",
            "_markdown_s3_key": f"{key}.md",
        }
        for key in ("unreadable", "ordinary")
    }
    rows["unreadable"]["status"] = status
    if failure == "audit":
        rows["unreadable"]["evidence_admissibility"] = {"schemaVersion": "legacy"}
    elif failure == "profile_audit":
        rows["unreadable"]["threat_data"] = {"evidenceAdmissibility": {"status": "invalid"}}
    original = deepcopy(rows["unreadable"])
    runs = [
        RuntimeRun(
            run_id=f"11111111-1111-1111-1111-11111111111{i}",
            state="running",
            attempt=1,
            lease_owner="worker",
            lease_version=1,
            input_ref={"report_id": key},
        )
        for i, key in enumerate(rows)
    ]
    runtime.claim.side_effect = runs
    reports.get_report.side_effect = lambda report_id, **_: rows[report_id]
    if failure in {"missing", "timeout"}:
        error = (
            FileNotFoundError("missing object")
            if failure == "missing"
            else TimeoutError("slow object")
        )
        reports.download_report_content.side_effect = [error, "Ordinary security analysis"]
    else:
        reports.download_report_content.return_value = "Ordinary security analysis"
    reports.begin_runtime_attempt.return_value = True
    reports.get_pending_runtime_evaluations.return_value = []

    def generate(report_id, *_):
        rows[report_id]["status"] = "completed"
        stop.set()

    generator = Mock(side_effect=generate)
    producer = Mock()
    monkeypatch.setattr(runner, "load_jobs", lambda: (reports, generator, Mock()))
    monkeypatch.setattr(runner, "runtime_clients_from_environment", lambda: (producer, runtime))
    monkeypatch.setattr(runner, "reconcile_runtime_reports", lambda *_: 0)
    monkeypatch.setattr(runner, "dispatch_pending_reports", lambda *_, **__: 0)
    assert runner.run_worker_loop(WorkerSettings(), stop, Mock()) == 0
    assert runtime.claim.call_count == 2
    runtime.fail.assert_called_once_with(
        runs[0].run_id,
        "worker",
        1,
        error_code=(
            "dependency_unavailable" if failure in {"missing", "timeout"} else "invalid_input"
        ),
        error_summary=(
            "retained report content is unavailable"
            if failure in {"missing", "timeout"}
            else "retained report policy contract is invalid"
        ),
    )
    assert reports.begin_runtime_attempt.call_count == 1
    assert reports.begin_runtime_attempt.call_args.args[0] == "ordinary"
    assert generator.call_args.args[0] == "ordinary"
    reports.mark_report_failed.assert_not_called()
    assert rows["unreadable"] == original
    runtime.complete.assert_called_once()
    runtime.close.assert_called_once()
    producer.close.assert_called_once()


@pytest.mark.parametrize("note", MARKERS + ["Security events need review.", None])
def test_disposition_note_admission_preserves_clean_report(monkeypatch, note):
    service = Mock()
    row = {**collection_report("retained"), "user_id": "reader"}
    original = deepcopy(row)
    service.get_report.return_value = row
    service.append_report_disposition.return_value = {
        "id": "event",
        "disposition": "needs_revision",
        "note": note,
        "evaluation_attempt": 1,
        "created_at": "2026-09-09T00:00:00Z",
        "is_current": True,
    }
    monkeypatch.setattr(api, "report_service", service)
    user = AuthenticatedUser(user_id="reader", email="reader@example.com", metadata={})
    request = api.AnalystDispositionCreate(disposition="needs_revision", note=note)
    if note in MARKERS:
        with pytest.raises(HTTPException) as error:
            asyncio.run(api.append_report_disposition("retained", request, user))
        assert error.value.status_code == 422
        service.append_report_disposition.assert_not_called()
        service.s3_manager.download_content.assert_not_called()
    else:
        event = asyncio.run(api.append_report_disposition("retained", request, user))
        assert event.note == note
        service.append_report_disposition.assert_called_once()
    assert row == original


@pytest.mark.parametrize("note", MARKERS)
def test_disposition_storage_rejects_prohibited_note_before_transaction(note):
    service = ReportStorageService.__new__(ReportStorageService)
    service.db_manager = Mock()
    service.db_manager.get_session.side_effect = AssertionError(
        "Prohibited note reached a transaction"
    )
    with pytest.raises(ContentPolicyExclusion):
        service.append_report_disposition(
            "retained",
            disposition="needs_revision",
            note=note,
            reviewer_user_id="reader",
            owner_user_id="reader",
        )
    service.db_manager.get_session.assert_not_called()


def test_disposition_note_check_preserves_owner_boundary(monkeypatch):
    service = Mock()
    service.get_report.return_value = {"user_id": "other-owner"}
    monkeypatch.setattr(api, "report_service", service)
    user = AuthenticatedUser(user_id="reader", email="reader@example.com", metadata={})
    with pytest.raises(HTTPException) as error:
        asyncio.run(
            api.append_report_disposition(
                "retained",
                api.AnalystDispositionCreate(disposition="needs_revision", note=MARKERS[0]),
                user,
            )
        )
    assert error.value.status_code == 404
    service.append_report_disposition.assert_not_called()


def test_markdown_download_checks_historical_dispositions_before_signing(monkeypatch):
    from tests.test_virtual_event_promotions import retained_storage

    service, session, reports = retained_storage(monkeypatch)
    reports[1].evaluation_attempts = 2
    service.s3_manager.download_content.side_effect = None
    service.s3_manager.download_content.return_value = "Security analysis"
    event = ReportDispositionEvent(
        id="historical",
        report_id="blocked",
        evaluation_attempt=1,
        disposition="needs_revision",
        note="[Virtual Event] Register now",
    )
    session.query(
        ReportDispositionEvent
    ).filter.return_value.order_by.return_value.all.return_value = [event]
    with pytest.raises(ContentPolicyExclusion):
        service.get_download_url("blocked")
    service.s3_manager.get_presigned_url.assert_not_called()
    session.commit.assert_not_called()
