"""Explicit integration suite; run with dev/check_runtime_consistency.py."""

import os
import io
import json
import uuid
from concurrent.futures import ThreadPoolExecutor
import threading
import time
from typing import Any, cast

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker

from src.core.source_ledger import canonicalize_profile_sources
from src.storage.database import DatabaseManager
from src.storage.models import Base, Report
from src.storage.report_service import ReportStorageService
from src.storage.s3_manager import S3StorageManager
from src.core.markdown_generator import generate_markdown


@pytest.fixture
def reports():
    url = make_url(os.environ["SENTRYSEARCH_TEST_DATABASE_URL"])
    # The runner owns a disposable server, and each test additionally owns its DB.
    name = "sentrysearch_test_" + uuid.uuid4().hex
    admin = create_engine(url, isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.execute(text(f'CREATE DATABASE "{name}"'))
    engine = create_engine(url.set(database=name))
    manager = DatabaseManager.__new__(DatabaseManager)
    manager.engine = engine
    manager.SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    manager.migrate_schema()
    service = ReportStorageService()
    service.db_manager = manager
    objects: dict[str, bytes] = {}

    class Client:
        def put_object(self, **kwargs):
            objects[kwargs["Key"]] = kwargs["Body"]

        def get_object(self, **kwargs):
            return {"Body": io.BytesIO(objects[kwargs["Key"]])}

    store = S3StorageManager()
    store._initialized = True
    store.s3_client = cast(Any, Client())
    service.s3_manager = store
    try:
        yield service, objects
    finally:
        engine.dispose()
        with admin.connect() as connection:
            connection.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))
        admin.dispose()


@pytest.fixture
def artifact(threat_profile_data):
    profile, sources = canonicalize_profile_sources(threat_profile_data)
    return {
        "tool_name": "Example Tool",
        "threat_data": profile,
        "web_sources": sources,
        "evidence_admissibility": {"schemaVersion": "1", "status": "passed"},
        "markdown_content": generate_markdown(profile),
        "evaluation_status": "pending",
        "evaluation_attempts": 1,
    }


@pytest.fixture
def runtime_clients():
    from dev.run_runtime_worker import runtime_clients_from_environment

    producer, worker = runtime_clients_from_environment()
    try:
        yield producer, worker
    finally:
        worker.close()
        producer.close()


def test_completed_report_cannot_be_downgraded(reports):
    service, _objects = reports
    report_id = str(uuid.uuid4())
    with service.db_manager.get_session() as session:
        session.add(
            Report(
                id=report_id, tool_name="Example", status="completed", generation_stage="completed"
            )
        )
    assert service.mark_report_failed(report_id) is False
    assert service.update_generation_stage(report_id, "researching") is False
    assert service.get_report(report_id)["status"] == "completed"


@pytest.mark.parametrize("owner", ["first", "worker-" + "x" * 300])
def test_replacement_attempt_fences_the_old_writer(reports, artifact, owner):
    from src.domain.execution import GenerationLease, GenerationLeaseLost

    service, objects = reports
    report_id, run_id = str(uuid.uuid4()), str(uuid.uuid4())
    service.create_pending_report(report_id, "Example", "owner", runtime_dispatch=True)
    first = GenerationLease(run_id, owner, 1)
    second = GenerationLease(run_id, "second", 2)
    assert service.begin_runtime_attempt(report_id, first)
    assert service.begin_runtime_attempt(report_id, second)
    with pytest.raises(GenerationLeaseLost):
        service.finalize_report(report_id, artifact, generation_lease=first)
    assert objects == {}

    service.finalize_report(report_id, artifact, generation_lease=second)
    assert service.get_report(report_id)["status"] == "completed"


def test_runtime_failure_and_exhaustion_are_reconciled_without_regeneration(reports):
    from src.domain.execution import GenerationLease
    from dev.run_runtime_worker import runtime_clients_from_environment
    from src.execution.dispatcher import dispatch_pending_reports
    from src.execution.reconciler import reconcile_runtime_reports
    from src.storage.models import ReportRuntimeDispatch

    service, _objects = reports
    producer, worker = runtime_clients_from_environment()
    try:
        report_id = str(uuid.uuid4())
        service.create_pending_report(report_id, "Example", "owner", runtime_dispatch=True)
        assert dispatch_pending_reports(producer, service) == 1
        run = worker.claim("crashing-worker", lease_seconds=60)
        assert run
        service.begin_runtime_attempt(
            report_id, GenerationLease(run.run_id, run.lease_owner, run.lease_version)
        )
        worker.fail(
            run.run_id,
            run.lease_owner,
            run.lease_version,
            error_code="invalid_result",
            error_summary="test failure",
        )
        # Simulate a process dying before it can persist product failure.
        assert service.get_report(report_id)["status"] == "generating"
        assert reconcile_runtime_reports(producer, service) == 1
        assert service.get_report(report_id)["status"] == "failed"
        assert reconcile_runtime_reports(producer, service) == 0
        service.mark_runtime_dispatch_submitted(report_id, run.run_id)
        with service.db_manager.get_session() as session:
            assert session.get(ReportRuntimeDispatch, uuid.UUID(report_id)).state == "failed"

        abandoned_id = str(uuid.uuid4())
        service.create_pending_report(abandoned_id, "Example", "owner", runtime_dispatch=True)
        # Direct contract submission sets a one-attempt budget for this proof.
        submitted = producer._post_run(
            "/v1/runs",
            {
                "product": "sentrysearch",
                "workflow_name": "generate_report",
                "workflow_version": "v1",
                "idempotency_key": abandoned_id,
                "input_ref": {"report_id": abandoned_id},
                "max_attempts": 1,
            },
        )
        service.mark_runtime_dispatch_submitted(abandoned_id, submitted.run_id)
        abandoned = worker.claim("lost-worker", lease_seconds=1)
        assert abandoned
        service.begin_runtime_attempt(
            abandoned_id,
            GenerationLease(abandoned.run_id, abandoned.lease_owner, abandoned.lease_version),
        )
        time.sleep(1.1)
        assert worker.claim("recovery-worker", lease_seconds=60) is None
        assert reconcile_runtime_reports(producer, service) == 1
        assert service.get_report(abandoned_id)["status"] == "failed"
    finally:
        worker.close()
        producer.close()


def test_takeover_during_upload_preserves_the_winning_object(
    reports, artifact, runtime_clients, monkeypatch
):
    from src.domain.execution import GenerationLease, GenerationLeaseLost
    from src.execution.dispatcher import dispatch_pending_reports
    from src.execution.reconciler import reconcile_runtime_reports
    from src.execution.runtime_client import RuntimeLeaseFenced

    service, objects = reports
    producer, worker = runtime_clients
    report_id = str(uuid.uuid4())
    service.create_pending_report(report_id, "Example", "owner", runtime_dispatch=True)
    dispatch_pending_reports(producer, service)
    run = worker.claim("first", lease_seconds=1)
    assert run and run.attempt == 1
    first = GenerationLease(run.run_id, run.lease_owner, run.lease_version)
    service.begin_runtime_attempt(report_id, first)
    uploading, release = threading.Event(), threading.Event()
    original = service.s3_manager.upload_markdown_report

    def upload(report_id, content):
        if content.endswith("late attempt"):
            uploading.set()
            assert release.wait(10)
        return original(report_id, content)

    monkeypatch.setattr(service.s3_manager, "upload_markdown_report", upload)
    stale_artifact = dict(
        artifact, markdown_content=artifact["markdown_content"] + "\nlate attempt"
    )
    with ThreadPoolExecutor(max_workers=1) as executor:
        late = executor.submit(
            service.finalize_report, report_id, stale_artifact, generation_lease=first
        )
        try:
            assert uploading.wait(10)
            time.sleep(1.1)  # The old worker remains paused after its runtime lease expires.
            replacement = worker.claim("second", lease_seconds=60)
            assert replacement and replacement.run_id == run.run_id and replacement.attempt == 2
            second = GenerationLease(
                replacement.run_id, replacement.lease_owner, replacement.lease_version
            )
            assert service.begin_runtime_attempt(report_id, second)
            service.finalize_report(report_id, artifact, generation_lease=second)
            worker.complete(second.run_id, second.owner, second.version, {"report_id": report_id})
        finally:
            release.set()
        with pytest.raises(GenerationLeaseLost):
            late.result(timeout=10)
    with service.db_manager.get_session() as session:
        report = session.get(Report, uuid.UUID(report_id))
        assert objects[report.markdown_s3_key] == artifact["markdown_content"].encode()
        assert report.status == "completed"
    assert len(objects) == 2  # The rejected upload is unreferenced, not published.
    with pytest.raises(RuntimeLeaseFenced):
        worker.complete(first.run_id, first.owner, first.version, {"report_id": report_id})
    assert reconcile_runtime_reports(producer, service) == 1
    with pytest.raises(GenerationLeaseLost):
        service.mark_report_failed(report_id, generation_lease=first)
    assert service.begin_runtime_attempt(report_id, first) is False


def test_missing_and_durable_reports_reject_unfenced_writes(reports, artifact):
    from src.domain.execution import GenerationLease, GenerationLeaseLost

    service, objects = reports
    report_id = str(uuid.uuid4())
    with pytest.raises(GenerationLeaseLost):
        service.finalize_report(report_id, artifact)
    service.create_pending_report(report_id, "Example", "owner", runtime_dispatch=True)
    lease = GenerationLease(str(uuid.uuid4()), "worker", 2)
    service.begin_runtime_attempt(report_id, lease)
    assert service.mark_report_failed(report_id) is False
    assert service.update_generation_stage(report_id, "researching") is False
    for wrong in [
        GenerationLease(lease.run_id, "other", 2),
        GenerationLease(lease.run_id, "old", 1),
        GenerationLease(str(uuid.uuid4()), "worker", 3),
    ]:
        with pytest.raises(GenerationLeaseLost):
            service.begin_runtime_attempt(report_id, wrong)
    with service.db_manager.get_session() as session:
        session.delete(session.get(Report, uuid.UUID(report_id)))
    with pytest.raises(GenerationLeaseLost):
        service.finalize_report(report_id, artifact, generation_lease=lease)
    assert objects == {}


def test_worker_passes_the_registered_fence_to_generation(reports, artifact):
    from dev.run_runtime_worker import runtime_clients_from_environment
    from src.execution.worker import DurableGenerationWorker
    from src.execution.dispatcher import dispatch_pending_reports

    service, _objects = reports
    producer, runtime = runtime_clients_from_environment()
    report_id = str(uuid.uuid4())
    service.create_pending_report(report_id, "Example", "owner", runtime_dispatch=True)
    seen = []

    def generate(report_id, tool_name, user_id, lease):
        seen.append(lease)
        assert service.update_generation_stage(report_id, "finalizing", generation_lease=lease)
        service.finalize_report(report_id, artifact, user_id, generation_lease=lease)

    try:
        dispatch_pending_reports(producer, service)
        worker = DurableGenerationWorker(
            runtime=runtime,
            reports=service,
            generate=generate,
            worker_id="proof-worker",
            lease_seconds=60,
        )
        assert worker.run_once()
        assert len(seen) == 1
        assert producer.get_run(seen[0].run_id).state == "succeeded"
        assert service.get_report(report_id)["status"] == "completed"
    finally:
        producer.close()
        runtime.close()


def test_interrupted_evaluation_is_reclaimed_and_old_results_are_fenced(reports, artifact):
    from src.domain.execution import GenerationLease

    service, objects = reports
    report_id = str(uuid.uuid4())
    service.create_pending_report(report_id, "Example", "owner", runtime_dispatch=True)
    lease = GenerationLease(str(uuid.uuid4()), "generator", 1)
    service.begin_runtime_attempt(report_id, lease)
    service.finalize_report(report_id, artifact, generation_lease=lease)
    assert service.get_pending_runtime_evaluations(limit=20) == [(report_id, "owner")]
    first = service.claim_report_evaluation(report_id, user_id="owner", lease_seconds=60)
    assert first
    assert service.claim_report_evaluation(report_id, user_id="owner") is None
    assert service.get_pending_runtime_evaluations(limit=20) == []
    with service.db_manager.get_session() as session:
        session.execute(
            text(
                "UPDATE reports SET evaluation_lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=:id"
            ),
            {"id": report_id},
        )
    assert service.get_pending_runtime_evaluations(limit=20) == [(report_id, "owner")]
    second = service.claim_report_evaluation(report_id, user_id="owner")
    assert second and second != first
    completion = {
        "quality_assessment": {"overall_score": 4.0},
        "evaluation_route": {},
        "threat_data": artifact["threat_data"],
        "markdown_content": artifact["markdown_content"] + "\nnew evaluation",
    }
    old_objects = dict(objects)
    assert (
        service.complete_report_evaluation(report_id, evaluation_lease=first, **completion) is False
    )
    assert objects == old_objects
    assert service.complete_report_evaluation(report_id, evaluation_lease=second, **completion)
    assert (
        service.fail_report_evaluation(report_id, evaluation_lease=first, error_code="late_failure")
        is False
    )
    result = service.get_report(report_id)
    assert result["evaluation_status"] == "completed"
    assert result["evaluation_attempts"] == 2
    assert result["status"] == "completed"


def test_evaluation_crash_recovery_has_a_budget_and_manual_retry(reports, artifact):
    service, _objects = reports
    report_id = str(uuid.uuid4())
    service.create_pending_report(report_id, "Example", "owner")
    service.finalize_report(report_id, artifact)
    for _ in range(3):
        assert service.claim_report_evaluation(report_id, user_id="owner")
        with service.db_manager.get_session() as session:
            session.execute(
                text(
                    "UPDATE reports SET evaluation_lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=:id"
                ),
                {"id": report_id},
            )
    assert service.claim_report_evaluation(report_id, user_id="owner") is None
    assert service.get_report(report_id)["evaluation_status"] == "failed"
    assert service.get_report(report_id)["evaluation_error_code"] == "evaluation_recovery_exhausted"
    assert service.begin_report_evaluation(report_id, user_id="owner")
    assert service.claim_report_evaluation(report_id, user_id="owner")


def test_unclaimed_evaluation_cannot_publish_with_a_missing_token(reports, artifact):
    service, objects = reports
    report_id = str(uuid.uuid4())
    service.create_pending_report(report_id, "Example", "owner")
    service.finalize_report(report_id, artifact)
    before = dict(objects)
    assert not service.complete_report_evaluation(
        report_id,
        evaluation_lease="None",
        quality_assessment={"overall_score": 4.0},
        evaluation_route={},
        threat_data=artifact["threat_data"],
        markdown_content=artifact["markdown_content"] + "\nunclaimed evaluation",
    )
    assert not service.fail_report_evaluation(
        report_id, evaluation_lease="None", error_code="unclaimed_failure"
    )
    assert service.get_report(report_id)["evaluation_status"] == "pending"
    assert objects == before


@pytest.mark.parametrize("published", [False, True])
@pytest.mark.parametrize("terminal", ["succeeded", "failed"])
def test_terminal_observation_preserves_published_artifacts(reports, artifact, published, terminal):
    from src.domain.execution import GenerationLease, GenerationLeaseLost
    from src.storage.models import ReportRuntimeDispatch

    service, objects = reports
    report_id, run_id = str(uuid.uuid4()), str(uuid.uuid4())
    lease = GenerationLease(run_id, "worker", 1)
    service.create_pending_report(report_id, "Example", "owner", runtime_dispatch=True)
    service.begin_runtime_attempt(report_id, lease)
    if published:
        service.finalize_report(report_id, artifact, generation_lease=lease)
    assert service.apply_runtime_observation(
        report_id, run_id, state=terminal, lease_version=1, error_code=None
    )
    with service.db_manager.get_session() as session:
        report = session.get(Report, uuid.UUID(report_id))
        dispatch = session.get(ReportRuntimeDispatch, uuid.UUID(report_id))
        assert dispatch.state == terminal
        assert report.status == ("completed" if published else "failed")
        if published:
            assert objects[report.markdown_s3_key] == artifact["markdown_content"].encode()
            assert dispatch.last_error_code == (
                "runtime_failed_after_publication" if terminal == "failed" else None
            )
        elif terminal == "succeeded":
            assert report.generation_error_code == "persistence_failed"
            assert dispatch.last_error_code == "runtime_result_missing"
    with pytest.raises(GenerationLeaseLost):
        service.finalize_report(report_id, artifact, generation_lease=lease)
    assert service.begin_runtime_attempt(report_id, lease) is False
    service.mark_runtime_dispatch_submitted(report_id, run_id)
    assert service.get_runtime_reconciliation_batch() == []
    with pytest.raises(ValueError, match="does not match"):
        service.mark_runtime_dispatch_submitted(report_id, str(uuid.uuid4()))


def test_reconciliation_rotates_nonterminal_unavailable_and_stale_runs(reports):
    from src.domain.execution import GenerationLease

    service, _objects = reports
    ids = [str(uuid.uuid4()) for _ in range(3)]
    runs = [str(uuid.uuid4()) for _ in ids]
    for report_id, run_id in zip(ids, runs):
        service.create_pending_report(report_id, "Example", "owner", runtime_dispatch=True)
        service.begin_runtime_attempt(report_id, GenerationLease(run_id, "worker", 2))
    assert service.get_runtime_reconciliation_batch(limit=1) == [(ids[0], runs[0])]
    assert not service.apply_runtime_observation(
        ids[0], runs[0], state="running", lease_version=2, error_code=None
    )
    assert service.get_runtime_reconciliation_batch(limit=1) == [(ids[1], runs[1])]
    service.record_runtime_check_error(ids[1], "runtime_unavailable")
    assert service.get_runtime_reconciliation_batch(limit=1) == [(ids[2], runs[2])]
    assert not service.apply_runtime_observation(
        ids[2], runs[2], state="failed", lease_version=1, error_code="worker_lost"
    )
    assert service.get_runtime_reconciliation_batch(limit=1) == [(ids[0], runs[0])]
    assert all(service.get_report(report_id)["status"] == "generating" for report_id in ids)


def test_evaluation_takeover_during_upload_keeps_the_winning_score(reports, artifact, monkeypatch):
    service, objects = reports
    report_id = str(uuid.uuid4())
    service.create_pending_report(report_id, "Example", "owner")
    service.finalize_report(report_id, artifact)
    first = service.claim_report_evaluation(report_id, user_id="owner")
    assert first
    assert not service.begin_report_evaluation(report_id, user_id="owner")
    uploading, release = threading.Event(), threading.Event()
    original = service.s3_manager.upload_markdown_report

    def upload(report_id, content):
        if content.endswith("old evaluation"):
            uploading.set()
            assert release.wait(10)
        return original(report_id, content)

    monkeypatch.setattr(service.s3_manager, "upload_markdown_report", upload)
    completion = {
        "quality_assessment": {"overall_score": 1.0},
        "evaluation_route": {},
        "threat_data": artifact["threat_data"],
        "markdown_content": artifact["markdown_content"] + "\nold evaluation",
    }
    with ThreadPoolExecutor(max_workers=1) as executor:
        old = executor.submit(
            service.complete_report_evaluation, report_id, evaluation_lease=first, **completion
        )
        try:
            assert uploading.wait(10)
            with service.db_manager.get_session() as session:
                session.execute(
                    text(
                        "UPDATE reports SET evaluation_lease_expires_at=clock_timestamp() WHERE id=:id"
                    ),
                    {"id": report_id},
                )
            second = service.claim_report_evaluation(report_id, user_id="owner")
            assert second and second != first
            winner = dict(
                completion,
                quality_assessment={"overall_score": 4.0},
                markdown_content=artifact["markdown_content"] + "\nwinning evaluation",
            )
            assert service.complete_report_evaluation(report_id, evaluation_lease=second, **winner)
        finally:
            release.set()
        assert old.result(timeout=10) is False
    with service.db_manager.get_session() as session:
        report = session.get(Report, uuid.UUID(report_id))
        assert report.quality_score == 4.0
        assert objects[report.markdown_s3_key].endswith(b"winning evaluation")
        assert report.evaluation_status == "completed"


def test_recovered_evaluation_uses_saved_evidence_without_generation(
    reports, artifact, monkeypatch
):
    from types import SimpleNamespace
    from src.api import main as api
    from src.domain.execution import GenerationLease

    service, _objects = reports
    report_id = str(uuid.uuid4())
    service.create_pending_report(report_id, "Example", "owner", runtime_dispatch=True)
    lease = GenerationLease(str(uuid.uuid4()), "worker", 1)
    service.begin_runtime_attempt(report_id, lease)
    service.finalize_report(report_id, artifact, generation_lease=lease)
    calls = []

    def evaluate(profile):
        calls.append(profile)
        return SimpleNamespace(
            succeeded=True,
            profile=profile,
            quality_assessment={"overall_score": 4.25},
            evaluation_route={"request_count": 1},
        )

    monkeypatch.setattr(api, "report_service", service)
    monkeypatch.setattr(api, "evaluate_saved_report", evaluate)
    # The process stopped after artifact publication and before evaluation.
    for pending_id, owner in service.get_pending_runtime_evaluations():
        api.run_report_evaluation(pending_id, owner)
    assert len(calls) == 1
    api.run_report_evaluation(report_id, "owner")
    assert len(calls) == 1
    assert service.get_pending_runtime_evaluations() == []
    report = service.get_report(report_id)
    assert report["evaluation_status"] == "completed"
    assert report["quality_score"] == 4.25
    assert report["web_sources"] == artifact["web_sources"]


def test_additive_migration_backfills_existing_intents_and_evaluations(reports, artifact):
    from src.storage.models import ReportRuntimeDispatch

    service, _objects = reports
    report_id = str(uuid.uuid4())
    service.create_pending_report(report_id, "Example", "owner", runtime_dispatch=True)
    # Remove only the new columns from this isolated test database to model an upgrade.
    with service.db_manager.get_session() as session:
        # Historical installations predate the explicit release revision ledger.
        session.execute(text("DROP TABLE sentrysearch_schema_migrations"))
        for column in (
            "evaluation_lease_id",
            "evaluation_lease_expires_at",
            "evaluation_recoveries",
        ):
            session.execute(text(f"ALTER TABLE reports DROP COLUMN {column}"))
        for column in ("lease_owner", "lease_version"):
            session.execute(text(f"ALTER TABLE report_runtime_dispatches DROP COLUMN {column}"))
    service.db_manager.migrate_schema()
    service.db_manager.migrate_schema()
    with service.db_manager.get_session() as session:
        report = session.get(Report, uuid.UUID(report_id))
        dispatch = session.get(ReportRuntimeDispatch, uuid.UUID(report_id))
        assert report.status == "generating"
        assert report.evaluation_recoveries == 0
        assert report.evaluation_lease_id is None
        assert dispatch.state == "pending"
        assert dispatch.lease_version == 0
        assert dispatch.lease_owner is None


def test_runtime_backlog_reports_counts_without_report_contents(reports, artifact):
    from src.domain.execution import GenerationLease

    service, _objects = reports
    pending, evaluating, legacy = [str(uuid.uuid4()) for _ in range(3)]
    for report_id in (pending, evaluating, legacy):
        service.create_pending_report(
            report_id, "Private tool name", "private-owner", runtime_dispatch=report_id != legacy
        )
    lease = GenerationLease(str(uuid.uuid4()), "worker", 1)
    service.begin_runtime_attempt(evaluating, lease)
    service.finalize_report(evaluating, artifact, generation_lease=lease)
    service.finalize_report(legacy, artifact)
    assert service.has_runtime_dispatch(pending)
    assert service.has_runtime_dispatch(evaluating)
    assert not service.has_runtime_dispatch(legacy)
    service.record_runtime_dispatch_failure(pending, "runtime_unavailable")
    sampled = service.get_runtime_backlog()
    # The one pending intent was created moments ago.
    assert 0 <= sampled.pop("oldest_pending_seconds") < 60
    assert sampled == {
        "pending_dispatches": 1,
        "submitted_dispatches": 1,
        "ready_evaluations": 1,
        "active_evaluations": 0,
        "dispatch_errors": 1,
    }
    assert service.claim_report_evaluation(evaluating, user_id="private-owner")
    backlog = service.get_runtime_backlog()
    assert backlog["ready_evaluations"] == 0
    assert backlog["active_evaluations"] == 1
    with service.db_manager.get_session() as session:
        session.execute(
            text("UPDATE reports SET evaluation_lease_expires_at=clock_timestamp() WHERE id=:id"),
            {"id": evaluating},
        )
    backlog = service.get_runtime_backlog()
    assert backlog["ready_evaluations"] == 1
    assert backlog["active_evaluations"] == 0


def deadline_evaluator_worker(settings, stop, emit):
    """Run the real loop/storage with only the model call replaced by blocked work."""
    from dev import run_runtime_worker as runner
    from src.api import main as api
    from unittest.mock import patch

    manager = DatabaseManager.__new__(DatabaseManager)
    manager.engine = create_engine(os.environ["SENTRYSEARCH_TEST_PRODUCT_URL"])
    manager.SessionLocal = sessionmaker(bind=manager.engine, expire_on_commit=False)
    service = ReportStorageService()
    service.db_manager = manager

    class Client:
        def get_object(self, **kwargs):
            objects = json.loads(os.environ["SENTRYSEARCH_TEST_ARTIFACTS"])
            return {"Body": io.BytesIO(objects[kwargs["Key"]].encode("utf-8"))}

    store = S3StorageManager()
    store._initialized = True
    store.s3_client = cast(Any, Client())
    service.s3_manager = store

    def unexpected_generation(*_args):
        raise AssertionError("saved-evidence recovery must not generate")

    def hung_judge(_profile):
        emit({"event": "backlog", "counts": service.get_runtime_backlog()})
        time.sleep(30)
        raise AssertionError("evaluation deadline did not stop the judge")

    with (
        patch.object(api, "report_service", service),
        patch.object(api, "evaluate_saved_report", hung_judge),
        patch.object(
            runner,
            "load_jobs",
            return_value=(service, unexpected_generation, api.run_report_evaluation),
        ),
    ):
        return runner.run_worker_loop(settings, stop, emit)


def test_evaluation_deadline_leaves_a_recoverable_product_lease(
    reports, artifact, runtime_clients, monkeypatch
):
    from types import SimpleNamespace
    from src.api import main as api
    from src.domain.execution import GenerationLease
    from src.execution.dispatcher import dispatch_pending_reports
    from src.execution.supervisor import WorkerSettings, WorkerSupervisor

    service, _objects = reports
    producer, runtime = runtime_clients
    report_id = str(uuid.uuid4())
    service.create_pending_report(report_id, "Example", "owner", runtime_dispatch=True)
    dispatch_pending_reports(producer, service)
    run = runtime.claim("setup-worker", lease_seconds=60)
    assert run
    lease = GenerationLease(run.run_id, run.lease_owner, run.lease_version)
    service.begin_runtime_attempt(report_id, lease)
    service.finalize_report(report_id, artifact, generation_lease=lease)
    runtime.complete(run.run_id, run.lease_owner, run.lease_version, {"report_id": report_id})
    monkeypatch.setenv(
        "SENTRYSEARCH_TEST_ARTIFACTS",
        json.dumps({key: value.decode("utf-8") for key, value in _objects.items()}),
    )
    monkeypatch.setenv("SENTRYSEARCH_TEST_PRODUCT_URL", str(service.db_manager.engine.url))
    supervisor = WorkerSupervisor(
        WorkerSettings(once=True, evaluation_seconds=0.5), deadline_evaluator_worker
    )
    assert supervisor.run() == 124
    assert supervisor.status.snapshot()["error_code"] == "evaluation_deadline_exceeded"
    assert supervisor.status.snapshot()["backlog"]["counts"]["active_evaluations"] == 1
    assert service.get_report(report_id)["status"] == "completed"
    assert service.claim_report_evaluation(report_id, user_id="owner") is None
    assert service.get_runtime_backlog()["active_evaluations"] == 1
    with service.db_manager.get_session() as session:
        session.execute(
            text("UPDATE reports SET evaluation_lease_expires_at=clock_timestamp() WHERE id=:id"),
            {"id": report_id},
        )
    calls = []

    def judge(profile):
        calls.append(True)
        return SimpleNamespace(
            succeeded=True,
            profile=profile,
            quality_assessment={"overall_score": 4.0},
            evaluation_route={"request_count": 1},
        )

    monkeypatch.setattr(api, "report_service", service)
    monkeypatch.setattr(api, "evaluate_saved_report", judge)
    api.run_report_evaluation(report_id, "owner")
    result = service.get_report(report_id)
    assert calls == [True]
    assert result["evaluation_status"] == "completed"
    assert result["evaluation_attempts"] == 2
    assert result["web_sources"] == artifact["web_sources"]
    assert producer.get_run(run.run_id).state == "succeeded"

    # Manual retry keeps durable ownership even when the API has no runtime URL.
    import asyncio
    from fastapi import BackgroundTasks
    from src.auth.supabase_auth import AuthenticatedUser

    monkeypatch.delenv("SENTRYRUNTIME_LOCAL_URL", raising=False)
    monkeypatch.delenv("SENTRYRUNTIME_URL", raising=False)
    monkeypatch.delenv("SENTRYRUNTIME_CA_FILE", raising=False)
    monkeypatch.setenv("SENTRYSEARCH_EXECUTION_MODE", "legacy")
    background = BackgroundTasks()
    user = AuthenticatedUser(
        user_id="owner", email="owner@example.com", metadata={"role": "analyst"}
    )
    response = asyncio.run(api.retry_report_evaluation(report_id, background, user))
    assert response["evaluation_status"] == "pending"
    assert background.tasks == []
    assert service.get_pending_runtime_evaluations() == [(report_id, "owner")]


def test_paused_api_does_not_reserve_reports_or_evaluation(reports, artifact, monkeypatch):
    import asyncio
    from fastapi import BackgroundTasks, HTTPException
    from src.api import main as api
    from src.auth.supabase_auth import AuthenticatedUser
    from src.storage.models import ReportRuntimeDispatch

    service, _objects = reports
    report_id = str(uuid.uuid4())
    service.create_pending_report(report_id, "Example", "owner")
    service.finalize_report(report_id, artifact)
    before = service.get_report(report_id, include_content=False)
    monkeypatch.setattr(api, "report_service", service)
    monkeypatch.setenv("SENTRYSEARCH_EXECUTION_MODE", "paused")
    user = AuthenticatedUser(user_id="owner", email="owner@example.com", metadata={})
    tasks = BackgroundTasks()
    for action in (
        lambda: api.create_report(api.ReportCreate(tool_name="Blocked"), tasks, user),
        lambda: api.retry_report_evaluation(report_id, tasks, user),
    ):
        with pytest.raises(HTTPException) as error:
            asyncio.run(action())
        assert error.value.status_code == 503
    assert tasks.tasks == []
    assert service.get_report(report_id, include_content=False) == before
    with service.db_manager.get_session() as session:
        assert session.query(Report).count() == 1
        assert session.query(ReportRuntimeDispatch).count() == 0


def test_accepted_intent_survives_outage_and_drains_during_admission_pause(
    reports, artifact, runtime_clients, monkeypatch
):
    import asyncio
    from fastapi import BackgroundTasks
    from src.api import main as api
    from src.auth.supabase_auth import AuthenticatedUser
    from src.execution.dispatcher import dispatch_pending_reports
    from src.execution.runtime_client import RuntimeUnavailable
    from src.execution.worker import DurableGenerationWorker

    service, _objects = reports
    producer, runtime = runtime_clients
    monkeypatch.setattr(api, "report_service", service)
    monkeypatch.setenv("SENTRYSEARCH_EXECUTION_MODE", "runtime")
    user = AuthenticatedUser(user_id="owner", email="owner@example.com", metadata={})
    tasks = BackgroundTasks()
    accepted = asyncio.run(api.create_report(api.ReportCreate(tool_name="Example"), tasks, user))
    report_id = accepted["report_id"]
    assert tasks.tasks == []

    class Outage:
        def submit_report(self, report_id):
            raise RuntimeUnavailable("fixture outage")

    assert dispatch_pending_reports(Outage(), service) == 0
    assert service.get_pending_runtime_dispatches() == [report_id]
    assert service.get_report(report_id, include_content=False)["status"] == "generating"
    monkeypatch.setenv("SENTRYSEARCH_EXECUTION_MODE", "paused")
    assert dispatch_pending_reports(producer, service) == 1

    def generate(report_id, tool_name, user_id, lease):
        service.finalize_report(report_id, artifact, user_id, generation_lease=lease)

    worker = DurableGenerationWorker(
        runtime=runtime,
        reports=service,
        generate=generate,
        worker_id="pause-drain",
        lease_seconds=60,
    )
    assert worker.run_once()
    assert service.get_report(report_id, include_content=False)["status"] == "completed"
    assert service.get_pending_runtime_dispatches() == []
    assert service.get_pending_runtime_evaluations() == [(report_id, "owner")]


def test_the_cutover_drain_counts_only_running_legacy_writers(reports):
    """release_kits.cutover's drain query, against PostgreSQL (AWS-08c)."""
    from datetime import UTC, datetime, timedelta

    from release_kits.cutover import drain_statement

    service, _objects = reports
    legacy_generating, runtime_generating = str(uuid.uuid4()), str(uuid.uuid4())
    service.create_pending_report(legacy_generating, "Legacy", "owner")
    service.create_pending_report(runtime_generating, "Runtime", "owner", runtime_dispatch=True)
    finished = str(uuid.uuid4())
    evaluating = str(uuid.uuid4())
    expired = str(uuid.uuid4())
    abandoned = str(uuid.uuid4())
    now = datetime.now(UTC)
    with service.db_manager.get_session() as session:
        session.add(Report(id=uuid.UUID(finished), tool_name="Done", status="completed"))
        session.add(Report(id=uuid.UUID(abandoned), tool_name="Abandoned", status="generating",
                           created_at=now - timedelta(hours=3)))  # fmt: skip
        session.add(Report(id=uuid.UUID(evaluating), tool_name="Evaluating", status="completed",
                           evaluation_lease_expires_at=now + timedelta(minutes=5)))  # fmt: skip
        session.add(Report(id=uuid.UUID(expired), tool_name="Expired lease", status="completed",
                           evaluation_lease_expires_at=now - timedelta(minutes=5)))  # fmt: skip
    with service.db_manager.get_session() as session:
        counts = dict(session.execute(drain_statement()).mappings().one())
    assert counts == {"legacy_generating": 1, "legacy_evaluating": 1, "legacy_abandoned": 1}


# Terminal-mismatch counting over the real product store (F079; plan section 12) -------
#
# Each case drives reconcile_runtime_reports through ReconcileCounts over the real
# ReportStorageService with a fake Runtime read port, and checks the store's result,
# the rows and the counts.


class RuntimeReads:
    """The Runtime read port, answering from runs the test sets."""

    def __init__(self, runs: dict[str, Any] | None = None) -> None:
        self.runs: dict[str, Any] = dict(runs or {})
        self.missing: set[str] = set()
        self.unavailable = False
        self.before_answer: Any = None

    def get_run(self, run_id: str):
        from src.execution.runtime_client import RuntimeRunMissing, RuntimeUnavailable

        if self.before_answer is not None:
            self.before_answer()
        if self.unavailable:
            raise RuntimeUnavailable("runtime is unavailable")
        if run_id in self.missing:
            raise RuntimeRunMissing("bound runtime run is unavailable")
        return self.runs[run_id]


def bound(service, *, lease_version: int = 1) -> tuple[str, str]:
    """A generating report whose submitted intent is bound to a run."""
    from src.domain.execution import GenerationLease

    report_id, run_id = str(uuid.uuid4()), str(uuid.uuid4())
    service.create_pending_report(report_id, "Example", "owner", runtime_dispatch=True)
    service.mark_runtime_dispatch_submitted(report_id, run_id)
    assert service.begin_runtime_attempt(
        report_id, GenerationLease(run_id, "worker", lease_version)
    )
    return report_id, run_id


def observed(run_id: str, report_id: str, state: str, *, lease_version: int = 1):
    from src.execution.runtime_client import RuntimeRun

    return RuntimeRun(run_id=run_id, state=state, attempt=1, lease_owner="worker",
                      lease_version=lease_version, input_ref={"report_id": report_id},
                      error_code="worker_error" if state == "failed" else None)  # fmt: skip


def dispatch_of(service, report_id: str) -> tuple[str, str | None] | None:
    from src.storage.models import ReportRuntimeDispatch

    with service.db_manager.get_session() as session:
        row = session.get(ReportRuntimeDispatch, uuid.UUID(report_id))
        return None if row is None else (row.state, row.last_error_code)


def one_pass(service, runtime) -> Any:
    from src.execution.reconciler import ReconcileCounts, reconcile_runtime_reports

    counts = ReconcileCounts(service)
    reconcile_runtime_reports(runtime, counts)
    return counts


def test_a_succeeded_run_without_its_published_report_counts_once(reports):
    service, _objects = reports
    report_id, run_id = bound(service)
    result = service.apply_runtime_observation(report_id, run_id, state="succeeded",
                                               lease_version=1, error_code=None)  # fmt: skip
    assert result and result.disagreement == "runtime_result_missing"
    # Through the reconciler: a second report in the same state, counted once, then gone.
    report_id, run_id = bound(service)
    runtime = RuntimeReads({run_id: observed(run_id, report_id, "succeeded")})
    counts = one_pass(service, runtime)
    assert (counts.checked, counts.mismatches) == (1, 1)
    assert dispatch_of(service, report_id) == ("succeeded", "runtime_result_missing")
    report = service.get_report(report_id)
    assert report["status"] == "failed" and report["generation_error_code"] == "persistence_failed"
    again = one_pass(service, runtime)
    assert (again.checked, again.mismatches) == (0, 0), "the report left the batch"


def test_a_run_failed_after_publication_counts_once_and_keeps_the_report(reports, artifact):
    from src.domain.execution import GenerationLease

    service, objects = reports
    report_id, run_id = bound(service)
    service.finalize_report(
        report_id, artifact, generation_lease=GenerationLease(run_id, "worker", 1)
    )
    published = dict(objects)
    runtime = RuntimeReads({run_id: observed(run_id, report_id, "failed")})
    counts = one_pass(service, runtime)
    assert (counts.checked, counts.mismatches) == (1, 1)
    assert dispatch_of(service, report_id) == ("failed", "runtime_failed_after_publication")
    assert service.get_report(report_id)["status"] == "completed" and objects == published
    again = one_pass(service, runtime)
    assert (again.checked, again.mismatches) == (0, 0), "the report left the batch"


def test_a_run_naming_another_report_counts_on_every_pass(reports):
    service, _objects = reports
    report_id, run_id = bound(service)
    runtime = RuntimeReads({run_id: observed(run_id, "another-report", "succeeded")})
    for _pass in range(2):
        counts = one_pass(service, runtime)
        assert (counts.checked, counts.mismatches) == (1, 1)
        assert dispatch_of(service, report_id) == ("submitted", "runtime_reference_mismatch")


def test_a_run_answering_as_another_run_counts_on_every_pass(reports):
    service, _objects = reports
    report_id, run_id = bound(service)
    runtime = RuntimeReads({run_id: observed(str(uuid.uuid4()), report_id, "succeeded")})
    for _pass in range(2):
        counts = one_pass(service, runtime)
        assert (counts.checked, counts.mismatches) == (1, 1)
        assert dispatch_of(service, report_id) == ("submitted", "runtime_reference_mismatch")


def test_a_missing_bound_run_counts_on_every_pass(reports):
    service, _objects = reports
    report_id, run_id = bound(service)
    runtime = RuntimeReads()
    runtime.missing.add(run_id)
    for _pass in range(2):
        counts = one_pass(service, runtime)
        assert (counts.checked, counts.mismatches) == (1, 1)
        assert dispatch_of(service, report_id) == ("submitted", "runtime_run_missing")


def test_agreement_and_the_designed_recovery_count_nothing(reports, artifact):
    from src.domain.execution import GenerationLease

    service, _objects = reports
    succeeded, succeeded_run = bound(service)
    service.finalize_report(succeeded, artifact,
                            generation_lease=GenerationLease(succeeded_run, "worker", 1))  # fmt: skip
    failed, failed_run = bound(service)
    runtime = RuntimeReads({succeeded_run: observed(succeeded_run, succeeded, "succeeded"),
                            failed_run: observed(failed_run, failed, "failed")})  # fmt: skip
    counts = one_pass(service, runtime)
    assert (counts.checked, counts.mismatches) == (2, 0)
    assert dispatch_of(service, succeeded) == ("succeeded", None)
    assert service.get_report(succeeded)["status"] == "completed"
    assert dispatch_of(service, failed) == ("failed", None)
    report = service.get_report(failed)
    assert report["status"] == "failed" and report["generation_error_code"] == "unknown"


@pytest.mark.parametrize("state", ["queued", "running", "retry_wait"])
def test_a_run_still_in_progress_is_refused_and_counts_nothing(reports, state):
    service, _objects = reports
    report_id, run_id = bound(service)
    result = service.apply_runtime_observation(report_id, run_id, state=state, lease_version=1,
                                               error_code=None)  # fmt: skip
    assert not result and result.disagreement is None
    counts = one_pass(service, RuntimeReads({run_id: observed(run_id, report_id, state)}))
    assert (counts.checked, counts.mismatches) == (1, 0)
    assert dispatch_of(service, report_id) == ("submitted", None)
    assert service.get_report(report_id)["status"] == "generating"


def test_a_stale_observation_is_refused_and_counts_nothing(reports):
    service, _objects = reports
    report_id, run_id = bound(service, lease_version=2)
    counts = one_pass(service, RuntimeReads({run_id: observed(run_id, report_id, "failed",
                                                              lease_version=1)}))  # fmt: skip
    assert (counts.checked, counts.mismatches) == (1, 0)
    assert dispatch_of(service, report_id) == ("submitted", "stale_runtime_observation")
    assert service.get_report(report_id)["status"] == "generating"


def test_a_repeated_or_raced_observation_counts_its_disagreement_once(reports):
    from src.execution.reconciler import ReconcileCounts, reconcile_runtime_reports
    from src.storage.report_service import ReportStorageService

    service, _objects = reports
    report_id, run_id = bound(service)
    first = service.apply_runtime_observation(report_id, run_id, state="succeeded",
                                              lease_version=1, error_code=None)  # fmt: skip
    repeat = service.apply_runtime_observation(report_id, run_id, state="succeeded",
                                               lease_version=1, error_code=None)  # fmt: skip
    assert first and first.disagreement == "runtime_result_missing"
    assert not repeat and repeat.disagreement is None
    # Two services over one database: the second read its batch before the first applied.
    other = ReportStorageService()
    other.db_manager, other.s3_manager = service.db_manager, service.s3_manager
    report_id, run_id = bound(service)
    run = observed(run_id, report_id, "succeeded")
    winner, loser = ReconcileCounts(service), ReconcileCounts(other)
    racing = RuntimeReads({run_id: run})
    applied: list[int] = []
    racing.before_answer = lambda: applied.append(
        reconcile_runtime_reports(RuntimeReads({run_id: run}), winner)
    )
    assert reconcile_runtime_reports(racing, loser) == 0, "the loser applies nothing"
    assert applied == [1], "the winner applies the observation once"
    assert (winner.checked, winner.mismatches) == (1, 1)
    assert (loser.checked, loser.mismatches) == (1, 0), "the lost race is no disagreement"
    assert dispatch_of(service, report_id) == ("succeeded", "runtime_result_missing")


def test_an_observation_of_a_deleted_report_counts_nothing(reports):
    service, _objects = reports
    report_id, run_id = bound(service)
    runtime = RuntimeReads({run_id: observed(run_id, report_id, "succeeded")})
    runtime.before_answer = lambda: service.delete_report(report_id)
    counts = one_pass(service, runtime)
    assert (counts.checked, counts.mismatches) == (1, 0)
    assert service.get_report(report_id) is None and dispatch_of(service, report_id) is None


def test_an_unavailable_runtime_is_recorded_but_counts_nothing(reports):
    service, _objects = reports
    report_id, _run_id = bound(service)
    runtime = RuntimeReads()
    runtime.unavailable = True
    counts = one_pass(service, runtime)
    assert (counts.checked, counts.mismatches) == (1, 0)
    assert dispatch_of(service, report_id) == ("submitted", "runtime_unavailable")


def test_a_commit_failure_changes_no_row_and_no_count(reports, monkeypatch):
    from sqlalchemy.orm import Session

    from src.execution.reconciler import ReconcileCounts, reconcile_runtime_reports

    service, _objects = reports
    report_id, run_id = bound(service)
    before = dispatch_of(service, report_id)
    armed = {"on": False}
    commit = Session.commit

    def failing(self):
        if armed["on"]:
            armed["on"] = False
            self.flush()  # the changes reach the database; the rollback must undo them
            raise RuntimeError("commit failed")
        return commit(self)

    monkeypatch.setattr(Session, "commit", failing)
    runtime = RuntimeReads({run_id: observed(run_id, report_id, "succeeded")})
    runtime.before_answer = lambda: armed.update(on=True)
    counts = ReconcileCounts(service)
    with pytest.raises(RuntimeError, match="commit failed"):
        reconcile_runtime_reports(runtime, counts)
    assert (counts.checked, counts.mismatches) == (1, 0)
    monkeypatch.setattr(Session, "commit", commit)
    assert dispatch_of(service, report_id) == before == ("submitted", None)
    assert service.get_report(report_id)["status"] == "generating"
