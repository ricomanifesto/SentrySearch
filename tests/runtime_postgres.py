"""Explicit integration suite; run with dev/check_runtime_consistency.py."""

import os
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
    from src.execution.runtime_client import RuntimeClient

    producer = RuntimeClient(
        os.environ["SENTRYRUNTIME_LOCAL_URL"],
        bearer_token=os.environ["SENTRYRUNTIME_PRODUCER_TOKEN"],
    )
    worker = RuntimeClient(
        os.environ["SENTRYRUNTIME_LOCAL_URL"], bearer_token=os.environ["SENTRYRUNTIME_WORKER_TOKEN"]
    )
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
    from src.execution.runtime_client import RuntimeClient
    from src.execution.dispatcher import dispatch_pending_reports
    from src.execution.reconciler import reconcile_runtime_reports
    from src.storage.models import ReportRuntimeDispatch

    service, _objects = reports
    producer = RuntimeClient(
        os.environ["SENTRYRUNTIME_LOCAL_URL"],
        bearer_token=os.environ["SENTRYRUNTIME_PRODUCER_TOKEN"],
    )
    worker = RuntimeClient(
        os.environ["SENTRYRUNTIME_LOCAL_URL"], bearer_token=os.environ["SENTRYRUNTIME_WORKER_TOKEN"]
    )
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
    from src.execution.runtime_client import RuntimeClient
    from src.execution.worker import DurableGenerationWorker
    from src.execution.dispatcher import dispatch_pending_reports

    service, _objects = reports
    producer = RuntimeClient(
        os.environ["SENTRYRUNTIME_LOCAL_URL"],
        bearer_token=os.environ["SENTRYRUNTIME_PRODUCER_TOKEN"],
    )
    runtime = RuntimeClient(
        os.environ["SENTRYRUNTIME_LOCAL_URL"], bearer_token=os.environ["SENTRYRUNTIME_WORKER_TOKEN"]
    )
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
