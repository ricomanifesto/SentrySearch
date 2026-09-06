#!/usr/bin/env python3
"""Run the opt-in SentrySearch durable-generation worker."""

from __future__ import annotations

import argparse
import logging
import os
import socket
import threading
import time

from dotenv import load_dotenv

from src.execution.dispatcher import dispatch_pending_reports
from src.execution.config import runtime_endpoint_from_environment
from src.execution.reconciler import reconcile_runtime_reports
from src.execution.runtime_client import (
    RuntimeAccessDenied,
    RuntimeClient,
    RuntimeUnavailable,
    validate_runtime_token,
)
from src.execution.worker import DurableGenerationWorker
from src.execution.supervisor import Emit, WorkerSettings, WorkerSupervisor

logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--once", action="store_true", help="run one dispatch, claim, and evaluation cycle"
    )
    parser.add_argument("--poll-seconds", type=float, default=2.0)
    parser.add_argument("--lease-seconds", type=int, default=60)
    parser.add_argument(
        "--health-port", type=int, default=0, help="loopback probe port; 0 selects a free port"
    )
    parser.add_argument("--startup-seconds", type=float, default=60)
    parser.add_argument("--maintenance-seconds", type=float, default=120)
    parser.add_argument("--generation-seconds", type=float, default=1800)
    parser.add_argument("--evaluation-seconds", type=float, default=600)
    parser.add_argument("--drain-seconds", type=float, default=30)
    return parser.parse_args()


def main() -> int:
    # TODO(sentryruntime-cutover): Move this local process into the deployed worker
    # service after report-write fencing, terminal reconciliation, authenticated
    # transport, and the deployed canary are verified.
    load_dotenv()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        settings = WorkerSettings(**vars(parse_args()))
        return WorkerSupervisor(settings, run_worker_loop).run()
    except ValueError as error:
        raise SystemExit(str(error)) from error


def load_jobs():
    # Construct application clients only inside the spawned worker process.
    from src.api.main import generate_report_artifact, run_report_evaluation
    from src.storage.report_service import report_service

    return report_service, generate_report_artifact, run_report_evaluation


def run_worker_loop(settings: WorkerSettings, stop: threading.Event, emit: Emit) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    worker_id = f"{socket.gethostname()}-{os.getpid()}"
    dispatcher_runtime, runtime = runtime_clients_from_environment()

    def runtime_ready() -> None:
        emit({"event": "recovered"})
        emit({"event": "ready", "value": True})

    def sample_backlog() -> None:
        sampled_at = time.monotonic()
        emit({"event": "backlog", "counts": report_service.get_runtime_backlog(), "at": sampled_at})

    try:
        report_service, generate, evaluate = load_jobs()
        worker = DurableGenerationWorker(
            runtime=runtime,
            reports=report_service,
            generate=generate,
            on_runtime_ready=runtime_ready,
            worker_id=worker_id,
            lease_seconds=settings.lease_seconds,
        )
        while not stop.is_set():
            emit({"event": "phase", "phase": "maintenance"})
            sample_backlog()
            reconcile_runtime_reports(dispatcher_runtime, report_service)
            if stop.is_set():
                break
            dispatched = dispatch_pending_reports(
                dispatcher_runtime, report_service, should_stop=stop.is_set
            )
            if stop.is_set():
                break
            emit({"event": "phase", "phase": "generation"})
            try:
                claimed = worker.run_once()
            except RuntimeUnavailable:
                logger.warning("Runtime is unavailable; retrying after the poll interval")
                emit({"event": "error", "code": "runtime_unavailable"})
                claimed = False
            if dispatched:
                logger.info("Submitted %d pending report run(s)", dispatched)
            if stop.is_set():
                break
            emit({"event": "phase", "phase": "maintenance"})
            reconcile_runtime_reports(dispatcher_runtime, report_service)
            sample_backlog()
            for report_id, user_id in report_service.get_pending_runtime_evaluations(limit=1):
                if stop.is_set():
                    break
                emit({"event": "phase", "phase": "evaluation"})
                evaluate(report_id, user_id)
            emit({"event": "phase", "phase": "idle"})
            if settings.once:
                return 0
            if not claimed:
                stop.wait(settings.poll_seconds)
    except RuntimeAccessDenied:
        logger.error("Runtime credentials or scope were rejected; stopping the worker")
        emit({"event": "error", "code": "runtime_access_denied"})
        return 1
    finally:
        runtime.close()
        dispatcher_runtime.close()
    return 0


def runtime_clients_from_environment() -> tuple[RuntimeClient, RuntimeClient]:
    """Keep submission authority separate from execution authority."""

    endpoint = runtime_endpoint_from_environment()
    producer_token = os.getenv("SENTRYRUNTIME_PRODUCER_TOKEN") or None
    worker_token = os.getenv("SENTRYRUNTIME_WORKER_TOKEN") or None
    if (producer_token is None) != (worker_token is None):
        raise ValueError("set both runtime producer and worker tokens, or neither for local mode")
    if endpoint.remote and (
        not producer_token or not worker_token or producer_token == worker_token
    ):
        raise ValueError("remote runtime requires distinct producer and worker tokens")
    validate_runtime_token(producer_token)
    validate_runtime_token(worker_token)
    producer = RuntimeClient(
        endpoint.url, bearer_token=producer_token, remote=endpoint.remote, ca_file=endpoint.ca_file
    )
    try:
        worker = RuntimeClient(
            endpoint.url,
            bearer_token=worker_token,
            remote=endpoint.remote,
            ca_file=endpoint.ca_file,
        )
    except Exception:
        producer.close()
        raise
    return producer, worker


if __name__ == "__main__":
    raise SystemExit(main())
