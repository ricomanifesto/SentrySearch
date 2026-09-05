#!/usr/bin/env python3
"""Run the opt-in local SentrySearch durable-generation worker."""

from __future__ import annotations

import argparse
import logging
import os
import signal
import socket
import threading

from src.api.main import generate_report_artifact, run_report_evaluation
from src.execution.dispatcher import dispatch_pending_reports
from src.execution.reconciler import reconcile_runtime_reports
from src.execution.runtime_client import (
    RuntimeAccessDenied,
    RuntimeClient,
    RuntimeUnavailable,
    validate_runtime_token,
)
from src.execution.worker import DurableGenerationWorker
from src.storage.report_service import report_service

logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true", help="run one dispatch and claim cycle")
    parser.add_argument("--poll-seconds", type=float, default=2.0)
    parser.add_argument("--lease-seconds", type=int, default=60)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    # TODO(sentryruntime-cutover): Move this local process into the deployed worker
    # service after report-write fencing, terminal reconciliation, authenticated
    # transport, and the deployed canary are verified.
    if args.poll_seconds <= 0:
        raise SystemExit("--poll-seconds must be positive")

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    stop = threading.Event()

    def request_stop(_signum: int, _frame: object) -> None:
        stop.set()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)

    worker_id = f"{socket.gethostname()}-{os.getpid()}"
    dispatcher_runtime, runtime = runtime_clients_from_environment()
    try:
        worker = DurableGenerationWorker(
            runtime=runtime,
            reports=report_service,
            generate=generate_report_artifact,
            after_complete=run_report_evaluation,
            worker_id=worker_id,
            lease_seconds=args.lease_seconds,
        )
        while not stop.is_set():
            reconcile_runtime_reports(dispatcher_runtime, report_service)
            dispatched = dispatch_pending_reports(dispatcher_runtime, report_service)
            try:
                claimed = worker.run_once()
            except RuntimeUnavailable:
                logger.warning("Local runtime is unavailable; retrying after the poll interval")
                claimed = False
            if dispatched:
                logger.info("Submitted %d pending report run(s)", dispatched)
            # Includes reports published just before a generation worker crashed,
            # even when that runtime run has already become terminal.
            reconcile_runtime_reports(dispatcher_runtime, report_service)
            for report_id, user_id in report_service.get_pending_runtime_evaluations(limit=1):
                if stop.is_set():
                    break
                run_report_evaluation(report_id, user_id)
            if args.once:
                return 0
            if not claimed:
                stop.wait(args.poll_seconds)
    except RuntimeAccessDenied:
        logger.error("Runtime credentials or scope were rejected; stopping the worker")
        return 1
    finally:
        runtime.close()
        dispatcher_runtime.close()
    return 0


def runtime_clients_from_environment() -> tuple[RuntimeClient, RuntimeClient]:
    """Keep submission authority separate from execution authority."""

    runtime_url = os.getenv("SENTRYRUNTIME_LOCAL_URL", "")
    if not runtime_url.strip():
        raise ValueError("SENTRYRUNTIME_LOCAL_URL is required")
    producer_token = os.getenv("SENTRYRUNTIME_PRODUCER_TOKEN") or None
    worker_token = os.getenv("SENTRYRUNTIME_WORKER_TOKEN") or None
    if (producer_token is None) != (worker_token is None):
        raise ValueError("set both runtime producer and worker tokens, or neither for local mode")
    validate_runtime_token(producer_token)
    validate_runtime_token(worker_token)
    producer = RuntimeClient(runtime_url, bearer_token=producer_token)
    try:
        worker = RuntimeClient(runtime_url, bearer_token=worker_token)
    except Exception:
        producer.close()
        raise
    return producer, worker


if __name__ == "__main__":
    raise SystemExit(main())
