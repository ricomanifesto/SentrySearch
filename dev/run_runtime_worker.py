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
from src.execution.runtime_client import RuntimeClient, RuntimeUnavailable
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
    # service after authenticated runtime connectivity is available.
    runtime_url = os.getenv("SENTRYRUNTIME_LOCAL_URL", "")
    if not runtime_url.strip():
        raise SystemExit("SENTRYRUNTIME_LOCAL_URL is required")
    if args.poll_seconds <= 0:
        raise SystemExit("--poll-seconds must be positive")

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    stop = threading.Event()

    def request_stop(_signum: int, _frame: object) -> None:
        stop.set()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)

    worker_id = f"{socket.gethostname()}-{os.getpid()}"
    runtime = RuntimeClient(runtime_url)
    worker = DurableGenerationWorker(
        runtime=runtime,
        reports=report_service,
        generate=generate_report_artifact,
        after_complete=run_report_evaluation,
        worker_id=worker_id,
        lease_seconds=args.lease_seconds,
    )
    try:
        while not stop.is_set():
            dispatched = dispatch_pending_reports(runtime, report_service)
            try:
                claimed = worker.run_once()
            except RuntimeUnavailable:
                logger.warning("Local runtime is unavailable; retrying after the poll interval")
                claimed = False
            if dispatched:
                logger.info("Submitted %d pending report run(s)", dispatched)
            if args.once:
                return 0
            if not claimed:
                stop.wait(args.poll_seconds)
    finally:
        runtime.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
