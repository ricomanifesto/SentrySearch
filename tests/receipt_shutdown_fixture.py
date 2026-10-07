"""Subprocess fixture: worker receipts on an unread stdout pipe, then normal exit.

Runs the real worker entrypoint wiring with a release identity. Only the
supervisor loop is replaced: it alternates readiness so every observation emits,
until the unread pipe fills and receipts start dropping. It then closes the
emitter with a short bound and lets the interpreter shut down normally.
Executed by tests/test_worker_readiness_receipts.py.
"""

import os
import resource
import sys
import time
from pathlib import Path

resource.setrlimit(resource.RLIMIT_CORE, (0, 0))  # an abort leaves no core file

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dev import run_runtime_worker  # noqa: E402


class FillingSupervisor:
    def __init__(self, settings, target, *, receipts=None):
        self.receipts = receipts

    def run(self):
        receipts = self.receipts
        assert receipts is not None
        print("APPLICATION_OUTPUT", flush=True)  # ordinary stdout still works
        deadline = time.monotonic() + 10
        ready = True
        # Paced so the writer keeps up until the pipe is really full; only a
        # writer blocked on stdout lets 100 receipts drop.
        while receipts.dropped < 100 and time.monotonic() < deadline:
            ready = not ready
            receipts.observe(
                {"alive": True, "ready": ready, "draining": False, "phase": "idle",
                 "phase_elapsed_seconds": 1.0, "phase_budget_seconds": 62.0,
                 "error_code": None}  # fmt: skip
            )
            time.sleep(0.001)
        print(f"DROPPED={receipts.dropped}", file=sys.stderr, flush=True)
        receipts.close({"alive": False, "ready": False, "phase": "stopped"}, timeout=0.1)
        print(f"WRITER_ALIVE={receipts._writer.is_alive()}", file=sys.stderr)
        print(f"STDOUT_BLOCKING={os.get_blocking(sys.stdout.fileno())}", file=sys.stderr)
        print("CLOSE_RETURNED", file=sys.stderr, flush=True)
        return 0


setattr(run_runtime_worker, "WorkerSupervisor", FillingSupervisor)
sys.argv = ["run_runtime_worker"]
raise SystemExit(run_runtime_worker.main())
