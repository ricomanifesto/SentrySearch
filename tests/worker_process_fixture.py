"""No-services executable fixture for real supervisor signal/parent-death tests."""

import argparse
import json
import os
import signal
import time
from unittest.mock import patch

from src.execution.supervisor import WorkerSettings, WorkerSupervisor


def cooperative(settings, stop, emit):
    print(json.dumps({"worker_pid": os.getpid()}), flush=True)
    emit({"event": "phase", "phase": "generation"})
    emit({"event": "ready", "value": True})
    stop.wait(20)
    time.sleep(0.7)
    return 0


def uncooperative(settings, stop, emit):
    print(json.dumps({"worker_pid": os.getpid()}), flush=True)
    emit({"event": "phase", "phase": "evaluation"})
    emit({"event": "ready", "value": True})
    time.sleep(20)
    return 0


class FixtureSupervisor(WorkerSupervisor):
    def _health_server(self):
        server = super()._health_server()
        print(json.dumps({"health_url": f"http://127.0.0.1:{server.server_port}"}), flush=True)
        return server


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("cooperative", "uncooperative", "locked-signal"))
    args = parser.parse_args()
    target = uncooperative if args.mode == "uncooperative" else cooperative
    supervisor = FixtureSupervisor(WorkerSettings(drain_seconds=2), target)
    if args.mode == "locked-signal":
        observe = supervisor.status.observe

        def signal_while_locked(event):
            if event["event"] == "ready":
                with supervisor.status._lock:
                    os.kill(os.getpid(), signal.SIGTERM)
            observe(event)

        with patch.object(supervisor.status, "observe", signal_while_locked):
            raise SystemExit(supervisor.run())
    raise SystemExit(supervisor.run())
