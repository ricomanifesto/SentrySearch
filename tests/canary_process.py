"""Importable spawn target: test-only I/O fixtures, production worker loop."""

from dev.run_runtime_worker import parse_args, run_worker_loop
from src.execution.supervisor import WorkerSettings, WorkerSupervisor
import json


def run_canary_worker(settings, stop, emit):
    from tests.canary_fixtures import install_worker_fixtures

    with install_worker_fixtures() as fixtures:
        result = run_worker_loop(settings, stop, emit)
        print(
            "Canary fixture receipt: "
            + json.dumps(
                {
                    "model_requests": fixtures.request_counts,
                    "source_requests": fixtures.source_requests,
                }
            ),
            flush=True,
        )
        return result


if __name__ == "__main__":
    raise SystemExit(
        WorkerSupervisor(WorkerSettings(**vars(parse_args())), run_canary_worker).run()
    )
