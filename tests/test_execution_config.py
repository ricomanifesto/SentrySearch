import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from src.execution.config import execution_mode_from_environment, runtime_endpoint_from_environment


@pytest.mark.parametrize(
    "env",
    [
        {},
        {"SENTRYRUNTIME_URL": "http://remote.example"},
        {"SENTRYRUNTIME_LOCAL_URL": "https://remote.example"},
        {
            "SENTRYRUNTIME_URL": "https://remote.example",
            "SENTRYRUNTIME_LOCAL_URL": "http://localhost:8080",
        },
    ],
)
def test_endpoint_requires_one_unambiguous_configuration(env):
    with pytest.raises(ValueError):
        runtime_endpoint_from_environment(env)


def test_execution_selection_is_explicit_and_pause_is_independent():
    assert execution_mode_from_environment({}) == "paused"
    assert (
        execution_mode_from_environment({"SENTRYRUNTIME_URL": "https://remote.example"}) == "paused"
    )
    assert execution_mode_from_environment({"SENTRYSEARCH_EXECUTION_MODE": "legacy"}) == "legacy"
    assert (
        execution_mode_from_environment(
            {
                "SENTRYSEARCH_EXECUTION_MODE": "runtime",
                "SENTRYRUNTIME_URL": "https://remote.example",
            }
        )
        == "runtime"
    )
    for env in [
        {"SENTRYSEARCH_EXECUTION_MODE": "runtime"},
        {"SENTRYSEARCH_EXECUTION_MODE": ""},
        {"SENTRYSEARCH_EXECUTION_MODE": "auto"},
        {
            "SENTRYSEARCH_EXECUTION_MODE": "legacy",
            "SENTRYRUNTIME_LOCAL_URL": "http://localhost:8080",
        },
        {"SENTRYSEARCH_EXECUTION_MODE": "legacy", "SENTRYRUNTIME_CA_FILE": "unused"},
    ]:
        with pytest.raises(ValueError):
            execution_mode_from_environment(env)


@pytest.mark.parametrize("tokens", [(None, None), ("p" * 40, None), ("p" * 40, "p" * 40)])
def test_remote_worker_requires_distinct_tokens_before_loading_jobs(monkeypatch, tokens):
    from dev import run_runtime_worker as runner
    from src.execution.supervisor import WorkerSettings

    monkeypatch.setenv("SENTRYRUNTIME_URL", "https://remote.example")
    monkeypatch.delenv("SENTRYRUNTIME_LOCAL_URL", raising=False)
    for name, token in zip(("SENTRYRUNTIME_PRODUCER_TOKEN", "SENTRYRUNTIME_WORKER_TOKEN"), tokens):
        if token is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, token)
    jobs = Mock(side_effect=AssertionError("loaded application before validating transport"))
    monkeypatch.setattr(runner, "load_jobs", jobs)
    with pytest.raises(ValueError, match="tokens"):
        runner.run_worker_loop(WorkerSettings(once=True), threading.Event(), lambda _: None)
    jobs.assert_not_called()


def test_worker_cli_loads_environment_before_spawning(monkeypatch):
    from dev import run_runtime_worker as runner

    calls = []
    monkeypatch.setattr(runner, "load_dotenv", lambda: calls.append("environment"), raising=False)
    monkeypatch.setattr(runner, "parse_args", lambda: SimpleNamespace())

    class Supervisor:
        def __init__(self, *_args):
            calls.append("supervisor")

        def run(self):
            return 0

    monkeypatch.setattr(runner, "WorkerSupervisor", Supervisor)
    assert runner.main() == 0
    assert calls == ["environment", "supervisor"]
