"""Explicit API admission and worker endpoint configuration."""

from dataclasses import dataclass
import os
from typing import Literal, Mapping

from src.execution.runtime_client import validate_runtime_url

# TODO(sentryruntime-cutover): Remove legacy admission after deployed canary,
# legacy-report migration, and compatible rollback are verified.
ExecutionMode = Literal["paused", "legacy", "runtime"]


@dataclass(frozen=True, repr=False)
class RuntimeEndpoint:
    url: str
    remote: bool
    ca_file: str | None


def runtime_endpoint_from_environment(env: Mapping[str, str] | None = None) -> RuntimeEndpoint:
    env = os.environ if env is None else env
    local, remote = env.get("SENTRYRUNTIME_LOCAL_URL", ""), env.get("SENTRYRUNTIME_URL", "")
    if bool(local) == bool(remote):
        raise ValueError("configure exactly one local or remote runtime URL")
    url = validate_runtime_url(remote or local, remote=bool(remote))
    ca_file = env.get("SENTRYRUNTIME_CA_FILE") or None
    if ca_file and not url.startswith("https://"):
        raise ValueError("runtime trust configuration requires HTTPS")
    return RuntimeEndpoint(url, bool(remote), ca_file)


def execution_mode_from_environment(env: Mapping[str, str] | None = None) -> ExecutionMode:
    env = os.environ if env is None else env
    mode = env.get("SENTRYSEARCH_EXECUTION_MODE", "paused")
    if mode not in {"paused", "legacy", "runtime"}:
        raise ValueError("execution mode must be paused, legacy, or runtime")
    if mode == "runtime":
        runtime_endpoint_from_environment(env)
        return "runtime"
    if mode == "legacy":
        if any(
            env.get(name)
            for name in ("SENTRYRUNTIME_LOCAL_URL", "SENTRYRUNTIME_URL", "SENTRYRUNTIME_CA_FILE")
        ):
            raise ValueError("legacy execution conflicts with runtime endpoint settings")
        return "legacy"
    return "paused"
