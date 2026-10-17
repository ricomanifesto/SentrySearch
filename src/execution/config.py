"""Explicit API admission and worker endpoint configuration."""

from collections.abc import Iterable
from dataclasses import dataclass
import hashlib
import os
import re
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
    """The explicit mode for traffic outside any runtime admission scope."""
    env = os.environ if env is None else env
    mode = env.get("SENTRYSEARCH_EXECUTION_MODE", "paused")
    if mode not in {"paused", "legacy", "runtime"}:
        raise ValueError("execution mode must be paused, legacy, or runtime")
    scoped = runtime_scope_from_environment(env) is not None
    if mode == "runtime":
        if scoped:
            raise ValueError("a runtime admission scope narrows legacy or paused admission only")
        runtime_endpoint_from_environment(env)
        return "runtime"
    if mode == "legacy":
        if not scoped and any(
            env.get(name)
            for name in ("SENTRYRUNTIME_LOCAL_URL", "SENTRYRUNTIME_URL", "SENTRYRUNTIME_CA_FILE")
        ):
            raise ValueError("legacy execution conflicts with runtime endpoint settings")
        return "legacy"
    return "paused"


# An explicit runtime admission scope: the identities whose new reports are admitted
# to the runtime while every other identity keeps the explicit mode above. The scope
# is a list of user ids and the SHA-256 of its canonical form: a guard against typos
# and truncation, not authentication (whoever sets these settings could set the mode
# itself). The admission-scope kit's verify ties a deployment to a recorded scope.
SCOPE_ENV = "SENTRYSEARCH_RUNTIME_SCOPE"
SCOPE_SHA256_ENV = "SENTRYSEARCH_RUNTIME_SCOPE_SHA256"
_IDENTITY = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
MAX_SCOPE = 1000


def canonical_scope(identities: Iterable[str]) -> str:
    """The scope's canonical form: sorted, distinct identities joined by commas."""
    found = sorted(set(identities))
    if not found or len(found) > MAX_SCOPE or not all(_IDENTITY.fullmatch(i) for i in found):
        raise ValueError("a runtime scope is 1 to 1000 lowercase UUID identities")
    return ",".join(found)


def runtime_scope_from_environment(env: Mapping[str, str] | None = None) -> frozenset[str] | None:
    env = os.environ if env is None else env
    listed, digest = env.get(SCOPE_ENV, ""), env.get(SCOPE_SHA256_ENV, "")
    if not listed and not digest:
        return None
    identities = listed.split(",")
    scope = canonical_scope(identities)
    if scope != listed:
        raise ValueError("the runtime scope must be in its canonical form")
    if hashlib.sha256(scope.encode()).hexdigest() != digest:
        raise ValueError("the runtime scope does not match its recorded hash")
    if env.get("SENTRYSEARCH_EXECUTION_MODE") not in {"legacy", "paused"}:
        raise ValueError("a runtime scope needs an explicit legacy or paused mode")
    runtime_endpoint_from_environment(env)
    return frozenset(identities)


def execution_mode_for(identity: str, env: Mapping[str, str] | None = None) -> ExecutionMode:
    """New-report admission for one identity: the runtime if it is in scope."""
    mode = execution_mode_from_environment(env)
    scope = runtime_scope_from_environment(env)
    if scope is not None and identity in scope:
        return "runtime"
    return mode
