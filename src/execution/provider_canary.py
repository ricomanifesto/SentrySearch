"""Caps for a real-provider canary (AWS-08b), enforced by the worker's own transports.

A canary manifest (``sentry.provider-canary.v1``) names each provider the worker
may reach, the hosts it may use, how many requests it may send, the budget it is
reviewed against and when it stops::

    {"schema": "sentry.provider-canary.v1", "canary_id": "aws-08b-1",
     "not_after": "2026-10-20T18:00:00Z", "budget_usd": 25,
     "providers": {"openrouter": {"hosts": ["openrouter.ai"], "max_requests": 40},
                   "sources": {"hosts": ["example.org"], "max_requests": 20}},
     "stop": {"max_consecutive_failures": 3}}

With ``SENTRYSEARCH_PROVIDER_CANARY`` set to that JSON, every model request and
every source fetch goes through ``CappedTransport``: a host the manifest does not
name, a request past its provider's count, a request after ``not_after``, or one
after the consecutive-failure limit is refused before the request is sent, and the
refusal is final for the process (no retry turns it into a request). The source
fetcher's own public-address check still resolves a source host in DNS before
its request reaches the cap; no connection is opened to a refused host. The
consecutive-failure limit counts every capped provider together: failing source
fetches in a row stop model requests too.

**This is not a hard spending cap.** Counts live in the worker process: a
restarted or replaced task starts from zero, several tasks each have their own
count, and a request in flight is billed even when its answer is refused. Model
spend is billed by the provider, not by AWS, so the AWS budget cannot see it. The
control for provider spend is the provider key's own credit limit (a hard cap on
the provider side), set to ``budget_usd``, with the provider's usage alerts; the
foundation's AWS budget alarm covers only the AWS costs of the canary (tasks,
endpoints, logs). These caps only bound what one worker sends.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
import json
import os
import re
import threading
from typing import Any, Callable, Mapping

import httpx

ENV = "SENTRYSEARCH_PROVIDER_CANARY"
SCHEMA = "sentry.provider-canary.v1"
PROVIDERS = ("openrouter", "sources")
_HOST = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+")
MAX_REQUESTS = 1000


class CanaryCapReached(httpx.TransportError):
    """A request the canary manifest does not allow; it is never sent.

    A transport error so the clients stop at their usual boundary, but never one
    their retry rules treat as transient: callers check for it first.
    """


@dataclass(frozen=True)
class Provider:
    hosts: frozenset[str]
    max_requests: int


@dataclass
class CanaryCaps:
    canary_id: str
    not_after: datetime
    budget_usd: int
    providers: dict[str, Provider]
    max_consecutive_failures: int
    now: Callable[[], datetime] = field(default=lambda: datetime.now(UTC))
    sent: dict[str, int] = field(default_factory=dict)
    consecutive_failures: int = 0
    stopped: str | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)

    def admit(self, provider: str, host: str) -> None:
        with self.lock:
            if self.stopped is not None:
                raise CanaryCapReached(f"canary stopped: {self.stopped}")
            allowed = self.providers.get(provider)
            if allowed is None or host not in allowed.hosts:
                raise CanaryCapReached(f"{provider}: host not named by the canary")
            if self.now() >= self.not_after:
                self.stopped = "past not_after"
                raise CanaryCapReached("canary stopped: past not_after")
            if self.sent.get(provider, 0) >= allowed.max_requests:
                raise CanaryCapReached(f"{provider}: request cap reached")
            self.sent[provider] = self.sent.get(provider, 0) + 1

    def outcome(self, failed: bool) -> None:
        with self.lock:
            self.consecutive_failures = self.consecutive_failures + 1 if failed else 0
            if self.consecutive_failures >= self.max_consecutive_failures:
                self.stopped = "consecutive failure limit"

    def transport(
        self, provider: str, inner: httpx.BaseTransport | None = None
    ) -> "CappedTransport":
        return CappedTransport(self, provider, inner or httpx.HTTPTransport())


class CappedTransport(httpx.BaseTransport):
    def __init__(self, caps: CanaryCaps, provider: str, inner: httpx.BaseTransport) -> None:
        self.caps, self.provider, self.inner = caps, provider, inner

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.caps.admit(self.provider, request.url.host)
        try:
            response = self.inner.handle_request(request)
        except httpx.TransportError:
            self.caps.outcome(failed=True)
            raise
        self.caps.outcome(failed=response.status_code >= 500 or response.status_code == 429)
        return response

    def close(self) -> None:
        # A model client keeps one transport for its life and opens a short-lived
        # httpx.Client per request, which closes its transport on exit. Closing the
        # shared pool there would cut every concurrent request, so it stays open for
        # the life of the process.
        return None


def load(document: Mapping[str, Any]) -> CanaryCaps:
    if not isinstance(document, Mapping) or document.get("schema") != SCHEMA:
        raise ValueError(f"the canary manifest is not {SCHEMA}")
    if set(document) != {"schema", "canary_id", "not_after", "budget_usd", "providers", "stop"}:
        raise ValueError("the canary manifest has exactly its six fields")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", str(document["canary_id"])):
        raise ValueError("canary_id is a lowercase name")
    try:
        not_after = datetime.strptime(str(document["not_after"]), "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise ValueError("not_after is a UTC time") from None
    budget = document["budget_usd"]
    if not isinstance(budget, int) or isinstance(budget, bool) or not 0 < budget <= 1000:
        raise ValueError("budget_usd is whole dollars up to 1000")
    providers: dict[str, Provider] = {}
    for name, spec in (document["providers"] or {}).items():
        if name not in PROVIDERS or not isinstance(spec, Mapping):
            raise ValueError(f"unknown provider {name!r}; providers are {PROVIDERS}")
        hosts, count = spec.get("hosts"), spec.get("max_requests")
        if (not isinstance(hosts, list) or not hosts
                or not all(isinstance(h, str) and _HOST.fullmatch(h) for h in hosts)):  # fmt: skip
            raise ValueError(f"{name}: hosts are explicit lowercase names")
        if not isinstance(count, int) or isinstance(count, bool) or not 0 < count <= MAX_REQUESTS:
            raise ValueError(f"{name}: max_requests is 1 to {MAX_REQUESTS}")
        providers[name] = Provider(frozenset(str(host) for host in hosts), count)
    if not providers:
        raise ValueError("the canary names at least one provider")
    stop = document["stop"]
    limit = stop.get("max_consecutive_failures") if isinstance(stop, Mapping) else None
    if (
        set(stop or {}) != {"max_consecutive_failures"}
        or not isinstance(limit, int)
        or not (0 < limit <= 20)
    ):
        raise ValueError("stop names max_consecutive_failures, 1 to 20")
    return CanaryCaps(str(document["canary_id"]), not_after.replace(tzinfo=UTC), budget,
                      providers, limit)  # fmt: skip


_CAPS: CanaryCaps | None = None
_LOADED = False
_GUARD = threading.Lock()


def configured(env: Mapping[str, str] | None = None) -> CanaryCaps | None:
    """The process's caps, loaded once from the environment; None outside a canary."""
    global _CAPS, _LOADED
    with _GUARD:
        if not _LOADED:
            raw = (os.environ if env is None else env).get(ENV, "")
            _CAPS = load(json.loads(raw)) if raw else None
            _LOADED = True
        return _CAPS


def transport_for(provider: str) -> httpx.BaseTransport | None:
    # A disabled worker reaches nothing: its source fetches are refused like its model
    # requests. Outside the worker no policy is installed and nothing changes.
    if _POLICY is not None and _POLICY.mode == "disabled":
        return RefusedTransport()
    caps = configured()
    return None if caps is None else caps.transport(provider)


# The worker's provider policy ----------------------------------------------------------
#
# The deployed worker either reaches no provider (the disabled scaffold: a placeholder
# key and the discard address) or reaches one only through a canary manifest. The
# worker entrypoint installs this policy in its process before any application client
# exists; the model-client factory consults it only when it is installed, so the API,
# legacy-generation and report-evaluation processes keep their contract unchanged.

KEY_ENV, BASE_URL_ENV = "OPENROUTER_API_KEY", "OPENROUTER_BASE_URL"
SENTINEL_KEY = "disabled-local-platform-fit"
DISCARD_BASE_URL = "http://127.0.0.1:9"
MISCONFIGURED = "provider_misconfigured"


class ProviderMisconfigured(ValueError):
    """The worker's provider settings are neither the disabled scaffold nor a valid canary."""


@dataclass(frozen=True)
class ProviderPolicy:
    mode: str  # "disabled" or "canary"
    caps: CanaryCaps | None = None


def worker_policy(env: Mapping[str, str]) -> ProviderPolicy:
    """The only provider settings a worker may run with; anything else is refused.

    The messages name the combination, never a key or an address.
    """
    key = env.get(KEY_ENV, "").strip()
    base_url = env.get(BASE_URL_ENV, "").strip().rstrip("/")
    raw = env.get(ENV, "")
    placeholder = key in ("", SENTINEL_KEY)
    if raw:
        try:
            caps = load(json.loads(raw))
        except (ValueError, TypeError, AttributeError, KeyError):
            raise ProviderMisconfigured("the canary manifest is not usable") from None
        if caps.now() >= caps.not_after:
            raise ProviderMisconfigured("the canary manifest has expired")
        if placeholder:
            raise ProviderMisconfigured("a canary needs a provider key")
        # A canary whose model host the manifest does not name would report ready and
        # refuse every model request; it is refused at startup instead.
        if not names_model_host(caps, base_url):
            raise ProviderMisconfigured("the canary does not name the provider address's host")
        return ProviderPolicy("canary", caps)
    if placeholder and base_url == DISCARD_BASE_URL:
        return ProviderPolicy("disabled")
    if placeholder:
        raise ProviderMisconfigured("a placeholder key with a provider address")
    raise ProviderMisconfigured("a provider key without a canary manifest")


def names_model_host(caps: CanaryCaps, base_url: str) -> bool:
    """Whether the canary lets the model client reach its base URL (the client's
    default when none is set)."""
    from src.core.openrouter_client import DEFAULT_OPENROUTER_BASE_URL

    try:
        host = httpx.URL(base_url or DEFAULT_OPENROUTER_BASE_URL).host
    except httpx.InvalidURL:
        return False
    allowed = caps.providers.get("openrouter")
    return allowed is not None and host in allowed.hosts


class RefusedTransport(httpx.BaseTransport):
    """The disabled worker's model transport: every request is refused unsent."""

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        raise CanaryCapReached("the worker's provider is disabled")


_POLICY: ProviderPolicy | None = None


def install_worker_policy(env: Mapping[str, str] | None = None) -> ProviderPolicy:
    """Decide the worker process's provider policy once. Its caps are the ones every
    capped transport in the process counts against, sources included."""
    global _POLICY, _CAPS, _LOADED
    policy = worker_policy(os.environ if env is None else env)
    with _GUARD:
        _POLICY = policy
        _CAPS, _LOADED = policy.caps, True
    return policy


def installed_policy() -> ProviderPolicy | None:
    return _POLICY


def model_transport(policy: ProviderPolicy) -> httpx.BaseTransport:
    if policy.mode == "canary" and policy.caps is not None:
        return policy.caps.transport("openrouter")
    return RefusedTransport()


def reset_for_tests() -> None:
    global _CAPS, _LOADED, _POLICY
    with _GUARD:
        _CAPS, _LOADED, _POLICY = None, False, None
