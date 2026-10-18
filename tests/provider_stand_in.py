"""The stand-in canary for a local stack's held-open provider stub.

A worker reaches a provider only through a canary manifest, so a local stack that
gives its worker a stub provider names the stub in a stand-in manifest. Manifests
name dotted hosts only, so the stub also answers at a dotted network alias. The
manifest allows that host alone and nothing else; no real provider is involved.
"""

from __future__ import annotations

from datetime import datetime, timedelta
import json


def stand_in_canary(host: str, now: datetime) -> str:
    return json.dumps({
        "schema": "sentry.provider-canary.v1", "canary_id": "local-provider-stub",
        "not_after": (now + timedelta(hours=12)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "budget_usd": 1,
        "providers": {"openrouter": {"hosts": [host], "max_requests": 1000}},
        "stop": {"max_consecutive_failures": 20},
    })  # fmt: skip
