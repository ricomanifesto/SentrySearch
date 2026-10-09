"""Exercise the Cloudflare entrypoint, runtime tunnel and receipt sink offline.

Executed by tests/test_cloudflare_offline.py with a poisoned environment
(ambient proxies, AWS and Cloudflare settings). Sockets are denied before any
import and every attempt is recorded with its target, so the receipt shows that
the only destinations are the two intercepted hosts. Prints one JSON receipt.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path
import socket
import sys

ATTEMPTS: list[list[str]] = []


def deny(name, *, method=False):
    def blocked(*args, **kwargs):
        target = args[1] if method and len(args) > 1 else (args[0] if args else None)
        ATTEMPTS.append([name, repr(target)])
        raise OSError(f"network access denied by offline Cloudflare test: {name}")

    return blocked


socket.socket.connect = deny("connect", method=True)  # type: ignore[method-assign]
socket.socket.connect_ex = deny("connect_ex", method=True)  # type: ignore[method-assign]
socket.create_connection = deny("create_connection")  # type: ignore[assignment]
socket.getaddrinfo = deny("getaddrinfo")  # type: ignore[assignment]
socket.gethostbyname = deny("gethostbyname")  # type: ignore[assignment]
socket.gethostbyname_ex = deny("gethostbyname_ex")  # type: ignore[assignment]

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "deploy" / "cloudflare"))

cfinit = importlib.import_module("sentrysearch_cloudflare.cfinit")
from src.execution.readiness_receipts import RECEIPT_MARKER, HttpReceiptSink  # noqa: E402
from src.execution.runtime_client import RuntimeClient  # noqa: E402

imported = list(ATTEMPTS)
results = {}
runtime = RuntimeClient(
    "https://runtime.test:8443",
    bearer_token="worker-token-" + "x" * 32,
    remote=True,
    ca_file=sys.argv[1],
    tunnel_url="ws://runtime.internal/v1/tunnel",
)
constructed = list(ATTEMPTS)
try:
    runtime.get_run("run-1")
    results["runtime"] = "reached"
except Exception as error:  # noqa: BLE001 - the type is the evidence
    results["runtime"] = type(error).__name__
runtime.close()
sink = HttpReceiptSink("http://evidence.internal/v1/receipts")
try:
    sink.write(f"{RECEIPT_MARKER} {{}}\n")
    results["receipt"] = "delivered"
except OSError as error:
    results["receipt"] = type(error).__name__
print(
    json.dumps(
        {
            "cfinit_profiles": sorted(cfinit.PROFILES),
            "attempts_at_import": imported,
            "attempts_at_construction": constructed[len(imported) :],
            "attempts": ATTEMPTS,
            "results": results,
        }
    )
)
