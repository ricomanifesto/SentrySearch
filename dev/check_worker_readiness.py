#!/usr/bin/env python3
"""Check one cached worker readiness response in the same network namespace."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import http.client
import ipaddress
import json
import math
import re
import signal
from typing import NoReturn


class InvalidResponse(ValueError):
    pass


class ProbeParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        # argparse's normal error includes argument values, which may be private.
        raise ValueError("invalid configuration")


def _target(address: str) -> tuple[str, int]:
    match = re.fullmatch(r"(?:\[([0-9a-fA-F:.]+)\]|([^:\s\[\]]+)):([0-9]+)", address)
    if match is None:
        raise ValueError("invalid address")
    host = match[1] or match[2]
    ip = ipaddress.ip_address(host)
    port = int(match[3])
    if not ip.is_loopback or not 1 <= port <= 65535:
        raise ValueError("invalid address")
    return str(ip), port


@contextmanager
def _deadline(seconds: float):
    """POSIX one-shot CLI deadline, including a peer that trickles HTTP headers."""
    if signal.getitimer(signal.ITIMER_REAL)[0]:
        raise ValueError("another process timer is active")

    def expired(*_args):
        raise TimeoutError

    previous = signal.signal(signal.SIGALRM, expired)
    try:
        signal.setitimer(signal.ITIMER_REAL, seconds)
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InvalidResponse
        result[key] = value
    return result


def _reject_constant(value):
    raise InvalidResponse


def _ready(body: bytes) -> bool:
    snapshot = json.loads(body, object_pairs_hook=_object, parse_constant=_reject_constant)
    if not isinstance(snapshot, dict):
        raise InvalidResponse
    for key in ("ready", "alive", "draining"):
        if type(snapshot.get(key)) is not bool:
            raise InvalidResponse
    phase = snapshot.get("phase")
    if phase not in {"starting", "maintenance", "generation", "evaluation", "idle", "stopped"}:
        raise InvalidResponse
    error = snapshot.get("error_code", "missing")
    if error not in {None, "runtime_unavailable", "runtime_access_denied", "worker_error"}:
        raise InvalidResponse
    for key in ("phase_elapsed_seconds", "phase_budget_seconds", "drain_elapsed_seconds"):
        value = snapshot.get(key)
        if type(value) not in {int, float} or not math.isfinite(value) or value < 0:
            raise InvalidResponse
    if snapshot["phase_budget_seconds"] <= 0:
        raise InvalidResponse
    if snapshot["ready"] and (
        not snapshot["alive"]
        or snapshot["draining"]
        or error is not None
        or phase in {"starting", "stopped"}
        or snapshot["phase_elapsed_seconds"] >= snapshot["phase_budget_seconds"]
    ):
        raise InvalidResponse
    return snapshot["ready"]


def _probe(host: str, port: int, seconds: float) -> bool:
    # Numeric loopback was validated before this call. http.client does not use
    # proxy environment variables, redirects, cookies, auth or application clients.
    connection = http.client.HTTPConnection(host, port, timeout=seconds)
    try:
        connection.request("GET", "/readyz", headers={"Connection": "close"})
        response = connection.getresponse()
        if response.status not in {200, 503}:
            raise InvalidResponse
        lengths = response.headers.get_all("Content-Length", [])
        types = response.headers.get_all("Content-Type", [])
        if (
            len(lengths) != 1
            or not re.fullmatch(r"[0-9]+", lengths[0])
            or len(lengths[0]) > 4
            or not 0 < int(lengths[0]) <= 4096
            or len(types) != 1
            or types[0].split(";", 1)[0].strip().lower() != "application/json"
            or response.getheader("Transfer-Encoding") is not None
            or response.getheader("Content-Encoding") is not None
        ):
            raise InvalidResponse
        length = int(lengths[0])
        body = response.read(length + 1)
        if len(body) != length:
            raise InvalidResponse
        ready = _ready(body)
        if ready != (response.status == 200):
            raise InvalidResponse
        return ready
    finally:
        connection.close()


def main(argv: list[str] | None = None) -> int:
    parser = ProbeParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--address", default="127.0.0.1:8081")
    parser.add_argument("--deadline-seconds", type=float, default=2.0)
    ready = False
    try:
        args = parser.parse_args(argv)
        host, port = _target(args.address)
        seconds = args.deadline_seconds
        if not math.isfinite(seconds) or not 0 < seconds <= 10:
            raise ValueError("invalid deadline")
    except (ValueError, argparse.ArgumentError):
        result, code = "invalid_configuration", 2
    else:
        try:
            with _deadline(seconds):
                ready = _probe(host, port, seconds)
            result, code = ("ready", 0) if ready else ("unready", 1)
        except TimeoutError:
            result, code = "timeout", 1
        except (
            InvalidResponse,
            http.client.HTTPException,
            UnicodeError,
            json.JSONDecodeError,
            TypeError,
            OverflowError,
            RecursionError,
        ):
            result, code = "invalid_response", 1
        except OSError:
            result, code = "unavailable", 1
        except ValueError:
            result, code = "invalid_configuration", 2
    print(json.dumps({"check": "worker_readiness", "ready": code == 0, "result": result}))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
