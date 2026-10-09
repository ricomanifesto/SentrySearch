"""Explicit log-volume measurement for the Runtime and API images (AWS-D010).

Run with dev/check_service_images.py. Each service runs as staging defines it on
the service suite's internal network, and a load container drives it as fast as
it answers for a fixed window with the requests a release and its probes make:
for the Runtime, authenticated health and readiness, an unauthenticated
readiness denial and a client that refuses the certificate; for the API,
liveness, readiness, a refused protected route and an unknown path. The bytes
each container writes to stdout and stderr during the window give its peak
output rate.

The awslogs ``max-buffer-size`` set in deploy/aws-platform-fit for each service
must hold at least ``HOLD_SECONDS`` of that peak, so a CloudWatch stall of that
length drops nothing at the measured worst case. This is a local measurement
method, not a Fargate guarantee: the driver's memory, CloudWatch latency and real
traffic are unmeasured. With SENTRYSEARCH_LOG_MEASUREMENT set, the results are
written there as JSON.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

import pytest

from tests import service_images as images

stack = images.stack

# Kept equal to deploy/aws-platform-fit's service log options (checked below).
BUFFERS = {"runtime": "8m", "api": "8m"}
HOLD_SECONDS = 300
WINDOW_SECONDS = 60
THREADS = 8
MAIN_TF = Path(__file__).resolve().parents[1] / "deploy" / "aws-platform-fit" / "main.tf"
LOAD = (
    "import http.client, json, ssl, sys, threading, time\n"
    "target, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])\n"
    "seconds, threads = float(sys.argv[4]), int(sys.argv[5])\n"
    "token = sys.stdin.read().strip()\n"
    "trusted = ssl.create_default_context(cafile='/run/trust/runtime-ca.pem')\n"
    "public = ssl.create_default_context()\n"
    "counts = []\n"
    "def runtime(k):\n"
    "    if k == 3:\n"
    "        c = http.client.HTTPSConnection(host, port, context=public, timeout=5)\n"
    "        try:\n"
    "            c.request('GET', '/healthz')\n"
    "        except ssl.SSLError:\n"
    "            pass\n"
    "        c.close(); return\n"
    "    c = http.client.HTTPSConnection(host, port, context=trusted, timeout=5)\n"
    "    auth = {} if k == 2 else {'Authorization': 'Bearer ' + token}\n"
    "    c.request('GET', ('/healthz', '/readyz', '/readyz')[k], headers=auth)\n"
    "    c.getresponse().read(); c.close()\n"
    "def api(k):\n"
    "    c = http.client.HTTPConnection(host, port, timeout=5)\n"
    "    c.request('GET', ('/', '/api/ready', '/api/reports', '/missing')[k])\n"
    "    c.getresponse().read(); c.close()\n"
    "def run():\n"
    "    end, n, call = time.monotonic() + seconds, 0, runtime if target == 'runtime' else api\n"
    "    while time.monotonic() < end:\n"
    "        try:\n"
    "            call(n % 4)\n"
    "        except Exception:\n"
    "            pass\n"
    "        n += 1\n"
    "    counts.append(n)\n"
    "workers = [threading.Thread(target=run) for _ in range(threads)]\n"
    "[w.start() for w in workers]; [w.join() for w in workers]\n"
    "print(json.dumps({'requests': sum(counts)}))\n"
)


def _mebibytes(value: str) -> int:
    assert value.endswith("m") and value[:-1].isdigit(), value
    return int(value[:-1]) * 1024 * 1024


def _streams(container: str) -> tuple[str, str]:
    result = images.docker("logs", container, check=False)
    return result.stdout, result.stderr


def _measure(stack: images.Stack, target: str, container: str, host: str, port: int) -> dict:
    before = _streams(container)
    started = time.monotonic()
    load = stack.run(
        images.SEARCH_IMAGE,
        stack.name(f"{target}-load"),
        {},
        ["python", "-c", LOAD, target, host, str(port), str(WINDOW_SECONDS), str(THREADS)],
        detach=False,
        stdin=stack.secrets["producer"],
    )
    elapsed = time.monotonic() - started
    assert load.returncode == 0, load.stderr
    requests = json.loads(load.stdout)["requests"]
    # Let the service flush what the window produced before counting it.
    time.sleep(2)
    after = _streams(container)
    assert all(now.startswith(then) for then, now in zip(before, after, strict=True))
    window = "".join(now[len(then) :] for then, now in zip(before, after, strict=True))
    lines = window.splitlines()
    stack.assert_no_secrets(window)
    return {
        "requests": requests,
        "seconds": round(elapsed, 1),
        "bytes": len(window.encode()),
        "bytes_per_second": round(len(window.encode()) / elapsed, 1),
        "bytes_per_request": round(len(window.encode()) / max(requests, 1), 1),
        "lines": len(lines),
        "longest_line": max((len(line.encode()) for line in lines), default=0),
        "buffer": BUFFERS[target],
        "hold_seconds_at_peak": (
            round(_mebibytes(BUFFERS[target]) / (len(window.encode()) / elapsed))
            if window
            else None
        ),
    }


def test_terraform_sets_the_measured_non_blocking_buffers():
    text = MAIN_TF.read_text()
    for target, size in BUFFERS.items():
        pattern = rf'\n\s+{target}\s+= {{ mode = "non-blocking", max-buffer-size = "{size}" }}\n'
        assert re.search(pattern, text), target


def test_runtime_and_api_peak_output_fits_their_buffers(stack: images.Stack):
    runtime = next(name for name, role in stack.hostnames.items() if role == "runtime")
    api = stack.name("measured-api")
    # The staging API: paused execution, no Runtime client calls from requests.
    stack.run(
        images.SEARCH_IMAGE,
        api,
        {**stack.product_env(), "SENTRYSEARCH_EXECUTION_MODE": "paused", "PORT": "8001"},
        images.API,
        detach=True,
        options=("--network-alias", "api"),
    )
    images.wait_for(
        "API startup", lambda: "Application startup complete" in images.logs(api), container=api
    )
    results: dict[str, dict] = {
        "runtime": _measure(stack, "runtime", runtime, "runtime", 8443),
        "api": _measure(stack, "api", api, "api", 8001),
    }
    measurements = {
        **results,
        "window_seconds": WINDOW_SECONDS,
        "threads": THREADS,
        "hold_seconds": HOLD_SECONDS,
    }
    destination = os.environ.get("SENTRYSEARCH_LOG_MEASUREMENT")
    if destination:
        Path(destination).write_text(json.dumps(measurements, indent=2, sort_keys=True) + "\n")
    print(json.dumps(measurements, sort_keys=True))
    for target, result in results.items():
        assert result["requests"] > 0, result
        # At the measured peak the buffer holds HOLD_SECONDS of output.
        assert result["bytes_per_second"] * HOLD_SECONDS <= _mebibytes(BUFFERS[target]), result
