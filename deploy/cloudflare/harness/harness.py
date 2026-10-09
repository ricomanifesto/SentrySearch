"""Run the Cloudflare Worker scripts locally under `wrangler dev` with containment.

Local only: no account, credential or registry is used. The host side runs
under ``sandbox-exec`` (outbound only to loopback and the Docker socket) with
an empty HOME, XDG and Docker configuration and poisoned Cloudflare settings.
Wrangler's Docker calls go through a shim that logs every call and answers a
``pull`` only for an image already present locally, so a run never contacts a
registry. Containers start with ``enableInternet: false``.

``--images fixture`` runs every service from one small static fixture binary
(deploy/cloudflare/harness/fixture), proving the Worker scripts, signed
control, receipt intake, the runtime relay, drain and job deadlines. It does
not prove the real images, their entrypoints or the capability drop.

``--images real`` runs the api, worker and runtime from locally built
``--target cloudflare`` images against a disposable PostgreSQL 16 with TLS,
migrated by the default images as in ``dev/check_service_images.py``. Wrangler
always builds ``linux/amd64``; on an arm64 Mac amd64 emulation refuses the
entrypoints' seccomp filter, so ``--native-platform linux/arm64`` makes the shim
build natively instead. Such a run proves the real images on arm64, not amd64.

Usage (from the repository root):
    .venv/bin/python deploy/cloudflare/harness/harness.py --images fixture \
        --run-dir /path/outside/the/repo --evidence result.json
    .venv/bin/python deploy/cloudflare/harness/harness.py --images real \
        --native-platform linux/arm64 --runtime-repo /path/to/sentryruntime \
        --run-dir /path/outside/the/repo --evidence result.json
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Callable, Iterator
import urllib.error
import urllib.request
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

REPO = Path(__file__).resolve().parents[3]
HARNESS = Path(__file__).resolve().parent
WORKER = HARNESS.parent / "worker"
WRANGLER = WORKER / "node_modules" / ".bin" / "wrangler"
SCRIPTS = ("edge", "api", "worker", "runtime", "jobs")
DOCKER_SOCKET = Path.home() / ".docker" / "run" / "docker.sock"
CONTROL_VERSION = "sentry.control.v1"
SANDBOX = """(version 1)
(allow default)
(deny network-outbound)
(allow network-outbound (remote ip "localhost:*"))
(allow network-outbound (remote unix-socket (path-literal "{socket}")))
(allow network-outbound (remote unix-socket (path-literal "/private/var/run/docker.sock")))
"""
DOCKER_SHIM = """#!/bin/sh
# Every Docker call Wrangler makes during a harness run is logged; a pull is
# answered only for an image already present, so no registry is contacted.
# With a native platform set, a build's linux/amd64 is rewritten to it; the log
# shows the command as run.
if [ -n "{native}" ] && {{ [ "$1" = build ] || [ "$1" = buildx ]; }}; then
  for argument do
    shift
    case "$argument" in
      linux/amd64) argument="{native}" ;;
      --platform=linux/amd64) argument="--platform={native}" ;;
    esac
    set -- "$@" "$argument"
  done
fi
printf '%s\\n' "$*" >> "{log}"
if [ "$1" = pull ]; then
  shift
  for argument in "$@"; do case "$argument" in --*) ;; *) image="$argument" ;; esac; done
  if {docker} image inspect "$image" >/dev/null 2>&1; then
    echo "harness: $image present locally; not pulled"; exit 0
  fi
  echo "harness: refusing to pull $image during a run" >&2; exit 1
fi
exec {docker} "$@"
"""


def canonical(command: dict[str, Any]) -> bytes:
    """Mirror of canonicalBytes in worker/src/shared/control.ts."""
    fields = [
        CONTROL_VERSION,
        command["method"],
        command["target"],
        command["action"],
        command["bodySha256"],
        command["releaseId"],
        command["session"],
        command["fence"],
        command["commandId"],
        str(command["expiresAt"]),
    ]
    return "\n".join(fields).encode()


class Control:
    """Signs operator control commands with a run-local Ed25519 key."""

    def __init__(self, base_url: str, release_id: str) -> None:
        self.key = Ed25519PrivateKey.generate()
        self.base_url, self.release_id = base_url, release_id
        raw = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.public_key = base64.b64encode(raw).decode()

    def headers(
        self, method: str, target: str, action: str, body: bytes, **overrides: Any
    ) -> dict[str, str]:
        command = {
            "method": method,
            "target": target,
            "action": action,
            "bodySha256": hashlib.sha256(body).hexdigest(),
            "releaseId": self.release_id,
            "session": "harness-session",
            "fence": "harness-fence",
            "commandId": uuid.uuid4().hex,
            "expiresAt": int(time.time()) + 60,
        }
        command.update(overrides)
        signature = self.key.sign(canonical(command))
        return {
            "x-sentry-command-id": command["commandId"],
            "x-sentry-release-id": command["releaseId"],
            "x-sentry-session": command["session"],
            "x-sentry-fence": command["fence"],
            "x-sentry-expires-at": str(command["expiresAt"]),
            "x-sentry-signature": base64.b64encode(signature).decode(),
        }

    def send(
        self,
        service: str,
        name: str,
        action: str,
        method: str = "POST",
        body: bytes = b"{}",
        headers: dict | None = None,
    ) -> tuple[int, Any]:
        target = f"{service}/{name}"
        headers = (
            headers
            if headers is not None
            else self.headers(method, target, action, body if method == "POST" else b"")
        )
        request = urllib.request.Request(
            f"{self.base_url}/control/{service}/{name}/{action}",
            data=body if method == "POST" else None,
            method=method,
            headers={**headers, "content-type": "application/json"},
        )
        return http(request)


def http(request: urllib.request.Request, timeout: float = 30) -> tuple[int, Any]:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=timeout) as response:
            raw = response.read()
            status = response.status
    except urllib.error.HTTPError as error:
        raw, status = error.read(), error.code
    try:
        return status, json.loads(raw) if raw else None
    except ValueError:
        return status, raw.decode(errors="replace")


def wait_for(check: Callable[[], Any], seconds: float, interval: float = 2.0) -> Any:
    deadline = time.monotonic() + seconds
    last = None
    while time.monotonic() < deadline:
        last = check()
        if last:
            return last
        time.sleep(interval)
    return last


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def lan_address() -> str | None:
    for interface in ("en0", "en1"):
        result = subprocess.run(
            ["ipconfig", "getifaddr", interface], capture_output=True, text=True
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    return None


@contextlib.contextmanager
def canary(host: str) -> Iterator[tuple[int, list[str]]]:
    """An HTTP listener that records every request: reaching it is an escape."""
    hits: list[str] = []
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, 0))
    server.listen(8)
    server.settimeout(0.5)
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                connection, address = server.accept()
            except OSError:
                continue
            hits.append(str(address))
            with contextlib.suppress(OSError):
                connection.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 6\r\n\r\ncanary")
                connection.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield server.getsockname()[1], hits
    finally:
        stop.set()
        thread.join(2)
        server.close()


class Run:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.dir = Path(args.run_dir).resolve()
        self.release_id = str(uuid.uuid4())
        self.port = free_port()
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.control = Control(self.base_url, self.release_id)
        self.evidence: dict[str, Any] = {
            "release_id": self.release_id,
            "images": args.images,
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "scenarios": {},
        }
        self.wrangler: subprocess.Popen | None = None
        self.trust_dir: Path | None = None  # Real images: CA files for host-side probes.
        self.admit: Callable[[str], None] | None = None  # Real images: admit one report.
        self.provider_connections: list[socket.socket] = []
        self.secret_values: dict[str, str] = {}  # Real images: removed from the run directory.

    # Setup -----------------------------------------------------------------

    def prepare(self, images: dict[str, str], container_env: dict[str, dict[str, str]]) -> None:
        for sub in ("home", "xdg", "dockercfg/cli-plugins", "config/images"):
            (self.dir / sub).mkdir(parents=True, exist_ok=True)
        buildx = Path("/Applications/Docker.app/Contents/Resources/cli-plugins/docker-buildx")
        if buildx.exists():
            (self.dir / "dockercfg/cli-plugins/docker-buildx").symlink_to(buildx)
        docker = shutil.which("docker") or "/usr/local/bin/docker"
        (self.dir / "local-only.sb").write_text(SANDBOX.format(socket=DOCKER_SOCKET))
        shim = self.dir / "docker-shim.sh"
        shim.write_text(
            DOCKER_SHIM.format(
                log=self.dir / "docker-calls.log",
                docker=docker,
                native=getattr(self.args, "native_platform", "") or "",
            )
        )
        shim.chmod(0o755)
        for image in (WORKER / "config" / "images").glob("*.Dockerfile"):
            shutil.copy(image, self.dir / "config" / "images" / image.name)
        for script in SCRIPTS:
            text = (WORKER / "config" / f"{script}.jsonc").read_text()
            text = text.replace('"../src/', f'"{WORKER / "src"}/')
            text = text.replace("@@RELEASE_ID@@", self.release_id).replace(
                "@@CONTROL_PUBLIC_KEY@@", self.control.public_key
            )
            for key, tag in images.items():
                text = text.replace(f"@@IMAGE_{key}@@", tag)
            config = json.loads(
                "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("//"))
            )
            if script != "edge":
                config["vars"].update(
                    {f"CONTAINER_{k}": v for k, v in container_env.get(script, {}).items()}
                )
            if "@@" in json.dumps(config):
                raise SystemExit(f"unfilled placeholder in {script}")
            (self.dir / "config" / f"{script}.jsonc").write_text(json.dumps(config, indent=2))

    def start_wrangler(self) -> None:
        command = [
            "/usr/bin/sandbox-exec",
            "-f",
            str(self.dir / "local-only.sb"),
            "/usr/bin/env",
            "-i",
            f"PATH={Path(sys.executable).parent}:{Path(shutil.which('node') or '/usr/bin/node').parent}:/usr/bin:/bin",
            f"HOME={self.dir / 'home'}",
            f"XDG_CONFIG_HOME={self.dir / 'xdg'}",
            f"DOCKER_CONFIG={self.dir / 'dockercfg'}",
            f"DOCKER_HOST=unix://{DOCKER_SOCKET}",
            f"WRANGLER_DOCKER_BIN={self.dir / 'docker-shim.sh'}",
            "WRANGLER_SEND_METRICS=false",
            "WRANGLER_SEND_ERROR_REPORTS=false",
            "CLOUDFLARE_CF_FETCH_ENABLED=false",
            "CLOUDFLARE_API_BASE_URL=http://192.0.2.1/client/v4",
            "CLOUDFLARE_API_TOKEN=poisoned-not-a-token",
            "CLOUDFLARE_ACCOUNT_ID=00000000000000000000000000000000",
            "AWS_EC2_METADATA_DISABLED=true",
            "CI=1",
            "NO_COLOR=1",
            str(WRANGLER),
            "dev",
            *(
                arg
                for script in SCRIPTS
                for arg in ("-c", str(self.dir / "config" / f"{script}.jsonc"))
            ),
            "--ip",
            "127.0.0.1",
            "--port",
            str(self.port),
            "--show-interactive-dev-session=false",
        ]
        log = (self.dir / "wrangler.log").open("w")
        self.wrangler = subprocess.Popen(
            command, stdout=log, stderr=subprocess.STDOUT, cwd=self.dir, start_new_session=True
        )
        ready = wait_for(lambda: "Ready on" in (self.dir / "wrangler.log").read_text(), 600, 2)
        if not ready:
            raise RuntimeError("wrangler dev did not become ready; see wrangler.log")

    def stop_wrangler(self) -> None:
        if self.wrangler and self.wrangler.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(self.wrangler.pid, signal.SIGINT)
            try:
                self.wrangler.wait(30)
            except subprocess.TimeoutExpired:
                os.killpg(self.wrangler.pid, signal.SIGKILL)
        names = subprocess.run(
            ["docker", "ps", "-a", "--format", "{{.Names}}"], capture_output=True, text=True
        ).stdout.split()
        leftovers = [name for name in names if name.startswith("workerd-sentry-")]
        for name in leftovers:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        self.evidence["removed_leftover_containers"] = len(leftovers)

    # Observation -----------------------------------------------------------

    def host_connections(self) -> list[str]:
        """Non-loopback TCP endpoints held by this run's wrangler/workerd processes."""
        if not self.wrangler:
            return []
        pids = subprocess.run(
            ["pgrep", "-g", str(self.wrangler.pid)], capture_output=True, text=True
        ).stdout.split()
        if not pids:
            return []
        output = subprocess.run(
            ["lsof", "-nP", "-a", "-i", "-p", ",".join(pids), "-F", "n"],
            capture_output=True,
            text=True,
        ).stdout
        outside = []
        for record in output.splitlines():
            if not record.startswith("n"):
                continue
            endpoints = record[1:].split("->")
            if not all(
                e.startswith(("127.0.0.1:", "[::1]:", "localhost:", "*:")) for e in endpoints
            ):
                outside.append(record[1:])
        return outside

    def scenario(self, name: str, function: Callable[[], dict[str, Any]]) -> None:
        started = time.monotonic()
        try:
            result = dict(function())
        except Exception as error:  # Evidence records failures instead of hiding them.
            result: dict[str, Any] = {"passed": False, "error": f"{type(error).__name__}: {error}"}
        result["seconds"] = round(time.monotonic() - started, 1)
        result["host_non_loopback_connections"] = self.host_connections()
        if result["host_non_loopback_connections"]:
            result["passed"] = False
        self.evidence["scenarios"][name] = result
        print(f"{name}: {'passed' if result.get('passed') else 'FAILED'}", flush=True)


def fixture_image(run_dir: Path) -> str:
    build = run_dir / "fixture-build"
    build.mkdir(parents=True)
    env = {
        "CGO_ENABLED": "0",
        "GOOS": "linux",
        "GOARCH": "amd64",
        "GOTOOLCHAIN": "local",
        "GOPROXY": "off",
    }
    subprocess.run(
        ["go", "build", "-trimpath", "-ldflags=-s -w", "-o", str(build / "fixture"), "."],
        cwd=HARNESS / "fixture",
        env={**os.environ, **env},
        check=True,
    )
    (build / "Dockerfile").write_text(
        "FROM scratch\nCOPY --chmod=0755 fixture /usr/local/bin/tini\nCOPY --chmod=0755 fixture /app/cfinit\n"
    )
    digest = hashlib.sha256((build / "fixture").read_bytes()).hexdigest()[:12]
    tag = f"sentry-cf-fixture:{digest}"
    subprocess.run(
        ["docker", "build", "--platform", "linux/amd64", "--tag", tag, str(build)],
        check=True,
        capture_output=True,
    )
    return tag


def fixture_scenarios(
    run: Run, lan: str | None, outside_port: int, long_job_seconds: int = 0
) -> None:
    control = run.control

    def started(service: str, name: str) -> dict[str, Any]:
        status, body = control.send(service, name, "start")
        return {"status": status, "body": body}

    def start_services() -> dict[str, Any]:
        results = {
            name: started(service, name)
            for service, name in (
                ("runtime", "runtime-0"),
                ("worker", "worker-0"),
                ("api", "api-0"),
            )
        }
        return {
            "passed": all(
                r["status"] == 200 and r["body"].get("started") for r in results.values()
            ),
            "results": results,
        }

    def worker_ready_through_tunnel() -> dict[str, Any]:
        def ready() -> Any:
            status, view = control.send("worker", "worker-0", "receipts", method="GET")
            if status == 200 and view.get("receipts") and any(r["ready"] for r in view["receipts"]):
                return view
            return None

        view = wait_for(ready, 180, 3)
        if not view:
            return {"passed": False, "detail": "no ready receipt (tunnel or intake failed)"}
        errors = sorted({r["error_code"] for r in view["receipts"] if r["error_code"]})
        return {
            "passed": view["duplicatesConflicting"] == 0 and not view["gaps"],
            "receipts": len(view["receipts"]),
            "ready_receipts": sum(r["ready"] for r in view["receipts"]),
            "errors_seen_before_ready": errors,
            "complete": view["complete"],
        }

    def api_ingress_and_denials() -> dict[str, Any]:
        def healthy() -> Any:
            status, body = http(urllib.request.Request(f"{run.base_url}/api/health"))
            return (status, body) if status == 200 else None

        health = wait_for(healthy, 120, 3)
        status, probe = http(urllib.request.Request(f"{run.base_url}/api/probe"))
        public_tunnel, _ = http(urllib.request.Request(f"{run.base_url}/v1/tunnel"))
        public_receipts, _ = http(
            urllib.request.Request(f"{run.base_url}/v1/receipts", data=b"{}", method="POST")
        )
        return {
            "passed": bool(health)
            and status == 200
            and isinstance(probe, dict)
            and probe.get("runtime_relay") == "unreachable"
            and probe.get("outside") == "unreachable"
            and probe.get("loopback_name") not in (None, "unresolved")
            and public_tunnel == 404
            and public_receipts == 404,
            "api_health": health,
            "api_probe": probe,
            "loopback_reverse_name": (probe or {}).get("loopback_name"),
            "public_tunnel_status": public_tunnel,
            "public_receipts_status": public_receipts,
        }

    def control_refusals() -> dict[str, Any]:
        target = "worker/worker-0"
        unsigned = control.send("worker", "worker-0", "status", "GET", headers={})[0]
        headers = control.headers("GET", target, "status", b"")
        first = control.send("worker", "worker-0", "status", "GET", headers=headers)[0]
        replay = control.send("worker", "worker-0", "status", "GET", headers=headers)[0]
        expired = control.send(
            "worker",
            "worker-0",
            "status",
            "GET",
            headers=control.headers("GET", target, "status", b"", expiresAt=int(time.time()) - 1),
        )[0]
        other_release = control.send(
            "worker",
            "worker-0",
            "status",
            "GET",
            headers=control.headers("GET", target, "status", b"", releaseId=str(uuid.uuid4())),
        )[0]
        wrong_target = control.send(
            "worker",
            "worker-0",
            "status",
            "GET",
            headers=control.headers("GET", "worker/worker-1", "status", b""),
        )[0]
        misdirected = control.send(
            "worker",
            "worker-1",
            "status",
            "GET",
            headers=control.headers("GET", target, "status", b""),
        )[0]
        stranger = Control(run.base_url, run.release_id)
        foreign_key = stranger.send("worker", "worker-0", "status", "GET")[0]
        observed = {
            "unsigned": unsigned,
            "first": first,
            "replay": replay,
            "expired": expired,
            "other_release": other_release,
            "signed_for_other_name": wrong_target,
            "sent_to_other_name": misdirected,
            "foreign_key": foreign_key,
        }
        expected = {"first": 200, "replay": 409}
        refused = all(observed[k] in (401, 403, 409) for k in observed if k not in expected)
        return {
            "passed": refused and all(observed[k] == v for k, v in expected.items()),
            "statuses": observed,
        }

    def keepalive() -> dict[str, Any]:
        time.sleep(120)
        status, body = control.send("worker", "worker-0", "status", "GET")
        return {
            "passed": status == 200 and body.get("running") is True,
            "status_after_120s_idle": body,
        }

    def restart_survival() -> dict[str, Any]:
        """Reload the worker script (a Durable Object restart) and check what survives."""
        _, before = control.send("worker", "worker-0", "receipts", "GET")
        _, status_before = control.send("worker", "worker-0", "status", "GET")
        log = run.dir / "wrangler.log"
        reloads_before = log.read_text().count("Reloading")
        source = WORKER / "src" / "worker.ts"
        os.utime(source)  # Content unchanged; wrangler rebuilds and restarts the object.
        wait_for(lambda: log.read_text().count("Reloading") > reloads_before, 60, 1)
        time.sleep(10)

        def receipts_after() -> Any:
            s, view = control.send("worker", "worker-0", "receipts", "GET")
            if s == 200 and len(view["receipts"]) > len(before["receipts"]):
                return view
            return None

        after = wait_for(receipts_after, 60, 3)
        _, status_after = control.send("worker", "worker-0", "status", "GET")
        kept = bool(after) and all(r in after["receipts"] for r in before["receipts"])
        same_start = (status_after.get("start") or {}).get("start_nonce") == (
            status_before.get("start") or {}
        ).get("start_nonce")
        return {
            "passed": kept and same_start and status_after.get("running") is True,
            "receipts_before": len(before["receipts"]),
            "receipts_after": len(after["receipts"]) if after else None,
            "receipts_kept": kept,
            "same_start_after_restart": same_start,
            "running_after_restart": status_after.get("running"),
        }

    def drain() -> dict[str, Any]:
        status, body = control.send("worker", "worker-0", "stop")

        def exited() -> Any:
            s, b = control.send("worker", "worker-0", "status", "GET")
            return b if s == 200 and b.get("start", {}).get("state") == "exited" else None

        final = wait_for(exited, 60, 2)
        _, view = control.send("worker", "worker-0", "receipts", "GET")
        receipts = (view or {}).get("receipts", [])
        draining = [r for r in receipts if r["draining"]]
        names = subprocess.run(
            ["docker", "ps", "-a", "--format", "{{.Names}}"], capture_output=True, text=True
        ).stdout.split()
        logs = [
            subprocess.run(
                ["docker", "logs", "--tail", "6", n], capture_output=True, text=True
            ).stdout
            for n in names
            if n.startswith("workerd-sentry-worker-WorkerService") and not n.endswith("-proxy")
        ]
        return {
            "passed": status == 200
            and bool(final)
            and final["start"]["exit_detail"] == "exit 0"
            and bool(draining)
            and (view or {}).get("ended") is True
            and (view or {}).get("unterminated") == [],
            "stop": body,
            "final": final,
            "ended": (view or {}).get("ended"),
            "unterminated": (view or {}).get("unterminated"),
            # Observed, not required: receipts posted while the Durable Object
            # reloaded (restart_survival) are lost and must show as gaps.
            "complete": (view or {}).get("complete"),
            "gaps": (view or {}).get("gaps"),
            "draining_receipts": len(draining),
            "last_receipts": [(r["sequence"], r["draining"], r["phase"]) for r in receipts[-4:]],
            "worker_output_tail": logs,
        }

    def jobs() -> dict[str, Any]:
        release_name = f"job-{run.release_id}-"
        natural = f"{release_name}grant"
        stuck = f"{release_name}proof"
        body_natural = json.dumps(
            {"job": "grant", "profile": "runtime-release", "deadline_seconds": 120}
        ).encode()
        body_stuck = json.dumps(
            {"job": "proof", "profile": "runtime-release", "deadline_seconds": 15}
        ).encode()
        n_status, n_start = control.send("jobs", natural, "run", body=body_natural)
        s_status, s_start = control.send("jobs", stuck, "run", body=body_stuck)

        def state(name: str, wanted: str) -> Callable[[], Any]:
            def check() -> Any:
                s, b = control.send("jobs", name, "status", "GET")
                return b if s == 200 and b.get("state") == wanted else None

            return check

        natural_final = wait_for(state(natural, "exited"), 90, 3)
        stuck_final = wait_for(state(stuck, "destroyed"), 120, 3)
        rerun = control.send("jobs", natural, "run", body=body_natural)[0]
        return {
            "passed": n_status == 200
            and s_status == 200
            and bool(natural_final)
            and natural_final["sql_outcome"] == "unknown"
            and bool(stuck_final)
            and stuck_final["sql_outcome"] == "unknown"
            and rerun == 409,
            "natural": natural_final,
            "deadline": stuck_final,
            "rerun_status": rerun,
        }

    run.scenario("start_services", start_services)
    run.scenario("worker_ready_through_tunnel", worker_ready_through_tunnel)
    run.scenario("api_ingress_and_denials", api_ingress_and_denials)
    run.scenario("control_refusals", control_refusals)
    run.scenario("keepalive_while_idle", keepalive)
    run.scenario("restart_survival", restart_survival)
    run.scenario("drain_on_stop", drain)
    run.scenario("job_outcomes_and_deadline", jobs)

    def long_job_deadline() -> dict[str, Any]:
        # H-J1: a deadline beyond the 15-minute monitor() window. The harness
        # stays silent until just before the deadline, so only the object's own
        # alarms keep it (and its container) alive in between.
        name = f"job-{run.release_id}-proof-long"
        body = json.dumps(
            {"job": "proof", "profile": "runtime-release", "deadline_seconds": long_job_seconds}
        ).encode()
        started = time.time()
        status, start = control.send("jobs", name, "run", body=body)
        if status != 200:
            return {"passed": False, "run_status": status, "run": start}
        time.sleep(max(0, long_job_seconds - 30))
        _, before = control.send("jobs", name, "status", "GET")

        def state(wanted: str) -> Callable[[], Any]:
            def check() -> Any:
                s, b = control.send("jobs", name, "status", "GET")
                return b if s == 200 and b.get("state") == wanted else None

            return check

        destroyed = wait_for(state("destroyed"), 150, 5)
        return {
            "passed": status == 200
            and (before or {}).get("state") == "running"
            and bool(destroyed)
            and destroyed.get("signalled_at") is not None
            and destroyed["signalled_at"] >= start["deadline_at"]
            and destroyed["sql_outcome"] == "unknown",
            "deadline_seconds": long_job_seconds,
            "state_30s_before_deadline": (before or {}).get("state"),
            "signalled_after_start_seconds": (
                round((destroyed["signalled_at"] / 1000) - started, 1) if destroyed else None
            ),
            "final": destroyed,
        }

    if long_job_seconds:
        run.scenario("long_job_deadline", long_job_deadline)


# Real images ----------------------------------------------------------------

# Same pin and application grants as tests/service_images.py.
POSTGRES_IMAGE = (
    "docker.io/library/postgres:16-alpine@sha256:"
    "cf78e76683b9ca8c5733cbbdce6c9262b45b6767934dd0a95e671f9a0fc20685"
)
SEARCH_APP_TABLES = (
    "reports, report_runtime_dispatches, report_disposition_events, report_searches, report_tags"
)
# Reads /proc in the services' PID namespaces; the pinned base check_entrypoint.py uses.
ENTRYPOINT_HELPER = "docker.io/library/python@sha256:0dd364ba7e10242f07755449e3a3d0e35f9efd987952737b90def6709ab0c5ce"
DB_HOST = "host.docker.internal"  # Host loopback, the only egress a local container keeps.
RUNTIME_NAME = "runtime.test"
SECRET_NAMES = (
    "postgres",
    "runtime_owner",
    "runtime_app",
    "search_release",
    "search_app",
    "producer",
    "worker",
    "probe",
    "provider",
    "aws",
)


def private_write(path: Path, text: str) -> None:
    """Create a file readable only by this user from the start."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write(text)


def docker(*args: str, check: bool = True, stdin: str | None = None) -> subprocess.CompletedProcess:
    result = subprocess.run(
        ["docker", *args], input=stdin, capture_output=True, text=True, check=False, timeout=300
    )
    if check and result.returncode:
        # Never echo the arguments: they can carry the run's disposable secrets.
        raise RuntimeError(f"docker {args[0]} exited {result.returncode}: {result.stderr[-400:]}")
    return result


@contextlib.contextmanager
def real_backing(
    run: Run, search_default: str, runtime_default: str, runtime_repo: Path
) -> Iterator[tuple[dict[str, dict[str, str]], dict[str, str]]]:
    """A disposable PostgreSQL 16 with TLS on host loopback, migrated for both services.

    Yields each service's container settings (material, its digest, database and
    runtime configuration) and the run's disposable secrets.
    """
    from dev.tls_fixtures import create_certificates

    # Docker bind-mounts these into containers, and macOS privacy controls can
    # keep Docker out of folders such as ~/Documents: use a private temp directory.
    root = Path(tempfile.mkdtemp(prefix="sentry-cf-real-"))
    run.evidence["real_material_dir"] = "temporary, removed after the run"
    values = {name: secrets.token_hex(24) for name in SECRET_NAMES}
    database = create_certificates(root / "postgres", hostname=DB_HOST)
    runtime = create_certificates(root / "runtime", hostname=RUNTIME_NAME)
    trust = root / "trust"
    trust.mkdir()
    shutil.copy(database.ca, trust / "postgres-ca.pem")
    shutil.copy(runtime.ca, trust / "runtime-ca.pem")
    for path in (*trust.iterdir(), database.certificate, database.key):
        path.chmod(0o644)  # Disposable test material, read by container users.
    for directory in (root, root / "postgres", trust):
        directory.chmod(0o755)
    port = free_port()
    postgres = f"sentry-cf-postgres-{uuid.uuid4().hex[:8]}"
    # A provider that accepts and never answers, so a generation stays in
    # progress (the busy-drain case). It listens on host loopback only.
    provider = socket.create_server(("127.0.0.1", 0))
    provider.settimeout(0.5)
    accepted: list[socket.socket] = []
    stop_provider = threading.Event()

    def hold_connections() -> None:
        while not stop_provider.is_set():
            try:
                accepted.append(provider.accept()[0])
            except OSError:
                continue

    threading.Thread(target=hold_connections, daemon=True).start()

    def psql(db: str, sql: str, user: str = "postgres") -> str:
        return docker(
            "exec", postgres, "psql", "-v", "ON_ERROR_STOP=1", "-U", user, "-d", db, "-tAc", sql
        ).stdout.strip()

    def plain(image: str, env: dict[str, str], command: list[str]) -> str:
        env_file = root / f"{uuid.uuid4().hex[:8]}.env"
        private_write(env_file, "".join(f"{k}={v}\n" for k, v in env.items()))
        scratch = "/var/lib/sentrysearch:uid=10001,gid=10001,mode=0700"
        result = docker(
            "run", "--rm", "--read-only", "--tmpfs", "/tmp", "--tmpfs", scratch,
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--env-file", str(env_file), "-v", f"{trust}:/run/trust:ro", image, *command,
            check=False,
        )  # fmt: skip
        env_file.unlink()
        if result.returncode:
            raise RuntimeError(
                f"{image} {command} exited {result.returncode}: {result.stderr[-500:]}"
            )
        return result.stdout

    def runtime_url(role: str, root_cert: str) -> str:
        return (
            f"postgres://{role}:{values[role]}@{DB_HOST}:{port}/sentryruntime"
            f"?sslmode=verify-full&sslrootcert={root_cert}"
        )

    def product(role: str, root_cert: str) -> dict[str, str]:
        return {
            "ENVIRONMENT": "staging",
            "DB_HOST": DB_HOST,
            "DB_PORT": str(port),
            "DB_NAME": "sentrysearch",
            "DB_USER": f"search_{role}",
            "DB_PASSWORD": values[f"search_{role}"],
            "DB_SSLMODE": "verify-full",
            "DB_SSLROOTCERT": root_cert,
            "DB_DEBUG": "false",
            "AWS_S3_BUCKET": "harness-bucket",
            "AWS_REGION": "us-east-1",
            # Non-empty disposable values only satisfy SDK resolution; no route exists.
            "AWS_ACCESS_KEY_ID": "harness-access-key",
            "AWS_SECRET_ACCESS_KEY": values["aws"],
            "AWS_EC2_METADATA_DISABLED": "true",
            "SENTRYSEARCH_EXECUTION_MODE": "runtime",
            "SENTRYRUNTIME_URL": f"https://{RUNTIME_NAME}:8443",
        }

    try:
        docker(
            "run", "-d", "--name", postgres, "-p", f"127.0.0.1:{port}:5432",
            "-e", f"POSTGRES_PASSWORD={values['postgres']}",
            "-v", f"{root / 'postgres'}:/tls-source:ro", "--entrypoint", "sh", POSTGRES_IMAGE, "-c",
            "install -o postgres -g postgres -m 0600 /tls-source/server-key.pem /var/lib/postgresql/server.key"
            " && install -o postgres -g postgres -m 0644 /tls-source/server.pem /var/lib/postgresql/server.crt"
            " && exec docker-entrypoint.sh postgres -c ssl=on"
            " -c ssl_cert_file=/var/lib/postgresql/server.crt -c ssl_key_file=/var/lib/postgresql/server.key",
        )  # fmt: skip
        ready = wait_for(
            lambda: docker(
                "exec", postgres, "pg_isready", "-h", "127.0.0.1", "-U", "postgres", check=False
            ).returncode
            == 0,
            60,
            1,
        )
        if not ready:
            raise RuntimeError("PostgreSQL did not become ready")
        time.sleep(2)  # The image restarts the server once after initialization.
        wait_for(
            lambda: docker("exec", postgres, "pg_isready", "-U", "postgres", check=False).returncode
            == 0,
            60,
            1,
        )
        for role in ("runtime_owner", "runtime_app", "search_release", "search_app"):
            psql("postgres", f"CREATE ROLE {role} LOGIN PASSWORD '{values[role]}'")
        psql("postgres", "CREATE DATABASE sentryruntime OWNER runtime_owner")
        psql("postgres", "CREATE DATABASE sentrysearch OWNER search_release")
        plain(
            runtime_default,
            {"DATABASE_URL": runtime_url("runtime_owner", "/run/trust/postgres-ca.pem")},
            ["/app/migrate"],
        )
        docker(
            "exec", "-i", postgres, "psql", "-X", "-v", "ON_ERROR_STOP=1",
            "-v", "database_name=sentryruntime", "-v", "service_role=runtime_app",
            "-U", "runtime_owner", "-d", "sentryruntime",
            stdin=(runtime_repo / "db" / "roles" / "service.sql").read_text(),
        )  # fmt: skip
        released = plain(
            search_default,
            product("release", "/run/trust/postgres-ca.pem"),
            ["python", "-m", "dev.migrate_storage"],
        )
        if "Storage schema ready" not in released:
            raise RuntimeError("Search storage release did not report a ready schema")
        psql("sentrysearch", "GRANT USAGE ON SCHEMA public TO search_app")
        psql(
            "sentrysearch",
            f"GRANT SELECT, INSERT, UPDATE, DELETE ON {SEARCH_APP_TABLES} TO search_app",
        )
        psql("sentrysearch", "GRANT SELECT ON sentrysearch_schema_migrations TO search_app")

        def material(files: dict[str, str]) -> dict[str, str]:
            payload = json.dumps(files)
            return {
                "CFINIT_MATERIAL": payload,
                "CFINIT_MATERIAL_SHA256": hashlib.sha256(payload.encode()).hexdigest(),
            }

        search_files = {
            "runtime-ca.pem": runtime.ca.read_text(),
            "postgres-ca.pem": database.ca.read_text(),
        }
        credentials = [
            {
                "token_sha256": hashlib.sha256(values[role].encode()).hexdigest(),
                "role": role,
                "product": "sentrysearch",
                "workflow_name": "generate_report",
                "workflow_version": "v1",
            }
            for role in ("producer", "worker")
        ]
        settings = {
            "runtime": {
                **material(
                    {
                        "server-cert.pem": runtime.certificate.read_text(),
                        "server-key.pem": runtime.key.read_text(),
                        "runtime-ca.pem": runtime.ca.read_text(),
                        "postgres-ca.pem": database.ca.read_text(),
                        "probe-token": values["probe"],
                    }
                ),
                "DATABASE_URL": runtime_url("runtime_app", "/run/material/postgres-ca.pem"),
                "SENTRYRUNTIME_LISTEN_ADDRESS": "0.0.0.0:8443",
                "SENTRYRUNTIME_AUTH_MODE": "token",
                "SENTRYRUNTIME_AUTH_CREDENTIALS": json.dumps(credentials),
                "SENTRYRUNTIME_TLS_CERT_FILE": "/run/material/server-cert.pem",
                "SENTRYRUNTIME_TLS_KEY_FILE": "/run/material/server-key.pem",
            },
            "worker": {
                **material(search_files),
                **product("app", "/run/material/postgres-ca.pem"),
                "SENTRYRUNTIME_CA_FILE": "/run/material/runtime-ca.pem",
                "SENTRYRUNTIME_TUNNEL_URL": "ws://runtime.internal/v1/tunnel",
                "SENTRYRUNTIME_PRODUCER_TOKEN": values["producer"],
                "SENTRYRUNTIME_WORKER_TOKEN": values["worker"],
                "OPENROUTER_API_KEY": values["provider"],
                "OPENROUTER_BASE_URL": f"http://{DB_HOST}:{provider.getsockname()[1]}/api/v1",
                "PYTHON_DOTENV_DISABLED": "1",
            },
            "api": {
                **material(search_files),
                **product("app", "/run/material/postgres-ca.pem"),
                "PYTHON_DOTENV_DISABLED": "1",
            },
        }
        run.evidence["real_backing"] = {
            "postgres_image": POSTGRES_IMAGE,
            "database_host": f"{DB_HOST}:{port}",
            "runtime_migrated": True,
            "search_schema": "ready",
        }
        run.trust_dir = trust

        def admit(report_id: str) -> None:
            """Admit one report for runtime dispatch, as the API would (busy-drain case)."""
            create = (
                "import sys\nfrom src.storage.report_service import report_service\n"
                "report_service.create_pending_report(sys.argv[1], 'Harness synthetic target',"
                " 'harness-user', runtime_dispatch=True)"
            )
            plain(
                search_default,
                product("app", "/run/trust/postgres-ca.pem"),
                ["python", "-c", create, report_id],
            )

        run.admit = admit
        run.provider_connections = accepted
        yield settings, values
    finally:
        stop_provider.set()
        provider.close()
        for held in accepted:
            with contextlib.suppress(OSError):
                held.close()
        docker("rm", "-f", "-v", postgres, check=False)
        shutil.rmtree(root, ignore_errors=True)


def settings_for(run: Run, script: str) -> dict[str, str]:
    """The CONTAINER_* settings a script's rendered configuration passes to its container."""
    config = json.loads((run.dir / "config" / f"{script}.jsonc").read_text())
    return {k: v for k, v in config["vars"].items() if k.startswith("CONTAINER_")}


def service_containers() -> dict[str, str]:
    names = docker("ps", "--format", "{{.Names}}").stdout.split()
    found = {}
    for service, marker in (
        ("api", "-ApiService-"),
        ("worker", "-WorkerService-"),
        ("runtime", "-RuntimeService-"),
    ):
        for name in names:
            if marker in name and not name.endswith("-proxy"):
                found[service] = name
    return found


STATUS_FIELDS = ("Uid", "Gid", "Groups", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb",
                 "NoNewPrivs", "Seccomp", "Seccomp_filters")  # fmt: skip
READ_STATUS = (
    "import json,os,sys\n"
    "out={}\n"
    "for pid in sorted((p for p in os.listdir('/proc') if p.isdigit()), key=int):\n"
    "    if int(pid) == os.getpid(): pid='helper'\n"
    "    try: lines=open('/proc/self/status' if pid == 'helper' else f'/proc/{pid}/status').read().splitlines()\n"
    "    except OSError: continue\n"
    "    f={}\n"
    "    for line in lines:\n"
    "        k,_,v=line.partition(':')\n"
    "        if k in sys.argv[1].split(','): f[k]=' '.join(v.split())\n"
    "    out[pid]=f\n"
    "print(json.dumps(out))\n"
)


def process_report(container: str, helper_image: str) -> dict[str, Any]:
    """Every process in a container: its user and the kernel's view of its privileges."""
    top = docker("top", container, "-o", "pid,uid,args").stdout.strip().splitlines()[1:]
    processes = [line.split(None, 2) for line in top]
    # /proc of the container's own PID namespace, read by a helper that joins it
    # (skipping itself and processes that exit while it reads).
    status = docker(
        "run", "--rm", "--pid", f"container:{container}", "--network", "none",
        "--entrypoint", "/usr/local/bin/python", helper_image, "-I", "-c", READ_STATUS,
        ",".join(STATUS_FIELDS) + ",Name",
        check=False,
    )  # fmt: skip
    kernel = json.loads(status.stdout) if status.returncode == 0 else {}
    return {"top": processes, "status": kernel, "helper_error": status.stderr[-300:] or None}


def follow_logs(run: Run, seconds: float = 1800) -> None:
    """Stream every service container's output into the run directory.

    workerd removes a container when it exits, taking its logs with it; these
    copies are local run evidence (the services never print secrets).
    """
    logs = run.dir / "container-logs"
    logs.mkdir(exist_ok=True)
    seen: set[str] = set()

    def watch() -> None:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline and (run.wrangler is None or run.wrangler.poll() is None):
            for service, name in service_containers().items():
                if name in seen:
                    continue
                seen.add(name)
                with (logs / f"{service}-{len(seen)}.log").open("w") as out:
                    subprocess.Popen(
                        ["docker", "logs", "-f", "--timestamps", name],
                        stdout=out,
                        stderr=subprocess.STDOUT,
                    )
            time.sleep(1)

    threading.Thread(target=watch, daemon=True).start()


def real_scenarios(run: Run, helper_image: str) -> None:
    control = run.control
    follow_logs(run)

    def start_services() -> dict[str, Any]:
        results: dict[str, tuple[int, Any]] = {}
        for service, name in (("runtime", "runtime-0"), ("worker", "worker-0"), ("api", "api-0")):
            results[name] = control.send(service, name, "start")
        return {
            "passed": all(
                status == 200 and isinstance(body, dict) and body.get("started")
                for status, body in results.values()
            ),
            "results": results,
        }

    def database_path() -> dict[str, Any]:
        """From inside each Search container's network: resolve and reach the database."""
        backing = run.evidence.get("real_backing", {})
        host, _, port = str(backing.get("database_host", ":")).rpartition(":")
        probe = (
            "import json,socket,sys\n"
            "out={}\n"
            "try: out['addresses']=sorted({a[4][0] for a in socket.getaddrinfo(sys.argv[1], int(sys.argv[2]))})\n"
            "except Exception as e: out['resolve_error']=repr(e)\n"
            "try:\n s=socket.create_connection((sys.argv[1], int(sys.argv[2])), 5); out['tcp']='connected'; s.close()\n"
            "except Exception as e: out['tcp_error']=repr(e)\n"
            "print(json.dumps(out))\n"
        )
        results: dict[str, Any] = {}
        for service in ("api", "worker"):
            name = wait_for(lambda s=service: service_containers().get(s), 120, 1)
            if not name:
                results[service] = {"error": "no container"}
                continue
            mode = docker("inspect", "--format", "{{.HostConfig.NetworkMode}}", name, check=False)
            result = docker(
                "run", "--rm", "--network", f"container:{name}",
                "--entrypoint", "/usr/local/bin/python", ENTRYPOINT_HELPER, "-I", "-c", probe, host, port,
                check=False,
            )  # fmt: skip
            results[service] = {
                "network_mode": mode.stdout.strip(),
                "probe": (
                    json.loads(result.stdout) if result.returncode == 0 else result.stderr[-300:]
                ),
            }
        # The application's own database check, from the API's network namespace.
        api = results.get("api", {})
        name = service_containers().get("api")
        # Join the namespace's owner (the egress sidecar): the API may be restarting.
        owner = str(api.get("network_mode", ""))
        if name and owner.startswith("container:") and run.trust_dir:
            env = {k.removeprefix("CONTAINER_"): v for k, v in settings_for(run, "api").items()}
            env.pop("CFINIT_MATERIAL", None)
            env.pop("CFINIT_MATERIAL_SHA256", None)
            env["DB_SSLROOTCERT"] = "/run/trust/postgres-ca.pem"
            env_file = run.trust_dir.parent / "api-probe.env"
            private_write(env_file, "".join(f"{k}={v}\n" for k, v in env.items()))
            check = (
                "from src.storage.database import db_manager\n"
                "try:\n db_manager.require_schema(); print('schema ok')\n"
                "except Exception as e:\n"
                " c=e.__cause__ or e.__context__\n"
                " print('schema failed', type(e).__name__, type(c).__name__ if c else None,"
                " str(c)[:300] if c else '')\n"
            )
            result = docker(
                "run", "--rm", "--network", owner, "--env-file", str(env_file),
                "-v", f"{run.trust_dir}:/run/trust:ro", run.args.search_default_image,
                "python", "-c", check,
                check=False,
            )  # fmt: skip
            env_file.unlink()
            api["application_check"] = (result.stdout or result.stderr)[-500:].strip()
        return {
            "passed": all(
                isinstance(r.get("probe"), dict) and r["probe"].get("tcp") == "connected"
                for r in results.values()
            ),
            "database": f"{host}:{port}",
            "results": results,
        }

    def worker_ready_through_tunnel() -> dict[str, Any]:
        started = time.monotonic()

        def ready() -> Any:
            status, view = control.send("worker", "worker-0", "receipts", method="GET")
            if status == 200 and any(r["ready"] for r in view.get("receipts", [])):
                return view
            return None

        view = wait_for(ready, 420, 5)
        _, status = control.send("worker", "worker-0", "status", "GET")
        return {
            "passed": bool(view) and view["duplicatesConflicting"] == 0 and not view["gaps"],
            "seconds_to_ready": round(time.monotonic() - started, 1),
            "receipts": len((view or {}).get("receipts", [])),
            "errors_before_ready": sorted(
                {r["error_code"] for r in (view or {}).get("receipts", []) if r["error_code"]}
            ),
            "worker_status": status,
        }

    def api_ready() -> dict[str, Any]:
        def ready() -> Any:
            status, body = http(urllib.request.Request(f"{run.base_url}/api/ready"))
            return (status, body) if status == 200 else None

        result = wait_for(ready, 240, 5)
        health = http(urllib.request.Request(f"{run.base_url}/api/health"))
        body = result[1] if result else None
        return {
            "passed": isinstance(body, dict) and body.get("schema") == "compatible",
            "ready": result,
            "health_status": health[0],
        }

    def dropped_processes() -> dict[str, Any]:
        containers = service_containers()
        reports = {s: process_report(c, helper_image) for s, c in containers.items()}
        problems = []
        expected = {"api": "10001", "worker": "10001", "runtime": "65532"}
        for service, report in reports.items():
            status = dict(report["status"])
            # The helper runs under Docker's default profile, as the containers do:
            # the entrypoint's own filter is one more than that.
            baseline = status.pop("helper", {}).get("Seccomp_filters")
            if not baseline or not baseline.isdigit():
                problems.append(f"{service}: no seccomp baseline")
                continue
            if status.get("1", {}).get("Name") == "tini":
                status.pop("1")  # PID 1 init: forwards signals and reaps (CF04-R23 residual)
            for pid, fields in status.items():
                identity = expected[service]
                if (
                    fields.get("Uid", "").split() != [identity] * 4
                    or fields.get("Gid", "").split() != [identity] * 4
                    or fields.get("Groups") != ""
                ):
                    problems.append(f"{service} pid {pid} {fields.get('Name')} identity {fields}")
                for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
                    if fields.get(key) != "0000000000000000":
                        problems.append(f"{service} pid {pid} {key}={fields.get(key)}")
                if (
                    fields.get("NoNewPrivs") != "1"
                    or fields.get("Seccomp") != "2"
                    or fields.get("Seccomp_filters") != str(int(baseline) + 1)
                ):
                    problems.append(f"{service} pid {pid} no_new_privs/seccomp {fields}")
        return {
            "passed": set(reports) == {"api", "worker", "runtime"}
            and all(r["status"] for r in reports.values())
            and not problems,
            "problems": problems,
            "processes": reports,
        }

    def stop_and_observe(service: str, name: str) -> dict[str, Any]:
        status, body = control.send(service, name, "stop")

        def ended() -> Any:
            s, b = control.send(service, name, "status", "GET")
            start = (b or {}).get("start") or {}
            return b if s == 200 and start.get("state") not in ("running", "draining") else None

        final = wait_for(ended, 90, 2)
        return {"stop": body, "final": (final or {}).get("start")}

    def drain_worker() -> dict[str, Any]:
        result = stop_and_observe("worker", "worker-0")
        _, view = control.send("worker", "worker-0", "receipts", "GET")
        final = result["final"] or {}
        return {
            "passed": final.get("state") == "exited"
            and final.get("exit_detail") == "exit 0"
            and (view or {}).get("ended") is True
            and (view or {}).get("unterminated") == []
            and (view or {}).get("complete") is True,
            **result,
            "receipts_complete": (view or {}).get("complete"),
            "last_receipts": [
                (r["sequence"], r["alive"], r["draining"], r["phase"], r["error_code"])
                for r in (view or {}).get("receipts", [])[-3:]
            ],
        }

    def busy_drain_deadline() -> dict[str, Any]:
        """A worker stopped mid-generation ends itself at its drain deadline (exit 124)."""
        status, body = control.send("worker", "worker-0", "start")
        if status != 200 or not body.get("started") or run.admit is None:
            return {"passed": False, "start": body}

        def ready() -> Any:
            s, view = control.send("worker", "worker-0", "receipts", method="GET")
            return view if s == 200 and any(r["ready"] for r in view.get("receipts", [])) else None

        if not wait_for(ready, 300, 5):
            return {"passed": False, "detail": "restarted worker not ready"}
        run.admit(str(uuid.uuid4()))

        def generating() -> Any:
            s, view = control.send("worker", "worker-0", "receipts", method="GET")
            busy = [r for r in view.get("receipts", []) if r["phase"] == "generation"]
            return view if s == 200 and busy and run.provider_connections else None

        busy = wait_for(generating, 180, 3)
        if not busy:
            return {"passed": False, "detail": "worker never reached the provider"}
        result = stop_and_observe("worker", "worker-0")
        _, view = control.send("worker", "worker-0", "receipts", "GET")
        final = result["final"] or {}
        last = (view or {}).get("receipts", [])[-1:] or [{}]
        return {
            "passed": final.get("state") == "exited"
            and "124" in str(final.get("exit_detail"))
            and last[0].get("error_code") == "drain_deadline_exceeded"
            and last[0].get("alive") is False
            and (view or {}).get("unterminated") == [],
            **result,
            "provider_connections": len(run.provider_connections),
            "last_receipt": {
                k: last[0].get(k) for k in ("phase", "alive", "draining", "error_code")
            },
            "receipts_complete": (view or {}).get("complete"),
        }

    def drain_api() -> dict[str, Any]:
        result = stop_and_observe("api", "api-0")
        final = result["final"] or {}
        # Uvicorn finishes its graceful shutdown, then re-raises SIGTERM: 128 + 15.
        return {
            "passed": final.get("state") == "exited" and "143" in str(final.get("exit_detail")),
            **result,
        }

    def drain_runtime() -> dict[str, Any]:
        result = stop_and_observe("runtime", "runtime-0")
        final = result["final"] or {}
        return {
            "passed": final.get("state") == "exited" and final.get("exit_detail") == "exit 0",
            **result,
        }

    run.scenario("start_services", start_services)
    run.scenario("database_path_from_containers", database_path)
    run.scenario("worker_ready_through_tunnel", worker_ready_through_tunnel)
    run.scenario("api_ready_through_ingress", api_ready)
    run.scenario("dropped_processes", dropped_processes)
    run.scenario("drain_worker", drain_worker)
    run.scenario("busy_drain_deadline", busy_drain_deadline)
    run.scenario("drain_api", drain_api)
    run.scenario("drain_runtime", drain_runtime)


def fixture_run(run: Run, args: argparse.Namespace, lan: str | None, outside_port: int) -> None:
    tag = fixture_image(run.dir)
    from dev.tls_fixtures import create_certificates

    certs = create_certificates(run.dir / "tls", hostname="runtime.test")
    token = "fixture-token-" + uuid.uuid4().hex
    container_env = {
        "runtime": {
            "FIXTURE_TLS_CERT": certs.certificate.read_text(),
            "FIXTURE_TLS_KEY": certs.key.read_text(),
            "FIXTURE_TOKEN": token,
        },
        "worker": {"FIXTURE_RUNTIME_CA": certs.ca.read_text(), "FIXTURE_TOKEN": token},
        "api": {"FIXTURE_OUTSIDE_TARGET": f"{lan}:{outside_port}" if lan else ""},
        "jobs": {"FIXTURE_JOB_SECONDS": "5"},
    }
    run.evidence["fixture_image"] = tag
    run.prepare({"SEARCH": tag, "RUNTIME": tag, "RELEASE_TOOLS": tag}, container_env)
    run.start_wrangler()
    fixture_scenarios(run, lan, outside_port, args.long_job_seconds)


def real_run(run: Run, args: argparse.Namespace) -> None:
    if args.runtime_repo is None:
        raise SystemExit("--images real needs --runtime-repo")
    images = {
        "SEARCH": args.search_image,
        "RUNTIME": args.runtime_image,
        "RELEASE_TOOLS": args.release_tools_image,
        "search_default": args.search_default_image,
        "runtime_default": args.runtime_default_image,
        "helper": ENTRYPOINT_HELPER,
    }
    identities = {}
    for key, tag in images.items():
        result = docker(
            "image", "inspect", "--format", "{{.Id}} {{.Architecture}}", tag, check=False
        )
        if result.returncode:
            raise SystemExit(f"{tag} is not present locally; build it first (this run never pulls)")
        image_id, architecture = result.stdout.split()
        identities[key] = {"tag": tag, "id": image_id, "architecture": architecture}
    run.evidence["real_images"] = identities
    run.evidence["native_platform"] = args.native_platform or None
    with real_backing(
        run, args.search_default_image, args.runtime_default_image, args.runtime_repo.resolve()
    ) as (settings, values):
        run.prepare({k: v for k, v in images.items() if k.isupper()}, settings)
        run.start_wrangler()
        real_scenarios(run, ENTRYPOINT_HELPER)
        evidence = json.dumps(run.evidence, default=str)
        run.evidence["secrets_in_evidence"] = sorted(
            name for name, value in values.items() if value in evidence
        )
        run.secret_values = dict(values)


def scrub_run_dir(run: Run) -> list[str]:
    """Redact the rendered container settings, then report any disposable secret left."""
    for config in (run.dir / "config").glob("*.jsonc"):
        rendered = json.loads(config.read_text())
        for key in rendered.get("vars", {}):
            if key.startswith("CONTAINER_"):
                rendered["vars"][key] = "<redacted after the run>"
        config.write_text(json.dumps(rendered, indent=2))
    found = []
    for path in run.dir.rglob("*"):
        if not path.is_file():
            continue
        text = path.read_text(errors="replace")
        for name, value in run.secret_values.items():
            if value in text:
                found.append(f"{path.relative_to(run.dir)}: {name}")
        if "PRIVATE KEY" in text:
            found.append(f"{path.relative_to(run.dir)}: private key")
    return sorted(found)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--images", choices=("fixture", "real"), required=True)
    parser.add_argument(
        "--native-platform",
        default="",
        choices=("", "linux/arm64", "linux/amd64"),
        help="build the Worker image map for this platform instead of linux/amd64 (real images)",
    )
    parser.add_argument("--runtime-repo", type=Path, help="SentryRuntime checkout (real images)")
    parser.add_argument("--search-image", default="sentrysearch:cf04-native-cloudflare")
    parser.add_argument("--search-default-image", default="sentrysearch:cf04-native")
    parser.add_argument(
        "--release-tools-image", default="sentrysearch:cf04-native-release-tools-cloudflare"
    )
    parser.add_argument("--runtime-image", default="sentryruntime:cf04-native-cloudflare")
    parser.add_argument("--runtime-default-image", default="sentryruntime:cf04-native")
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument(
        "--long-job-seconds",
        type=int,
        default=0,
        help="also run one job past this deadline (over 900 for H-J1); 0 skips it",
    )
    args = parser.parse_args()

    if not WRANGLER.exists():
        raise SystemExit(
            "install the worker package first: (cd deploy/cloudflare/worker && npm ci --ignore-scripts)"
        )
    run = Run(args)

    def terminated(signum: int, _frame: Any) -> None:
        # A watchdog's SIGTERM must still stop Wrangler (its own session) and
        # remove the run's containers: turn it into an ordinary exit that fails.
        run.evidence["interrupted"] = f"signal {signum}"
        signal.signal(signal.SIGTERM, signal.SIG_IGN)  # Let the cleanup finish.
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGTERM, terminated)
    if run.dir.exists() and any(run.dir.iterdir()):
        raise SystemExit("run directory must be new or empty")
    run.dir.mkdir(parents=True, exist_ok=True)
    lan = lan_address()
    try:
        with canary(lan or "127.0.0.1") as (outside_port, outside_hits):
            run.evidence["outside_canary"] = f"{lan}:{outside_port}" if lan else None
            if args.images == "real":
                real_run(run, args)
            else:
                fixture_run(run, args, lan, outside_port)
            run.evidence["outside_canary_hits"] = list(outside_hits)
    finally:
        run.stop_wrangler()
        if run.secret_values:
            run.evidence["secrets_left_in_run_dir"] = scrub_run_dir(run)
        calls = (
            (run.dir / "docker-calls.log").read_text().splitlines()
            if (run.dir / "docker-calls.log").exists()
            else []
        )
        run.evidence["docker_calls"] = {
            "total": len(calls),
            "pulls": [call for call in calls if call.startswith("pull")],
            "commands": sorted({call.split()[0] for call in calls if call.split()}),
        }
        run.evidence["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        scenarios = run.evidence["scenarios"]
        run.evidence["passed"] = (
            bool(scenarios)
            and all(s.get("passed") for s in scenarios.values())
            and not run.evidence.get("outside_canary_hits")
            and not run.evidence.get("secrets_in_evidence")
            and not run.evidence.get("interrupted")
            and not run.evidence.get("secrets_left_in_run_dir")
        )
        Path(args.evidence).write_text(json.dumps(run.evidence, indent=2, default=str))
    print(f"overall: {'passed' if run.evidence['passed'] else 'FAILED'}")
    return 0 if run.evidence["passed"] else 1


if __name__ == "__main__":
    sys.path.insert(0, str(REPO))
    raise SystemExit(main())
