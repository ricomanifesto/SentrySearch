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
not prove the real images, their entrypoints or the capability drop; ``--images
real`` with locally built ``--target cloudflare`` images does.

Usage (from the repository root):
    .venv/bin/python deploy/cloudflare/harness/harness.py --images fixture \
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
import shutil
import signal
import socket
import subprocess
import sys
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
        shim.write_text(DOCKER_SHIM.format(log=self.dir / "docker-calls.log", docker=docker))
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


def fixture_scenarios(run: Run, lan: str | None, outside_port: int) -> None:
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
            and probe == {"runtime_relay": "unreachable", "outside": "unreachable"}
            and public_tunnel == 404
            and public_receipts == 404,
            "api_health": health,
            "api_probe": probe,
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


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--images", choices=("fixture",), required=True)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--evidence", required=True)
    args = parser.parse_args()
    if not WRANGLER.exists():
        raise SystemExit(
            "install the worker package first: (cd deploy/cloudflare/worker && npm ci --ignore-scripts)"
        )
    run = Run(args)
    if run.dir.exists() and any(run.dir.iterdir()):
        raise SystemExit("run directory must be new or empty")
    run.dir.mkdir(parents=True, exist_ok=True)
    lan = lan_address()
    try:
        with canary(lan or "127.0.0.1") as (outside_port, outside_hits):
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
            run.evidence["outside_canary"] = f"{lan}:{outside_port}" if lan else None
            run.prepare({"SEARCH": tag, "RUNTIME": tag, "RELEASE_TOOLS": tag}, container_env)
            run.start_wrangler()
            fixture_scenarios(run, lan, outside_port)
            run.evidence["outside_canary_hits"] = list(outside_hits)
    finally:
        run.stop_wrangler()
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
        )
        Path(args.evidence).write_text(json.dumps(run.evidence, indent=2, default=str))
    print(f"overall: {'passed' if run.evidence['passed'] else 'FAILED'}")
    return 0 if run.evidence["passed"] else 1


if __name__ == "__main__":
    sys.path.insert(0, str(REPO))
    raise SystemExit(main())
