"""Explicit observer container suite; run with dev/check_release_tools.py.

The release-tools observers run against the real Runtime and API images on the
service suite's internal network (tests/service_images.py's stack). The observed
Runtime serves a certificate for its private name under a stand-in namespace and
accepts a dedicated probe credential; the API runs the Search image under its own
private name. A second internal network carries the stand-in ECS metadata endpoint
at its link-local address. Each observer runs read-only, without capabilities, as
the observer uid with owner-only material, as deploy/aws-platform-fit/observe.tf
defines the task. No AWS request, registry push or real credential is involved.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from dev.tls_fixtures import create_certificates
from release_tools import receipt
from tests import service_images as images
from tests.release_tools_images import METADATA_IP, METADATA_SERVER, PYTHON, SUBNET, stamp, task_arn

TOOLS_IMAGE = os.environ.get("RELEASE_TOOLS_TEST_IMAGE", "")
NAMESPACE = "release-check.internal"
OBSERVER_UID = 65532
PORTS = {"runtime": "8443", "api": "8001"}
MATERIAL_SCRIPT = (
    "import json, os, sys\n"
    "files = json.load(sys.stdin)\n"
    "for name, text in files.items():\n"
    "    fd = os.open('/run/material/' + name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)\n"
    "    os.write(fd, text.encode()); os.fchmod(fd, 0o400)\n"
    f"    os.fchown(fd, {OBSERVER_UID}, {OBSERVER_UID}); os.close(fd)\n"
    "os.chmod('/run/material', 0o700)\n"
    f"os.chown('/run/material', {OBSERVER_UID}, {OBSERVER_UID})\n"
)

stack = images.stack


@dataclass
class ObserverRun:
    name: str
    code: int
    stdout: str
    stderr: str

    @property
    def receipt(self) -> dict | None:
        return receipt.parse_receipt(self.stdout.splitlines(), "operational")


@dataclass
class Observed:
    stack: images.Stack
    metadata_network: str
    release_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    runtime: str = ""
    api: str = ""
    runtime_ca: Path = Path()
    probe_token: str = ""
    owned: list[str] = field(default_factory=list)
    volumes: list[str] = field(default_factory=list)

    def container(self, role: str) -> str:
        name = self.stack.name(role)
        self.owned.append(name)
        return name

    def address(self, container: str) -> str:
        networks = json.loads(
            images.docker(
                "inspect", "--format", "{{json .NetworkSettings.Networks}}", container
            ).stdout
        )
        return networks[self.stack.network]["IPAddress"]

    def material(self, ca: Path, token: str) -> str:
        """The runtime-observer init profile's result: the CA and probe token, owner-only."""
        name = f"{self.stack.network}-observer-material-{len(self.volumes)}"
        images.docker("volume", "create", name)
        self.volumes.append(name)
        images.docker(
            "run", "--rm", "-i", "--network", "none", "--user", "0", "--mount",
            f"type=volume,source={name},target=/run/material", *PYTHON, TOOLS_IMAGE,
            "-I", "-B", "-c", MATERIAL_SCRIPT,
            stdin=json.dumps({"runtime-ca.pem": ca.read_text(), "probe-token": token}),
        )  # fmt: skip
        return name

    def observe(self, target: str, *, material: str | None = None, **overrides: str) -> ObserverRun:
        name = self.container(f"{target}-observe")
        env = {
            "RELEASE_ID": self.release_id,
            "RELEASE_CHECK_ID": f"{target}-observe",
            "RELEASE_NOT_AFTER": stamp(datetime.now(UTC) + timedelta(minutes=10)),
            "RELEASE_CHECK_BUDGET_SECONDS": "300",
            "RELEASE_TARGET_HOST": f"{target}.{NAMESPACE}",
            "RELEASE_TARGET_PORT": PORTS[target],
            "ECS_CONTAINER_METADATA_URI_V4": f"http://{METADATA_IP}/v4/{name}",
            **overrides,
        }
        env_file = self.stack.root / f"{name}.env"
        env_file.write_text("".join(f"{key}={value}\n" for key, value in env.items()))
        env_file.chmod(0o600)
        mount = (
            (
                "--mount",
                f"type=volume,source={material},target=/run/material,readonly,volume-nocopy",
            )
            if material
            else ()
        )
        images.docker(
            "create", "--name", name, "--network", self.stack.network, "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--user", f"{OBSERVER_UID}:{OBSERVER_UID}", *mount, "--env-file", str(env_file),
            TOOLS_IMAGE, f"observe-{target}",
        )  # fmt: skip
        # The task-metadata endpoint is reachable only on its own link-local network.
        images.docker("network", "connect", self.metadata_network, name)
        images.docker("start", name)
        code = int(images.docker("wait", name, timeout=120).stdout.strip())
        logs = images.docker("logs", name)
        run = ObserverRun(name, code, logs.stdout, logs.stderr)
        self.stack.assert_no_secrets(run.stdout + run.stderr)
        for line in run.stdout.splitlines():
            assert line.startswith(receipt.RECEIPT_MARKER + " "), line
        for line in run.stderr.splitlines():
            assert set(json.loads(line)) <= receipt.LOG_FIELDS | {"event"}, line
        return run

    def start_api(self, role: str) -> str:
        api = self.container(role)
        self.stack.run(
            images.SEARCH_IMAGE, api, self.stack.product_env(), images.API, detach=True,
            options=("--network-alias", f"api.{NAMESPACE}"),
        )  # fmt: skip
        images.wait_for(
            "API startup", lambda: "Application startup complete" in images.logs(api), container=api
        )
        return api


@pytest.fixture(scope="module")
def observed(stack: images.Stack) -> Iterator[Observed]:
    if not TOOLS_IMAGE:
        pytest.fail("RELEASE_TOOLS_TEST_IMAGE is required")
    network = f"{stack.network}-metadata"
    images.docker("network", "create", "--internal", "--subnet", SUBNET, network)
    observed = Observed(stack, network, probe_token=secrets.token_hex(24))
    # Covered by the stack's output checks like every other disposable secret.
    stack.secrets["observer_probe"] = observed.probe_token
    try:
        metadata = observed.container("metadata")
        images.docker(
            "run", "-d", "--name", metadata, "--network", network, "--ip", METADATA_IP,
            "--read-only", "--cap-drop", "ALL", *PYTHON, TOOLS_IMAGE, "-I", "-B", "-c",
            METADATA_SERVER,
        )  # fmt: skip
        images.wait_for(
            "metadata", lambda: "listening" in images.logs(metadata), container=metadata
        )
        directory = stack.root / "observed-runtime"
        certificates = create_certificates(directory, hostname=f"runtime.{NAMESPACE}")
        for path in (certificates.certificate, certificates.key):
            path.chmod(0o644)
        directory.chmod(0o755)
        observed.runtime_ca = certificates.ca
        credentials = [
            {
                "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
                "role": role,
                "product": "sentrysearch",
                "workflow_name": "generate_report",
                "workflow_version": "v1",
            }
            for role, token in (
                ("producer", stack.secrets["producer"]),
                ("worker", stack.secrets["worker"]),
                # The observer's own probe credential, as its bundle carries it.
                ("producer", observed.probe_token),
            )
        ]
        observed.runtime = observed.container("observed-runtime")
        stack.run(
            images.RUNTIME_IMAGE,
            observed.runtime,
            {
                "DATABASE_URL": (
                    f"postgres://runtime_app:{stack.secrets['runtime_app']}@postgres:5432/"
                    "sentryruntime?sslmode=verify-full&sslrootcert=/run/trust/postgres-ca.pem"
                ),
                "SENTRYRUNTIME_LISTEN_ADDRESS": "0.0.0.0:8443",
                "SENTRYRUNTIME_AUTH_MODE": "token",
                "SENTRYRUNTIME_AUTH_CREDENTIALS": json.dumps(credentials),
                "SENTRYRUNTIME_TLS_CERT_FILE": "/run/tls/server.pem",
                "SENTRYRUNTIME_TLS_KEY_FILE": "/run/tls/server-key.pem",
            },
            [],
            detach=True,
            options=("--network-alias", f"runtime.{NAMESPACE}", "-v", f"{directory}:/run/tls:ro"),
        )
        images.wait_for(
            "observed runtime",
            lambda: "runtime listening" in images.logs(observed.runtime),
            container=observed.runtime,
        )
        observed.api = observed.start_api("observed-api")
        yield observed
    finally:
        for name in reversed(observed.owned):
            images.docker("rm", "-f", "-v", name, check=False)
        for name in observed.volumes:
            images.docker("volume", "rm", "-f", name, check=False)
        images.docker("network", "rm", network, check=False)


def test_runtime_observer_passes_against_the_real_runtime_and_names_its_peer(observed):
    material = observed.material(observed.runtime_ca, observed.probe_token)
    run = observed.observe("runtime", material=material)
    assert run.code == 0, (run.stdout, run.stderr)
    assert run.receipt == {
        "schema": "sentry.operational.v1",
        "release_id": observed.release_id,
        "check_id": "runtime-observe",
        "task_arn": task_arn(run.name),
        "status": "passed",
        "result": {
            "target": "runtime",
            "host": f"runtime.{NAMESPACE}",
            # The address actually connected to: the controller binds it to the task's ENI.
            "peer": observed.address(observed.runtime),
            "port": "8443",
            "tls": "verified",
            "checks": "healthz,readyz",
            "denials": "no_token,wrong_ca",
        },
    }


def test_api_observer_passes_against_the_real_api_and_names_its_peer(observed):
    run = observed.observe("api")
    assert run.code == 0, (run.stdout, run.stderr)
    document = run.receipt
    assert document is not None
    result = document.pop("result")
    assert document == {
        "schema": "sentry.operational.v1",
        "release_id": observed.release_id,
        "check_id": "api-observe",
        "task_arn": task_arn(run.name),
        "status": "passed",
    }
    denial = result.pop("denials")
    assert denial in {"unauthenticated:401", "unauthenticated:403", "unauthenticated:503"}
    assert result == {
        "target": "api",
        "host": f"api.{NAMESPACE}",
        "peer": observed.address(observed.api),
        "port": "8001",
        "tls": "none",
        "checks": "liveness,api_ready",
    }


@pytest.mark.parametrize(
    ("material", "reason"),
    [
        # A CA that did not issue the runtime's certificate: verify-full refuses it.
        ("wrong_ca", "tls_untrusted"),
        # A token the runtime does not hold: the runtime denies the probe.
        ("wrong_token", "healthz_failed"),
    ],
)
def test_runtime_observer_fails_closed_with_a_failed_receipt(observed, material, reason):
    ca = observed.stack.trust / "wrong-ca.pem" if material == "wrong_ca" else observed.runtime_ca
    token = secrets.token_hex(24) if material == "wrong_token" else observed.probe_token
    observed.stack.secrets[f"observer_{material}"] = token
    run = observed.observe("runtime", material=observed.material(ca, token))
    assert run.code == 12, (run.stdout, run.stderr)
    assert run.receipt is not None
    assert (run.receipt["status"], run.receipt["result"]) == ("failed", {"reason": reason})


def test_api_observer_refuses_a_private_name_with_two_answers(observed):
    # DNS naming two tasks cannot say which one answers: the check fails closed.
    second = observed.start_api("observed-api-second")
    try:
        run = observed.observe("api")
    finally:
        images.docker("rm", "-f", "-v", second, check=False)
    assert run.code == 12, (run.stdout, run.stderr)
    assert run.receipt is not None
    assert (run.receipt["status"], run.receipt["result"]) == (
        "failed",
        {"reason": "target_ambiguous"},
    )
