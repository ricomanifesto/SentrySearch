"""Explicit AWS-08a topology cases the other local suites do not cover; Docker only.

Run through ``python -m release_kits.aws_08a`` (or with the service-image suite's
environment: SENTRYSEARCH_TEST_IMAGE, SENTRYRUNTIME_TEST_IMAGE and
SENTRYRUNTIME_TEST_REPO). Each case restarts the real Runtime image on the
suite's internal network with changed credentials or certificates and checks
what a worker and a probe then see. No AWS request is made.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import secrets
import shutil
import uuid

from dev.tls_fixtures import create_certificates
from tests.service_images import (
    FAST_WORKER,
    RUNTIME_GET,
    RUNTIME_IMAGE,
    SEARCH_IMAGE,
    Stack,
    docker,
    local_probe,
    logs,
    stack,  # noqa: F401
    stop,
    wait_for,
)


def runtime_containers(stack: Stack) -> list[str]:
    return [name for name in stack.containers if stack.hostnames.get(name) == "runtime"]


def restart_runtime(stack: Stack, tokens: dict[str, str], tls: Path) -> str:
    """Replace the suite's Runtime with one holding these tokens and this certificate."""
    for name in runtime_containers(stack):
        docker("rm", "-f", "-v", name, check=False)
    database = (
        f"postgres://runtime_app:{stack.secrets['runtime_app']}@postgres:5432/"
        "sentryruntime?sslmode=verify-full&sslrootcert=/run/trust/postgres-ca.pem"
    )
    credentials = [
        {"token_sha256": hashlib.sha256(token.encode()).hexdigest(), "role": role,
         "product": "sentrysearch", "workflow_name": "generate_report", "workflow_version": "v1"}
        for role, token in tokens.items()
    ]  # fmt: skip
    runtime = stack.name("runtime")
    stack.run(
        RUNTIME_IMAGE, runtime,
        {"DATABASE_URL": database, "SENTRYRUNTIME_LISTEN_ADDRESS": "0.0.0.0:8443",
         "SENTRYRUNTIME_AUTH_MODE": "token",
         "SENTRYRUNTIME_AUTH_CREDENTIALS": json.dumps(credentials),
         "SENTRYRUNTIME_TLS_CERT_FILE": "/run/tls/server.pem",
         "SENTRYRUNTIME_TLS_KEY_FILE": "/run/tls/server-key.pem"},
        [], detach=True, options=("--network-alias", "runtime", "-v", f"{tls}:/run/tls:ro"),
    )  # fmt: skip
    wait_for("runtime", lambda: "runtime listening" in logs(runtime), container=runtime)
    return runtime


def runtime_status(stack: Stack, token: str, *, ca: str = "runtime-ca.pem") -> int:
    """The Runtime's answer to an authenticated read of a run that does not exist."""
    probe = RUNTIME_GET.replace("/run/trust/runtime-ca.pem", f"/run/trust/{ca}")
    result = stack.run(SEARCH_IMAGE, stack.name("probe"), {},
                       ["python", "-c", probe, f"/v1/runs/{uuid.uuid4()}"], detach=False,
                       stdin=token)  # fmt: skip
    if result.returncode:
        return 0  # the TLS handshake or the connection failed
    return int(result.stdout.split("\n", 1)[0])


def worker_ready(stack: Stack, env: dict[str, str], label: str) -> tuple[bool, str]:
    worker = stack.name(label)
    stack.run(SEARCH_IMAGE, worker, env, FAST_WORKER, detach=True)
    try:
        wait_for("worker decision", lambda: local_probe(worker, "/readyz")[0] == 200
                 or local_probe(worker, "/status")[1].get("error_code") is not None,
                 container=worker)  # fmt: skip
        ready = local_probe(worker, "/readyz")[0] == 200
        error = local_probe(worker, "/status")[1].get("error_code")
    finally:
        stop(worker)
    stack.assert_no_secrets(logs(worker))
    return ready, str(error)


def worker_refused(stack: Stack, env: dict[str, str], label: str) -> tuple[int, str | None]:
    """A worker whose Runtime refuses its tokens stops: its exit code and final error."""
    worker = stack.name(label)
    stack.run(SEARCH_IMAGE, worker, env, FAST_WORKER, detach=True)
    code = int(docker("wait", worker, timeout=90).stdout.strip())
    output = logs(worker)
    stack.assert_no_secrets(output)
    final = output.rsplit("Worker supervisor stopped: ", 1)
    error = json.loads(final[1].splitlines()[0]).get("error_code") if len(final) == 2 else None
    return code, error


def test_secret_rotation_retires_the_old_runtime_tokens(stack: Stack):
    old = {"producer": stack.secrets["producer"], "worker": stack.secrets["worker"]}
    assert runtime_status(stack, old["producer"]) == 404, "the current token is accepted"
    rotated = {role: secrets.token_hex(24) for role in old}
    stack.secrets.update({f"rotated-{role}": token for role, token in rotated.items()})
    restart_runtime(stack, rotated, stack.root / "runtime")
    try:
        assert runtime_status(stack, old["producer"]) == 401, "a retired token is refused"
        assert runtime_status(stack, rotated["producer"]) == 404, "the new token is accepted"
        # A worker still holding a retired token is refused and stops for correction.
        stale = worker_refused(stack, stack.worker_env(), "worker-stale-tokens")
        assert stale == (1, "runtime_access_denied"), stale
        env = {**stack.worker_env(), "SENTRYRUNTIME_PRODUCER_TOKEN": rotated["producer"],
               "SENTRYRUNTIME_WORKER_TOKEN": rotated["worker"]}  # fmt: skip
        assert worker_ready(stack, env, "worker-rotated-tokens")[0] is True
    finally:
        for name in runtime_containers(stack):
            stack.assert_no_secrets(logs(name))
        restart_runtime(stack, old, stack.root / "runtime")


def test_certificate_rollover_needs_the_new_authority_trusted_first(stack: Stack):
    current = (stack.trust / "runtime-ca.pem").read_text()
    renewed = create_certificates(stack.root / "runtime-renewed", hostname="runtime")
    misnamed = create_certificates(stack.root / "runtime-misnamed", hostname="not-runtime")
    for directory in (stack.root / "runtime-renewed", stack.root / "runtime-misnamed"):
        directory.chmod(0o755)
        for path in directory.glob("*.pem"):
            path.chmod(0o644)
    # The bundle a rollover ships before the certificate changes: both authorities.
    (stack.trust / "runtime-both-ca.pem").write_text(current + renewed.ca.read_text())
    shutil.copy(renewed.ca, stack.trust / "runtime-renewed-ca.pem")
    shutil.copy(misnamed.ca, stack.trust / "runtime-misnamed-ca.pem")
    for path in stack.trust.iterdir():
        path.chmod(0o644)
    tokens = {"producer": stack.secrets["producer"], "worker": stack.secrets["worker"]}
    try:
        restart_runtime(stack, tokens, stack.root / "runtime-renewed")
        token = stack.secrets["producer"]
        assert runtime_status(stack, token, ca="runtime-both-ca.pem") == 404
        assert runtime_status(stack, token, ca="runtime-renewed-ca.pem") == 404
        assert runtime_status(stack, token, ca="runtime-ca.pem") == 0, "the old authority alone"
        both = {**stack.worker_env(), "SENTRYRUNTIME_CA_FILE": "/run/trust/runtime-both-ca.pem"}
        assert worker_ready(stack, both, "worker-both-authorities")[0] is True
        old_only = worker_ready(stack, stack.worker_env(), "worker-old-authority")
        assert old_only == (False, "runtime_unavailable"), old_only
        # A certificate from a trusted authority for another name is still refused.
        restart_runtime(stack, tokens, stack.root / "runtime-misnamed")
        assert runtime_status(stack, token, ca="runtime-misnamed-ca.pem") == 0
        wrong = {
            **stack.worker_env(),
            "SENTRYRUNTIME_CA_FILE": "/run/trust/runtime-misnamed-ca.pem",
        }
        assert worker_ready(stack, wrong, "worker-misnamed")[0] is False
    finally:
        restart_runtime(stack, tokens, stack.root / "runtime")
