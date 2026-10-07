"""Fargate-shaped local volumes and process proof; no AWS requests or deployment."""

from collections.abc import Iterator
import json

import pytest

from tests import service_images as images


class VolumeStack(images.Stack):
    """Reuse real service lifecycle assertions with task-local named volumes."""

    volumes: list[str]

    def volume(self, suffix: str) -> str:
        name = f"{self.network}-{suffix}-{len(self.volumes)}"
        images.docker("volume", "create", name)
        self.volumes.append(name)
        return name

    def initialize(self, profile: str, name: str, *, invalid: bool = False):
        material = self.volume(f"{name}-material")
        mounts = ["--mount", f"type=volume,source={material},target=/run/material,volume-nocopy"]
        command = [
            "python",
            "-m",
            "dev.prepare_service_volumes",
            "--profile",
            profile,
            "--material-dir",
            "/run/material",
            "--fixture-stdin",
        ]
        payload = {"postgres-ca.pem": (self.trust / "postgres-ca.pem").read_text()}
        if profile in {"runtime", "search"}:
            payload["runtime-ca.pem"] = (self.trust / "runtime-ca.pem").read_text()
        scratch_mounts = []
        if profile == "runtime":
            payload.update(
                {
                    "server-cert.pem": (self.root / "runtime/server.pem").read_text(),
                    "server-key.pem": (self.root / "runtime/server-key.pem").read_text(),
                    "probe-token": self.secrets["producer"],
                }
            )
        elif profile == "search":
            for suffix, target, argument in (
                ("tmp", "/tmp", "--tmp-dir"),
                ("work", "/var/lib/sentrysearch", "--work-dir"),
            ):
                volume = self.volume(f"{name}-{suffix}")
                scratch_mounts += [
                    "--mount",
                    f"type=volume,source={volume},target={target},volume-nocopy",
                ]
                command += [argument, target]
            mounts += scratch_mounts
        if invalid:
            payload["unexpected"] = "reject-this-fixture"
        initialized = images.docker(
            "run",
            "--rm",
            "-i",
            "--network",
            self.network,
            "--user",
            "0:0",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "CHOWN",
            "--security-opt",
            "no-new-privileges",
            *mounts,
            images.SEARCH_IMAGE,
            *command,
            stdin=json.dumps(payload),
            check=False,
        )
        self.assert_no_secrets(initialized.stdout + initialized.stderr)
        readonly = [
            "--mount",
            f"type=volume,source={material},target=/run/material,readonly,volume-nocopy",
        ]
        return initialized, [*readonly, *scratch_mounts]

    def run(self, image, name, env, command, *, detach, options=(), stdin=None):
        # Every service invocation models SUCCESS dependency ordering: the app
        # launch is unreachable on init failure. ECS itself is not running here.
        runtime = image == images.RUNTIME_IMAGE and not command
        profile = "runtime" if image == images.RUNTIME_IMAGE else "search"
        if command == ["/app/migrate"]:
            profile = "runtime-release"
        elif command[:3] == images.RELEASE:
            profile = "search-release"
        initialized, mounts = self.initialize(profile, name)
        assert initialized.returncode == 0, initialized.stderr
        env = {key: value.replace("/run/trust/", "/run/material/") for key, value in env.items()}
        if runtime:
            env.update(
                {
                    "SENTRYRUNTIME_TLS_CERT_FILE": "/run/material/server-cert.pem",
                    "SENTRYRUNTIME_TLS_KEY_FILE": "/run/material/server-key.pem",
                }
            )
            # The old fixture TLS bind is unnecessary once initialized privately.
            options = ("--network-alias", "runtime")
        env_file = self.root / f"{name}.env"
        env_file.write_text("".join(f"{key}={value}\n" for key, value in env.items()))
        env_file.chmod(0o600)
        return images.docker(
            "run",
            "-d" if detach else "--rm",
            *(("-i",) if stdin is not None else ()),
            "--name",
            name,
            "--hostname",
            self.hostnames[name],
            "--network",
            self.network,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--env-file",
            str(env_file),
            *mounts,
            *options,
            image,
            *command,
            check=detach,
            stdin=stdin,
            timeout=180,
        )

    def runtime_get(self, path):
        # Existing probe helper uses /run/trust; substitute only its trust path.
        result = self.run(
            images.SEARCH_IMAGE,
            self.name("probe"),
            {},
            ["python", "-c", images.RUNTIME_GET.replace("/run/trust/", "/run/material/"), path],
            detach=False,
            stdin=self.secrets["producer"],
        )
        status, body = result.stdout.split("\n", 1)
        return int(status), json.loads(body)


@pytest.fixture(scope="module")
def stack() -> Iterator[VolumeStack]:
    patch = pytest.MonkeyPatch()
    patch.setattr(images, "Stack", VolumeStack)
    VolumeStack.volumes = []
    try:
        yield from getattr(images.stack, "__wrapped__")()
    finally:
        # The underlying fixture stops/removes its containers first.
        for name in reversed(VolumeStack.volumes):
            images.docker("volume", "rm", name, check=False)
        patch.undo()


def test_fresh_task_volumes_are_private_readonly_material_and_writable_scratch(stack):
    command = """
import os, pathlib, stat
assert os.getuid() == 10001
for directory in ['/run/material', '/tmp', '/var/lib/sentrysearch']:
    path = pathlib.Path(directory)
    assert path.stat().st_uid == 10001 and stat.S_IMODE(path.stat().st_mode) == 0o700
for path in pathlib.Path('/run/material').iterdir():
    assert path.stat().st_uid == 10001 and stat.S_IMODE(path.stat().st_mode) == 0o400
    assert path.read_text().startswith('-----BEGIN CERTIFICATE-----')
for name in ['/run/material/runtime-ca.pem', '/app/run_api.py', '/forbidden']:
    try:
        pathlib.Path(name).write_text('forbidden')
    except OSError:
        pass
    else:
        raise AssertionError('read-only write succeeded')
for name in ['/tmp/owned', '/var/lib/sentrysearch/owned']:
    pathlib.Path(name).write_text('disposable')
print('named-volume permissions verified')
"""
    result = stack.run(
        images.SEARCH_IMAGE, stack.name("permissions"), {}, ["python", "-c", command], detach=False
    )
    assert result.returncode == 0, result.stderr
    assert "named-volume permissions verified" in result.stdout


@pytest.mark.parametrize("profile,uid", [("runtime-release", 65532), ("search-release", 10001)])
def test_release_material_contains_only_database_ca(stack, profile, uid):
    initialized, mounts = stack.initialize(profile, stack.name("release-material"))
    assert initialized.returncode == 0, initialized.stderr
    assert len(mounts) == 2  # No runtime identity, probe token or writable scratch.
    inspected = images.docker(
        "run",
        "--rm",
        "--network=none",
        "--user",
        f"{uid}:{uid}",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        *mounts,
        images.SEARCH_IMAGE,
        "python",
        "-c",
        "import pathlib,os,stat; p=pathlib.Path('/run/material'); "
        "assert {v.name for v in p.iterdir()} == {'postgres-ca.pem'}; "
        "assert p.stat().st_uid == os.getuid(); "
        "assert stat.S_IMODE(p.stat().st_mode) == 0o700; "
        "c=p/'postgres-ca.pem'; assert c.stat().st_uid == os.getuid(); "
        "assert stat.S_IMODE(c.stat().st_mode) == 0o400; "
        "assert c.read_text().startswith('-----BEGIN CERTIFICATE-----')",
        check=False,
    )
    assert inspected.returncode == 0, inspected.stderr


def test_init_failure_blocks_modeled_service_start_without_exposing_secret(stack, monkeypatch):
    name = stack.name("failed-init")
    initialized, _ = stack.initialize("runtime", name, invalid=True)
    assert initialized.returncode == 1
    assert initialized.stdout == ""
    assert initialized.stderr == "Service volume initialization failed\n"
    monkeypatch.setattr(stack, "initialize", lambda *args: (initialized, []))
    with pytest.raises(AssertionError, match="Service volume initialization failed"):
        stack.run(images.RUNTIME_IMAGE, name, {}, [], detach=True)
    # No service is launched on failure. This verifies the local ordering guard,
    # not a real ECS scheduler's dependsOn implementation.
    assert images.docker("inspect", name, check=False).returncode != 0


def test_same_named_volume_cannot_alias_readonly_material_and_writable_scratch(stack):
    material = stack.volume("aliased-material")
    work = stack.volume("aliased-work")
    payload = {
        key: (stack.trust / key).read_text() for key in ("runtime-ca.pem", "postgres-ca.pem")
    }
    mounts = []
    for volume, target in (
        (material, "/run/material"),
        (material, "/tmp"),
        (work, "/var/lib/sentrysearch"),
    ):
        mounts += ["--mount", f"type=volume,source={volume},target={target},volume-nocopy"]
    result = images.docker(
        "run",
        "--rm",
        "-i",
        "--network",
        stack.network,
        "--user",
        "0:0",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--cap-add",
        "CHOWN",
        *mounts,
        images.SEARCH_IMAGE,
        "python",
        "-m",
        "dev.prepare_service_volumes",
        "--profile",
        "search",
        "--material-dir",
        "/run/material",
        "--tmp-dir",
        "/tmp",
        "--work-dir",
        "/var/lib/sentrysearch",
        "--fixture-stdin",
        stdin=json.dumps(payload),
        check=False,
    )
    assert result.returncode == 1 and result.stdout == ""
    assert result.stderr == "Service volume initialization failed\n"


def test_runtime_probes_read_uid65532_private_files_from_named_volume(stack):
    runtime = next(name for name, role in stack.hostnames.items() if role == "runtime")
    config = json.loads(images.docker("inspect", runtime).stdout)[0]
    assert config["Config"]["User"] == "65532:65532"
    assert config["HostConfig"]["ReadonlyRootfs"] and not config["HostConfig"].get("Tmpfs")
    material = next(mount for mount in config["Mounts"] if mount["Destination"] == "/run/material")
    assert material["Type"] == "volume" and not material["RW"]
    for route in ("healthz", "readyz"):
        result = images.docker(
            "exec",
            "-e",
            "SENTRYRUNTIME_PROBE_ADDRESS=127.0.0.1:8443",
            "-e",
            "SENTRYRUNTIME_PROBE_SERVER_NAME=runtime",
            "-e",
            "SENTRYRUNTIME_PROBE_CA_FILE=/run/material/runtime-ca.pem",
            "-e",
            "SENTRYRUNTIME_PROBE_TOKEN_FILE=/run/material/probe-token",
            runtime,
            "/app/probe",
            route,
        )
        assert result.returncode == 0, result.stderr
        stack.assert_no_secrets(result.stdout + result.stderr)


def test_api_readiness_and_graceful_stop_on_named_volumes(stack):
    images.test_api_serves_readiness_and_stops_gracefully_on_sigterm(stack)


def test_worker_live_ready_and_clean_drain_on_named_volumes(stack):
    worker = stack.name("health-worker")
    stack.run(images.SEARCH_IMAGE, worker, stack.worker_env(), images.FAST_WORKER, detach=True)
    images.wait_for(
        "worker readiness",
        lambda: images.local_probe(worker, "/readyz")[0] == 200,
        container=worker,
    )
    assert images.local_probe(worker, "/healthz")[0] == 200
    inspected = json.loads(images.docker("inspect", worker).stdout)[0]
    assert not inspected["HostConfig"].get("Tmpfs")
    assert inspected["HostConfig"]["ReadonlyRootfs"]
    mounts = {item["Destination"]: item for item in inspected["Mounts"]}
    for path in ("/run/material", "/tmp", "/var/lib/sentrysearch"):
        assert mounts[path]["Type"] == "volume"
    assert not mounts["/run/material"]["RW"]
    assert mounts["/tmp"]["RW"] and mounts["/var/lib/sentrysearch"]["RW"]
    assert images.stop(worker)[0] == 0


def test_busy_worker_drain_and_restart_recover_on_named_volumes(stack):
    images.test_busy_worker_drain_deadline_kills_child_and_restart_recovers_lease(stack)
