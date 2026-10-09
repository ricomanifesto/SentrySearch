"""The Cloudflare entrypoint's two phases, with the process effects replaced."""

from __future__ import annotations

import hashlib
import importlib
import json
from pathlib import Path
import sys

import pytest

from dev.tls_fixtures import create_certificates

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "deploy" / "cloudflare"))
cfinit = importlib.import_module("sentrysearch_cloudflare.cfinit")

API = ("/app/.venv/bin/python", "/app/run_api.py")
WORKER = ("/app/.venv/bin/python", "-m", "dev.run_runtime_worker", "--health-port", "8081")
PROBE = ("/app/.venv/bin/python", "-m", "dev.check_worker_readiness")
DROPPED_10001 = """Name:\tpython
Uid:\t10001\t10001\t10001\t10001
Gid:\t10001\t10001\t10001\t10001
Groups:\t
NoNewPrivs:\t1
CapInh:\t0000000000000000
CapPrm:\t0000000000000000
CapEff:\t0000000000000000
CapBnd:\t0000000000000000
CapAmb:\t0000000000000000
"""


class Executed(Exception):
    pass


class FakeSystem:
    def __init__(self, *, euid=0, status=DROPPED_10001, prepare_error=None, exec_error=None):
        self.euid, self.status = euid, status
        self.prepared: list[tuple] = []
        self.chdirs: list[Path] = []
        self.executed: tuple | None = None
        self.prepare_error, self.exec_error = prepare_error, exec_error

    def system(self) -> cfinit.System:
        def prepare(*args):
            if self.prepare_error:
                raise self.prepare_error
            self.prepared.append(args)

        def execve(path, argv, env):
            if self.exec_error:
                raise self.exec_error
            self.executed = (path, list(argv), dict(env))
            raise Executed()

        return cfinit.System(
            geteuid=lambda: self.euid,
            read_status=lambda: self.status,
            prepare=prepare,
            chdir=self.chdirs.append,
            execve=execve,
        )


@pytest.fixture
def material(tmp_path):
    certs = create_certificates(tmp_path / "certs", hostname="runtime.test")
    payload = json.dumps(
        {"runtime-ca.pem": certs.ca.read_text(), "postgres-ca.pem": certs.ca.read_text()}
    )
    return {
        "CFINIT_MATERIAL": payload,
        "CFINIT_MATERIAL_SHA256": hashlib.sha256(payload.encode()).hexdigest(),
    }


def executed(fake: FakeSystem) -> tuple:
    assert fake.executed is not None
    return fake.executed


def invoke(fake: FakeSystem, argv, environ):
    try:
        return cfinit.run(argv, environ, fake.system())
    except Executed:
        return "executed"


def setpriv_prefix(uid):
    return [
        "/usr/bin/setpriv",
        f"--reuid={uid}",
        f"--regid={uid}",
        "--clear-groups",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--bounding-set=-all",
        "--no-new-privs",
        "--",
    ]


def test_start_materializes_as_root_then_drops_through_setpriv(material):
    fake = FakeSystem()
    environ = {**material, "DB_HOST": "db", "PYTHONPATH": "/app"}
    assert invoke(fake, ["start", "--profile", "search", "--", *API], environ) == "executed"
    assert fake.prepared == [
        (
            "search",
            material["CFINIT_MATERIAL"],
            Path("/run/material"),
            Path("/run/tmp"),
            Path("/run/work"),
        )
    ]
    path, argv, env = executed(fake)
    assert path == "/usr/bin/setpriv"
    assert argv[:9] == setpriv_prefix(10001)
    assert argv[9:] == [
        *cfinit._interpreter(),
        "-m",
        "sentrysearch_cloudflare.cfinit",
        "continue",
        "--profile",
        "search",
        "--",
        *API,
    ]
    assert env == {"DB_HOST": "db", "PYTHONPATH": "/app"}


def test_continue_requires_the_kernel_to_report_a_full_drop():
    fake = FakeSystem()
    environ = {"DB_HOST": "db"}
    assert invoke(fake, ["continue", "--profile", "search", "--", *WORKER], environ) == "executed"
    assert fake.executed == (WORKER[0], list(WORKER), {"DB_HOST": "db", "TMPDIR": "/run/tmp"})
    assert fake.chdirs == [Path("/run/work")]


@pytest.mark.parametrize(
    "line,replacement",
    [
        ("CapInh:\t0000000000000000", "CapInh:\t0000000000000400"),
        ("CapPrm:\t0000000000000000", "CapPrm:\t0000000000000001"),
        ("CapEff:\t0000000000000000", "CapEff:\t0000000000000001"),
        ("CapBnd:\t0000000000000000", "CapBnd:\t000001ffffffffff"),
        ("CapAmb:\t0000000000000000", "CapAmb:\t0000000000002000"),
        ("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
        ("Uid:\t10001\t10001\t10001\t10001", "Uid:\t10001\t0\t10001\t10001"),
        ("Gid:\t10001\t10001\t10001\t10001", "Gid:\t10001\t10001\t10001\t0"),
        ("Groups:\t", "Groups:\t0"),
    ],
)
def test_continue_refuses_any_remaining_privilege(line, replacement):
    fake = FakeSystem(status=DROPPED_10001.replace(line, replacement))
    assert (
        invoke(fake, ["continue", "--profile", "search", "--", *API], {}) == cfinit.EXIT_PRIVILEGE
    )
    assert fake.executed is None and fake.chdirs == []


def test_continue_refuses_the_wrong_identity_for_the_profile():
    fake = FakeSystem()
    argv = ["continue", "--profile", "runtime-release", "--", *cfinit.RELEASE_PYTHON, "grant"]
    assert invoke(fake, argv, {}) == cfinit.EXIT_PRIVILEGE


def test_probe_drops_with_a_minimal_environment_and_no_material():
    fake = FakeSystem()
    environ = {"PYTHONPATH": "/app", "DB_PASSWORD": "secret", "PATH": "/app/.venv/bin"}
    assert invoke(fake, ["probe", "--profile", "search", "--", *PROBE], environ) == "executed"
    path, argv, env = executed(fake)
    assert argv[:9] == setpriv_prefix(10001) and "continue-probe" in argv
    assert env == {"PYTHONPATH": "/app", "PATH": "/app/.venv/bin"}
    assert fake.prepared == []
    fake = FakeSystem()
    assert (
        invoke(fake, ["continue-probe", "--profile", "search", "--", *PROBE], {"PATH": "/x"})
        == "executed"
    )
    assert fake.executed == (PROBE[0], list(PROBE), {"PATH": "/x"}) and fake.chdirs == []


def test_release_profiles_select_their_own_identity(material):
    for profile, uid in (("search-release", 10001), ("runtime-release", 65532)):
        fake = FakeSystem()
        argv = ["start", "--profile", profile, "--", *cfinit.RELEASE_PYTHON, "proof"]
        assert invoke(fake, argv, material) == "executed"
        assert executed(fake)[1][:9] == setpriv_prefix(uid)
        assert fake.prepared[0][2:] == (Path("/run/material"), None, None)


@pytest.mark.parametrize(
    "argv,code",
    [
        (["start", "--profile", "search", "--", "/bin/sh"], cfinit.EXIT_USAGE),
        (["start", "--profile", "search", "--", *API, "--reload"], cfinit.EXIT_USAGE),
        (["start", "--profile", "search", "--", *PROBE], cfinit.EXIT_USAGE),
        (["probe", "--profile", "search", "--", *API], cfinit.EXIT_USAGE),
        (["start", "--profile", "runtime-release", "--", *API], cfinit.EXIT_USAGE),
        (["start", "--profile", "admin", "--", *API], cfinit.EXIT_USAGE),
        (["shell", "--profile", "search", "--", *API], cfinit.EXIT_USAGE),
        (["start", "--profile", "search", *API], cfinit.EXIT_USAGE),
    ],
)
def test_unlisted_invocations_are_refused_before_any_effect(material, argv, code):
    fake = FakeSystem()
    assert invoke(fake, argv, material) == code
    assert fake.prepared == [] and fake.executed is None


def test_refusals_before_the_drop(material, capsys):
    cases = [
        (FakeSystem(euid=10001), material, cfinit.EXIT_PRIVILEGE),
        (FakeSystem(), {**material, "CFINIT_UID": "0"}, cfinit.EXIT_CONFIG),
        (FakeSystem(), {**material, "CFINIT_MATERIAL_SHA256": "0" * 64}, cfinit.EXIT_CONFIG),
        (FakeSystem(), {"CFINIT_MATERIAL": material["CFINIT_MATERIAL"]}, cfinit.EXIT_CONFIG),
        (FakeSystem(prepare_error=ValueError("bad pem")), material, cfinit.EXIT_CONFIG),
    ]
    for fake, environ, code in cases:
        assert invoke(fake, ["start", "--profile", "search", "--", *API], environ) == code
        assert fake.executed is None
    probe = FakeSystem()
    assert (
        invoke(probe, ["probe", "--profile", "search", "--", *PROBE], material)
        == cfinit.EXIT_CONFIG
    )
    leaked = FakeSystem()
    assert (
        invoke(leaked, ["continue", "--profile", "search", "--", *API], material)
        == cfinit.EXIT_CONFIG
    )
    output = capsys.readouterr()
    assert "BEGIN" not in output.err and "bad pem" not in output.err and output.out == ""


def test_exec_failure_is_reported_without_details():
    fake = FakeSystem(exec_error=FileNotFoundError("/app/run_api.py"))
    assert invoke(fake, ["continue", "--profile", "search", "--", *API], {}) == cfinit.EXIT_EXEC
