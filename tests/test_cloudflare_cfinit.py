"""The Cloudflare entrypoint's two phases, with the process effects replaced."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
from pathlib import Path
import sys

import pytest

from dev.tls_fixtures import create_certificates

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "deploy" / "cloudflare"))
cfinit = importlib.import_module("sentrysearch_cloudflare.cfinit")
REPO_ROOT = Path(__file__).resolve().parents[1]

API = ("/app/.venv/bin/python", "/app/run_api.py")
WORKER = ("/app/.venv/bin/python", "-m", "dev.run_runtime_worker", "--health-port", "8081")
PROBE = ("/app/.venv/bin/python", "-m", "dev.check_worker_readiness")
DROPPED_10001 = """Name:\tpython
Uid:\t10001\t10001\t10001\t10001
Gid:\t10001\t10001\t10001\t10001
Groups:\t
NoNewPrivs:\t1
Seccomp:\t2
Seccomp_filters:\t2
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
        self.filters: list[bytes] = []
        self.closed_filter_files = 0

    def close_filter_files(self) -> None:
        self.closed_filter_files += 1

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

        def seccomp_path(program: bytes) -> str:
            self.filters.append(program)
            return "/proc/self/fd/9"

        return cfinit.System(
            machine=lambda: "x86_64",
            seccomp_path=seccomp_path,
            home=lambda uid: {10001: "/nonexistent", 65532: "/home/nonroot"}[uid],
            close_filter_files=self.close_filter_files,
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
        "--seccomp-filter=/proc/self/fd/9",
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
    assert argv[:10] == setpriv_prefix(10001)
    assert argv[10:] == [
        *cfinit._interpreter(),
        "-m",
        "sentrysearch_cloudflare.cfinit",
        "continue",
        "--profile",
        "search",
        "--filters",
        "3",
        "--",
        *API,
    ]
    assert env == {"DB_HOST": "db", "PYTHONPATH": "/app", "HOME": "/nonexistent"}


def test_continue_requires_the_kernel_to_report_a_full_drop():
    fake = FakeSystem()
    environ = {"DB_HOST": "db"}
    assert (
        invoke(fake, ["continue", "--profile", "search", "--filters", "2", "--", *WORKER], environ)
        == "executed"
    )
    assert fake.executed == (WORKER[0], list(WORKER), {"DB_HOST": "db", "TMPDIR": "/run/tmp"})
    assert fake.chdirs == [Path("/run/work")]
    assert fake.closed_filter_files == 1


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
        ("Seccomp:\t2", "Seccomp:\t0"),
        ("Seccomp_filters:\t2", "Seccomp_filters:\t1"),
        ("Seccomp_filters:\t2", "Seccomp_filters:\t3"),
        ("Seccomp_filters:\t2\n", ""),
    ],
)
def test_continue_refuses_any_remaining_privilege(line, replacement):
    fake = FakeSystem(status=DROPPED_10001.replace(line, replacement))
    assert (
        invoke(fake, ["continue", "--profile", "search", "--filters", "2", "--", *API], {})
        == cfinit.EXIT_PRIVILEGE
    )
    assert fake.executed is None and fake.chdirs == []


def test_continue_refuses_the_wrong_identity_for_the_profile():
    fake = FakeSystem()
    argv = [
        "continue",
        "--profile",
        "runtime-release",
        "--filters",
        "2",
        "--",
        *cfinit.RELEASE_PYTHON,
        "grant",
    ]
    assert invoke(fake, argv, {}) == cfinit.EXIT_PRIVILEGE


def test_probe_drops_with_a_minimal_environment_and_no_material():
    fake = FakeSystem()
    environ = {"PYTHONPATH": "/app", "DB_PASSWORD": "secret", "PATH": "/app/.venv/bin"}
    assert invoke(fake, ["probe", "--profile", "search", "--", *PROBE], environ) == "executed"
    path, argv, env = executed(fake)
    assert argv[:10] == setpriv_prefix(10001) and "continue-probe" in argv
    assert env == {"PYTHONPATH": "/app", "PATH": "/app/.venv/bin", "HOME": "/nonexistent"}
    assert fake.prepared == []
    fake = FakeSystem()
    assert (
        invoke(
            fake,
            ["continue-probe", "--profile", "search", "--filters", "2", "--", *PROBE],
            {"PATH": "/x"},
        )
        == "executed"
    )
    assert fake.executed == (PROBE[0], list(PROBE), {"PATH": "/x"}) and fake.chdirs == []


def test_release_profiles_select_their_own_identity(material):
    for profile, uid in (("search-release", 10001), ("runtime-release", 65532)):
        fake = FakeSystem()
        argv = ["start", "--profile", profile, "--", *cfinit.RELEASE_PYTHON, "proof"]
        assert invoke(fake, argv, material) == "executed"
        assert executed(fake)[1][:10] == setpriv_prefix(uid)
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
        invoke(leaked, ["continue", "--profile", "search", "--filters", "2", "--", *API], material)
        == cfinit.EXIT_CONFIG
    )
    output = capsys.readouterr()
    assert "BEGIN" not in output.err and "bad pem" not in output.err and output.out == ""


def test_exec_failure_is_reported_without_details():
    fake = FakeSystem(exec_error=FileNotFoundError("/app/run_api.py"))
    assert (
        invoke(fake, ["continue", "--profile", "search", "--filters", "2", "--", *API], {})
        == cfinit.EXIT_EXEC
    )


def run_filter(program: bytes, arch: int, nr: int, flags: int) -> int:
    """Evaluate a classic BPF seccomp program for one call (seccomp_data layout)."""
    import struct

    data = struct.pack("<iIQQ", nr, arch, 0, flags) + bytes(40)
    instructions = [struct.unpack("=HBBI", program[i : i + 8]) for i in range(0, len(program), 8)]
    accumulator, pc = 0, 0
    while pc < len(instructions):
        code, jt, jf, k = instructions[pc]
        if code == 0x20:
            accumulator = struct.unpack_from("<I", data, k)[0]
        elif code in (0x15, 0x35, 0x45):
            taken = (
                (code == 0x15 and accumulator == k)
                or (code == 0x35 and accumulator >= k)
                or (code == 0x45 and accumulator & k)
            )
            pc += jt if taken else jf
        elif code == 0x06:
            return k
        pc += 1
    raise AssertionError("program fell off the end")


@pytest.mark.parametrize(
    "machine,arch,unshare,clone",
    [("x86_64", 0xC000003E, 272, 56), ("aarch64", 0xC00000B7, 97, 220)],
)
def test_namespace_filter_refuses_only_new_user_namespaces(machine, arch, unshare, clone):
    program = cfinit.namespace_filter(machine)
    allow, eperm, enosys, kill = 0x7FFF0000, 0x00050001, 0x00050026, 0x80000000
    assert run_filter(program, arch, unshare, cfinit.CLONE_NEWUSER) == eperm
    assert run_filter(program, arch, clone, cfinit.CLONE_NEWUSER | 0x11) == eperm
    assert run_filter(program, arch, unshare, 0x00020000) == allow
    assert run_filter(program, arch, clone, 0x003D0F00) == allow
    assert run_filter(program, arch, 435, 0) == enosys
    assert run_filter(program, arch, 0, 0) == allow
    assert run_filter(program, 0x40000003, unshare, 0) == kill


def test_start_hands_setpriv_the_filter_for_this_machine(material):
    fake = FakeSystem()
    assert invoke(fake, ["start", "--profile", "search", "--", *API], material) == "executed"
    assert fake.filters == [cfinit.namespace_filter("x86_64")]
    with pytest.raises(cfinit.Refused):
        cfinit.namespace_filter("riscv64")


def test_continue_requires_the_filter_count_the_root_phase_expected():
    for argv in (
        ["continue", "--profile", "search", "--", *API],
        ["continue", "--profile", "search", "--filters", "-1", "--", *API],
        ["continue", "--profile", "search", "--filters", "", "--", *API],
        ["start", "--profile", "search", "--filters", "2", "--", *API],
    ):
        fake = FakeSystem()
        assert invoke(fake, argv, {}) == cfinit.EXIT_USAGE, argv
        assert fake.executed is None
    # A kernel without the count: both phases agree it is unknown, filter mode still required.
    without = DROPPED_10001.replace("Seccomp_filters:\t2\n", "")
    fake = FakeSystem(status=without)
    argv = ["continue", "--profile", "search", "--filters", "unknown", "--", *API]
    assert invoke(fake, argv, {}) == "executed"
    fake = FakeSystem(status=without.replace("Seccomp:\t2", "Seccomp:\t0"))
    assert invoke(fake, argv, {}) == cfinit.EXIT_PRIVILEGE


def test_start_expects_one_filter_more_than_it_has(material):
    fake = FakeSystem(status=DROPPED_10001.replace("Seccomp_filters:\t2", "Seccomp_filters:\t0"))
    assert invoke(fake, ["start", "--profile", "search", "--", *API], material) == "executed"
    argv = executed(fake)[1]
    assert argv[argv.index("--filters") + 1] == "1"
    fake = FakeSystem(status=DROPPED_10001.replace("Seccomp_filters:\t2\n", ""))
    assert invoke(fake, ["start", "--profile", "search", "--", *API], material) == "executed"
    argv = executed(fake)[1]
    assert argv[argv.index("--filters") + 1] == "unknown"


@pytest.mark.skipif(sys.platform != "linux", reason="memfd and /proc/self/fd are Linux")
def test_the_filter_file_is_closed_before_the_service_starts():
    path = cfinit._inherited_memfd(cfinit.namespace_filter("x86_64"))
    descriptor = int(path.rsplit("/", 1)[1])
    cfinit._close_filter_files()
    with pytest.raises(OSError):
        os.fstat(descriptor)


def test_every_root_phase_interpreter_ignores_the_working_directory():
    # The root phase runs before the drop with a writable working directory:
    # its interpreter must not put that directory (or a script's) on sys.path.
    worker = REPO_ROOT / "deploy" / "cloudflare" / "worker" / "src"
    for source in ("api.ts", "worker.ts"):
        text = (worker / source).read_text()
        assert 'PYTHON, "-P", "-m", "sentrysearch_cloudflare.cfinit"' in text, source
    assert (
        'const RELEASE_PYTHON = ["/usr/local/bin/python3.11", "-I", "-B", "-m"];'
        in (worker / "jobs.ts").read_text()
    )


def test_cloudflare_targets_leave_the_whole_command_to_the_durable_object():
    # start({entrypoint}) may replace or extend an image entrypoint; with none in
    # the image, the Durable Object's fixed argv (wrapper first) runs either way.
    for dockerfile in ("container/Dockerfile", "container/release-tools.Dockerfile"):
        stage = (REPO_ROOT / dockerfile).read_text().split(" AS cloudflare\n", 1)[1]
        stage = stage.split("\nFROM ", 1)[0]
        directives = [line for line in stage.splitlines() if line.startswith(("ENTRYPOINT", "CMD"))]
        assert directives == ["ENTRYPOINT []", "CMD []"], dockerfile
    worker = REPO_ROOT / "deploy" / "cloudflare" / "worker" / "src"
    for source, wrapper in (
        (
            "api.ts",
            '"/usr/local/bin/tini", "--", PYTHON, "-P", "-m", "sentrysearch_cloudflare.cfinit", "start"',
        ),
        (
            "worker.ts",
            '"/usr/local/bin/tini", "--", PYTHON, "-P", "-m", "sentrysearch_cloudflare.cfinit", "start"',
        ),
        ("runtime.ts", '["/app/cfinit", "run", "--", "/app/sentryruntime"]'),
        (
            "jobs.ts",
            '"/usr/local/bin/tini", "--", ...RELEASE_PYTHON, "sentrysearch_cloudflare.cfinit", "start"',
        ),
    ):
        assert wrapper in (worker / source).read_text(), source


def test_the_root_home_never_follows_the_service_user(material):
    # libpq reads ~/.postgresql/postgresql.crt and fails on anything but "absent";
    # /root is unreadable to the service user, so HOME must be the user's own.
    for profile, uid, home in (
        ("search", 10001, "/nonexistent"),
        ("runtime-release", 65532, "/home/nonroot"),
    ):
        fake = FakeSystem()
        command = API if profile == "search" else (*cfinit.RELEASE_PYTHON, "proof")
        argv = ["start", "--profile", profile, "--", *command]
        assert invoke(fake, argv, {**material, "HOME": "/root"}) == "executed"
        assert executed(fake)[2]["HOME"] == home, uid
