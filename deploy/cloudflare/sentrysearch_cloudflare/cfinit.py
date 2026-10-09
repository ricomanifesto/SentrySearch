"""Start a SentrySearch process in a Cloudflare container with AWS-equivalent privilege.

A Cloudflare Durable Object container runs one image with no init container or
secret volume, and under the ``durable_object`` scheduling policy every process
in a deployed container starts with root-equivalent Linux capabilities. The AWS
deployment instead prepares file material in a separate root initializer and
runs services as non-root users with no capabilities. This module restores that
boundary in two phases inside the one container:

``start`` (root, the image entrypoint) validates the profile and its fixed
command, writes the profile's material from ``CFINIT_MATERIAL`` after checking
it against ``CFINIT_MATERIAL_SHA256`` (using ``prepare_service_volumes``, the
same validation and fresh-directory rules as the AWS initializer), removes every
``CFINIT_`` variable and executes util-linux ``setpriv`` to clear supplementary
groups, the inheritable, ambient and bounding capability sets, switch to the
profile's user and set ``no_new_privs``.

``setpriv`` also loads a seccomp filter refusing new user namespaces: inside
one, even a fully dropped process regains every capability (scoped to that
namespace), which a container granted ``SYS_ADMIN`` would otherwise allow.

``continue`` (after the drop) refuses unless the kernel reports every capability
set empty, ``NoNewPrivs`` set, exactly one seccomp filter more than the root
phase saw (Docker's default profile is a filter too, so filter mode alone proves
nothing) and exactly the profile's identity, then executes the command. ``probe`` and ``continue-probe`` do the same for a fixed readiness
probe with a minimal environment and no material: a platform ``exec()`` is a new
process that does not inherit the main process's drop.

Errors never include material, values or paths.
"""

from __future__ import annotations

from dataclasses import dataclass
import importlib
import os
from pathlib import Path
import platform
import re
import struct
import sys
from types import ModuleType
from typing import Callable, Mapping, NoReturn, Sequence


def _materializer() -> ModuleType:
    # The service image ships it as dev.prepare_service_volumes; the
    # release-tools image ships a copy inside this package.
    try:
        return importlib.import_module("dev.prepare_service_volumes")
    except ImportError:
        return importlib.import_module(f"{__package__}.prepare_service_volumes")


volumes = _materializer()

EXIT_USAGE = 64
EXIT_PRIVILEGE = 77
EXIT_CONFIG = 78
EXIT_EXEC = 126

SETPRIV = "/usr/bin/setpriv"
VARIABLE_PREFIX = "CFINIT_"
MATERIAL = Path("/run/material")

SERVICE_PYTHON = "/app/.venv/bin/python"
RELEASE_PYTHON = ("/usr/local/bin/python3.11", "-I", "-B", "-m", "release_tools")
RELEASE_JOBS = ("bootstrap", "grant", "proof", "reconcile")


@dataclass(frozen=True)
class Profile:
    uid: int
    tmp: Path | None
    work: Path | None
    commands: tuple[tuple[str, ...], ...]
    probes: tuple[tuple[str, ...], ...] = ()


PROFILES = {
    # API and worker in the service image (runtime and PostgreSQL CA material).
    "search": Profile(
        uid=10001,
        tmp=Path("/run/tmp"),
        work=Path("/run/work"),
        commands=(
            (SERVICE_PYTHON, "/app/run_api.py"),
            (SERVICE_PYTHON, "-m", "dev.run_runtime_worker", "--health-port", "8081"),
        ),
        probes=((SERVICE_PYTHON, "-m", "dev.check_worker_readiness"),),
    ),
    # Product database jobs: the service image's migration roles and the
    # release-tools image's product jobs (PostgreSQL CA material only).
    "search-release": Profile(
        uid=10001,
        tmp=None,
        work=None,
        commands=(
            (SERVICE_PYTHON, "-m", "dev.migrate_storage"),
            (SERVICE_PYTHON, "-m", "dev.migrate_storage", "--check"),
            *((*RELEASE_PYTHON, job) for job in RELEASE_JOBS),
        ),
    ),
    # Runtime database jobs in the release-tools image.
    "runtime-release": Profile(
        uid=65532,
        tmp=None,
        work=None,
        commands=tuple((*RELEASE_PYTHON, job) for job in RELEASE_JOBS),
    ),
}

# A probe receives only what the interpreter needs to import the probe module.
PROBE_VARIABLES = (
    "PATH",
    "PYTHONPATH",
    "PYTHONSAFEPATH",
    "PYTHONDONTWRITEBYTECODE",
    "PYTHON_DOTENV_DISABLED",
)


class Refused(Exception):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass
class System:
    """The process effects, replaceable in tests."""

    geteuid: Callable[[], int] = os.geteuid
    read_status: Callable[[], str] = lambda: Path("/proc/self/status").read_text()
    machine: Callable[[], str] = platform.machine
    seccomp_path: Callable[[bytes], str] = lambda program: _inherited_memfd(program)
    close_filter_files: Callable[[], None] = lambda: _close_filter_files()
    prepare: Callable[..., None] = volumes.prepare
    chdir: Callable[[Path], None] = os.chdir
    execve: Callable[..., NoReturn] = os.execve


FILTERS = re.compile(r"[0-9]{1,4}|unknown")


def _parse(argv: Sequence[str]) -> tuple[str, str, Profile, str | None, tuple[str, ...]]:
    """``start|probe --profile NAME -- COMMAND`` or, after the drop,
    ``continue|continue-probe --profile NAME --filters COUNT -- COMMAND``."""
    usage = Refused(
        EXIT_USAGE,
        "usage: cfinit start|probe --profile NAME -- COMMAND "
        "(continue|continue-probe also take --filters COUNT)",
    )
    if len(argv) < 4 or argv[1] != "--profile":
        raise usage
    mode, name = argv[0], argv[2]
    filters = None
    rest = list(argv[3:])
    if mode in {"continue", "continue-probe"}:
        if len(rest) < 3 or rest[0] != "--filters" or not FILTERS.fullmatch(rest[1]):
            raise usage
        filters, rest = rest[1], rest[2:]
    if len(rest) < 2 or rest[0] != "--":
        raise usage
    command = tuple(rest[1:])
    profile = PROFILES.get(name)
    if profile is None or mode not in {"start", "continue", "probe", "continue-probe"}:
        raise Refused(EXIT_USAGE, "unknown mode or profile")
    allowed = profile.probes if mode in {"probe", "continue-probe"} else profile.commands
    if command not in allowed:
        raise Refused(EXIT_USAGE, "command is not permitted")
    return mode, name, profile, filters, command


def _check_settings(environ: Mapping[str, str]) -> None:
    for name in environ:
        if name.startswith(VARIABLE_PREFIX) and name not in {
            volumes.MATERIAL_VARIABLE,
            volumes.DIGEST_VARIABLE,
        }:
            raise Refused(EXIT_CONFIG, f"unexpected {VARIABLE_PREFIX} setting")


CLONE_NEWUSER = 0x10000000
# (audit arch, unshare, clone, clone3) per machine; same program as sentryruntime's cfinit.
SYSCALLS = {"x86_64": (0xC000003E, 272, 56, 435), "aarch64": (0xC00000B7, 97, 220, 435)}


def namespace_filter(machine: str) -> bytes:
    """A seccomp program (struct sock_filter array) refusing new user namespaces.

    unshare and clone with CLONE_NEWUSER fail with EPERM; clone3, whose flags
    sit behind a pointer, fails with ENOSYS so libc falls back to clone.
    Another architecture, or the x32 ABI, kills the process.
    """
    if machine not in SYSCALLS:
        raise Refused(EXIT_PRIVILEGE, "no namespace filter for this architecture")
    arch, unshare, clone, clone3 = SYSCALLS[machine]
    load, equal, at_least, has_bit, ret = 0x20, 0x15, 0x35, 0x45, 0x06
    kill, allow, eperm, enosys = 0x80000000, 0x7FFF0000, 0x00050001, 0x00050026
    program = [(load, 0, 0, 4), (equal, 1, 0, arch), (ret, 0, 0, kill), (load, 0, 0, 0)]
    if machine == "x86_64":
        program += [(at_least, 0, 1, 0x40000000), (ret, 0, 0, kill)]
    program += [
        (equal, 0, 1, clone3),
        (ret, 0, 0, enosys),
        (equal, 2, 0, unshare),
        (equal, 1, 0, clone),
        (ret, 0, 0, allow),
        (load, 0, 0, 16),
        (has_bit, 0, 1, CLONE_NEWUSER),
        (ret, 0, 0, eperm),
        (ret, 0, 0, allow),
    ]
    return b"".join(struct.pack("=HBBI", *instruction) for instruction in program)


def _setpriv(
    uid: int,
    filter_path: str,
    python: Sequence[str],
    mode: str,
    name: str,
    filters: str,
    command: Sequence[str],
) -> list[str]:
    return [
        SETPRIV,
        f"--reuid={uid}",
        f"--regid={uid}",
        "--clear-groups",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--bounding-set=-all",
        "--no-new-privs",
        f"--seccomp-filter={filter_path}",
        "--",
        *python,
        "-m",
        "sentrysearch_cloudflare.cfinit",
        mode,
        "--profile",
        name,
        "--filters",
        filters,
        "--",
        *command,
    ]


def _interpreter() -> list[str]:
    """Re-run this module with the interpreter and isolation it was started with."""
    flags = [
        flag
        for flag, on in (
            ("-I", sys.flags.isolated),
            ("-P", sys.flags.safe_path and not sys.flags.isolated),
            ("-B", sys.flags.dont_write_bytecode),
        )
        if on
    ]
    return [sys.executable, *flags]


FILTER_FILE = "cfinit-seccomp"


def _inherited_memfd(program: bytes) -> str:
    """Hand setpriv the filter through an inherited memory file; nothing is written to disk."""
    if sys.platform != "linux":
        raise Refused(EXIT_PRIVILEGE, "seccomp requires Linux")
    descriptor = os.memfd_create(FILTER_FILE, 0)
    os.write(descriptor, program)
    os.lseek(descriptor, 0, os.SEEK_SET)
    os.set_inheritable(descriptor, True)
    return f"/proc/self/fd/{descriptor}"


def _fields(status: str) -> dict[str, str]:
    fields = {}
    for line in status.splitlines():
        key, _, value = line.partition(":")
        fields[key] = " ".join(value.split())
    return fields


def _expected_filters(status: str) -> str:
    """setpriv adds exactly one filter to those this process already has."""
    count = _fields(status).get("Seccomp_filters")
    if count is None:
        return "unknown"  # a kernel that does not report the count
    if not count.isdigit():
        raise Refused(EXIT_PRIVILEGE, "unreadable seccomp state")
    return str(int(count) + 1)


def _close_filter_files() -> None:
    """The filter's memory file reaches the dropped phase through setpriv; the service never gets it."""
    for name in os.listdir("/proc/self/fd"):
        try:
            target = os.readlink(f"/proc/self/fd/{name}")
        except OSError:
            continue  # the listing's own descriptor, already closed
        if target.startswith(f"/memfd:{FILTER_FILE}"):
            os.close(int(name))


def verify_dropped(status: str, uid: int, filters: str) -> None:
    """Refuse unless the kernel's view matches a fully dropped service process."""
    fields = _fields(status)
    if fields.get("Seccomp_filters", "unknown") != filters:
        raise Refused(EXIT_PRIVILEGE, "namespace filter not installed")
    for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        if fields.get(name) != "0000000000000000":
            raise Refused(EXIT_PRIVILEGE, f"capability set not empty: {name}")
    identity = " ".join([str(uid)] * 4)
    if (
        fields.get("NoNewPrivs") != "1"
        or fields.get("Seccomp") != "2"
        or fields.get("Uid") != identity
        or fields.get("Gid") != identity
        or fields.get("Groups") != ""
    ):
        raise Refused(EXIT_PRIVILEGE, "process identity not dropped")


def run(argv: Sequence[str], environ: Mapping[str, str], system: System) -> int:
    try:
        mode, name, profile, filters, command = _parse(argv)
        _check_settings(environ)
        if mode in {"start", "probe"}:
            if system.geteuid() != 0:
                raise Refused(EXIT_PRIVILEGE, "must start as root to drop privileges")
            if mode == "start":
                try:
                    payload = volumes.payload_from_environment(environ)
                    system.prepare(name, payload, MATERIAL, profile.tmp, profile.work)
                except Exception:
                    raise Refused(EXIT_CONFIG, "material was rejected") from None
                env = {
                    key: value
                    for key, value in environ.items()
                    if not key.startswith(VARIABLE_PREFIX)
                }
                follow = "continue"
            else:
                if volumes.MATERIAL_VARIABLE in environ:
                    raise Refused(EXIT_CONFIG, "probe must not receive material")
                env = {key: environ[key] for key in PROBE_VARIABLES if key in environ}
                follow = "continue-probe"
            program = namespace_filter(system.machine())
            target = _setpriv(
                profile.uid,
                system.seccomp_path(program),
                _interpreter(),
                follow,
                name,
                _expected_filters(system.read_status()),
                command,
            )
        else:
            verify_dropped(system.read_status(), profile.uid, filters or "")
            system.close_filter_files()
            if volumes.MATERIAL_VARIABLE in environ or volumes.DIGEST_VARIABLE in environ:
                raise Refused(EXIT_CONFIG, "material reached the dropped process")
            env = dict(environ)
            if mode == "continue" and profile.tmp is not None and profile.work is not None:
                env["TMPDIR"] = str(profile.tmp)
                system.chdir(profile.work)
            target = list(command)
    except Refused as refusal:
        print(f"cfinit: {refusal}", file=sys.stderr)
        return refusal.code
    try:
        system.execve(target[0], target, env)
    except OSError:
        print("cfinit: command could not be executed", file=sys.stderr)
        return EXIT_EXEC
    return 0  # pragma: no cover - execve does not return


def main() -> None:
    raise SystemExit(run(sys.argv[1:], dict(os.environ), System()))


if __name__ == "__main__":
    main()
