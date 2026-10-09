"""Prove the Search Cloudflare entrypoint's privilege drop in real containers.

Builds a small test image on the pinned Python base the service image takes its
interpreter and util-linux ``setpriv`` from, adds the real
``sentrysearch_cloudflare`` package and ``dev/prepare_service_volumes.py``, and
puts an observer at the allowlisted ``/app/run_api.py`` path (with
``/app/.venv/bin/python`` linked to the base interpreter), so no test-only path
exists in the entrypoint. Each case runs with no container network, as root
with every capability added or Docker's defaults, through the image's two-phase
start. The base image must already be present: this check never pulls.

Usage: .venv/bin/python deploy/cloudflare/harness/check_entrypoint.py --evidence out.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Any

REPO = Path(__file__).resolve().parents[3]
BASE = "docker.io/library/python@sha256:0dd364ba7e10242f07755449e3a3d0e35f9efd987952737b90def6709ab0c5ce"
ENTRY = ["/usr/local/bin/python", "-m", "sentrysearch_cloudflare.cfinit"]
API = ["/app/.venv/bin/python", "/app/run_api.py"]
OBSERVER = r"""
import json, os, pathlib, stat, subprocess, sys
fields = {}
for line in pathlib.Path("/proc/self/status").read_text().splitlines():
    key, _, value = line.partition(":")
    if key in {"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs", "Uid", "Gid", "Groups"}:
        fields[key] = " ".join(value.split())
def attempt(action):
    try:
        action()
        return "succeeded"
    except Exception as error:
        return type(error).__name__
regain = {
    "setuid0": attempt(lambda: os.setuid(0)),
    "setgid0": attempt(lambda: os.setgid(0)),
    "setgroups0": attempt(lambda: os.setgroups([0])),
    "read_root_only": attempt(lambda: open("/etc/shadow").read()),
    "write_app": attempt(lambda: open("/app/owned", "w").write("x")),
}
setuid_euid = subprocess.run(["/app/regain", "-c", "import os; print(os.geteuid())"], capture_output=True, text=True).stdout.strip()
material = {}
root = pathlib.Path("/run/material")
for path in sorted(root.iterdir()) if root.exists() else []:
    info = path.lstat()
    material[path.name] = [oct(stat.S_IMODE(info.st_mode)), info.st_uid, info.st_gid]
root_info = root.stat()
child = subprocess.run([sys.executable, "-c", "print(open('/proc/self/status').read())"], capture_output=True, text=True).stdout
child_fields = {line.split(":")[0]: " ".join(line.split(":", 1)[1].split()) for line in child.splitlines() if ":" in line}
print(json.dumps({
    "status": fields,
    "child_status": {k: child_fields.get(k) for k in ("CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs", "Uid")},
    "regain": regain,
    "setuid_binary_euid": setuid_euid,
    "material": material,
    "material_dir": [oct(stat.S_IMODE(root_info.st_mode)), root_info.st_uid],
    "env_names": sorted(os.environ),
    "cwd": os.getcwd(),
    "tmpdir": os.environ.get("TMPDIR"),
}))
"""


def docker(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=check)


def build(work: Path) -> str:
    if docker("image", "inspect", BASE, check=False).returncode != 0:
        raise SystemExit("pinned Python base image is not present locally; this check never pulls")
    shutil.copytree(
        REPO / "deploy" / "cloudflare" / "sentrysearch_cloudflare", work / "sentrysearch_cloudflare"
    )
    (work / "dev").mkdir()
    shutil.copy(
        REPO / "dev" / "prepare_service_volumes.py", work / "dev" / "prepare_service_volumes.py"
    )
    (work / "dev" / "__init__.py").write_text("")
    (work / "run_api.py").write_text(OBSERVER)
    (work / "Dockerfile").write_text(
        f"FROM {BASE}\n"
        "COPY sentrysearch_cloudflare /app/sentrysearch_cloudflare\n"
        "COPY dev /app/dev\n"
        "COPY run_api.py /app/run_api.py\n"
        "RUN --network=none set -eu; mkdir -p /app/.venv/bin /run/material /run/tmp /run/work; "
        "ln -s /usr/local/bin/python /app/.venv/bin/python; "
        "cp /usr/local/bin/python3.11 /app/regain; chmod 4755 /app/regain; "
        "groupadd --system --gid 10001 sentrysearch; "
        "useradd --system --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent sentrysearch\n"
        "ENV PYTHONPATH=/app PYTHONSAFEPATH=1 PYTHONDONTWRITEBYTECODE=1\n"
    )
    tag = (
        "sentrysearch-cfinit-check:"
        + hashlib.sha256((work / "Dockerfile").read_bytes()).hexdigest()[:12]
    )
    docker("build", "--pull=false", "--tag", tag, str(work))
    return tag


def material() -> tuple[str, str]:
    sys.path.insert(0, str(REPO))
    from dev.tls_fixtures import create_certificates

    with tempfile.TemporaryDirectory() as directory:
        certs = create_certificates(Path(directory), hostname="runtime.test")
        payload = json.dumps(
            {"runtime-ca.pem": certs.ca.read_text(), "postgres-ca.pem": certs.ca.read_text()}
        )
    return payload, hashlib.sha256(payload.encode()).hexdigest()


def run(tag: str, *flags: str, env: dict[str, str], command: list[str]) -> tuple[int, str, str]:
    arguments = ["run", "--rm", "--network", "none", "--user", "0:0", *flags]
    for key, value in env.items():
        arguments += ["-e", f"{key}={value}"]
    result = docker(*arguments, tag, *command, check=False)
    return result.returncode, result.stdout, result.stderr


def dropped(report: dict) -> list[str]:
    problems = []
    for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        if report["status"].get(key) != "0000000000000000":
            problems.append(f"{key}={report['status'].get(key)}")
    for key in ("CapPrm", "CapEff", "CapBnd", "CapAmb"):
        if report["child_status"].get(key) != "0000000000000000":
            problems.append(f"child {key}={report['child_status'].get(key)}")
    if report["status"].get("NoNewPrivs") != "1" or report["child_status"].get("NoNewPrivs") != "1":
        problems.append("no_new_privs not set")
    if (
        report["status"].get("Uid") != "10001 10001 10001 10001"
        or report["status"].get("Groups") != ""
    ):
        problems.append(
            f"identity {report['status'].get('Uid')} groups {report['status'].get('Groups')!r}"
        )
    problems += [f"regained via {k}" for k, v in report["regain"].items() if v == "succeeded"]
    if report["setuid_binary_euid"] != "10001":
        problems.append(f"setuid binary euid {report['setuid_binary_euid']}")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True)
    args = parser.parse_args()
    payload, digest = material()
    good = {"CFINIT_MATERIAL": payload, "CFINIT_MATERIAL_SHA256": digest, "DB_HOST": "db"}
    results: dict[str, Any] = {}
    with tempfile.TemporaryDirectory() as directory:
        tag = build(Path(directory))
    results["image"] = {
        "tag": tag,
        "id": docker("image", "inspect", "--format", "{{.Id}}", tag).stdout.strip(),
    }
    start = [*ENTRY, "start", "--profile", "search", "--", *API]
    for name, flags in (("cap_add_all", ["--cap-add", "ALL"]), ("docker_defaults", [])):
        code, out, err = run(tag, *flags, env=good, command=start)
        report = json.loads(out) if code == 0 else {}
        problems = dropped(report) if report else [f"exit {code}: {err[-300:]}"]
        if report:
            if report["material"] != {
                "postgres-ca.pem": ["0o400", 10001, 10001],
                "runtime-ca.pem": ["0o400", 10001, 10001],
            } or report["material_dir"] != ["0o700", 10001]:
                problems.append(f"material {report['material']} dir {report['material_dir']}")
            if (
                any(n.startswith("CFINIT_") for n in report["env_names"])
                or "DB_HOST" not in report["env_names"]
            ):
                problems.append("environment not scrubbed or not passed")
            if report["cwd"] != "/run/work" or report["tmpdir"] != "/run/tmp":
                problems.append(f"cwd {report['cwd']} tmpdir {report['tmpdir']}")
        results[name] = {"passed": not problems, "problems": problems, "report": report}
    refusals = {
        "non_root": (["--user", "10001:10001"], good, start, 77),
        "wrong_digest": ([], {**good, "CFINIT_MATERIAL_SHA256": "0" * 64}, start, 78),
        "unknown_setting": ([], {**good, "CFINIT_UID": "0"}, start, 78),
        "unlisted_command": (
            [],
            good,
            [*ENTRY, "start", "--profile", "search", "--", "/bin/sh"],
            64,
        ),
        "continue_as_root": ([], {}, [*ENTRY, "continue", "--profile", "search", "--", *API], 77),
    }
    for name, (flags, env, command, expected) in refusals.items():
        code, out, err = run(tag, *flags, env=env, command=command)
        results[name] = {
            "passed": code == expected and out == "",
            "exit": code,
            "stderr": err.strip()[-200:],
        }
    docker("rmi", tag, check=False)
    results["passed"] = all(v.get("passed") for k, v in results.items() if k != "image")
    Path(args.evidence).write_text(json.dumps(results, indent=2))
    for name, result in results.items():
        if isinstance(result, dict) and "passed" in result:
            print(
                f"{name}: {'passed' if result['passed'] else 'FAILED ' + str(result.get('problems') or result)}"
            )
    return 0 if results["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
