"""Build-time integrity and provenance for the temporary Debian backport.

No downloads occur here: APT authenticates the pinned snapshot indexes and source
chain before these additional content checks. Compilation runs without network.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

INPUTS = Path(__file__).resolve().parent
WORK = Path("/work")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_files(root: Path, expected: dict[str, str]) -> None:
    for name, sha256 in expected.items():
        if Path(name).name != name or name in {".", ".."}:
            raise ValueError("Pinned input must be a basename")
        path = root / name
        if path.is_symlink():
            raise ValueError(f"Pinned input must be a regular file: {name}")
        if digest(path) != sha256:
            raise ValueError(f"SHA-256 mismatch: {name}")


def run(*args: str, cwd: Path = WORK) -> str:
    # These commands handle public build inputs only. Keep diagnostics visible
    # on failure instead of hiding the reason inside CalledProcessError.
    result = subprocess.run(args, cwd=cwd, text=True, stdout=subprocess.PIPE)
    if result.returncode:
        print(result.stdout, file=sys.stderr)
        result.check_returncode()
    return result.stdout


def export_source_records(source: Path, output: Path) -> None:
    for pattern in ("*.dsc", "*.tar.xz", "*.tar.xz.asc", "*.buildinfo", "*.changes"):
        for path in source.glob(pattern):
            shutil.copy2(path, output / path.name)


def main() -> None:
    manifest = json.loads((INPUTS / "manifest.json").read_text())
    phase = sys.argv[1]
    source = WORK / "xz"
    if phase == "indexes":
        actual = sorted(digest(p) for p in Path("/var/lib/apt/lists").glob("*_InRelease"))
        if actual != sorted(manifest["snapshot_release_sha256"].values()):
            raise ValueError("APT Release inputs differ from the reviewed snapshots")
    elif phase == "prepare":
        verify_files(WORK, manifest["source_sha256"])
        verify_files(INPUTS, {p["file"]: p["sha256"] for p in manifest["patches"]})
        version = manifest["original_source_version"]
        run("dpkg-source", "-x", f"xz-utils_{version}.dsc", str(source))
        for patch in manifest["patches"]:
            with (INPUTS / patch["file"]).open() as stream:
                subprocess.run(
                    ["patch", "--batch", "--fuzz=0", "--no-backup-if-mismatch", "-p1"],
                    cwd=source,
                    stdin=stream,
                    check=True,
                )
        subprocess.run(
            ["dpkg-source", "--commit", ".", "sentry-decoder-reinit.patch"],
            cwd=source,
            env={**os.environ, "EDITOR": "true"},
            check=True,
        )
        changelog = source / "debian/changelog"
        changelog.write_text(
            f"xz-utils ({manifest['patched_version']}) UNRELEASED; urgency=high\n\n"
            "  * Local security backport, not an official Debian release.\n"
            "  * Backport GHSA-5qpq-xqfv-j9pg fixes fe4d763 and e5e63d5;\n"
            "    retain Debian patches and add upstream regression ff834f2.\n\n"
            " -- SentrySearch maintainers <noreply@example.invalid>  "
            "Tue, 06 Oct 2026 23:59:00 +0000\n\n" + changelog.read_text()
        )
        # Export before autoreconf/build rules alter generated source files.
        run("dpkg-source", "-b", ".", cwd=source)
    elif phase == "export":
        if os.environ.get("SOURCE_DATE_EPOCH") != str(manifest["source_date_epoch"]):
            raise ValueError("SOURCE_DATE_EPOCH differs from the pinned manifest")
        arch = run("dpkg", "--print-architecture").strip()
        package = WORK / f"liblzma5_{manifest['patched_version']}_{arch}.deb"
        if run("dpkg-deb", "-f", str(package), "Version").strip() != manifest["patched_version"]:
            raise ValueError("Unexpected backport package version")
        if run("dpkg-deb", "-f", str(package), "Architecture").strip() != arch:
            raise ValueError("Unexpected backport package architecture")
        output = Path("/out")
        output.mkdir()
        shutil.copy2(package, output / "liblzma5.deb")
        # Preserve exact source/build records independently of the minimal image.
        export_source_records(WORK, output)
        inventory = run("dpkg-query", "-W", "-f=${binary:Package}=${Version}\\n")
        (output / "build-packages.txt").write_text(inventory)
        staged = WORK / "package-payload"
        run("dpkg-deb", "-x", str(package), str(staged))
        libraries = list(staged.glob("usr/lib/*/liblzma.so.5.8.1"))
        if len(libraries) != 1:
            raise ValueError("Expected exactly one packaged liblzma shared object")
        provenance = {
            **manifest,
            "architecture": arch,
            "package_sha256": digest(package),
            "library_sha256": digest(libraries[0]),
        }
        (output / "liblzma-backport.json").write_text(json.dumps(provenance, indent=2) + "\n")
    else:
        raise ValueError(f"Unknown recipe phase: {phase}")


if __name__ == "__main__":
    main()
