"""Build-time checks that the Debian inputs are exactly the reviewed ones.

APT has already authenticated the pinned snapshot indexes and every download
against them. These checks add the exact bytes recorded in manifest.json: the
snapshots' Release files, the binary packages and the source files. Nothing is
downloaded or built here.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tarfile

INPUTS = Path(__file__).resolve().parent
PACKAGES = ("liblzma5", "liblzma-dev")


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


def verify_indexes(lists: Path, manifest: dict) -> None:
    actual = sorted(digest(path) for path in lists.glob("*_InRelease"))
    if actual != sorted(manifest["snapshot_release_sha256"].values()):
        raise ValueError("APT Release inputs differ from the reviewed snapshots")


def verify_packages(root: Path, manifest: dict, architecture: str) -> None:
    """Each downloaded package is the recorded one; leave it under a fixed name."""
    for package in PACKAGES:
        name = f"{package}_{manifest['version']}_{architecture}.deb"
        if name not in manifest["package_sha256"]:
            raise ValueError(f"No reviewed package for this architecture: {name}")
        # APT percent-encodes some characters of a version in the file name.
        found = [path for path in root.glob(f"{package}_*.deb")
                 if path.name.replace("%2b", "+").replace("%2B", "+") == name]  # fmt: skip
        if len(found) != 1 or len(list(root.glob(f"{package}_*.deb"))) != 1:
            raise ValueError(f"Expected exactly one downloaded package: {name}")
        if found[0].is_symlink() or digest(found[0]) != manifest["package_sha256"][name]:
            raise ValueError(f"SHA-256 mismatch: {name}")
        found[0].rename(root / f"{package}.deb")


def extract_fixture(archive: Path, member: str, output: Path) -> None:
    """One regular file from the authenticated upstream source, and nothing else."""
    with tarfile.open(archive) as source:
        info = source.getmember(member)
        if not info.isfile():
            raise ValueError("Fixture must be a regular file")
        stream = source.extractfile(info)
        assert stream is not None
        (output / Path(member).name).write_bytes(stream.read())


def main() -> None:
    manifest = json.loads((INPUTS / "manifest.json").read_text())
    phase = sys.argv[1]
    if phase == "indexes":
        verify_indexes(Path("/var/lib/apt/lists"), manifest)
    elif phase == "packages":
        architecture = subprocess.run(
            ["dpkg", "--print-architecture"], check=True, text=True, stdout=subprocess.PIPE
        ).stdout.strip()
        verify_packages(Path(sys.argv[2]), manifest, architecture)
    elif phase == "sources":
        verify_files(Path(sys.argv[2]), manifest["source_sha256"])
    elif phase == "fixture":
        fixture = manifest["fixture"]
        extract_fixture(Path(sys.argv[2]) / fixture["archive"], fixture["member"],
                        Path(sys.argv[3]))  # fmt: skip
    else:
        raise ValueError(f"Unknown phase: {phase}")


if __name__ == "__main__":
    main()
