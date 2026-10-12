"""Offline guards for the pinned official liblzma package and its build inputs."""

import hashlib
import io
import json
from pathlib import Path
import re
import tarfile

import pytest

from container.liblzma.verify import (
    extract_fixture,
    verify_files,
    verify_indexes,
    verify_packages,
)

ROOT = Path(__file__).resolve().parents[1]
INPUTS = ROOT / "container" / "liblzma"
MANIFEST = json.loads((INPUTS / "manifest.json").read_text())
VERSION = MANIFEST["version"]


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_pinned_file_accepts_exact_bytes(tmp_path):
    (tmp_path / "source.tar.xz").write_bytes(b"fixture")
    verify_files(tmp_path, {"source.tar.xz": sha(b"fixture")})


@pytest.mark.parametrize("replacement", [b"tampered", b""])
def test_pinned_file_rejects_changed_bytes(tmp_path, replacement):
    (tmp_path / "source.tar.xz").write_bytes(replacement)
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        verify_files(tmp_path, {"source.tar.xz": sha(b"fixture")})


def test_pinned_file_requires_presence(tmp_path):
    with pytest.raises(FileNotFoundError):
        verify_files(tmp_path, {"missing.dsc": "0" * 64})


@pytest.mark.parametrize("name", ["../outside", "/absolute", "nested/source"])
def test_manifest_paths_are_basenames(tmp_path, name):
    with pytest.raises(ValueError, match="basename"):
        verify_files(tmp_path, {name: "0" * 64})


def test_pinned_file_rejects_symlink(tmp_path):
    (tmp_path / "original").write_bytes(b"fixture")
    (tmp_path / "alias.dsc").symlink_to("original")
    with pytest.raises(ValueError, match="regular file"):
        verify_files(tmp_path, {"alias.dsc": sha(b"fixture")})


def test_release_files_must_be_exactly_the_reviewed_snapshots(tmp_path):
    reviewed = {"trixie": b"main", "trixie-updates": b"updates", "trixie-security": b"security"}
    manifest = {"snapshot_release_sha256": {name: sha(data) for name, data in reviewed.items()}}
    for name, data in reviewed.items():
        (tmp_path / f"snapshot_{name}_InRelease").write_bytes(data)
    verify_indexes(tmp_path, manifest)
    (tmp_path / "snapshot_trixie-security_InRelease").write_bytes(b"a later security index")
    with pytest.raises(ValueError, match="reviewed snapshots"):
        verify_indexes(tmp_path, manifest)
    (tmp_path / "snapshot_trixie-security_InRelease").write_bytes(b"security")
    (tmp_path / "another_archive_InRelease").write_bytes(b"unreviewed")
    with pytest.raises(ValueError, match="reviewed snapshots"):
        verify_indexes(tmp_path, manifest)


def downloaded(tmp_path: Path, architecture: str = "arm64", encode: bool = True) -> dict:
    """Both packages as APT names them, with a manifest that records their bytes."""
    manifest = {"version": VERSION, "package_sha256": {}}
    for package in ("liblzma5", "liblzma-dev"):
        name = f"{package}_{VERSION}_{architecture}.deb"
        data = f"{package} {architecture}".encode()
        (tmp_path / (name.replace("+", "%2b") if encode else name)).write_bytes(data)
        manifest["package_sha256"][name] = sha(data)
    return manifest


@pytest.mark.parametrize("encode", [True, False])
def test_recorded_packages_are_accepted_and_left_under_fixed_names(tmp_path, encode):
    manifest = downloaded(tmp_path, encode=encode)
    verify_packages(tmp_path, manifest, "arm64")
    assert sorted(path.name for path in tmp_path.iterdir()) == ["liblzma-dev.deb", "liblzma5.deb"]
    assert (tmp_path / "liblzma5.deb").read_bytes() == b"liblzma5 arm64"


@pytest.mark.parametrize("problem", ["bytes", "architecture", "extra", "missing", "symlink"])
def test_any_other_package_is_refused(tmp_path, problem):
    manifest = downloaded(tmp_path)
    name = f"liblzma5_{VERSION}_arm64.deb".replace("+", "%2b")
    architecture = "arm64"
    if problem == "bytes":
        (tmp_path / name).write_bytes(b"another build of the same version")
    elif problem == "architecture":
        architecture = "riscv64"
    elif problem == "extra":
        (tmp_path / "liblzma5_5.8.1-1%2bdeb13u1_arm64.deb").write_bytes(b"the donor's version")
    elif problem == "missing":
        (tmp_path / name).unlink()
    else:
        (tmp_path / name).rename(tmp_path / "elsewhere")
        (tmp_path / name).symlink_to("elsewhere")
    with pytest.raises(ValueError):
        verify_packages(tmp_path, manifest, architecture)
    assert not (tmp_path / "liblzma5.deb").exists()


def test_only_the_named_regular_fixture_is_taken_from_the_source_archive(tmp_path):
    archive = tmp_path / "source.tar.xz"
    with tarfile.open(archive, "w:xz") as source:
        for name, data in (("xz/tests/files/good.lzma", b"fixture"), ("xz/other", b"other")):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            source.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo("xz/tests/files/link.lzma")
        link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
        source.addfile(link)
    output = tmp_path / "probe"
    output.mkdir()
    extract_fixture(archive, "xz/tests/files/good.lzma", output)
    assert [(path.name, path.read_bytes()) for path in output.iterdir()] == [
        ("good.lzma", b"fixture")
    ]
    with pytest.raises(ValueError, match="regular file"):
        extract_fixture(archive, "xz/tests/files/link.lzma", output)
    with pytest.raises(KeyError):
        extract_fixture(archive, "xz/tests/files/absent.lzma", output)


def test_the_build_names_one_reviewed_version_from_one_pinned_snapshot():
    dockerfile = (ROOT / "container" / "Dockerfile").read_text()
    sources = (INPUTS / "debian.sources").read_text()
    # Every version the build names for liblzma or its source is the manifest's.
    named = set(re.findall(r"(?:liblzma5|liblzma-dev|xz-utils)=(\S+)", dockerfile))
    assert named == {VERSION}
    assert f"= '{MANIFEST['donor_version']}'" in dockerfile and f"= '{VERSION}'" in dockerfile
    # Only the reviewed dated snapshots are package sources; signatures stay on.
    assert re.findall(r"^URIs: (\S+)$", sources, re.M) == list(MANIFEST["snapshots"].values())
    assert sources.count("Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg") == 2
    assert "trusted=yes" not in sources and "allow-insecure" not in sources.lower()
    for package in ("liblzma5", "liblzma-dev"):
        for architecture in ("arm64", "amd64"):
            assert f"{package}_{VERSION}_{architecture}.deb" in MANIFEST["package_sha256"]
    for digest in [*MANIFEST["package_sha256"].values(), *MANIFEST["source_sha256"].values(),
                   *MANIFEST["snapshot_release_sha256"].values()]:  # fmt: skip
        assert re.fullmatch(r"[0-9a-f]{64}", digest)


def test_the_build_checks_every_download_before_anything_uses_it():
    # One shell chain per fetch: each check follows its download and precedes
    # whatever consumes the bytes, so a failed check fails the build there.
    dockerfile = (ROOT / "container" / "Dockerfile").read_text()
    official = dockerfile[dockerfile.index("AS liblzma-official") :
                          dockerfile.index("AS liblzma-test-build")]  # fmt: skip
    probe = dockerfile[dockerfile.index("AS liblzma-test-build") :
                       dockerfile.index("AS liblzma-test-tools")]  # fmt: skip
    for stage, chain in (
        (official, ["apt-get update --error-on=any && python /inputs/verify.py indexes && ",
                    "apt-get download ", "python /inputs/verify.py packages /packages && "]),
        (probe, ["apt-get source --download-only ", "python /inputs/verify.py sources /work && ",
                 "dpkg -i /packages/liblzma5.deb ", "python /inputs/verify.py fixture /work /probe"]),
    ):  # fmt: skip
        positions = [stage.index(step) for step in chain]
        assert positions == sorted(positions), chain
    assert dockerfile.count("verify.py") == 6  # the copy, the comment and the four checks
    # The service takes the package from the checked stage and from nowhere else.
    assert dockerfile.count("liblzma5.deb") == 5
    assert "COPY --from=liblzma-official /packages/liblzma5.deb /tmp/liblzma5.deb" in dockerfile


def test_nothing_of_the_local_backport_remains():
    assert sorted(path.name for path in INPUTS.iterdir() if path.name != "__pycache__") == [
        "NOTICE", "debian.sources", "decoder_reinit_test.c", "manifest.json", "verify.py",
    ]  # fmt: skip
    dockerfile = (ROOT / "container" / "Dockerfile").read_text()
    for stale in ("TODO(liblzma-backport)", "sentry1", "liblzma-backport.json",
                  "dpkg-buildpackage", "recipe.py", "liblzma-build"):  # fmt: skip
        assert stale not in dockerfile, stale
    # The test tools are their own target and the service never copies from it.
    assert "FROM scratch AS liblzma-test-tools" in dockerfile
    service = dockerfile[dockerfile.index("FROM runtime-base AS service") :]
    assert "liblzma" not in service
