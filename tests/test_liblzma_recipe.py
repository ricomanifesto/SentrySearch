"""Offline integrity guards for the temporary native-library recipe."""

import hashlib
import json
from pathlib import Path

import pytest

from container.liblzma.recipe import export_source_records, verify_files


def test_pinned_file_accepts_exact_bytes(tmp_path):
    (tmp_path / "source.tar.xz").write_bytes(b"fixture")
    verify_files(tmp_path, {"source.tar.xz": hashlib.sha256(b"fixture").hexdigest()})


@pytest.mark.parametrize("replacement", [b"tampered", b""])
def test_pinned_file_rejects_changed_bytes(tmp_path, replacement):
    (tmp_path / "source.tar.xz").write_bytes(replacement)
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        verify_files(tmp_path, {"source.tar.xz": hashlib.sha256(b"fixture").hexdigest()})


def test_pinned_file_requires_presence(tmp_path):
    with pytest.raises(FileNotFoundError):
        verify_files(tmp_path, {"missing.patch": "0" * 64})


@pytest.mark.parametrize("name", ["../outside", "/absolute", "nested/source"])
def test_manifest_paths_are_basenames(tmp_path, name):
    with pytest.raises(ValueError, match="basename"):
        verify_files(tmp_path, {name: "0" * 64})


def test_pinned_file_rejects_symlink(tmp_path):
    (tmp_path / "original").write_bytes(b"fixture")
    (tmp_path / "alias.patch").symlink_to("original")
    with pytest.raises(ValueError, match="regular file"):
        verify_files(tmp_path, {"alias.patch": hashlib.sha256(b"fixture").hexdigest()})


def test_checked_in_patches_match_manifest():
    root = Path(__file__).resolve().parents[1] / "container" / "liblzma"
    manifest = json.loads((root / "manifest.json").read_text())
    verify_files(root, {item["file"]: item["sha256"] for item in manifest["patches"]})


def test_source_export_preserves_all_dsc_members(tmp_path):
    source = tmp_path / "source"
    output = tmp_path / "out"
    source.mkdir()
    output.mkdir()
    members = ["xz.orig.tar.xz", "xz.orig.tar.xz.asc", "xz.debian.tar.xz"]
    dsc = "Checksums-Sha256:\n" + "".join(f" {'0' * 64} 7 {name}\n" for name in members)
    (source / "xz.dsc").write_text(dsc)
    for name in members:
        (source / name).write_bytes(b"fixture")
    export_source_records(source, output)
    assert (output / "xz.dsc").read_text() == dsc
    for name in members:
        assert (output / name).read_bytes() == b"fixture"
