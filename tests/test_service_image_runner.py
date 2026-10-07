from pathlib import Path
import subprocess

from dev import check_service_images


def test_build_returns_immutable_id_and_selects_requested_target(monkeypatch):
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="sha256:" + "a" * 64 + "\n")

    monkeypatch.setattr(check_service_images.subprocess, "run", run)
    image = check_service_images.build(
        Path("repo"),
        "fixture:tag",
        Path("container/Dockerfile"),
        None,
        target="liblzma-test-tools",
    )
    assert image == "sha256:" + "a" * 64
    assert calls[0] == [
        "docker",
        "build",
        "--tag",
        "fixture:tag",
        "--file",
        "container/Dockerfile",
        "--target",
        "liblzma-test-tools",
        "repo",
    ]


def test_build_rejects_missing_immutable_identity(monkeypatch):
    def run(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, stdout="")

    monkeypatch.setattr(check_service_images.subprocess, "run", run)
    import pytest

    with pytest.raises(ValueError, match="immutable"):
        check_service_images.build(Path("repo"), "fixture:tag", None, None)
