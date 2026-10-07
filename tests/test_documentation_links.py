"""Relative links in tracked Markdown must reach files a clean checkout contains."""

from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest

REPO = Path(__file__).resolve().parents[1]
LINK = re.compile(r"\]\(([^)#\s]+)(?:#[^)]*)?\)")


def tracked_files() -> set[str]:
    if shutil.which("git") is None or not (REPO / ".git").exists():
        pytest.skip("not a Git checkout")
    result = subprocess.run(
        ["git", "-C", str(REPO), "ls-files"], capture_output=True, text=True, check=True
    )
    return set(result.stdout.splitlines())


def test_relative_markdown_links_point_to_tracked_files():
    tracked = tracked_files()
    broken = []
    for name in sorted(t for t in tracked if t.endswith(".md") and not t.startswith("frontend/")):
        for target in LINK.findall((REPO / name).read_text(encoding="utf-8", errors="replace")):
            if "://" in target or target.startswith("mailto:"):
                continue
            path = os.path.normpath(os.path.join(os.path.dirname(name), target))
            if path not in tracked and not any(t.startswith(path + "/") for t in tracked):
                broken.append(f"{name} -> {target}")
    assert broken == []
