"""The service image ships every first-party module its entry points import.

Built-image checks only see a missing module when a code path imports it at run
time; this walks the imports statically, so a package added to ``src`` imports
(as the shared R2 client was) cannot be left out of the image unnoticed.
"""

from __future__ import annotations

import ast
from pathlib import Path
import re

REPO = Path(__file__).resolve().parents[1]
DOCKERFILE = REPO / "container" / "Dockerfile"
# Python the final service image runs: its fixed commands and the Cloudflare entrypoint.
ENTRY_POINTS = (
    "run_api.py",
    "dev/run_runtime_worker.py",
    "dev/migrate_storage.py",
    "dev/prepare_service_volumes.py",
    "dev/check_worker_readiness.py",
)
FIRST_PARTY = {"src", "dev", "release_cloudflare", "release", "release_tools"}


def shipped_files() -> set[str]:
    """Repository paths the Dockerfile copies from the build context into /app."""
    shipped: set[str] = set()
    for line in DOCKERFILE.read_text().splitlines():
        match = re.match(r"COPY (?!--from)(?:--\S+ )*(.+) (\S+)$", line)
        if not match or not match.group(2).startswith("/app"):
            continue
        for source in match.group(1).split():
            path = REPO / source
            if path.is_dir():
                shipped.update(str(p.relative_to(REPO)) for p in path.rglob("*.py"))
            else:
                shipped.add(source)
    return shipped


def module_file(name: str) -> str | None:
    parts = name.split(".")
    for candidate in ("/".join(parts) + ".py", "/".join(parts) + "/__init__.py"):
        if (REPO / candidate).exists():
            return candidate
    return None


def first_party_imports(path: str) -> set[str]:
    tree = ast.parse((REPO / path).read_text(), path)
    package = path.removesuffix(".py").replace("/", ".").removesuffix(".__init__")
    if not path.endswith("__init__.py"):
        package = package.rpartition(".")[0]
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = package.split(".")[: len(package.split(".")) - node.level + 1]
                module = ".".join(base + ([node.module] if node.module else []))
            else:
                module = node.module or ""
            names = [module] + [f"{module}.{alias.name}" for alias in node.names]
        else:
            continue
        for name in names:
            if name.split(".")[0] in FIRST_PARTY:
                # Every package on the way down is imported too.
                for depth in range(1, len(name.split(".")) + 1):
                    if file := module_file(".".join(name.split(".")[:depth])):
                        found.add(file)
    return found


def test_every_imported_first_party_module_is_in_the_service_image():
    shipped = shipped_files()
    seen: set[str] = set()
    pending = [p for p in ENTRY_POINTS]
    while pending:
        path = pending.pop()
        if path in seen:
            continue
        seen.add(path)
        pending.extend(first_party_imports(path) - seen)
    missing = sorted(seen - shipped)
    assert not missing, f"imported by the service image but not copied into it: {missing}"
    assert "release_cloudflare/r2_client.py" in seen
