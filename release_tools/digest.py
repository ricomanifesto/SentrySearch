"""Content digests that bind the executed programs and SQL to a task definition."""

import hashlib
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent


class IntegrityError(ValueError):
    pass


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tools_files(root: Path = PACKAGE_ROOT) -> list[Path]:
    files = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if "__pycache__" in relative.parts or path.suffix == ".pyc":
            continue
        if path.is_symlink():
            raise IntegrityError(f"symlink in release tools: {relative.as_posix()}")
        if path.is_file():
            files.append(path)
    return files


def tools_sha256(root: Path = PACKAGE_ROOT) -> str:
    """Hash every program and SQL file with its relative path and length."""
    digest = hashlib.sha256()
    for path in tools_files(root):
        data = path.read_bytes()
        name = path.relative_to(root).as_posix().encode()
        digest.update(name + b"\0" + str(len(data)).encode() + b"\0" + data)
    return digest.hexdigest()


def report(root: Path = PACKAGE_ROOT) -> dict[str, object]:
    """Build-receipt pins for the task definitions that run these tools."""
    return {
        "tools_sha256": tools_sha256(root),
        "sql": {
            path.relative_to(root).as_posix(): file_sha256(path)
            for path in tools_files(root)
            if path.suffix == ".sql"
        },
    }
