"""Hashed receipts, each chained to the one before it, in a kit's work directory.

A receipt is canonical JSON written once (exclusive create, read-only afterwards).
Its hash is the SHA-256 of its bytes and the next receipt names that hash, so a
receipt edited, removed or reordered before the newest one breaks the chain. The
newest receipt has nothing after it to name it: the kits print its hash and the
next command must be given that hash (``--chain-head``), so an edited or removed
newest receipt is refused too. Receipts hold identifiers, digests, exit codes and the commands that
ran, never a credential or secret value: a write that would contain one of the
values it is told to keep out is refused.
"""

from __future__ import annotations

from datetime import UTC, datetime
import json
import os
from pathlib import Path
import re
from typing import Any, Iterable

from release_kits.plan import sha256

SCHEMA = "sentry.kit-receipt.v1"
NAME = re.compile(r"(\d{3})-([a-z0-9-]+)\.json")


class ChainBroken(Exception):
    """The receipts on disk are not one unbroken chain for this plan."""


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def encode(document: dict[str, Any]) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()


class Ledger:
    def __init__(self, directory: Path, *, kit: str, plan_sha256: str) -> None:
        self.directory = directory
        self.kit = kit
        self.plan_sha256 = plan_sha256

    def receipts(self) -> list[tuple[Path, dict[str, Any], str]]:
        """Every receipt in order with its hash; ChainBroken if the chain does not hold."""
        if not self.directory.exists():
            return []
        found = []
        for path in self.directory.iterdir():
            match = NAME.fullmatch(path.name)
            if match is None or path.is_symlink() or not path.is_file():
                raise ChainBroken(f"unexpected entry in the receipt directory: {path.name}")
            found.append((int(match.group(1)), path))
        found.sort()
        chain, previous = [], None
        for index, (sequence, path) in enumerate(found):
            raw = path.read_bytes()
            document = json.loads(raw)
            if sequence != index or document.get("sequence") != index:
                raise ChainBroken(f"{path.name} is out of sequence")
            if document.get("schema") != SCHEMA or document.get("kit") != self.kit:
                raise ChainBroken(f"{path.name} is not a {self.kit} receipt")
            if document.get("plan_sha256") != self.plan_sha256:
                raise ChainBroken(f"{path.name} belongs to another plan")
            if document.get("previous_sha256") != previous:
                raise ChainBroken(f"{path.name} does not name the receipt before it")
            if raw != encode(document):
                raise ChainBroken(f"{path.name} is not in canonical form")
            previous = sha256(raw)
            chain.append((path, document, previous))
        return chain

    def head(self) -> tuple[dict[str, Any] | None, str | None]:
        chain = self.receipts()
        return (chain[-1][1], chain[-1][2]) if chain else (None, None)

    def completed(self) -> dict[str, dict[str, Any]]:
        """The latest successful receipt of each step."""
        return {document["step"]: document for _, document, _ in self.receipts()
                if document["result"] == "ok"}  # fmt: skip

    def write(self, step: str, body: dict[str, Any], *, keep_out: Iterable[str] = ()) -> str:
        """Append a receipt and return its hash."""
        chain = self.receipts()
        document = {
            "schema": SCHEMA, "kit": self.kit, "sequence": len(chain), "step": step,
            "plan_sha256": self.plan_sha256,
            "previous_sha256": chain[-1][2] if chain else None,
            "written_at": utc_now(), **body,
        }  # fmt: skip
        raw = encode(document)
        text = raw.decode()
        for value in keep_out:
            # As written, and as JSON escapes it (a PEM key's newlines, for one).
            if value and (value in text or json.dumps(value)[1:-1] in text):
                raise ValueError("refusing to write a receipt that contains a secret value")
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = self.directory / f"{len(chain):03d}-{step}.json"
        with path.open("xb") as stream:
            stream.write(raw)
        os.chmod(path, 0o444)
        return sha256(raw)
