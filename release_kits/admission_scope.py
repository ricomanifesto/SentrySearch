"""AWS-08c admission scope: each cutover milestone and its rollback as a hashed receipt.

    python -m release_kits.admission_scope expand   --target TARGET.json --work DIR \\
        --milestone NAME --identities FILE [--chain-head HASH]
    python -m release_kits.admission_scope rollback --target TARGET.json --work DIR \\
        --chain-head HASH
    python -m release_kits.admission_scope verify   --target TARGET.json --work DIR \\
        --deployed ENV_FILE --chain-head HASH

The API's runtime admission scope (``src/execution/config.py``) admits the named
identities' new reports to the runtime while every other identity keeps the
explicit base mode. This kit decides nothing and changes no deployment: it
renders the exact settings for one milestone, waits for the milestone's name to
be typed, and records the milestone manifest (``sentry.admission-scope.v1``) in
a receipt chained to the previous one. The rendered settings are checked with the
API's own admission rules before anything is asked, and the exact scope text is
written to an owner-only file in the work directory (``scopes/<milestone>.scope``)
to copy from. An expansion is only ever a superset of the scope before it.
``rollback`` records the return to the base mode: the two scope settings are
removed (and under a ``legacy`` base the runtime endpoint settings too), admitted
work stays with the runtime (durable dispatch ownership), and nothing completed
is touched. ``verify`` compares a deployed environment (a ``KEY=VALUE`` file of
the API's settings) with the newest receipt.

The target (``sentry.admission-target.v1``) names the environment, its explicit
base mode (``legacy`` or ``paused``) and the runtime URL the scoped identities use.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Callable, TextIO

from release_kits.ledger import ChainBroken, Ledger, utc_now
from release_kits.plan import sha256
from src.execution.config import (
    SCOPE_ENV,
    SCOPE_SHA256_ENV,
    canonical_scope,
    execution_mode_for,
    execution_mode_from_environment,
)

ENDPOINT_KEYS = ("SENTRYRUNTIME_URL", "SENTRYRUNTIME_LOCAL_URL", "SENTRYRUNTIME_CA_FILE")

KIT = "admission-scope"
TARGET_SCHEMA = "sentry.admission-target.v1"
MILESTONE_SCHEMA = "sentry.admission-scope.v1"
EXIT_OK, EXIT_REFUSED = 0, 2
MILESTONE = re.compile(r"[a-z0-9][a-z0-9-]{0,39}")


class Refused(Exception):
    pass


def load_target(path: Path) -> tuple[dict[str, Any], str]:
    raw = path.read_bytes()
    target = json.loads(raw)
    if not isinstance(target, dict) or target.get("schema") != TARGET_SCHEMA:
        raise Refused(f"the target is not a {TARGET_SCHEMA} document")
    if target.get("base_mode") not in ("legacy", "paused"):
        raise Refused("the base mode is the explicit legacy or paused mode the API keeps")
    if not str(target.get("runtime_url", "")).startswith("https://"):
        raise Refused("scoped identities need an https runtime URL")
    if not target.get("environment"):
        raise Refused("the target names its environment")
    return target, sha256(raw)


class ScopeKit:
    def __init__(self, target: dict[str, Any], target_sha256: str, work: Path, *,
                 out: TextIO = sys.stdout, prompt: Callable[[str], str] = input) -> None:  # fmt: skip
        self.target = target
        self.work = work
        self.out = out
        self.prompt = prompt
        self.ledger = Ledger(work / "receipts", kit=KIT, plan_sha256=target_sha256)

    def say(self, text: str) -> None:
        print(text, file=self.out, flush=True)

    def head(self, given: str | None) -> dict[str, Any] | None:
        document, digest = self.ledger.head()
        if digest is None and given is not None:
            # A lost history must not read as an empty scope (a narrowing as an expansion).
            raise Refused(
                "--chain-head names a receipt, but this work directory has none: its history "
                "is missing or this is the wrong directory"
            )
        if digest is not None and given != digest:
            raise Refused("give --chain-head with the hash the last milestone printed")
        return document

    def current(self) -> list[str]:
        document, _ = self.ledger.head()
        if document is None or document["step"] == "rollback":
            return []
        return document["outputs"]["identities"]

    def settings(self, scope: str) -> dict[str, str]:
        return {"SENTRYSEARCH_EXECUTION_MODE": self.target["base_mode"],
                "SENTRYRUNTIME_URL": self.target["runtime_url"], SCOPE_ENV: scope,
                SCOPE_SHA256_ENV: hashlib.sha256(scope.encode()).hexdigest()}  # fmt: skip

    def confirm(self, word: str) -> None:
        if self.prompt(f"Type {word} to record this milestone (anything else stops): ").strip() != (
            word
        ):
            raise Refused(f"not confirmed: expected {word!r}")

    def admitted(self, settings: dict[str, str], scope: str) -> None:
        """Refuse settings the API itself would refuse (a 503 for every identity)."""
        try:
            base = execution_mode_from_environment(settings)
            scoped = execution_mode_for(scope.split(",")[0], settings)
        except ValueError as error:
            raise Refused(f"the API would refuse these settings: {error}") from None
        if base != self.target["base_mode"] or scoped != "runtime":
            raise Refused("the API would not admit the scope to the runtime over the base mode")

    def scope_file(self, milestone: str, scope: str) -> Path:
        """The exact scope text, owner-only, for the operator to copy into the API."""
        folder = self.work / "scopes"
        folder.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = folder / f"{milestone}.scope"
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            if path.read_text() != scope:
                raise Refused(f"{path} already holds a different scope") from None
            return path
        with os.fdopen(descriptor, "w") as handle:
            handle.write(scope)
        return path

    def expand(self, milestone: str, identities_path: Path, chain_head: str | None) -> int:
        self.head(chain_head)
        if not MILESTONE.fullmatch(milestone):
            raise Refused("a milestone name is 1 to 40 lowercase letters, digits and hyphens")
        listed = json.loads(identities_path.read_bytes())
        if not isinstance(listed, list):
            raise Refused("the identities file is a JSON list of user ids")
        try:
            scope = canonical_scope(listed)
        except ValueError as error:
            raise Refused(str(error)) from None
        before = self.current()
        if not set(before) <= set(scope.split(",")):
            raise Refused("an expansion keeps every identity already in scope; roll back instead")
        if before and scope == ",".join(before):
            raise Refused("the scope would not change")
        settings = self.settings(scope)
        self.admitted(settings, scope)
        path = self.scope_file(milestone, scope)
        manifest = {"schema": MILESTONE_SCHEMA, "environment": self.target["environment"],
                    "milestone": milestone, "base_mode": self.target["base_mode"],
                    "scope_sha256": settings[SCOPE_SHA256_ENV],
                    "identities": len(scope.split(",")), "added": len(set(scope.split(","))
                                                                       - set(before)),
                    "previous_scope_sha256": (hashlib.sha256(",".join(before).encode()).hexdigest()
                                              if before else None),
                    "rollback": {"remove": self.removals(),
                                 "keeps": "the explicit base mode; admitted work stays with "
                                          "the runtime"}}  # fmt: skip
        self.say(f"Milestone {milestone} for {self.target['environment']}: "
                 f"{manifest['identities']} identities ({manifest['added']} new), "
                 f"base mode {self.target['base_mode']}")  # fmt: skip
        self.say("Set exactly these API settings (a configuration change, made by you):")
        for key, value in settings.items():
            shown = value if key != SCOPE_ENV else (f"<the exact contents of {path}: "
                                                    f"{manifest['identities']} identities>")  # fmt: skip
            self.say(f"  {key}={shown}")
        self.confirm(milestone)
        digest = self.ledger.write("expand", {"at": utc_now(), "result": "ok",
                                              "outputs": {"manifest": manifest,
                                                          "identities": scope.split(",")}})  # fmt: skip
        self.say(f"Recorded. Give the next command --chain-head {digest}")
        return EXIT_OK

    def removals(self) -> list[str]:
        """What a rollback removes: the scope, and under legacy the runtime endpoint too.

        Legacy admission refuses runtime endpoint settings when no scope is set, so
        leaving them would fail every new report closed.
        """
        keys = [SCOPE_ENV, SCOPE_SHA256_ENV]
        return keys + list(ENDPOINT_KEYS) if self.target["base_mode"] == "legacy" else keys

    def rollback(self, chain_head: str | None) -> int:
        self.head(chain_head)
        before = self.current()
        if not before:
            raise Refused("no scope is in force")
        self.say(f"Rollback of {self.target['environment']} to base mode "
                 f"{self.target['base_mode']}: remove {', '.join(self.removals())} from the API; "
                 "work already admitted stays with the runtime")  # fmt: skip
        self.confirm("rollback")
        digest = self.ledger.write("rollback", {"at": utc_now(), "result": "ok", "outputs": {
            "removed_scope_sha256": hashlib.sha256(",".join(before).encode()).hexdigest(),
            "base_mode": self.target["base_mode"], "remove": self.removals()}})  # fmt: skip
        self.say(f"Recorded. Give the next command --chain-head {digest}")
        return EXIT_OK

    def verify(self, deployed: Path, chain_head: str | None) -> int:
        self.head(chain_head)
        values = {}
        for line in deployed.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, _, value = line.partition("=")
                values[key.strip()] = value.strip()
        before = self.current()
        if not before:
            wanted = {"SENTRYSEARCH_EXECUTION_MODE": self.target["base_mode"]}
            stray = [key for key in self.removals() if values.get(key)]
            if stray:
                self.say(f"MISMATCH: no scope is recorded but the deployment sets {stray}")
                return EXIT_REFUSED
        else:
            wanted = self.settings(",".join(before))
        wrong = sorted(key for key, value in wanted.items() if values.get(key) != value)
        if wrong:
            self.say(f"MISMATCH: the deployment differs from the newest milestone in {wrong}")
            return EXIT_REFUSED
        # The settings must also be ones the API itself accepts (a scoped identity, if any,
        # admitted to the runtime; everyone else in the base mode).
        try:
            base = execution_mode_from_environment(values)
            if before and execution_mode_for(before[0], values) != "runtime":
                raise ValueError("a scoped identity is not admitted to the runtime")
        except ValueError as error:
            self.say(f"MISMATCH: the API would refuse these settings: {error}")
            return EXIT_REFUSED
        if base != self.target["base_mode"]:
            self.say(f"MISMATCH: the API would admit others as {base}")
            return EXIT_REFUSED
        self.say("The deployment matches the newest milestone and the API accepts it")
        return EXIT_OK


def main(argv: list[str] | None = None, **options: Any) -> int:
    parser = argparse.ArgumentParser(prog="python -m release_kits.admission_scope",
                                     allow_abbrev=False)  # fmt: skip
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("expand", "rollback", "verify"):
        command = commands.add_parser(name, allow_abbrev=False)
        command.add_argument("--target", type=Path, required=True)
        command.add_argument("--work", type=Path, required=True)
        command.add_argument("--chain-head")
        if name == "expand":
            command.add_argument("--milestone", required=True)
            command.add_argument("--identities", type=Path, required=True)
        if name == "verify":
            command.add_argument("--deployed", type=Path, required=True)
    args = parser.parse_args(argv)
    out = options.get("out", sys.stdout)
    try:
        target, digest = load_target(args.target)
        kit = ScopeKit(target, digest, args.work, **options)
        if args.command == "expand":
            return kit.expand(args.milestone, args.identities, args.chain_head)
        if args.command == "rollback":
            return kit.rollback(args.chain_head)
        return kit.verify(args.deployed, args.chain_head)
    except (Refused, ChainBroken) as error:
        print(f"admission_scope: refused: {error}", file=out)
        return EXIT_REFUSED


if __name__ == "__main__":
    raise SystemExit(main())
