"""AWS-08c preconditions as commands: pre-cutover, legacy-writer drain, compatibility retention.

    python -m release_kits.cutover pre-cutover --target TARGET.json --work DIR \\
        --deployed ENV_FILE [--gate] [--chain-head HASH]
    python -m release_kits.cutover drain       --target TARGET.json --work DIR \\
        --database-url-file FILE --chain-head HASH
    python -m release_kits.cutover retention   --target TARGET.json --work DIR \\
        --chain-head HASH

Each writes a hashed receipt chained to the previous one and prints its hash; the
next command takes it as ``--chain-head`` (the target is the admission kit's
``sentry.admission-target.v1``; keep this kit's work directory apart from the
admission kit's).

- ``pre-cutover`` runs this checkout with explicit legacy admission, no runtime
  URL and no scope, the way production runs today: the API smoke and the
  admission tests (and, with ``--gate``, the full local gate), and checks the
  deployed API's settings (``--deployed``: explicit legacy, no runtime endpoint,
  no scope; the file's hash is recorded). Together they show that the main push that must come
  before the cutover changes nothing until a scope is set.
- ``drain`` counts the legacy writers still running in the product database:
  reports generating in-process (no dispatch intent) and evaluations held by an
  in-process evaluator. A generating report older than two hours is counted as
  abandoned, reported apart and not waited for. A scope expansion should wait for
  zero running. It reads only, with the URL from an owner-only file outside any
  repository; nothing ambient.
- ``retention`` checks that this checkout still carries everything a return to
  legacy admission needs: legacy mode, the legacy generation and evaluation paths
  (each marked ``TODO(sentryruntime-cutover)``) and the rule that runtime-owned
  work stays with the runtime under legacy admission.
"""

from __future__ import annotations

import argparse
from datetime import timedelta
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Any, TextIO

from release_kits.admission_scope import Refused, load_target
from release_kits.ledger import ChainBroken, Ledger, utc_now
from release_kits.plan import sha256

KIT = "cutover"
REPO = Path(__file__).resolve().parents[1]
EXIT_OK, EXIT_REFUSED, EXIT_FAILED = 0, 2, 3
ADMISSION_TESTS = (
    "tests/test_execution_admission.py",
    "tests/test_execution_config.py",
    "tests/test_admission_scope.py::test_without_a_scope_explicit_legacy_admission_is_unchanged",
)
# Legacy paths a return to legacy admission needs, by file and marker.
RETAINED = (
    ("src/execution/config.py", "TODO(sentryruntime-cutover): Remove legacy admission"),
    ("src/api/main.py", "TODO(sentryruntime-cutover): Remove explicit legacy generation"),
    ("src/api/main.py", "TODO(sentryruntime-cutover): Remove this in-process evaluator path"),
)
# A legacy generation older than this is abandoned (its API process is gone), not running:
# in-process generation has no lease, so a restarted API leaves its rows "generating".
ABANDONED_AFTER = timedelta(hours=2)
RETENTION_TESTS = (
    "tests/test_execution_admission.py::test_legacy_mode_cannot_override_durable_ownership",
    "tests/test_admission_scope.py::"
    "test_rollback_removes_the_scope_and_runtime_owned_work_stays_with_the_runtime",
)


def production_today() -> dict[str, str]:
    """The API's settings as production runs today: explicit legacy, no runtime."""
    keep = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR")
    environment = {key: value for key, value in os.environ.items() if key in keep}
    return environment | {"SENTRYSEARCH_EXECUTION_MODE": "legacy", "PYTHON_DOTENV_DISABLED": "1",
                          "PYTHONDONTWRITEBYTECODE": "1"}  # fmt: skip


def drain_statement():
    """Counts of in-process legacy work: running, and abandoned (reported, not waited for)."""
    from sqlalchemy import exists, func, select

    from src.storage.models import Report, ReportRuntimeDispatch

    legacy = ~exists().where(ReportRuntimeDispatch.report_id == Report.id)
    cutoff = func.statement_timestamp() - ABANDONED_AFTER
    generating = (
        select(func.count()).select_from(Report).where(Report.status == "generating", legacy)
    )
    evaluating = (
        select(func.count())
        .select_from(Report)
        .where(Report.evaluation_lease_expires_at > func.statement_timestamp(), legacy)
    )
    return select(
        generating.where(Report.created_at > cutoff).scalar_subquery().label("legacy_generating"),
        evaluating.scalar_subquery().label("legacy_evaluating"),
        generating.where(Report.created_at <= cutoff).scalar_subquery().label("legacy_abandoned"),
    )  # fmt: skip


DEPLOYED_FORBIDDEN = ("SENTRYRUNTIME_URL", "SENTRYRUNTIME_LOCAL_URL", "SENTRYRUNTIME_CA_FILE",
                      "SENTRYSEARCH_RUNTIME_SCOPE", "SENTRYSEARCH_RUNTIME_SCOPE_SHA256")  # fmt: skip


def deployed_matches_today(path: Path) -> dict[str, Any]:
    """The deployed API's settings: explicit legacy, no runtime endpoint, no scope."""
    values = {}
    for line in path.read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip()
    stray = sorted(key for key in DEPLOYED_FORBIDDEN if values.get(key))
    mode = values.get("SENTRYSEARCH_EXECUTION_MODE")
    return {"sha256": sha256(path.read_bytes()), "mode": mode, "stray": stray,
            "ok": mode == "legacy" and not stray}  # fmt: skip


class CutoverKit:
    def __init__(self, target: dict[str, Any], target_sha256: str, work: Path, *,
                 out: TextIO = sys.stdout, run=subprocess.run) -> None:  # fmt: skip
        self.target = target
        self.out = out
        self.run_command = run
        self.ledger = Ledger(work / "receipts", kit=KIT, plan_sha256=target_sha256)
        self.logs = work / "logs"

    def say(self, text: str) -> None:
        print(text, file=self.out, flush=True)

    def _run(self, name: str, command: list[str]) -> dict[str, Any]:
        self.logs.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.say(f"  $ {' '.join(command)}")
        result = self.run_command(command, cwd=REPO, env=production_today(), text=True,
                                  capture_output=True, check=False)  # fmt: skip
        text = (result.stdout or "") + (result.stderr or "")
        with (self.logs / f"{len(self.ledger.receipts()):03d}-{name}.log").open("x") as stream:
            stream.write(text)
        return {"command": command, "exit": result.returncode, "log_sha256": sha256(text.encode())}

    def head(self, given: str | None) -> None:
        _, digest = self.ledger.head()
        if digest is None and given is not None:
            raise Refused(
                "--chain-head names a receipt, but this work directory has none: its history "
                "is missing or this is the wrong directory"
            )
        if digest is not None and given != digest:
            raise Refused("give --chain-head with the hash the last check printed")

    def _record(self, step: str, checks: dict[str, Any], passed: bool) -> int:
        digest = self.ledger.write(step, {"at": utc_now(), "result": "ok" if passed else "failed",
                                          "outputs": checks})  # fmt: skip
        self.say(f"{step}: {'passed' if passed else 'FAILED'}. Receipt {digest}; give the next "
                 f"command --chain-head {digest}")  # fmt: skip
        return EXIT_OK if passed else EXIT_FAILED

    def pre_cutover(self, *, gate: bool, deployed: Path) -> int:
        from src.execution.config import execution_mode_from_environment

        python = [sys.executable, "-B"]
        # The environment the checks run under is admitted as legacy, as production is.
        checks: dict[str, Any] = {
            "admission_today": execution_mode_from_environment(production_today())
        }
        # The deployed API's own settings: only these show the push changes nothing.
        checks["deployed"] = deployed_matches_today(deployed)
        checks["smoke"] = self._run("smoke", [*python, "dev/smoke_api.py"])
        checks["admission"] = self._run("admission", [*python, "-m", "pytest", "-p",
                                                      "no:cacheprovider", "-q", *ADMISSION_TESTS])  # fmt: skip
        if gate:
            checks["gate"] = self._run("gate", [*python, "dev/check_local_setup.py"])
        commands_ok = all(c["exit"] == 0 for c in checks.values() if isinstance(c, dict)
                          and "exit" in c)  # fmt: skip
        passed = checks["admission_today"] == "legacy" and commands_ok and checks["deployed"]["ok"]
        return self._record("pre-cutover", checks, passed)

    def drain(self, url_file: Path) -> int:
        info = os.lstat(url_file)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
            raise Refused("the database URL file must be an owner-only regular file")
        if any((parent / ".git").exists() for parent in url_file.resolve().parents):
            raise Refused("the database URL file is inside a repository")
        from sqlalchemy import create_engine, text

        engine = create_engine(url_file.read_text().strip(), pool_pre_ping=False)
        try:
            with engine.connect() as connection:
                connection.execute(text("SET TRANSACTION READ ONLY"))
                counts = dict(connection.execute(drain_statement()).mappings().one())
        finally:
            engine.dispose()
        counts = {key: int(value) for key, value in counts.items()}
        running = counts["legacy_generating"] + counts["legacy_evaluating"]
        return self._record("drain", {"counts": counts, "abandoned_after_hours": 2}, running == 0)

    def retention(self) -> int:
        markers = {f"{path}: {marker}": marker in (REPO / path).read_text()
                   for path, marker in RETAINED}  # fmt: skip
        from src.execution.config import execution_mode_from_environment

        legacy = execution_mode_from_environment({"SENTRYSEARCH_EXECUTION_MODE": "legacy"})
        checks: dict[str, Any] = {"markers": markers, "legacy_mode": legacy,
                                  "tests": self._run("retention", [sys.executable, "-B", "-m",
                                                                   "pytest", "-p",
                                                                   "no:cacheprovider", "-q",
                                                                   *RETENTION_TESTS])}  # fmt: skip
        passed = all(markers.values()) and legacy == "legacy" and checks["tests"]["exit"] == 0
        return self._record("retention", checks, passed)


def main(argv: list[str] | None = None, **options: Any) -> int:
    parser = argparse.ArgumentParser(prog="python -m release_kits.cutover", allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("pre-cutover", "drain", "retention"):
        command = commands.add_parser(name, allow_abbrev=False)
        command.add_argument("--target", type=Path, required=True)
        command.add_argument("--work", type=Path, required=True)
        command.add_argument("--chain-head")
        if name == "pre-cutover":
            command.add_argument("--gate", action="store_true")
            command.add_argument("--deployed", type=Path, required=True,
                                 help="the deployed API's settings as KEY=VALUE lines")  # fmt: skip
        if name == "drain":
            command.add_argument("--database-url-file", type=Path, required=True)
    args = parser.parse_args(argv)
    out = options.get("out", sys.stdout)
    try:
        target, digest = load_target(args.target)
        kit = CutoverKit(target, digest, args.work, **options)
        kit.head(args.chain_head)
        if args.command == "pre-cutover":
            return kit.pre_cutover(gate=args.gate, deployed=args.deployed)
        if args.command == "drain":
            return kit.drain(args.database_url_file)
        return kit.retention()
    except (Refused, ChainBroken, OSError) as error:
        print(f"cutover: refused: {type(error).__name__}: {error}", file=out)
        return EXIT_REFUSED


if __name__ == "__main__":
    raise SystemExit(main())
