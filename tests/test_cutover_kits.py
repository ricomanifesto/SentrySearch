"""The AWS-08c kits offline: scope milestones, their rollback, and the cutover checks.

The scope kit renders settings and records receipts; it changes no deployment.
The cutover checks run against fixture commands here: the drain query is proven
against PostgreSQL in ``tests/runtime_postgres.py``.
"""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import subprocess

import pytest
from sqlalchemy.dialects import postgresql

from release_kits import admission_scope, cutover
from src.execution import config

A = "11111111-1111-4111-8111-111111111111"
B = "22222222-2222-4222-8222-222222222222"


def target(tmp_path: Path, **changes) -> Path:
    path = tmp_path / "target.json"
    path.write_text(json.dumps({"schema": admission_scope.TARGET_SCHEMA,
                                "environment": "production", "base_mode": "legacy",
                                "runtime_url": "https://runtime.example", **changes}))  # fmt: skip
    return path


def identities(tmp_path: Path, name: str, *ids: str) -> Path:
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps(list(ids)))
    return path


def run(tmp_path, *argv, typed=()) -> tuple[int, str]:
    out = io.StringIO()
    answers = list(typed)
    code = admission_scope.main([*argv], out=out, prompt=lambda _text: answers.pop(0))
    return code, out.getvalue()


def head(tmp_path: Path) -> str | None:
    loaded, digest = admission_scope.load_target(tmp_path / "target.json")
    return admission_scope.ScopeKit(loaded, digest, tmp_path / "work").ledger.head()[1]


def test_milestones_only_expand_and_the_rendered_settings_are_what_the_api_accepts(tmp_path):
    common = ["--target", str(target(tmp_path)), "--work", str(tmp_path / "work")]
    code, out = run(tmp_path, "expand", *common, "--milestone", "first",
                    "--identities", str(identities(tmp_path, "one", A)), typed=["first"])  # fmt: skip
    assert code == 0, out
    first = head(tmp_path)
    code, out = run(tmp_path, "expand", *common, "--milestone", "narrower", "--chain-head", first,
                    "--identities", str(identities(tmp_path, "none", B)), typed=["narrower"])  # fmt: skip
    assert code == 2 and "keeps every identity" in out
    code, out = run(tmp_path, "expand", *common, "--milestone", "second", "--chain-head", first,
                    "--identities", str(identities(tmp_path, "two", B, A)), typed=["second"])  # fmt: skip
    assert code == 0, out
    loaded, digest = admission_scope.load_target(tmp_path / "target.json")
    kit = admission_scope.ScopeKit(loaded, digest, tmp_path / "work")
    settings = kit.settings(",".join(kit.current()))
    assert config.execution_mode_for(A, settings) == "runtime"
    assert config.execution_mode_for("33333333-3333-4333-8333-333333333333", settings) == "legacy"
    newest, _ = kit.ledger.head()
    assert newest is not None
    manifest = newest["outputs"]["manifest"]
    assert manifest["identities"] == 2 and manifest["added"] == 1
    assert manifest["previous_scope_sha256"] == hashlib.sha256(A.encode()).hexdigest()


def test_a_milestone_without_its_typed_name_or_the_last_hash_is_refused(tmp_path):
    common = ["--target", str(target(tmp_path)), "--work", str(tmp_path / "work")]
    ids = str(identities(tmp_path, "one", A))
    code, out = run(tmp_path, "expand", *common, "--milestone", "first", "--identities", ids,
                    typed=["yes"])  # fmt: skip
    assert code == 2 and "not confirmed" in out and head(tmp_path) is None
    assert run(tmp_path, "expand", *common, "--milestone", "first", "--identities", ids,
               typed=["first"])[0] == 0  # fmt: skip
    code, out = run(tmp_path, "rollback", *common, typed=["rollback"])
    assert code == 2 and "chain-head" in out


def test_rollback_returns_to_the_base_mode_and_verify_checks_the_deployment(tmp_path):
    common = ["--target", str(target(tmp_path)), "--work", str(tmp_path / "work")]
    run(tmp_path, "expand", *common, "--milestone", "first",
        "--identities", str(identities(tmp_path, "one", A)), typed=["first"])  # fmt: skip
    deployed = tmp_path / "deployed.env"
    listed = A
    deployed.write_text(
        f"SENTRYSEARCH_EXECUTION_MODE=legacy\nSENTRYRUNTIME_URL=https://runtime.example\n"
        f"{config.SCOPE_ENV}={listed}\n"
        f"{config.SCOPE_SHA256_ENV}={hashlib.sha256(listed.encode()).hexdigest()}\n"
    )
    assert run(tmp_path, "verify", *common, "--deployed", str(deployed),
               "--chain-head", head(tmp_path))[0] == 0  # fmt: skip
    assert run(tmp_path, "rollback", *common, "--chain-head", head(tmp_path),
               typed=["rollback"])[0] == 0  # fmt: skip
    code, out = run(tmp_path, "verify", *common, "--deployed", str(deployed),
                    "--chain-head", head(tmp_path))  # fmt: skip
    assert code == 2 and "no scope is recorded" in out
    deployed.write_text("SENTRYSEARCH_EXECUTION_MODE=legacy\n")
    assert run(tmp_path, "verify", *common, "--deployed", str(deployed),
               "--chain-head", head(tmp_path))[0] == 0  # fmt: skip


@pytest.mark.parametrize("change", [{"base_mode": "runtime"}, {"runtime_url": "http://x"},
                                    {"schema": "other"}])  # fmt: skip
def test_a_target_outside_the_rules_is_refused(tmp_path, change):
    with pytest.raises(admission_scope.Refused):
        admission_scope.load_target(target(tmp_path, **change))


def test_the_drain_query_counts_only_running_legacy_work():
    sql = str(cutover.drain_statement().compile(dialect=postgresql.dialect()))
    assert "report_runtime_dispatches" in sql and "NOT (EXISTS" in sql
    assert "reports.status = " in sql and "evaluation_lease_expires_at >" in sql


class Fixture:
    def __init__(self, codes: dict[str, int]) -> None:
        self.codes = codes
        self.calls: list[tuple[list[str], dict]] = []

    def __call__(self, command, *, cwd, env, text, capture_output, check):
        self.calls.append((command, env))
        name = next((key for key in self.codes if key in " ".join(command)), "")
        return subprocess.CompletedProcess(command, self.codes.get(name, 0), "ok\n", "")


def test_pre_cutover_runs_as_production_does_today_and_records_the_outcome(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTRYRUNTIME_URL", "https://ambient.example")
    monkeypatch.setenv("AWS_PROFILE", "ambient")
    loaded, digest = admission_scope.load_target(target(tmp_path))
    fixture = Fixture({"smoke_api": 0})
    kit = cutover.CutoverKit(loaded, digest, tmp_path / "work", out=io.StringIO(), run=fixture)
    deployed = tmp_path / "deployed.env"
    deployed.write_text("SENTRYSEARCH_EXECUTION_MODE=legacy\n")
    assert kit.pre_cutover(gate=True, deployed=deployed) == cutover.EXIT_OK
    recorded = json.loads(sorted((tmp_path / "work" / "receipts").iterdir())[-1].read_text())
    assert (
        recorded["outputs"]["deployed"]["sha256"]
        == hashlib.sha256(deployed.read_bytes()).hexdigest()
    )
    for _command, env in fixture.calls:
        assert env["SENTRYSEARCH_EXECUTION_MODE"] == "legacy"
        assert not {key for key in env if key.startswith(("SENTRYRUNTIME_", "AWS_"))}
        assert config.SCOPE_ENV not in env
    assert [c[0][-1] for c in fixture.calls][-1] == "dev/check_local_setup.py"
    failing = cutover.CutoverKit(loaded, digest, tmp_path / "work2", out=io.StringIO(),
                                 run=Fixture({"smoke_api": 1}))  # fmt: skip
    assert failing.pre_cutover(gate=False, deployed=deployed) == cutover.EXIT_FAILED


def test_retention_holds_at_this_head(tmp_path):
    loaded, digest = admission_scope.load_target(target(tmp_path))
    kit = cutover.CutoverKit(loaded, digest, tmp_path / "work", out=io.StringIO(),
                             run=Fixture({}))  # fmt: skip
    assert kit.retention() == cutover.EXIT_OK
    receipt, _ = kit.ledger.head()
    assert receipt is not None
    assert all(receipt["outputs"]["markers"].values()) and receipt["outputs"]["legacy_mode"] == (
        "legacy"
    )


def test_drain_refuses_a_database_url_file_others_can_read(tmp_path):
    loaded, digest = admission_scope.load_target(target(tmp_path))
    kit = cutover.CutoverKit(loaded, digest, tmp_path / "work", out=io.StringIO())
    url = tmp_path / "url"
    url.write_text("postgresql+psycopg://reader@db.invalid/sentrysearch")
    url.chmod(0o644)
    with pytest.raises(admission_scope.Refused, match="owner-only"):
        kit.drain(url)


def test_a_legacy_rollback_also_removes_the_runtime_endpoint_and_verify_uses_the_api_rules(
    tmp_path,
):
    common = ["--target", str(target(tmp_path)), "--work", str(tmp_path / "work")]
    run(tmp_path, "expand", *common, "--milestone", "first",
        "--identities", str(identities(tmp_path, "one", A)), typed=["first"])  # fmt: skip
    code, out = run(tmp_path, "rollback", *common, "--chain-head", head(tmp_path),
                    typed=["rollback"])  # fmt: skip
    assert code == 0 and "SENTRYRUNTIME_URL" in out
    deployed = tmp_path / "deployed.env"
    # The runbook's old advice: only the two scope settings removed, the URL left.
    deployed.write_text(
        "SENTRYSEARCH_EXECUTION_MODE=legacy\nSENTRYRUNTIME_URL=https://runtime.example\n"
    )
    code, out = run(tmp_path, "verify", *common, "--deployed", str(deployed),
                    "--chain-head", head(tmp_path))  # fmt: skip
    assert code == 2 and "SENTRYRUNTIME_URL" in out
    with pytest.raises(ValueError, match="conflicts"):
        config.execution_mode_from_environment(
            {
                "SENTRYSEARCH_EXECUTION_MODE": "legacy",
                "SENTRYRUNTIME_URL": "https://runtime.example",
            }
        )


def test_verify_refuses_settings_the_api_itself_would_refuse(tmp_path):
    common = ["--target", str(target(tmp_path)), "--work", str(tmp_path / "work")]
    run(tmp_path, "expand", *common, "--milestone", "first",
        "--identities", str(identities(tmp_path, "one", A)), typed=["first"])  # fmt: skip
    deployed = tmp_path / "deployed.env"
    listed = A
    deployed.write_text(
        f"SENTRYSEARCH_EXECUTION_MODE=legacy\nSENTRYRUNTIME_URL=https://runtime.example\n"
        f"SENTRYRUNTIME_LOCAL_URL=http://127.0.0.1:9\n{config.SCOPE_ENV}={listed}\n"
        f"{config.SCOPE_SHA256_ENV}={hashlib.sha256(listed.encode()).hexdigest()}\n"
    )
    code, out = run(tmp_path, "verify", *common, "--deployed", str(deployed),
                    "--chain-head", head(tmp_path))  # fmt: skip
    assert code == 2 and "would refuse" in out


def test_pre_cutover_fails_when_the_deployed_api_is_not_set_as_production_is_today(tmp_path):
    loaded, digest = admission_scope.load_target(target(tmp_path))
    deployed = tmp_path / "deployed.env"
    deployed.write_text("SENTRYSEARCH_EXECUTION_MODE=legacy\n")
    kit = cutover.CutoverKit(loaded, digest, tmp_path / "work", out=io.StringIO(), run=Fixture({}))
    assert kit.pre_cutover(gate=False, deployed=deployed) == cutover.EXIT_OK
    for text in ("", "SENTRYSEARCH_EXECUTION_MODE=legacy\nSENTRYRUNTIME_URL=https://x.example\n"):
        deployed.write_text(text)
        other = cutover.CutoverKit(loaded, digest, tmp_path / f"work-{len(text)}",
                                   out=io.StringIO(), run=Fixture({}))  # fmt: skip
        assert other.pre_cutover(gate=False, deployed=deployed) == cutover.EXIT_FAILED


def test_cutover_commands_take_the_last_receipts_hash(tmp_path):
    loaded, digest = admission_scope.load_target(target(tmp_path))
    kit = cutover.CutoverKit(loaded, digest, tmp_path / "work", out=io.StringIO(), run=Fixture({}))
    kit.retention()
    with pytest.raises(admission_scope.Refused, match="chain-head"):
        kit.head("0" * 64)
    kit.head(kit.ledger.head()[1])


def test_the_drain_reports_abandoned_legacy_rows_apart_from_running_ones():
    sql = str(cutover.drain_statement().compile(dialect=postgresql.dialect()))
    assert sql.count("reports.created_at") == 2 and "legacy_abandoned" in sql


@pytest.mark.parametrize(
    "url", ["https://runtime.example:8443/api", "https://user@runtime.example"]
)
def test_expand_refuses_settings_the_api_would_refuse_before_asking(tmp_path, url):
    common = ["--target", str(target(tmp_path, runtime_url=url)), "--work", str(tmp_path / "work")]
    code, out = run(tmp_path, "expand", *common, "--milestone", "first",
                    "--identities", str(identities(tmp_path, "one", A)))  # fmt: skip
    assert code == 2 and "the API would refuse" in out and "Type first" not in out
    assert head(tmp_path) is None


def test_expand_writes_the_exact_scope_text_owner_only_and_names_it(tmp_path):
    common = ["--target", str(target(tmp_path)), "--work", str(tmp_path / "work")]
    code, out = run(tmp_path, "expand", *common, "--milestone", "first",
                    "--identities", str(identities(tmp_path, "two", B, A)), typed=["first"])  # fmt: skip
    path = tmp_path / "work" / "scopes" / "first.scope"
    assert code == 0 and str(path) in out and A not in out
    assert path.read_text() == f"{A},{B}"
    assert path.stat().st_mode & 0o777 == 0o600 and path.parent.stat().st_mode & 0o077 == 0
    settings = {
        "SENTRYSEARCH_EXECUTION_MODE": "legacy",
        "SENTRYRUNTIME_URL": "https://runtime.example",
        config.SCOPE_ENV: path.read_text(),
        config.SCOPE_SHA256_ENV: hashlib.sha256(path.read_bytes()).hexdigest(),
    }
    assert config.execution_mode_for(A, settings) == "runtime"
    assert config.execution_mode_for("33333333-3333-4333-8333-333333333333", settings) == "legacy"


def test_a_milestone_name_is_a_plain_file_name(tmp_path):
    common = ["--target", str(target(tmp_path)), "--work", str(tmp_path / "work")]
    code, out = run(tmp_path, "expand", *common, "--milestone", "../first",
                    "--identities", str(identities(tmp_path, "one", A)))  # fmt: skip
    assert code == 2 and "milestone name" in out


def test_pre_cutover_needs_the_deployed_settings(tmp_path):
    with pytest.raises(SystemExit):
        cutover.main(["pre-cutover", "--target", str(target(tmp_path)), "--work",
                      str(tmp_path / "work")], out=io.StringIO())  # fmt: skip
