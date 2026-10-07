"""Offline contracts for the guarded release-tools jobs.

Real subprocesses exercise the watchdog and a fake psql replaces the database.
No container, database, network service or AWS identity is used.
"""

import base64
import hashlib
import hmac
import json
import os
import signal
import subprocess
import sys
import textwrap
import threading
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from release.manifest import RUNTIME_GRANT_PIN
from release_tools import config, digest, guard, jobs, receipt, scram, session

RELEASE_ID = "22222222-2222-4222-8222-222222222222"
TASK_ARN = "arn:aws:ecs:us-east-1:111122223333:task/sentry-staging/" + "a" * 32
NOW = datetime(2026, 10, 7, 12, 0, tzinfo=UTC)
PACKAGE = Path(__file__).resolve().parents[1] / "release_tools"


def environment(kind: str, database: str = "runtime", **overrides: str) -> dict[str, str]:
    main = config.MAIN_SQL[(kind, database)]
    values = {
        "RELEASE_ID": RELEASE_ID,
        "RELEASE_JOB_ID": f"{database}-{kind}",
        "RELEASE_DATABASE": database,
        "RELEASE_NOT_AFTER": "2026-10-07T13:00:00Z",
        "RELEASE_JOB_BUDGET_SECONDS": "900",
        "RELEASE_TOOLS_SHA256": digest.tools_sha256(),
        "RELEASE_SQL_SHA256": digest.file_sha256(PACKAGE / main),
        "RELEASE_EXPECT_DATABASE": "sentryruntime" if database == "runtime" else "sentrysearch",
        "ECS_CONTAINER_METADATA_URI_V4": "http://169.254.170.2/v4/fixture",
    }
    owner, service = ("runtime_owner", "runtime_app")
    if database == "product":
        owner, service = ("search_owner", "search_app")
    principal = {"grant": owner, "reconcile": owner, "proof": service, "bootstrap": "postgres"}
    values["RELEASE_EXPECT_PRINCIPAL"] = principal[kind]
    if kind in {"grant", "bootstrap"}:
        values["RELEASE_SERVICE_ROLE"] = service
    if kind in {"proof", "bootstrap"}:
        values["RELEASE_OWNER_ROLE"] = owner
    if kind == "bootstrap":
        values["RELEASE_EXPECT_DATABASE"] = "postgres"
        values["RELEASE_TARGET_DATABASE"] = (
            "sentryruntime" if database == "runtime" else "sentrysearch"
        )
        values["RELEASE_OWNER_PASSWORD"] = "owner-" + "x" * 30
        values["RELEASE_SERVICE_PASSWORD"] = "service-" + "y" * 30
    user = values["RELEASE_EXPECT_PRINCIPAL"]
    dbname = values["RELEASE_EXPECT_DATABASE"]
    if database == "runtime" and kind != "bootstrap":
        values["DATABASE_URL"] = (
            f"postgres://{user}:s3cret-pw@db.internal.example:5432/{dbname}"
            "?sslmode=verify-full&sslrootcert=/run/material/postgres-ca.pem"
        )
    else:
        values.update(
            DB_HOST="db.internal.example",
            DB_PORT="5432",
            DB_NAME=dbname,
            DB_USER=user,
            DB_PASSWORD="s3cret-pw",
        )
    values.update(overrides)
    return values


# --- integrity -------------------------------------------------------------


def test_vendored_runtime_grant_is_the_pinned_reviewed_source():
    path = PACKAGE / "sql" / "runtime" / "service.sql"
    assert digest.file_sha256(path) == RUNTIME_GRANT_PIN["sha256"]


def test_tools_digest_is_deterministic_and_binds_every_file(tmp_path):
    copy = tmp_path / "release_tools"
    subprocess.run(["cp", "-R", str(PACKAGE), str(copy)], check=True)
    for cache in copy.rglob("__pycache__"):
        subprocess.run(["rm", "-rf", str(cache)], check=True)
    assert digest.tools_sha256(copy) == digest.tools_sha256(PACKAGE)
    (copy / "sql" / "reconcile.sql").write_text("-- changed\n")
    assert digest.tools_sha256(copy) != digest.tools_sha256(PACKAGE)


def test_tools_digest_rejects_symlinks(tmp_path):
    root = tmp_path / "tools"
    root.mkdir()
    (root / "a.py").write_text("x = 1\n")
    (root / "b.py").symlink_to(root / "a.py")
    with pytest.raises(digest.IntegrityError):
        digest.tools_sha256(root)


# --- configuration ---------------------------------------------------------


@pytest.mark.parametrize("kind", sorted(config.KINDS))
@pytest.mark.parametrize("database", sorted(config.DATABASES))
def test_valid_job_configuration_loads(kind, database):
    loaded = config.load(kind, environment(kind, database))
    assert loaded.kind == kind and loaded.database == database
    assert loaded.connection.user == loaded.expect_principal
    assert "s3cret" not in repr(loaded)


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"RELEASE_ID": "not-a-uuid"}, "release_id_invalid"),
        ({"RELEASE_JOB_ID": "Runtime_Grant"}, "job_id_invalid"),
        ({"RELEASE_DATABASE": "shared"}, "database_invalid"),
        ({"RELEASE_NOT_AFTER": "2026-10-07 13:00"}, "not_after_invalid"),
        ({"RELEASE_JOB_BUDGET_SECONDS": "59"}, "budget_invalid"),
        ({"RELEASE_JOB_BUDGET_SECONDS": "3601"}, "budget_invalid"),
        ({"RELEASE_JOB_BUDGET_SECONDS": "\u0666\u0660"}, "budget_invalid"),
        ({"RELEASE_TOOLS_SHA256": "latest"}, "tools_sha256_invalid"),
        ({"RELEASE_SQL_SHA256": "A" * 64}, "sql_sha256_invalid"),
        ({"RELEASE_EXPECT_DATABASE": "Runtime-DB"}, "identifier_invalid"),
        ({"RELEASE_SERVICE_ROLE": "runtime_owner"}, "roles_not_distinct"),
        ({"RELEASE_EXPECT_PRINCIPAL": "someone_else"}, "principal_mismatch"),
        ({"RELEASE_JOB_ID": "r" + "x" * 40}, "application_name_too_long"),
        ({"DATABASE_URL": "postgres://u:p@h/db?sslmode=require"}, "database_url_invalid"),
        ({"DATABASE_URL": "postgres://runtime_owner:p@a,b/sentryruntime"}, "database_url_invalid"),
        ({"DATABASE_URL": "mysql://runtime_owner:p@h/sentryruntime"}, "database_url_invalid"),
        ({"DB_HOST": "db.internal.example"}, "credentials_ambiguous"),
    ],
)
def test_invalid_runtime_grant_configuration_is_rejected(change, reason):
    with pytest.raises(config.ConfigError) as error:
        config.load("grant", environment("grant", "runtime", **change))
    assert error.value.reason == reason


def test_missing_credentials_and_incomplete_db_settings_are_rejected():
    values = environment("grant", "runtime")
    del values["DATABASE_URL"]
    with pytest.raises(config.ConfigError, match="credentials_missing"):
        config.load("grant", values)
    values = environment("grant", "product")
    del values["DB_PORT"]
    with pytest.raises(config.ConfigError, match="credentials_incomplete"):
        config.load("grant", values)


def test_non_ascii_port_digits_are_a_configuration_error():
    with pytest.raises(config.ConfigError, match="port_invalid"):
        config.load("grant", environment("grant", "product", DB_PORT="\u0665\u0664\u0663\u0662"))


def test_proof_principal_cannot_be_the_owner():
    values = environment(
        "proof", "product", RELEASE_EXPECT_PRINCIPAL="search_owner", DB_USER="search_owner"
    )
    with pytest.raises(config.ConfigError, match="roles_not_distinct"):
        config.load("proof", values)


def test_bootstrap_requires_printable_distinct_passwords():
    with pytest.raises(config.ConfigError, match="password_invalid"):
        config.load("bootstrap", environment("bootstrap", RELEASE_OWNER_PASSWORD="short"))
    with pytest.raises(config.ConfigError, match="password_invalid"):
        config.load(
            "bootstrap", environment("bootstrap", RELEASE_SERVICE_PASSWORD="tab\tin" + "z" * 30)
        )
    same = "same-" + "q" * 30
    with pytest.raises(config.ConfigError, match="password_invalid"):
        config.load(
            "bootstrap",
            environment("bootstrap", RELEASE_OWNER_PASSWORD=same, RELEASE_SERVICE_PASSWORD=same),
        )


# --- deadlines and session limits ------------------------------------------


def test_deadline_is_the_earlier_of_window_and_job_budget():
    loaded = config.load("grant", environment("grant"))
    assert guard.job_deadline(loaded, NOW) == NOW + timedelta(seconds=900)
    late = NOW + timedelta(minutes=55)
    assert guard.job_deadline(loaded, late) == datetime(2026, 10, 7, 13, 0, tzinfo=UTC)


def test_session_limits_are_capped_by_remaining_budget():
    limits = session.limits(remaining_seconds=600)
    assert limits.statement_ms == 60_000 and limits.lock_ms == 3_000
    assert limits.idle_ms == 10_000 and limits.check_interval_ms == 1_000
    short = session.limits(remaining_seconds=4.5)
    assert short.statement_ms == 2_500 and short.lock_ms == 2_500
    with pytest.raises(session.BudgetExhausted):
        session.limits(remaining_seconds=2.9)


def test_psql_receives_credentials_only_through_environment():
    loaded = config.load("grant", environment("grant"))
    limits = session.limits(remaining_seconds=600)
    env = session.psql_environment(loaded.connection, "release:x:runtime-grant", limits, {})
    argv = session.psql_argv([Path("/x.sql")], {"database_name": "sentryruntime"})
    assert env["PGPASSWORD"] == "s3cret-pw" and "s3cret" not in " ".join(argv)
    assert env["PGSSLMODE"] == "verify-full"
    assert env["PGSSLROOTCERT"] == "/run/material/postgres-ca.pem"
    assert env["PGGSSENCMODE"] == "disable" and env["PGAPPNAME"] == "release:x:runtime-grant"
    assert env["PGOPTIONS"] == (
        "-c statement_timeout=60000 -c lock_timeout=3000 "
        "-c idle_in_transaction_session_timeout=10000 -c client_connection_check_interval=1000"
    )
    assert not set(env) - set(session.PSQL_ENVIRONMENT_KEYS)
    assert argv[:2] == [str(session.PSQL), "-X"] and "ON_ERROR_STOP=1" in argv
    with pytest.raises(ValueError):
        session.psql_argv([Path("/x.sql")], {"bad name": "x"})
    with pytest.raises(ValueError):
        session.psql_argv([Path("/x.sql")], {"role": "x'; DROP"})


@pytest.mark.parametrize(
    ("stderr", "reason"),
    [
        ("psql:/app/x.sql:9: ERROR:  RT001", "wrong_database"),
        ("psql:/app/x.sql:9: ERROR:  RT002", "wrong_principal"),
        ("psql:/app/x.sql:9: ERROR:  RT010", "budget_exhausted"),
        ("psql:/app/x.sql:9: ERROR:  RT117", "denial_failed"),
        ("psql:/app/x.sql:9: ERROR:  RT105", "privilege_inventory_mismatch"),
        ("psql:/app/x.sql:9: ERROR:  RT203", "bootstrap_conflict"),
        ("psql:/app/x.sql:9: ERROR:  42501", "permission_denied"),
        ("psql:/app/x.sql:9: ERROR:  57014", "statement_timeout"),
        ("psql:/app/x.sql:9: ERROR:  55P03", "lock_timeout"),
        ("psql:/app/x.sql:9: ERROR:  P0001", "sql_error"),
        (
            'psql: error: connection to server at "h" (10.0.0.1), port 5432 failed: '
            "root certificate file ... certificate verify failed",
            "tls_untrusted",
        ),
        ("psql: error: ... server does not support SSL, but SSL was required", "tls_unavailable"),
        ('psql: error: ... FATAL:  password authentication failed for user "u"', "auth_failed"),
        ('psql: error: ... FATAL:  permission denied for database "postgres"', "connect_denied"),
        ("psql: error: could not translate host name", "unreachable"),
        ("psql: error: something else", "connection_failed"),
    ],
)
def test_errors_are_classified_without_echoing_text(stderr, reason):
    assert session.classify(stderr) == reason


def test_results_parse_only_marked_unique_lines():
    out = "sentryruntime\nresult|database|sentryruntime\nresult|principal|runtime_owner\n"
    assert session.parse_results(out) == {
        "database": "sentryruntime",
        "principal": "runtime_owner",
    }
    with pytest.raises(session.SessionError):
        session.parse_results("result|database|a\nresult|database|b\n")


# --- watchdog --------------------------------------------------------------


def _alive(pid: int) -> bool:
    """A zombie awaiting its (re)parent's reap no longer runs, so it counts as dead."""
    try:
        state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
    except (FileNotFoundError, ProcessLookupError):
        return False
    return state != "Z"


def test_watchdog_returns_completed_child_output():
    result = guard.Watchdog(time.monotonic() + 10).run(
        [sys.executable, "-c", "print('ok')"], env={}
    )
    assert result.outcome is guard.Outcome.COMPLETED and result.returncode == 0
    assert result.stdout.strip() == "ok"


def test_watchdog_kills_hung_process_group_including_term_ignoring_grandchild(tmp_path):
    pids = tmp_path / "pids"
    script = textwrap.dedent(f"""
        import os, signal, subprocess, sys, time
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        child = subprocess.Popen([sys.executable, "-c",
            "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(600)"])
        open({str(pids)!r}, "w").write(f"{{os.getpid()}} {{child.pid}}")
        time.sleep(600)
        """)
    started = time.monotonic()
    result = guard.Watchdog(started + 1.0, grace=0.5).run([sys.executable, "-c", script], env={})
    assert result.outcome is guard.Outcome.DEADLINE
    assert time.monotonic() - started < 6
    for pid in map(int, pids.read_text().split()):
        for _ in range(50):
            if not _alive(pid):
                break
            time.sleep(0.05)
        assert not _alive(pid)


def test_guard_forwards_termination_to_the_child_group(tmp_path):
    marker = tmp_path / "child"
    harness = textwrap.dedent(f"""
        import sys, time
        sys.path.insert(0, {str(PACKAGE.parent)!r})
        from release_tools import guard
        result = guard.Watchdog(time.monotonic() + 60).run(
            [sys.executable, "-c",
             "import os,time; open({str(marker)!r},'w').write(str(os.getpid())); time.sleep(600)"],
            env={{}})
        print(result.outcome.value, flush=True)
        """)
    process = subprocess.Popen([sys.executable, "-c", harness], stdout=subprocess.PIPE, text=True)
    for _ in range(100):
        if marker.exists() and marker.read_text():
            break
        time.sleep(0.05)
    process.send_signal(signal.SIGTERM)
    out, _ = process.communicate(timeout=20)
    assert out.strip() == "terminated"
    assert not _alive(int(marker.read_text()))


def test_stop_requested_before_launch_terminates_the_new_child_gracefully(tmp_path):
    marker = tmp_path / "got-term"
    script = textwrap.dedent(f"""
        import signal, sys, time
        def stop(*_):
            open({str(marker)!r}, "w").write("term")
            sys.exit(0)
        signal.signal(signal.SIGTERM, stop)
        time.sleep(30)
        """)
    watchdog = guard.Watchdog(time.monotonic() + 30, grace=2.0)
    watchdog._on_signal(signal.SIGTERM, None)
    started = time.monotonic()
    result = watchdog.run([sys.executable, "-c", script], env={})
    # SIGTERM arrives at once (possibly before the child's handler exists), not
    # as a SIGKILL after the 2-second grace.
    assert result.outcome is guard.Outcome.TERMINATED
    assert time.monotonic() - started < 1.5
    assert result.returncode == -signal.SIGTERM or (
        result.returncode == 0 and marker.read_text() == "term"
    )


def test_escaped_descendant_holding_output_cannot_hang_the_watchdog(tmp_path):
    pidfile = tmp_path / "escaped"
    script = textwrap.dedent(f"""
        import signal, subprocess, sys, time
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"],
                                 start_new_session=True)
        open({str(pidfile)!r}, "w").write(str(child.pid))
        time.sleep(60)
        """)
    started = time.monotonic()
    try:
        result = guard.Watchdog(started + 1.0, grace=0.5).run(
            [sys.executable, "-c", script], env={}
        )
        assert result.outcome is guard.Outcome.DEADLINE
        assert time.monotonic() - started < 6
    finally:
        if pidfile.exists():
            os.kill(int(pidfile.read_text()), signal.SIGKILL)


# --- receipts and logs -----------------------------------------------------


def test_success_receipt_is_the_controller_envelope(capsys):
    receipt.emit_receipt(
        release_id=RELEASE_ID,
        job_id="runtime-grant",
        task_arn=TASK_ARN,
        status="succeeded",
        result={"database": "sentryruntime", "principal": "runtime_owner"},
    )
    line = capsys.readouterr().out.strip()
    marker, payload = line.split(" ", 1)
    assert marker == receipt.RECEIPT_MARKER
    assert json.loads(payload) == {
        "schema": receipt.RECEIPT_SCHEMA,
        "release_id": RELEASE_ID,
        "job_id": "runtime-grant",
        "task_arn": TASK_ARN,
        "status": "succeeded",
        "result": {"database": "sentryruntime", "principal": "runtime_owner"},
    }


def test_log_events_accept_only_bounded_allowlisted_fields(capsys):
    receipt.log("job_failed", reason="auth_failed", job_id="runtime-grant")
    event = json.loads(capsys.readouterr().err)
    assert event == {"event": "job_failed", "reason": "auth_failed", "job_id": "runtime-grant"}
    with pytest.raises(ValueError):
        receipt.log("job_failed", stderr="raw driver text")


# --- SCRAM verifiers ---------------------------------------------------------


def test_scram_keys_reproduce_the_rfc_7677_exchange():
    salt = base64.b64decode("W22ZaJ0SNY7soEsUEjb6gQ==")
    stored, server = scram.keys("pencil", salt, 4096)
    auth = (
        "n=user,r=rOprNGfwEbeRWgbNEkqO,"
        "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,"
        "s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,"
        "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"
    ).encode()
    salted = hashlib.pbkdf2_hmac("sha256", b"pencil", salt, 4096)
    client_key = hmac.new(salted, b"Client Key", "sha256").digest()
    assert hashlib.sha256(client_key).digest() == stored
    signature = hmac.new(stored, auth, "sha256").digest()
    proof = bytes(a ^ b for a, b in zip(client_key, signature))
    assert base64.b64encode(proof).decode() == "dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
    server_signature = hmac.new(server, auth, "sha256").digest()
    assert base64.b64encode(server_signature).decode() == (
        "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="
    )


def test_scram_verifier_has_postgres_format_and_fresh_salt():
    first, second = scram.verifier("pencil"), scram.verifier("pencil")
    assert first != second
    assert first.startswith("SCRAM-SHA-256$4096:") and "pencil" not in first


# --- job orchestration with a fake psql --------------------------------------


class _Metadata(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - http.server API
        body = json.dumps({"TaskARN": TASK_ARN}).encode()
        self.send_response(200 if self.path.endswith("/task") else 404)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - http.server API
        pass


@pytest.fixture
def metadata():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Metadata)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}/v4/fixture"
    server.shutdown()


@pytest.fixture
def fake_psql(tmp_path, monkeypatch):
    """A psql stand-in that records argv/env and replays a scripted reply."""
    calls = tmp_path / "calls.jsonl"
    script = tmp_path / "psql"
    script.write_text(textwrap.dedent(f"""\
            #!{sys.executable}
            import json, os, sys, time
            with open({str(calls)!r}, "a") as f:
                f.write(json.dumps({{"argv": sys.argv[1:], "env": dict(os.environ)}}) + "\\n")
            reply = json.loads(os.environ.get("FAKE_REPLY", "{{}}"))
            time.sleep(reply.get("sleep", 0))
            sys.stdout.write(reply.get("stdout", ""))
            sys.stderr.write(reply.get("stderr", ""))
            sys.exit(reply.get("code", 0))
            """))
    script.chmod(0o755)
    material = tmp_path / "postgres-ca.pem"
    material.write_text("-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n")
    material.chmod(0o400)
    monkeypatch.setattr(session, "PSQL", script)
    monkeypatch.setattr(session, "CA_PATH", material)
    replies: list[dict] = []

    def reply(**values):
        replies.append(values)

    original = session.run_psql

    def scripted(*args, **kwargs):
        extra = dict(kwargs.pop("extra_env", {}) or {})
        if replies:
            extra["FAKE_REPLY"] = json.dumps(replies.pop(0))
        return original(*args, extra_env=extra, **kwargs)

    monkeypatch.setattr(session, "run_psql", scripted)
    monkeypatch.setattr(
        session, "PSQL_ENVIRONMENT_KEYS", (*session.PSQL_ENVIRONMENT_KEYS, "FAKE_REPLY")
    )

    def recorded() -> list[dict]:
        if not calls.exists():
            return []
        return [json.loads(line) for line in calls.read_text().splitlines()]

    return reply, recorded


def _run(kind, database, metadata, capsys, **overrides):
    env = environment(kind, database, ECS_CONTAINER_METADATA_URI_V4=metadata, **overrides)
    code = jobs.main([kind], env, now=lambda: NOW)
    captured = capsys.readouterr()
    receipts = [
        json.loads(line.split(" ", 1)[1])
        for line in captured.out.splitlines()
        if line.startswith(receipt.RECEIPT_MARKER + " ")
    ]
    return code, receipts, captured


def test_grant_success_emits_bound_receipt_after_one_session(fake_psql, metadata, capsys):
    reply, recorded = fake_psql
    reply(stdout="result|database|sentryruntime\nresult|principal|runtime_owner\n")
    code, receipts, captured = _run("grant", "runtime", metadata, capsys)
    assert code == 0
    assert receipts == [
        {
            "schema": receipt.RECEIPT_SCHEMA,
            "release_id": RELEASE_ID,
            "job_id": "runtime-grant",
            "task_arn": TASK_ARN,
            "status": "succeeded",
            "result": {
                "database": "sentryruntime",
                "principal": "runtime_owner",
                "service_role": "runtime_app",
                "sql_digest": RUNTIME_GRANT_PIN["sha256"],
            },
        }
    ]
    (call,) = recorded()
    files = [call["argv"][i + 1] for i, a in enumerate(call["argv"]) if a == "-f"]
    assert [Path(f).name for f in files] == [
        "session_check.sql",
        "refresh.sql",
        "service.sql",
        "refresh.sql",
        "identity.sql",
    ]
    assert "s3cret" not in captured.out + captured.err + json.dumps(call["argv"])


def test_observed_identity_mismatch_is_not_success(fake_psql, metadata, capsys):
    reply, _ = fake_psql
    reply(stdout="result|database|sentrysearch\nresult|principal|runtime_owner\n")
    code, receipts, _ = _run("grant", "runtime", metadata, capsys)
    assert code != 0 and receipts[0]["status"] == "failed"
    assert receipts[0]["result"] == {"reason": "observation_mismatch", "sql_outcome": "unknown"}


@pytest.mark.parametrize(
    ("override", "reason", "code"),
    [
        ({"RELEASE_NOT_AFTER": "2026-10-07T11:59:59Z"}, "deadline_expired", 4),
        ({"RELEASE_SQL_SHA256": "0" * 64}, "sql_hash_mismatch", 3),
        ({"RELEASE_TOOLS_SHA256": "0" * 64}, "tools_hash_mismatch", 3),
        (
            {"ECS_CONTAINER_METADATA_URI_V4": "http://127.0.0.1:9/v4/x"},
            "task_identity_unavailable",
            6,
        ),
    ],
)
def test_preflight_failures_never_start_psql(fake_psql, metadata, capsys, override, reason, code):
    _, recorded = fake_psql
    env = environment("grant", "runtime", **{"ECS_CONTAINER_METADATA_URI_V4": metadata, **override})
    result = jobs.main(["grant"], env, now=lambda: NOW)
    captured = capsys.readouterr()
    assert result == code and recorded() == []
    assert json.loads(captured.err.splitlines()[-1])["reason"] == reason


def test_missing_ca_material_fails_before_any_connection(fake_psql, metadata, capsys, monkeypatch):
    _, recorded = fake_psql
    monkeypatch.setattr(session, "CA_PATH", Path("/nonexistent/postgres-ca.pem"))
    code, receipts, _ = _run("grant", "runtime", metadata, capsys)
    assert code == 5 and recorded() == []
    assert receipts[0]["result"] == {"reason": "material_invalid", "sql_outcome": "none"}


def test_group_or_world_readable_trust_material_is_rejected(fake_psql, metadata, capsys):
    _, recorded = fake_psql
    session.CA_PATH.chmod(0o440)
    code, receipts, _ = _run("grant", "runtime", metadata, capsys)
    assert code == 5 and recorded() == []
    assert receipts[0]["result"] == {"reason": "material_invalid", "sql_outcome": "none"}


def test_budget_exhausted_after_sql_ran_is_unknown_not_none(fake_psql, metadata, capsys):
    reply, recorded = fake_psql
    reply(
        stdout="result|database|sentrysearch\nresult|principal|search_app\n"
        "result|schema|sentrysearch:1:0123456789abcdef\n"
    )
    clock = iter([NOW, NOW])
    env = environment("proof", "product", ECS_CONTAINER_METADATA_URI_V4=metadata)
    code = jobs.main(["proof"], env, now=lambda: next(clock, NOW + timedelta(seconds=899)))
    receipts = [
        json.loads(line.split(" ", 1)[1])
        for line in capsys.readouterr().out.splitlines()
        if line.startswith(receipt.RECEIPT_MARKER + " ")
    ]
    assert len(recorded()) == 1 and code == 124
    assert receipts[0]["result"] == {"reason": "deadline_exceeded", "sql_outcome": "unknown"}


def test_connection_failure_is_sql_outcome_none(fake_psql, metadata, capsys):
    reply, _ = fake_psql
    reply(
        code=2,
        stderr='psql: error: connection to server failed: FATAL:  password authentication failed for user "x"\n',
    )
    code, receipts, captured = _run("grant", "runtime", metadata, capsys)
    assert code == 10
    assert receipts[0]["result"] == {"reason": "auth_failed", "sql_outcome": "none"}
    assert "password authentication" not in captured.err


def test_sql_failure_after_connect_is_unknown_outcome(fake_psql, metadata, capsys):
    reply, _ = fake_psql
    reply(code=3, stderr="psql:/app/release_tools/sql/session_check.sql:20: ERROR:  RT001\n")
    code, receipts, _ = _run("grant", "runtime", metadata, capsys)
    assert code == 11
    assert receipts[0]["result"] == {"reason": "wrong_database", "sql_outcome": "unknown"}


def test_deadline_during_sql_stops_psql_and_holds(fake_psql, metadata, capsys, monkeypatch):
    reply, _ = fake_psql
    reply(sleep=30)
    monkeypatch.setattr(guard, "MINIMUM_GRACE_SECONDS", 0.2)
    env = environment(
        "grant",
        "runtime",
        ECS_CONTAINER_METADATA_URI_V4=metadata,
        RELEASE_NOT_AFTER=(datetime.now(UTC) + timedelta(seconds=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    started = time.monotonic()
    code = jobs.main(["grant"], env)
    captured = capsys.readouterr()
    assert code == 124 and time.monotonic() - started < 15
    assert '"reason":"deadline_exceeded"' in captured.out.replace(" ", "")
    assert '"sql_outcome":"unknown"' in captured.out.replace(" ", "")


def test_proof_requires_cross_database_denial(fake_psql, metadata, capsys):
    reply, recorded = fake_psql
    reply(
        stdout="result|database|sentrysearch\nresult|principal|search_app\n"
        "result|schema|sentrysearch:1:0123456789abcdef\n"
    )
    reply(code=2, stderr='psql: error: ... FATAL:  permission denied for database "postgres"\n')
    code, receipts, _ = _run("proof", "product", metadata, capsys)
    assert code == 0, receipts
    assert receipts[0]["result"]["schema"] == "sentrysearch:1:0123456789abcdef"
    second = recorded()[1]
    assert second["env"]["PGDATABASE"] == "postgres" and "-c" in second["argv"]


def test_proof_fails_when_service_can_reach_another_database(fake_psql, metadata, capsys):
    reply, _ = fake_psql
    reply(
        stdout="result|database|sentrysearch\nresult|principal|search_app\n"
        "result|schema|sentrysearch:1:0123456789abcdef\n"
    )
    reply(stdout="1\n")
    code, receipts, _ = _run("proof", "product", metadata, capsys)
    assert code == 11
    assert receipts[0]["result"] == {"reason": "cross_database_access", "sql_outcome": "unknown"}


def test_bootstrap_passes_only_scram_verifiers_to_psql(fake_psql, metadata, capsys):
    reply, recorded = fake_psql
    reply(
        stdout="result|database|sentryruntime\nresult|principal|postgres\n"
        "result|owner_role|runtime_owner\nresult|service_role|runtime_app\n"
    )
    code, receipts, _ = _run("bootstrap", "runtime", metadata, capsys)
    assert code == 0, receipts
    (call,) = recorded()
    serialized = json.dumps(call)
    assert "owner-xxxx" not in serialized and "service-yyyy" not in serialized
    assert call["env"]["RELEASE_OWNER_VERIFIER"].startswith("SCRAM-SHA-256$4096:")
    assert receipts[0]["result"] == {
        "database": "sentryruntime",
        "principal": "postgres",
        "owner_role": "runtime_owner",
        "service_role": "runtime_app",
    }


def test_reconcile_reports_session_counts_and_logs_exact_identities(fake_psql, metadata, capsys):
    reply, _ = fake_psql
    reply(
        stdout="result|database|sentryruntime\nresult|principal|runtime_owner\n"
        "result|schema|goose:1,2,3\nresult|release_sessions|1\nresult|owner_sessions|1\n"
        "session|4242|2026-10-07T11:59:00.000000Z|sentryruntime|runtime_owner|"
        f"release:{RELEASE_ID}:runtime-grant|active\n"
    )
    code, receipts, captured = _run("reconcile", "runtime", metadata, capsys)
    assert code == 0
    assert receipts[0]["result"]["release_sessions"] == "1"
    events = [json.loads(line) for line in captured.err.splitlines()]
    assert {
        "event": "session_observed",
        "pid": "4242",
        "backend_start": "2026-10-07T11:59:00.000000Z",
        "database": "sentryruntime",
        "principal": "runtime_owner",
        "application_name": f"release:{RELEASE_ID}:runtime-grant",
        "state": "active",
    } in events


def test_unknown_command_is_rejected(capsys):
    assert jobs.main(["drop-everything"], {}) == 2
    assert jobs.main([], {}) == 2


def test_digest_command_reports_build_pins(capsys):
    assert jobs.main(["digest"], {}) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["tools_sha256"] == digest.tools_sha256()
    assert report["sql"]["sql/runtime/service.sql"] == RUNTIME_GRANT_PIN["sha256"]


# --- controller contract -------------------------------------------------------


def test_receipt_schema_and_result_keys_match_the_manifest_contract():
    from pydantic import TypeAdapter

    from release.manifest import (
        PRODUCT_GRANT_PATH,
        RELEASE_TOOLS_RECEIPT_SCHEMA,
        RELEASE_TOOLS_RESULT_KEYS,
        Expectation,
    )

    assert receipt.RECEIPT_SCHEMA == RELEASE_TOOLS_RECEIPT_SCHEMA
    assert PRODUCT_GRANT_PATH == "release_tools/" + config.MAIN_SQL[("grant", "product")]
    assert (PACKAGE.parent / PRODUCT_GRANT_PATH).is_file()
    adapter = TypeAdapter(Expectation)
    grant = {"database": "a", "principal": "b", "service_role": "c", "sql_digest": "d" * 64}
    proof = {"database": "a", "principal": "c", "schema": "goose:1,2,3"}
    assert set(grant) == RELEASE_TOOLS_RESULT_KEYS["grant"]
    assert set(proof) == RELEASE_TOOLS_RESULT_KEYS["proof"]
    adapter.validate_python(grant)
    adapter.validate_python(proof)


def test_tool_receipt_is_accepted_by_the_controller_only_when_exact(fake_psql, metadata, capsys):
    from release.machine import evaluate_job
    from release.manifest import load_manifest
    from tests.release_fakes import encode, manifest_document

    reply, _ = fake_psql
    reply(stdout="result|database|sentryruntime\nresult|principal|runtime_owner\n")
    code, receipts, captured = _run("grant", "runtime", metadata, capsys)
    assert code == 0
    document = manifest_document()
    images = {name: document["images"][name]["arm64_digest"] for name in document["images"]}
    job = document["jobs"][2]
    job["expect"] = dict(receipts[0]["result"])
    document["jobs"][0]["expect"].update(database="sentryruntime", principal="runtime_owner")
    document["jobs"][4]["expect"].update(database="sentryruntime", principal="runtime_app")
    document["release_id"] = RELEASE_ID
    manifest = load_manifest(encode(document)).manifest
    task = {
        "taskArn": TASK_ARN,
        "taskDefinitionArn": job["task"]["task_definition"],
        "lastStatus": "STOPPED",
        "startedBy": "launch-token",
        "stopCode": "EssentialContainerExited",
        "containers": [
            {"name": "init", "imageDigest": images["search"], "exitCode": 0},
            {"name": "grant", "imageDigest": images["release_tools"], "exitCode": 0},
        ],
    }
    lines = captured.out.splitlines() + captured.err.splitlines()
    found = receipt.extract_receipt(lines)
    assert found is not None
    evaluate = lambda value: evaluate_job(  # noqa: E731
        manifest.jobs[2], images, release_id=RELEASE_ID, token="launch-token",
        task=task, receipt=value,
    )  # fmt: skip
    assert evaluate(found) is None
    assert evaluate({**found, "task_arn": TASK_ARN[:-1] + "b"}) == "job_receipt_mismatch"
    assert evaluate({**found, "result": {**found["result"], "sql_digest": "0" * 64}}) == (
        "job_receipt_mismatch"
    )


def test_receipt_extraction_holds_on_missing_or_ambiguous_streams():
    good = (
        receipt.RECEIPT_MARKER
        + " "
        + json.dumps(
            {
                "schema": receipt.RECEIPT_SCHEMA,
                "release_id": RELEASE_ID,
                "job_id": "runtime-grant",
                "task_arn": TASK_ARN,
                "status": "failed",
                "result": {"reason": "auth_failed", "sql_outcome": "none"},
            }
        )
    )
    assert receipt.extract_receipt(['{"event":"job_started"}']) is None
    extracted = receipt.extract_receipt([good])
    assert extracted is not None and extracted["status"] == "failed"
    for stream in (
        [good, good],
        [receipt.RECEIPT_MARKER + " {not json"],
        [receipt.RECEIPT_MARKER + "{}"],
        [receipt.RECEIPT_MARKER + ' {"schema": "x"}'],
        [receipt.RECEIPT_MARKER + " " + json.dumps({**json.loads(good.split(" ", 1)[1]), "x": 1})],
    ):
        with pytest.raises(receipt.ReceiptAmbiguous):
            receipt.extract_receipt(stream)


# --- additional preflight and job outcomes -------------------------------------


@pytest.mark.parametrize(
    "uri",
    ["http://10.0.0.8/v4/x", "https://169.254.170.2/v4/x", "http://169.254.170.2/v3/x", ""],
)
def test_task_identity_comes_only_from_the_ecs_metadata_endpoint(fake_psql, capsys, uri):
    _, recorded = fake_psql
    env = environment("grant", "runtime", ECS_CONTAINER_METADATA_URI_V4=uri)
    assert jobs.main(["grant"], env, now=lambda: NOW) == 6 and recorded() == []
    assert json.loads(capsys.readouterr().err.splitlines()[-1])["reason"] == (
        "task_identity_unavailable"
    )


def test_budget_too_short_for_a_session_never_connects(fake_psql, metadata, capsys):
    _, recorded = fake_psql
    code, receipts, _ = _run(
        "grant", "runtime", metadata, capsys, RELEASE_NOT_AFTER="2026-10-07T12:00:06Z"
    )
    assert code == 4 and recorded() == []
    assert receipts[0]["result"] == {"reason": "deadline_expired", "sql_outcome": "none"}


def test_symlinked_trust_material_is_rejected(fake_psql, metadata, capsys, monkeypatch, tmp_path):
    _, recorded = fake_psql
    link = tmp_path / "linked-ca.pem"
    link.symlink_to(session.CA_PATH)
    monkeypatch.setattr(session, "CA_PATH", link)
    code, receipts, _ = _run("grant", "runtime", metadata, capsys)
    assert code == 5 and recorded() == []
    assert receipts[0]["result"]["reason"] == "material_invalid"


def test_proof_cross_database_check_requires_an_explicit_privilege_denial(
    fake_psql, metadata, capsys
):
    reply, _ = fake_psql
    reply(
        stdout="result|database|sentrysearch\nresult|principal|search_app\n"
        "result|schema|sentrysearch:1:0123456789abcdef\n"
    )
    reply(code=2, stderr="psql: error: could not translate host name\n")
    code, receipts, _ = _run("proof", "product", metadata, capsys)
    assert code == 11
    assert receipts[0]["result"] == {"reason": "cross_database_unproven", "sql_outcome": "unknown"}


def test_duplicate_results_are_not_success(fake_psql, metadata, capsys):
    reply, _ = fake_psql
    reply(stdout="result|database|sentryruntime\nresult|database|sentryruntime\n")
    code, receipts, _ = _run("grant", "runtime", metadata, capsys)
    assert code == 11
    assert receipts[0]["result"] == {"reason": "result_invalid", "sql_outcome": "unknown"}


def test_reconcile_marks_unexpected_session_fields_invalid(fake_psql, metadata, capsys):
    reply, _ = fake_psql
    reply(
        stdout="result|database|sentryruntime\nresult|principal|runtime_owner\n"
        "result|schema|goose:1,2,3\nresult|release_sessions|0\nresult|owner_sessions|1\n"
        "session|77|unknown|sentryruntime|runtime_app|release x|active\n"
        "session|1|2|3\n"
    )
    code, receipts, captured = _run("reconcile", "runtime", metadata, capsys)
    assert code == 0 and receipts[0]["result"]["owner_sessions"] == "1"
    events = [json.loads(line) for line in captured.err.splitlines()]
    observed = [event for event in events if event["event"] == "session_observed"]
    assert observed[0]["backend_start"] == "unknown"
    assert observed[0]["application_name"] == "invalid"
    assert {"event": "session_unparsed"} in events
