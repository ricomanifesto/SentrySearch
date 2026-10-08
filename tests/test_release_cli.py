"""Operator CLI: local validation, isolated clients, preflight, Clock and commands.

Every client here is built by the production ``AwsClients`` factory from fixture
session credentials; the offline bridge (tests/aws_offline.py) then answers each
validated request in process. Nothing reaches a network, a real credential or a
real account. The STS preflight's identity and ``Date`` header are fixtures.
"""

from __future__ import annotations

import copy
import io
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from pathlib import Path
from typing import Any

import pytest

from release.manifest import load_manifest
from release.ports import ClockUntrusted
from release_cli import main as cli
from release_cli.clients import AwsClients, client_config, isolated_session
from release_cli.clock import (
    MAX_DIVERGENCE_SECONDS,
    MonotonicUtcClock,
    ReferenceSample,
    parse_reference_date,
    reference_offset_bounds,
)
from release_cli.credentials import (
    SCHEMA,
    CredentialsRefused,
    SessionCredentials,
    load_session_credentials,
)
from release_cli.preflight import OperatorIdentity, PreflightRefused
from tests.aws_offline import FakeAws, ServiceError, network_denied
from tests.release_fakes import (
    ACCOUNT,
    REGION,
    START,
    FakeClock,
    FakeEcs,
    FakeEvidence,
    FakeLogs,
    FakeStore,
    JobPlan,
    SimulatedCrash,
    Trace,
    OPERATOR_ROLE,
    FAILED_RELEASE_ID,
    ROLLBACK_RELEASE_ID,
    approval_document,
    encode,
    forward_document,
    manifest_document,
    rollback_run_document,
    sha,
)
from release.journal import Journal, journal_key

ENVIRONMENT = (
    "sentry-staging"  # the roots' name_prefix: control bucket sentry-staging-<acct>-control
)
OPERATOR = "fixture-operator"
ROLE_ARN = OPERATOR_ROLE
ASSUMED = f"arn:aws:sts::{ACCOUNT}:assumed-role/sentry-staging-operator/{OPERATOR}"
ROLE_ID = "AROA" + "Q" * 17
KEY_ID = "ASIA" + "F" * 16
SECRET = "fixture/secret+value/not+a+credential00"[:40].ljust(40, "0")
TOKEN = "Zml4dHVyZS1zZXNzaW9uLXRva2VuLW5vdC1yZWFs"


@pytest.fixture(autouse=True)
def no_network():
    with network_denied() as attempts:
        yield
    assert attempts == [], "a CLI test attempted network access"


def cli_document() -> dict:
    """Schema 2: the approved operator role travels with the hash-approved manifest."""
    document = forward_document(bootstrap=False)
    document["environment"]["name"] = ENVIRONMENT
    return document


def imf_date(moment: datetime) -> str:
    return format_datetime(moment.astimezone(UTC).replace(microsecond=0), usegmt=True)


@dataclass
class CliRig:
    tmp: Path
    document: dict
    clock: FakeClock
    store: FakeStore
    ecs: FakeEcs
    aws: FakeAws
    identity: dict[str, Any] = field(default_factory=dict)
    date_offset: timedelta = timedelta(0)
    sts_delay: float = 0.0
    built: list[str] = field(default_factory=list)
    sessions: list[str] = field(default_factory=list)

    @property
    def manifest_path(self) -> str:
        return str(self.tmp / "manifest.json")

    @property
    def approval_path(self) -> str:
        return str(self.tmp / "approval.json")

    @property
    def credentials_path(self) -> str:
        return str(self.tmp / "custody" / "session.json")

    def sts_identity(self, _params: dict) -> dict:
        self.clock.advance(seconds=self.sts_delay)
        response: dict[str, Any] = {
            "UserId": f"{ROLE_ID}:{OPERATOR}",
            "Account": ACCOUNT,
            "Arn": ASSUMED,
        }
        response.update(self.identity)
        date = imf_date(self.clock.now() + self.date_offset)
        response["ResponseMetadata"] = {"HTTPHeaders": {"date": date}}
        if self.identity.get("ResponseMetadata") == "omit":
            del response["ResponseMetadata"]
        return response

    def clients(self, credentials: SessionCredentials, region: str):
        rig = self

        class Bridged:
            def __init__(self) -> None:
                self.real = AwsClients(credentials, region)

            def client(self, service: str):
                rig.built.append(service)
                return rig.aws.bridge.attach(self.real.client(service))

        return Bridged()

    def operator_clock(self) -> MonotonicUtcClock:
        seconds = lambda: self.clock.now().timestamp()  # noqa: E731
        return MonotonicUtcClock(wall=seconds, monotonic=seconds, wait=self.clock.sleep)

    def main(self, *argv: str, session: str = "cli-session-a", environ=None) -> tuple[int, dict]:
        out = io.StringIO()
        self.sessions.append(session)
        code = cli.main(
            list(argv),
            clients=self.clients,
            clock_factory=self.operator_clock,
            tokens=self.tokens,
            session_ids=lambda: session,
            out=out,
            environ={} if environ is None else environ,
        )
        return code, json.loads(out.getvalue())

    def tokens(self) -> str:
        self._count = getattr(self, "_count", 0) + 1
        return f"clitok{self._count:04d}" + "0" * 26

    def args(self, command: str, *, approval: bool = True) -> list[str]:
        base = [command, "--manifest", self.manifest_path]
        if approval:
            base += ["--approval", self.approval_path]
        return base + ["--credentials", self.credentials_path]

    def calls(self) -> list[tuple[str, str]]:
        return [(service, operation) for service, operation, _ in self.aws.bridge.calls]


def write_credentials(path: Path, **changes: Any) -> None:
    document = {
        "schema": SCHEMA,
        "access_key_id": KEY_ID,
        "secret_access_key": SECRET,
        "session_token": TOKEN,
        "expires_at": (START + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "session_name": OPERATOR,
    }
    document.update(changes)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists():
        path.chmod(0o600)
        path.unlink()
    path.write_text(json.dumps(document))
    path.chmod(0o400)


def cli_rig(tmp_path: Path, *, document: dict | None = None, **approval) -> CliRig:
    tmp = tmp_path.resolve()
    document = document or cli_document()
    loaded = load_manifest(encode(document))
    clock, trace = FakeClock(), Trace()
    store, ecs = FakeStore(trace), FakeEcs(clock, trace)
    ecs.configure(document)
    aws = FakeAws(ecs, FakeLogs(ecs, document), FakeEvidence(ecs, document), store, document)
    r = CliRig(tmp=tmp, document=document, clock=clock, store=store, ecs=ecs, aws=aws)
    aws.bridge.handlers[("sts", "GetCallerIdentity")] = r.sts_identity
    (tmp / "manifest.json").write_bytes(encode(document))
    (tmp / "approval.json").write_bytes(
        encode({**approval_document(loaded.sha256, environment=ENVIRONMENT), **approval})
    )
    write_credentials(Path(r.credentials_path))
    return r


def lock_key() -> str:
    return f"locks/{ENVIRONMENT}.json"


# validate --------------------------------------------------------------------------


def test_validate_is_local_with_no_clients_credentials_or_clock(tmp_path):
    r = cli_rig(tmp_path)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("validate must not build clients or read the clock")

    out = io.StringIO()
    code = cli.main(
        ["validate", "--manifest", r.manifest_path, "--approval", r.approval_path],
        clients=forbidden,
        clock_factory=forbidden,
        out=out,
    )
    report = json.loads(out.getvalue())
    assert code == cli.EXIT_OK, report
    assert report["result"] == "valid" and report["execution"] == "forward"
    assert report["manifest_sha256"] == load_manifest(encode(r.document)).sha256
    assert r.aws.bridge.calls == []


def test_validate_takes_no_credentials_and_reports_binding_errors(tmp_path):
    r = cli_rig(tmp_path, manifest_sha256="0" * 64)
    with pytest.raises(SystemExit):
        cli.main(["validate", "--manifest", r.manifest_path, "--approval", r.approval_path,
                  "--credentials", r.credentials_path], out=io.StringIO())  # fmt: skip
    out = io.StringIO()
    code = cli.main(
        ["validate", "--manifest", r.manifest_path, "--approval", r.approval_path], out=out
    )
    assert code == cli.EXIT_REFUSED
    assert json.loads(out.getvalue())["error"] == "approval_manifest_mismatch"


# run, status, recover, cleanup -------------------------------------------------------


def test_run_completes_a_release_through_isolated_clients_after_preflight(tmp_path):
    r = cli_rig(tmp_path)
    code, report = r.main(*r.args("run"))
    assert code == cli.EXIT_OK, report
    assert report["state"] == "held_paused" and report["session_id"] == "cli-session-a"
    assert r.calls()[0] == ("sts", "GetCallerIdentity")
    assert ("sts", "GetCallerIdentity") not in r.calls()[1:]
    assert {("ecs", "RunTask"), ("ecs", "UpdateService"), ("s3", "PutObject")} <= set(r.calls())
    assert r.store.journal()["session_id"] == "cli-session-a"
    assert lock_key() not in r.store.objects
    for service, _operation, _params in r.aws.bridge.calls:
        assert service in {"sts", "s3", "ecs", "logs"}


def test_status_reads_only_and_reports_the_journal_and_lock(tmp_path):
    r = cli_rig(tmp_path)
    definition = r.document["jobs"][0]["task"]["task_definition"]
    r.ecs.plans[definition] = JobPlan(hang=True)
    original = r.ecs.describe_tasks
    seen = []

    def crash_in_job(cluster, arns):
        seen.append(1)
        if len(seen) == 3:
            raise SimulatedCrash("operator lost mid-job")
        return original(cluster, arns)

    setattr(r.ecs, "describe_tasks", crash_in_job)
    with pytest.raises(SimulatedCrash):
        r.main(*r.args("run"))
    setattr(r.ecs, "describe_tasks", original)
    before = (copy.deepcopy(r.store.objects), list(r.ecs.mutations))
    r.aws.bridge.calls.clear()
    code, report = r.main(*r.args("status", approval=False), session="cli-status")
    assert code == cli.EXIT_OK, report
    assert set(r.calls()) == {("sts", "GetCallerIdentity"), ("s3", "GetObject")}
    assert (r.store.objects, r.ecs.mutations) == before
    journal = report["journal"]
    assert journal["session_id"] == "cli-session-a" and journal["state"] == "quiesced"
    assert report["lock"]["session_id"] == "cli-session-a"
    assert report["lock"]["etag"] == r.store.objects[lock_key()][1]
    assert [item["action"] for item in journal["outstanding"]] == []


def test_status_of_a_release_that_never_started(tmp_path):
    r = cli_rig(tmp_path)
    code, report = r.main(*r.args("status", approval=False))
    assert code == cli.EXIT_OK and report["journal"] is None and report["lock"] is None


def test_a_new_run_never_continues_another_sessions_journal(tmp_path):
    r = cli_rig(tmp_path)
    r.ecs.crash[("run_task", "after")] = 1
    with pytest.raises(SimulatedCrash):
        r.main(*r.args("run"))
    mutations = len(r.ecs.mutations)
    code, report = r.main(*r.args("run"), session="cli-session-b")
    assert code == cli.EXIT_HALTED and report["detail"] == "session_conflict"
    assert len(r.ecs.mutations) == mutations


def recovery_args(r: CliRig, command: str, prior: str = "cli-session-a") -> list[str]:
    return r.args(command) + [
        "--prior-session", prior,
        "--lock-etag", r.store.objects[lock_key()][1],
        "--fence-evidence-sha256", sha("prior operator process confirmed terminated"),
        "--authorized-by", "fixture-release-owner",
    ]  # fmt: skip


def test_recover_takes_the_exact_lock_then_continues_the_release(tmp_path):
    r = cli_rig(tmp_path)
    r.ecs.crash[("run_task", "after")] = 1
    with pytest.raises(SimulatedCrash):
        r.main(*r.args("run"))
    code, report = r.main(*recovery_args(r, "recover"), session="cli-session-b")
    assert code == cli.EXIT_OK, report
    assert report["state"] == "held_paused" and report["session_id"] == "cli-session-b"
    events = r.store.journal()["events"]
    assert any(e.get("action") == "recovered" for e in events)
    # Six database jobs and two observers, each launched exactly once.
    launched = [t.tags.get("sentry:job-id") for t in r.ecs.tasks.values()]
    assert sorted(filter(None, launched)) == sorted(
        [job["id"] for job in r.document["jobs"]] + ["runtime-observe", "api-observe"]
    )


def test_recover_refuses_a_wrong_lock_etag_without_any_ecs_request(tmp_path):
    r = cli_rig(tmp_path)
    r.ecs.crash[("run_task", "after")] = 1
    with pytest.raises(SimulatedCrash):
        r.main(*r.args("run"))
    mutations = len(r.ecs.mutations)
    args = recovery_args(r, "recover")
    args[args.index("--lock-etag") + 1] = '"etag-stale"'
    code, report = r.main(*args, session="cli-session-b")
    assert code == cli.EXIT_HALTED and report["detail"] == "recovery_refused"
    assert len(r.ecs.mutations) == mutations


def test_cleanup_stops_only_the_releases_running_job_and_holds(tmp_path):
    r = cli_rig(tmp_path)
    definition = r.document["jobs"][0]["task"]["task_definition"]
    r.ecs.plans[definition] = JobPlan(hang=True)
    original = r.ecs.describe_tasks
    seen = []

    def crash_in_job(cluster, arns):
        seen.append(1)
        if len(seen) == 3:
            raise SimulatedCrash("operator lost mid-job")
        return original(cluster, arns)

    setattr(r.ecs, "describe_tasks", crash_in_job)
    with pytest.raises(SimulatedCrash):
        r.main(*r.args("run"))
    setattr(r.ecs, "describe_tasks", original)
    launches = [m for m in r.ecs.mutations if m[0] == "run_task"]
    code, report = r.main(*recovery_args(r, "cleanup"), session="cli-session-b")
    assert code == cli.EXIT_HELD, report
    assert report["reason"] == "operator_abort"
    assert [m for m in r.ecs.mutations if m[0] == "run_task"] == launches
    assert not [m for m in r.ecs.mutations if m[0] == "update_service"]
    assert [m[1]["task"] for m in r.ecs.mutations if m[0] == "stop_task"] == [
        next(t.arn for t in r.ecs.tasks.values() if t.tags.get("sentry:job-id"))
    ]


# preflight: identity and reference time -----------------------------------------------


def assert_refused_before_release(r: CliRig, code: int, report: dict, reason: str) -> None:
    assert code == cli.EXIT_REFUSED, report
    assert report["error"] == reason or report.get("detail") == reason, report
    assert set(r.calls()) <= {("sts", "GetCallerIdentity")}
    assert r.store.objects == {} and r.ecs.mutations == []


@pytest.mark.parametrize(
    "identity",
    [
        {"Account": "999999999999"},
        {"Arn": ASSUMED.replace("sentry-staging-operator", "other-role")},
        {"Arn": ASSUMED.replace(OPERATOR, "someone-else")},
        {"UserId": f"{ROLE_ID}:someone-else"},
        {"UserId": "AIDA" + "Q" * 17},  # an IAM user, not an assumed-role session
        {"UserId": "AIDA" + "Q" * 17 + ":" + OPERATOR},  # a user id with a matching suffix
        {"Arn": f"arn:aws:iam::{ACCOUNT}:user/{OPERATOR}"},
    ],
    ids=[
        "account",
        "role",
        "session-arn",
        "session-id",
        "iam-user-id",
        "iam-user-suffix",
        "iam-user-arn",
    ],
)
def test_a_caller_other_than_the_approved_operator_session_is_refused(tmp_path, identity):
    r = cli_rig(tmp_path)
    r.identity = identity
    code, report = r.main(*r.args("run"))
    assert_refused_before_release(r, code, report, "identity_mismatch")


@pytest.mark.parametrize(
    "configure, reason",
    [
        (lambda r: setattr(r, "date_offset", timedelta(seconds=7)), "reference_time_offset"),
        (lambda r: setattr(r, "date_offset", timedelta(seconds=-6)), "reference_time_offset"),
        (lambda r: setattr(r, "sts_delay", 2.5), "reference_time_uncertain"),
        (lambda r: r.identity.update(ResponseMetadata="omit"), "reference_time_malformed"),
    ],
    ids=["ahead", "behind", "slow", "missing"],
)
def test_an_unproven_reference_time_refuses_before_any_release_action(tmp_path, configure, reason):
    r = cli_rig(tmp_path)
    configure(r)
    code, report = r.main(*r.args("run"))
    assert_refused_before_release(r, code, report, "clock_untrusted")
    assert report["detail"] == reason


def test_preflight_errors_are_refusals_without_provider_text(tmp_path):
    r = cli_rig(tmp_path)
    r.aws.bridge.fail("sts", "GetCallerIdentity", ServiceError("ExpiredToken", 403))
    code, report = r.main(*r.args("run"))
    assert_refused_before_release(r, code, report, "identity_refused")
    assert "fixture error" not in json.dumps(report)


def test_a_schema_one_manifest_names_no_approved_role_and_is_refused_unread(tmp_path):
    document = manifest_document()
    document["environment"]["name"] = ENVIRONMENT
    r = cli_rig(tmp_path, document=document)
    os.chmod(r.credentials_path, 0o600)  # would be refused if it were read
    code, report = r.main(*r.args("run"))
    assert_refused_before_release(r, code, report, "operator_role_unapproved")
    assert r.built == []


def test_no_command_line_role_can_replace_the_approved_one(tmp_path):
    r = cli_rig(tmp_path)
    with pytest.raises(SystemExit):
        r.main(*r.args("run"), "--operator-role", "arn:aws:iam::111122223333:role/Admin")
    # A session for another role in the approved account is refused by the preflight.
    r.identity = {"Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/OrganizationAccountAccessRole/"
                         f"{OPERATOR}"}  # fmt: skip
    code, report = r.main(*r.args("run"))
    assert_refused_before_release(r, code, report, "identity_mismatch")


def test_a_tls_key_log_in_the_environment_refuses_before_any_client(tmp_path):
    r = cli_rig(tmp_path)
    log = tmp_path / "keys.log"
    code, report = r.main(*r.args("run"), environ={"SSLKEYLOGFILE": str(log)})
    assert_refused_before_release(r, code, report, "unsafe_environment")
    assert report["detail"] == "SSLKEYLOGFILE" and r.built == [] and not log.exists()


def test_refused_credentials_build_no_client(tmp_path):
    r = cli_rig(tmp_path)
    write_credentials(Path(r.credentials_path), access_key_id="AKIA" + "F" * 16)
    code, report = r.main(*r.args("run"))
    assert_refused_before_release(r, code, report, "long_lived_key_refused")
    assert r.built == [] and r.aws.bridge.calls == []


# credentials file ----------------------------------------------------------------------


def load(path: Path, **overrides) -> SessionCredentials:
    options: dict[str, Any] = {
        "operator": OPERATOR,
        "now": START,
        "required_until": START + timedelta(hours=1),
    }
    options.update(overrides)
    return load_session_credentials(path, **options)


def refused(path: Path, **overrides) -> str:
    with pytest.raises(CredentialsRefused) as error:
        load(path, **overrides)
    return error.value.reason


@pytest.fixture
def custody(tmp_path) -> Path:
    directory = tmp_path.resolve() / "custody"
    directory.mkdir(mode=0o700)
    return directory


def test_a_valid_session_file_is_read_without_echoing_its_values(custody):
    path = custody / "session.json"
    write_credentials(path)
    loaded = load(path)
    assert loaded.access_key_id == KEY_ID and loaded.session_name == OPERATOR
    assert KEY_ID not in repr(loaded) and SECRET not in repr(loaded) and TOKEN not in repr(loaded)


@pytest.mark.parametrize(
    "changes, reason",
    [
        ({"access_key_id": "AKIA" + "F" * 16}, "long_lived_key_refused"),
        ({"access_key_id": "ASIA123"}, "credentials_malformed"),
        ({"session_token": ""}, "session_token_required"),
        ({"secret_access_key": "short"}, "credentials_malformed"),
        ({"expires_at": "2026-10-07T13:09:59Z"}, "session_expires_too_soon"),
        ({"expires_at": "2026-10-09T00:00:01Z"}, "session_lifetime_implausible"),
        ({"expires_at": "2026-10-07 14:00:00"}, "credentials_malformed"),
        ({"session_name": "someone-else"}, "session_name_not_operator"),
        ({"schema": "sentry.operator-session.v0"}, "credentials_malformed"),
        ({"extra": "x"}, "credentials_malformed"),
        ({"session_token": 7}, "credentials_malformed"),
    ],
)
def test_session_contents_that_are_not_a_short_lived_operator_session_are_refused(
    custody, changes, reason
):
    path = custody / "session.json"
    write_credentials(path, **changes)
    assert refused(path) == reason
    assert "F" * 16 not in reason


def test_the_session_must_cover_the_window_plus_ten_minutes_exactly(custody):
    path = custody / "session.json"
    write_credentials(path, expires_at="2026-10-07T13:10:00Z")
    assert load(path).expires_at == START + timedelta(hours=1, minutes=10)


@pytest.mark.parametrize("mode", [0o600, 0o440, 0o404, 0o500, 0o000])
def test_only_an_owner_read_only_file_is_accepted(custody, mode):
    path = custody / "session.json"
    write_credentials(path)
    path.chmod(mode)
    assert refused(path) in {"credentials_file_unsafe", "credentials_unreadable"}


def test_symlinks_hard_links_fifos_and_directories_are_refused(custody):
    target = custody / "session.json"
    write_credentials(target)
    link = custody / "link.json"
    link.symlink_to(target)
    assert refused(link) == "credentials_path_unsafe"
    hard = custody / "hard.json"
    os.link(target, hard)
    assert refused(hard) == "credentials_file_unsafe"
    fifo = custody / "fifo.json"
    os.mkfifo(fifo, 0o400)
    assert refused(fifo) in {"credentials_file_unsafe", "credentials_unreadable"}
    folder = custody / "folder.json"
    folder.mkdir(mode=0o500)
    assert refused(folder) in {"credentials_file_unsafe", "credentials_unreadable"}


def test_a_symlinked_parent_or_relative_path_is_refused(custody, tmp_path):
    write_credentials(custody / "session.json")
    alias = tmp_path.resolve() / "alias"
    alias.symlink_to(custody)
    assert refused(alias / "session.json") == "credentials_path_unsafe"
    assert refused(Path("custody/session.json")) == "credentials_path_unsafe"


def test_a_group_or_world_writable_parent_is_refused(custody):
    path = custody / "session.json"
    write_credentials(path)
    custody.chmod(0o770)
    try:
        assert refused(path) == "credentials_path_unsafe"
    finally:
        custody.chmod(0o700)


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS extended ACLs")
def test_an_acl_allowing_anyone_anything_on_the_file_or_a_parent_is_refused(custody):
    path = custody / "session.json"
    write_credentials(path)
    chmod = "/bin/chmod"
    subprocess.run([chmod, "+a", "everyone allow read", str(path)], check=True)
    assert refused(path) == "credentials_file_unsafe"
    subprocess.run([chmod, "-N", str(path)], check=True)
    assert load(path).session_name == OPERATOR
    subprocess.run([chmod, "+a", "everyone allow list,search,add_file,delete_child", str(custody)],
                   check=True)  # fmt: skip
    try:
        assert refused(path) == "credentials_path_unsafe"
    finally:
        subprocess.run([chmod, "-N", str(custody)], check=True)
    # Deny-only entries (macOS gives home folders "everyone deny delete") only restrict.
    subprocess.run([chmod, "+a", "everyone deny delete", str(custody)], check=True)
    try:
        assert load(path).session_name == OPERATOR
    finally:
        subprocess.run([chmod, "-N", str(custody)], check=True)


def test_a_file_inside_a_repository_is_refused(custody):
    (custody / ".git").mkdir()
    path = custody / "session.json"
    write_credentials(path)
    assert refused(path) == "credentials_in_repository"


def test_a_file_owned_by_another_user_is_refused(custody):
    path = custody / "session.json"
    write_credentials(path)
    assert refused(path, euid=lambda: os.geteuid() + 1) == "credentials_path_unsafe"


def test_oversized_or_malformed_json_is_refused_without_quoting_it(custody):
    path = custody / "session.json"
    path.write_text("{" + '"a":"' + "x" * 9000 + '"}')
    path.chmod(0o400)
    assert refused(path) == "credentials_file_unsafe"
    path.chmod(0o600)
    path.write_text('{"schema": "' + SCHEMA + '", "schema": "dup"}')
    path.chmod(0o400)
    assert refused(path) == "credentials_malformed"
    path.chmod(0o600)
    path.write_text('{"secret_access_key": "leak-me", ')
    path.chmod(0o400)
    with pytest.raises(CredentialsRefused) as error:
        load(path)
    assert "leak-me" not in str(error.value) and error.value.__context__ is None


# Clock -------------------------------------------------------------------------------------


class Readings:
    def __init__(self, wall: float = 1_000_000.0, monotonic: float = 50.0) -> None:
        self.wall, self.monotonic, self.waited = wall, monotonic, []

    def clock(self) -> MonotonicUtcClock:
        return MonotonicUtcClock(wall=lambda: self.wall, monotonic=lambda: self.monotonic,
                                 wait=self.wait)  # fmt: skip

    def wait(self, seconds: float) -> None:
        self.waited.append(seconds)
        self.wall += seconds / 2  # an early wake-up: the clock must wait again
        self.monotonic += seconds / 2

    def advance(self, seconds: float) -> None:
        self.wall += seconds
        self.monotonic += seconds


def test_now_is_anchored_to_monotonic_time_and_never_moves_backwards():
    readings = Readings()
    clock = readings.clock()
    first = clock.now()
    readings.advance(3.0)
    readings.wall += 1.0  # wall drift within the limit never moves anchored time
    assert clock.now() == first + timedelta(seconds=3)
    readings.wall -= 0.5  # any backwards wall step is a fault, not a guess
    with pytest.raises(ClockUntrusted):
        clock.now()
    assert clock.fault == "wall_clock_regression"
    with pytest.raises(ClockUntrusted):
        clock.now()  # and it stays untrusted
    assert first == datetime.fromtimestamp(1_000_000.0, UTC)


@pytest.mark.parametrize(
    "step, fault",
    [
        (lambda r: setattr(r, "wall", r.wall + MAX_DIVERGENCE_SECONDS + 0.001),
         "wall_monotonic_divergence"),
        (lambda r: setattr(r, "monotonic", r.monotonic + 3600), "wall_monotonic_divergence"),
        (lambda r: setattr(r, "monotonic", r.monotonic - 0.5), "monotonic_regression"),
        (lambda r: setattr(r, "wall", float("nan")), "clock_reading_invalid"),
    ],
    ids=["wall-jump", "host-sleep-or-monotonic-jump", "monotonic-back", "nan"],
)  # fmt: skip
def test_divergence_or_regression_makes_the_clock_untrusted_for_good(step, fault):
    readings = Readings()
    clock = readings.clock()
    clock.now()
    step(readings)
    with pytest.raises(ClockUntrusted):
        clock.now()
    assert clock.fault == fault
    with pytest.raises(ClockUntrusted):
        clock.sleep(1)


def test_divergence_up_to_the_limit_is_tolerated():
    readings = Readings()
    clock = readings.clock()
    readings.wall += MAX_DIVERGENCE_SECONDS
    assert clock.now() == datetime.fromtimestamp(1_000_000.0, UTC)


def test_sleep_waits_the_full_time_despite_early_wakeups_and_never_moves_time():
    readings = Readings()
    clock = readings.clock()
    clock.sleep(4)
    assert readings.monotonic - 50.0 >= 4 and len(readings.waited) > 1
    assert clock.now() == datetime.fromtimestamp(readings.wall, UTC)
    for bad in (-1, 61, float("inf"), float("nan"), True):
        with pytest.raises(ValueError):
            clock.sleep(bad)


def sample(sent: float, received: float, reference: datetime) -> ReferenceSample:
    base = datetime(2026, 10, 7, 12, 0, tzinfo=UTC)
    return ReferenceSample(
        base + timedelta(seconds=sent), base + timedelta(seconds=received), reference
    )


REF = datetime(2026, 10, 7, 12, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    "sent, received, reference, accepted",
    [
        (0.0, 0.1, REF, True),
        (0.0, 2.0, REF, True),  # the slowest accepted round trip
        (0.0, 2.001, REF, False),
        (5.0, 5.0, REF, True),  # local ahead by exactly 5 s at most
        (5.001, 5.001, REF, False),
        (-4.0, -4.0, REF, True),  # reference [12:00:00, 12:00:01): local behind by at most 5 s
        (-4.001, -4.0, REF, False),
        (-0.5, 1.0, REF + timedelta(seconds=-5), False),
    ],
)
def test_reference_binding_needs_the_whole_uncertainty_interval_within_five_seconds(
    sent, received, reference, accepted
):
    readings = Readings()
    clock = readings.clock()
    probe = sample(sent, received, reference)
    if accepted:
        lowest, highest = clock.bind_reference(probe)
        assert (lowest, highest) == reference_offset_bounds(probe)
        assert clock.reference_bound
    else:
        with pytest.raises(ClockUntrusted):
            clock.bind_reference(probe)
        assert not clock.reference_bound


@pytest.mark.parametrize(
    "value",
    [None, "", "Wed, 07 Oct 2026 12:00:00 UTC", "Wednesday, 07-Oct-26 12:00:00 GMT",
     "Wed Oct  7 12:00:00 2026", "Wed, 07 Oct 2026 12:00:00 +0000", "Wed, 32 Oct 2026 12:00:00 GMT"],
)  # fmt: skip
def test_only_an_imf_fixdate_reference_is_accepted(value):
    with pytest.raises(ClockUntrusted):
        parse_reference_date(value)
    assert parse_reference_date("Wed, 07 Oct 2026 12:00:00 GMT") == REF


# Isolated clients ------------------------------------------------------------------------


def fixture_credentials() -> SessionCredentials:
    return SessionCredentials(KEY_ID, SECRET, TOKEN, START + timedelta(hours=2), OPERATOR)


def test_every_client_is_explicit_isolated_and_accepted_by_the_adapters():
    factory = AwsClients(fixture_credentials(), REGION)
    endpoints = {}
    for service in ("ecs", "logs", "s3", "sts"):
        client = factory.client(service)
        config = client.meta.config
        assert client.meta.region_name == REGION
        assert config.retries == {"total_max_attempts": 1, "mode": "standard"}
        assert config.connect_timeout == 10 and config.read_timeout == 30
        assert config.proxies == {}
        credentials = client._request_signer._credentials
        assert credentials.method == "explicit"
        assert (credentials.access_key, credentials.token) == (KEY_ID, TOKEN)
        endpoints[service] = client.meta.endpoint_url
    assert endpoints == {
        "ecs": "https://ecs.us-east-1.amazonaws.com",
        "logs": "https://logs.us-east-1.amazonaws.com",
        "s3": "https://s3.us-east-1.amazonaws.com",
        "sts": "https://sts.us-east-1.amazonaws.com",
    }
    with pytest.raises(ValueError):
        factory.client("iam")


def test_the_isolated_session_has_no_credential_chain_or_customer_models():
    session = isolated_session()
    assert session.get_credentials() is None
    loader = session.get_component("data_loader")
    assert all(not path.endswith(os.path.join(".aws", "models")) for path in loader.search_paths)
    assert getattr(client_config(), "proxies") == {}


def test_operator_identity_inputs_are_validated():
    with pytest.raises(PreflightRefused):
        OperatorIdentity(ACCOUNT, "arn:aws:iam::999999999999:role/x", OPERATOR)
    with pytest.raises(PreflightRefused):
        OperatorIdentity(ACCOUNT, ROLE_ARN, "a b")
    assert OperatorIdentity(ACCOUNT, ROLE_ARN, OPERATOR).assumed_role_arn == ASSUMED


def test_deeply_nested_json_is_a_refusal_and_unexpected_errors_report_only_their_class(
    tmp_path, custody
):
    path = custody / "session.json"
    path.write_text("[" * 4000 + "]" * 4000)
    path.chmod(0o400)
    assert refused(path) == "credentials_malformed"
    r = cli_rig(tmp_path)

    def broken_factory(credentials, region):
        raise RuntimeError(f"factory failed for {credentials.access_key_id}")

    out = io.StringIO()
    code = cli.main(r.args("run"), clients=broken_factory, clock_factory=r.operator_clock,
                    out=out, environ={})  # fmt: skip
    report = json.loads(out.getvalue())
    assert (code, report["error"], report["detail"]) == (cli.EXIT_HALTED, "unexpected",
                                                          "RuntimeError")  # fmt: skip
    assert KEY_ID not in out.getvalue()


def test_status_cannot_write_even_if_its_reader_tried(tmp_path, monkeypatch):
    r = cli_rig(tmp_path)
    store = cli.ReadOnlyStore(r.store)
    for write in (
        lambda: store.create("locks/x.json", b"{}"),
        lambda: store.replace("locks/x.json", b"{}", if_match='"e"'),
        lambda: store.delete("locks/x.json", if_match='"e"'),
    ):
        with pytest.raises(PermissionError):
            write()

    class WritingJournal(cli.Journal):
        def load(self) -> bool:
            self.store.create(self.key, b"{}")
            return False

    monkeypatch.setattr(cli, "Journal", WritingJournal)
    code, report = r.main(*r.args("status", approval=False))
    assert (code, report["error"], report["detail"]) == (cli.EXIT_HALTED, "unexpected",
                                                          "PermissionError")  # fmt: skip
    assert r.store.objects == {}


def test_the_session_lifetime_is_rechecked_against_the_referenced_clock(tmp_path):
    # Valid by the first reading; one second of preflight later it no longer
    # covers the window plus ten minutes.
    r = cli_rig(tmp_path)
    # Window 3600 s + 120 s journal-start slack + 10 min margin from 12:00:00.
    write_credentials(Path(r.credentials_path), expires_at="2026-10-07T13:12:00Z")
    r.sts_delay = 1.0
    code, report = r.main(*r.args("run"))
    assert_refused_before_release(r, code, report, "session_expires_too_soon")


# rollback run ------------------------------------------------------------------------


def rollback_cli_rig(tmp_path: Path) -> CliRig:
    """A rollback of the retained prior pair after a failed release that still holds the lock."""
    document = rollback_run_document()
    document["environment"]["name"] = ENVIRONMENT
    document["purpose"]["failed_release_id"] = FAILED_RELEASE_ID
    r = cli_rig(tmp_path, document=document, release_id=ROLLBACK_RELEASE_ID)
    journal = Journal(r.store, journal_key(FAILED_RELEASE_ID))
    journal.create(
        {"schema_version": 1, "release_id": FAILED_RELEASE_ID, "environment": ENVIRONMENT,
         "manifest_sha256": sha("failed manifest"), "session_id": "cli-session-failed"},
        {"at": "2026-10-07T11:40:00Z", "kind": "transition", "to": "prepared"},
    )  # fmt: skip
    journal.append({"at": "2026-10-07T11:41:00Z", "kind": "transition", "to": "hold"})
    r.store.create(lock_key(), encode({"release_id": FAILED_RELEASE_ID,
                                       "session_id": "cli-session-failed"}))  # fmt: skip
    return r


def handoff_args(r: CliRig, **changes: str) -> list[str]:
    values = {
        "--failed-session": "cli-session-failed",
        "--failed-lock-etag": r.store.objects[lock_key()][1],
        "--fence-evidence-sha256": sha("failed operator process confirmed terminated"),
        "--authorized-by": "fixture-release-owner",
        **changes,
    }
    return [item for key, value in values.items() if value is not None for item in (key, value)]


def test_a_rollback_run_takes_the_failed_lock_under_its_handoff_and_restores_the_prior_pair(
    tmp_path,
):
    r = rollback_cli_rig(tmp_path)
    code, report = r.main(*r.args("run"), *handoff_args(r))
    assert code == cli.EXIT_OK, report
    assert report["state"] == "held_paused"
    events = json.loads(r.store.objects[journal_key(ROLLBACK_RELEASE_ID)][0])["events"]
    assert any(e.get("result") == "lock_handed_off" for e in events)
    assert lock_key() not in r.store.objects
    launched = [t.tags.get("sentry:job-id") for t in r.ecs.tasks.values() if t.tags]
    assert not any(job and job.endswith(("-migrate", "-grant", "-bootstrap")) for job in launched)


def test_a_rollback_without_its_handoff_holds_with_the_failed_lock_untouched(tmp_path):
    r = rollback_cli_rig(tmp_path)
    lock = r.store.objects[lock_key()]
    code, report = r.main(*r.args("run"))
    assert code == cli.EXIT_HELD, report
    assert report["reason"] == "handoff_refused"
    assert r.store.objects[lock_key()] == lock
    assert not [call for call in r.calls() if call[0] == "ecs" and call[1] in {
        "RunTask", "UpdateService", "StopTask"}]  # fmt: skip


@pytest.mark.parametrize(
    "rollback, changes, error",
    [
        (True, {"--authorized-by": None}, "handoff_incomplete"),
        (True, {"--failed-lock-etag": None}, "handoff_incomplete"),
        (False, {}, "handoff_not_applicable"),
    ],
)
def test_handoff_arguments_are_all_or_none_and_rollback_only(tmp_path, rollback, changes, error):
    r = rollback_cli_rig(tmp_path) if rollback else cli_rig(tmp_path)
    if not rollback:
        r.store.create(lock_key(), encode({"release_id": FAILED_RELEASE_ID, "session_id": "x"}))
    code, report = r.main(*r.args("run"), *handoff_args(r, **changes))
    assert code == cli.EXIT_REFUSED, report
    assert report["error"] == error
    assert r.built == [] and r.aws.bridge.calls == []


def lose_rollback_before_handoff(r: CliRig, monkeypatch) -> None:
    original = r.store.replace

    def crash(key, body, *, if_match):
        if key == lock_key():
            raise SimulatedCrash("lock handoff")
        return original(key, body, if_match=if_match)

    monkeypatch.setattr(r.store, "replace", crash)
    with pytest.raises(SimulatedCrash):
        r.main(*r.args("run"), *handoff_args(r))
    monkeypatch.setattr(r.store, "replace", original)


def recover_handoff_args(r: CliRig, **changes: str | None) -> list[str]:
    values = {
        "--failed-session": "cli-session-failed",
        "--failed-lock-etag": r.store.objects[lock_key()][1],
        "--failed-fence-evidence-sha256": sha("failed operator process confirmed terminated"),
        **changes,
    }
    return [item for key, value in values.items() if value is not None for item in (key, value)]


def test_recover_continues_a_rollback_lost_before_its_handoff(tmp_path, monkeypatch):
    r = rollback_cli_rig(tmp_path)
    lose_rollback_before_handoff(r, monkeypatch)
    assert json.loads(r.store.objects[lock_key()][0])["release_id"] == FAILED_RELEASE_ID
    code, report = r.main(*recovery_args(r, "recover"), *recover_handoff_args(r),
                          session="cli-session-b")  # fmt: skip
    assert code == cli.EXIT_OK, report
    assert report["state"] == "held_paused" and report["session_id"] == "cli-session-b"
    events = json.loads(r.store.objects[journal_key(ROLLBACK_RELEASE_ID)][0])["events"]
    assert [e["prior_session_id"] for e in events if e.get("action") == "recovered"] == [
        "cli-session-a"
    ]
    [moved] = [e for e in events if e.get("result") == "lock_handed_off"]
    assert moved["from_release_id"] == FAILED_RELEASE_ID
    # Each fence names its own session: the recovery the lost rollback session,
    # the handoff the failed release's.
    [recovered] = [e for e in events if e.get("action") == "recovered"]
    assert recovered["fence_evidence_sha256"] == sha("prior operator process confirmed terminated")
    intents = [e for e in events if e.get("action") == "lock_handoff"]
    assert {e["fence_evidence_sha256"] for e in intents} == {
        sha("failed operator process confirmed terminated")
    }
    assert intents[-1]["authorized_by"] == "fixture-release-owner"
    assert lock_key() not in r.store.objects


def test_recover_without_the_handoff_holds_with_the_failed_lock_untouched(tmp_path, monkeypatch):
    r = rollback_cli_rig(tmp_path)
    lose_rollback_before_handoff(r, monkeypatch)
    lock = r.store.objects[lock_key()]
    code, report = r.main(*recovery_args(r, "recover"), session="cli-session-b")
    assert code == cli.EXIT_HELD, report
    assert report["reason"] == "handoff_refused"
    assert r.store.objects[lock_key()] == lock


@pytest.mark.parametrize(
    "rollback, changes, error",
    [
        (True, {"--failed-fence-evidence-sha256": None}, "handoff_incomplete"),
        (True, {"--failed-session": None}, "handoff_incomplete"),
        (False, {}, "handoff_not_applicable"),
    ],
)
def test_recover_handoff_arguments_are_all_or_none_and_rollback_only(
    tmp_path, monkeypatch, rollback, changes, error
):
    if rollback:
        r = rollback_cli_rig(tmp_path)
        lose_rollback_before_handoff(r, monkeypatch)
    else:
        r = cli_rig(tmp_path)
        r.ecs.crash[("run_task", "after")] = 1
        with pytest.raises(SimulatedCrash):
            r.main(*r.args("run"))
    before = dict(r.store.objects)
    code, report = r.main(*recovery_args(r, "recover"), *recover_handoff_args(r, **changes),
                          session="cli-session-b")  # fmt: skip
    assert code == cli.EXIT_REFUSED, report
    assert report["error"] == error
    assert r.store.objects == before
