"""The AWS-08a kit offline: the matrix, target checks, the local runner and the ledger.

Suites are not run here: a fake executor answers with pytest and Go outcome lines.
Platform runners talk to an in-memory HTTP transport and fake AWS clients; no
socket opens and no credential is read.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
import subprocess
from typing import Any

import httpx
import pytest

from release_kits import aws_08a
from release_kits.ledger import Ledger

REPO = Path(__file__).resolve().parents[1]
RUNTIME = REPO.parent / "sentryruntime-aws-platform"
MATRIX = (
    "auth-valid", "auth-invalid", "auth-expired", "auth-wrong-owner", "outbox-dispatch",
    "runtime-claim", "artifacts", "evaluation", "readback", "duplicate-submission",
    "worker-death-before-publication", "worker-death-after-publication", "stale-fence",
    "evaluation-only-recovery", "dependency-outage", "retry-exhaustion", "cross-prefix-s3-denial",
    "tls-runtime-hostname", "secret-rotation", "certificate-rollover",
    "termination-grace-and-replacement", "alert-delivery", "pitr-restore",
)  # fmt: skip


def local_target(tmp_path: Path, runtime: Path) -> Path:
    path = tmp_path / "target.json"
    path.write_text(json.dumps({
        "schema": aws_08a.TARGET_SCHEMA, "name": "local-canary", "kind": "local",
        "platform": False, "endpoint": None, "deployer_session": None, "identities": None,
        "images": {"search": "sha256:" + "1" * 64, "runtime": "sha256:" + "2" * 64,
                   "release_tools": "sha256:" + "3" * 64},
        "runtime_checkout": str(runtime),
    }))  # fmt: skip
    return path


@pytest.fixture
def runtime(tmp_path) -> Path:
    """A stand-in Runtime checkout holding exactly the Go tests the matrix names."""
    root = tmp_path / "runtime"
    (root / "tests" / "integration").mkdir(parents=True)
    names = sorted({proof.node for case in aws_08a.CASES for proof in case.proofs
                    if proof.suite == "runtime-integration"})  # fmt: skip
    (root / "tests" / "integration" / "runtime_test.go").write_text(
        "".join(f"func {name}(t *testing.T) {{}}\n" for name in names)
    )
    return root


class Executor:
    def __init__(self, failing: set[str] | None = None, missing: set[str] | None = None,
                 nonzero: set[str] | None = None) -> None:  # fmt: skip
        self.calls: list[list[str]] = []
        self.failing = failing or set()
        self.missing = missing or set()
        # Suites (by a fragment of their command) that exit nonzero although every node
        # the matrix names passed: an unmapped failure or a failing teardown.
        self.nonzero = nonzero or set()

    def __call__(self, command, *, cwd, env, text, capture_output, check):
        """Outcomes as the suites really report them: JUnit XML and go test -json."""
        self.calls.append(command)
        assert not any(key.startswith("AWS_") and key != "AWS_EC2_METADATA_DISABLED"
                       for key in env), "a suite inherited an AWS setting"  # fmt: skip
        if command[0] == "go":
            lines = [json.dumps({"Action": "run", "Test": "TestOther"})]
            for proof in {p for case in aws_08a.CASES for p in case.proofs
                          if p.suite == "runtime-integration"}:  # fmt: skip
                if proof.node in self.missing:
                    continue
                action = "fail" if proof.node in self.failing else "pass"
                lines += [
                    json.dumps({"Action": action, "Test": f"{proof.node}/subcase"}),
                    json.dumps({"Action": action, "Test": proof.node}),
                ]
            return subprocess.CompletedProcess(
                command, self.code(command), "\n".join(lines) + "\n", ""
            )
        junit = env["PYTEST_ADDOPTS"].split("=", 1)[1]
        cases = []
        for proof in {p for case in aws_08a.CASES for p in case.proofs
                      if p.suite != "runtime-integration"}:  # fmt: skip
            if proof.node in self.missing:
                continue
            path, _, name = proof.node.partition("::")
            classname = path.removesuffix(".py").replace("/", ".")
            body = "<failure/>" if proof.node in self.failing else ""
            # Parametrized nodes report each case with a [param] suffix.
            for suffix in ("[one]", "[two]") if "transport" in path else ("",):
                cases.append(
                    f'<testcase classname="{classname}" name="{name}{suffix}">' f"{body}</testcase>"
                )
        if self.code(command):
            # The suite's own failure is in a node the matrix does not name.
            cases.append(
                '<testcase classname="tests.unmapped" name="test_other"><failure/></testcase>'
            )
        Path(junit).write_text(f"<testsuites><testsuite>{''.join(cases)}</testsuite></testsuites>")
        # Console text is never read: a printed line between a node and its outcome is harmless.
        return subprocess.CompletedProcess(command, self.code(command),
                                           'tests/x.py::y {"proof": 1}\nPASSED\n', "")  # fmt: skip

    def code(self, command) -> int:
        return 1 if any(fragment in " ".join(command) for fragment in self.nonzero) else 0


def run_local(tmp_path, runtime, **executor):
    out = io.StringIO()
    fake = Executor(**executor)
    code = aws_08a.main(["run", "--target", str(local_target(tmp_path, runtime)), "--ledger",
                         str(tmp_path / "ledger")], out=out, execute=fake)  # fmt: skip
    target = aws_08a.load_target(tmp_path / "target.json")
    ledger = Ledger(tmp_path / "ledger" / "receipts", kit="aws-08a", plan_sha256=target.sha256)
    return code, {doc["step"]: doc for _, doc, _ in ledger.receipts()}, fake, out.getvalue()


def test_the_case_table_is_exactly_the_aws_08a_matrix():
    assert aws_08a.REQUIRED == MATRIX
    for case in aws_08a.CASES:
        assert case.proofs or case.platform, f"{case.id} has neither a local proof nor a reason"


def test_every_named_pytest_proof_exists_in_this_checkout():
    for case in aws_08a.CASES:
        for proof in case.proofs:
            if proof.suite == "runtime-integration":
                continue
            path, _, name = proof.node.partition("::")
            assert f"def {name}(" in (REPO / path).read_text(), proof


@pytest.mark.skipif(not (RUNTIME / "tests" / "integration").is_dir(),
                    reason="needs the Runtime checkout beside this one")  # fmt: skip
def test_every_named_go_proof_exists_in_the_runtime_checkout():
    sources = "".join(p.read_text() for p in (RUNTIME / "tests" / "integration").glob("*_test.go"))
    for case in aws_08a.CASES:
        for proof in case.proofs:
            if proof.suite == "runtime-integration":
                assert f"func {proof.node}(t *testing.T)" in sources, proof


def test_a_local_run_proves_every_local_case_and_skips_platform_cases_with_a_reason(
    tmp_path, runtime
):
    code, records, fake, out = run_local(tmp_path, runtime)
    assert code == aws_08a.EXIT_OK, out
    assert list(records) == list(MATRIX)
    for case in aws_08a.CASES:
        record = records[case.id]
        assert record["identity"].startswith("test auth double")
        if case.platform:
            assert record["result"] == "skip" and record["reason"].startswith("platform: ")
        else:
            assert record["result"] == "passed"
            assert {p["node"] for p in record["proofs"]} == {p.node for p in case.proofs}
            assert all(len(p["log_sha256"]) == 64 for p in record["proofs"])
    # One invocation per suite, each selecting only what the matrix names.
    assert [call[0] for call in fake.calls].count("go") == 1
    assert len(fake.calls) == len(aws_08a.SUITES)


def test_a_failed_or_missing_proof_fails_its_case(tmp_path, runtime):
    failing = "TestIllegalTransitionsAreFenced"
    missing = (
        "tests/test_artifact_keys.py::test_different_content_never_overwrites_a_published_object"
    )
    code, records, _, _ = run_local(tmp_path, runtime, failing={failing}, missing={missing})
    assert code == aws_08a.EXIT_FAILED
    assert records["stale-fence"]["result"] == "failed"
    assert records["artifacts"]["result"] == "failed"
    assert {p["outcome"] for p in records["artifacts"]["proofs"]} == {"passed", "missing"}
    assert records["retry-exhaustion"]["result"] == "passed"


@pytest.mark.parametrize("fragment, suite", [("check_runtime_consistency.py", "runtime-consistency"),
                                             ("go test", "runtime-integration")])  # fmt: skip
def test_a_suite_that_exits_nonzero_fails_its_cases_though_every_named_node_passed(
    tmp_path, runtime, fragment, suite
):
    code, records, _, out = run_local(tmp_path, runtime, nonzero={fragment})
    assert code == aws_08a.EXIT_FAILED, out
    touched = [c.id for c in aws_08a.CASES if any(p.suite == suite for p in c.proofs)]
    assert touched
    for case in aws_08a.CASES:
        record = records[case.id]
        if case.id in touched:
            assert record["result"] == "failed" and f"{suite} (1)" in record["reason"], record
            # The named nodes' own outcomes are kept as they were observed.
            assert {p["outcome"] for p in record["proofs"]} == {"passed"}
            assert {p["suite_exit"] for p in record["proofs"] if p["suite"] == suite} == {1}
        elif not case.platform:
            assert record["result"] == "passed", case.id


def test_a_proof_that_names_no_test_is_refused_before_anything_runs(tmp_path, runtime):
    (runtime / "tests" / "integration" / "runtime_test.go").write_text("")
    code, records, fake, out = run_local(tmp_path, runtime)
    assert code == aws_08a.EXIT_REFUSED and "names no test" in out
    assert fake.calls == [] and records == {}


@pytest.mark.parametrize("change, message", [
    ({"endpoint": "https://api.example.invalid"}, "names no endpoint"),
    ({"kind": "platform", "platform": True, "endpoint": "http://api.example.invalid"}, "https"),
    ({"kind": "platform", "platform": True, "endpoint": "https://api.example.invalid",
      "deployer_session": None}, "deployer_session"),
    ({"schema": "other"}, "aws-08a-target"),
])  # fmt: skip
def test_targets_that_are_not_explicit_are_refused(tmp_path, runtime, change, message):
    path = local_target(tmp_path, runtime)
    path.write_text(json.dumps({**json.loads(path.read_text()), **change}))
    with pytest.raises(aws_08a.Refused, match=message):
        aws_08a.load_target(path)


def identities(tmp_path: Path, project: str = "aws-08a-isolated") -> Path:
    tokens = {}
    for name in ("owner", "other", "expired"):
        token = tmp_path / f"{name}.token"
        token.write_text(f"fixture-{name}-token-value")
        token.chmod(0o400)
        tokens[name] = str(token)
    path = tmp_path / "identities.json"
    path.write_text(json.dumps({"schema": aws_08a.IDENTITIES_SCHEMA, "service": "fixture-auth",
                                "project": project, "tokens": tokens}))  # fmt: skip
    return path


def platform_target(tmp_path: Path, project: str = "aws-08a-isolated") -> Path:
    path = tmp_path / "platform.json"
    path.write_text(json.dumps({
        "schema": aws_08a.TARGET_SCHEMA, "name": "staging", "kind": "platform",
        "platform": True, "endpoint": "https://api.staging.example.invalid",
        "deployer_session": str(tmp_path / "session.json"),
        "identities": str(identities(tmp_path, project)),
        "aws_07b_work": str(tmp_path / "work"), "aws_07b_chain_head": "0" * 64,
        "plan": str(tmp_path / "plan"),
        "plan_sha256": "a" * 64,
    }))  # fmt: skip
    return path


def test_identities_for_a_production_project_are_refused(tmp_path):
    with pytest.raises(aws_08a.Refused, match="production"):
        aws_08a.load_target(platform_target(tmp_path, project="sentry-prod"))


def api(request: httpx.Request) -> httpx.Response:
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    owner, other = "fixture-owner-token-value", "fixture-other-token-value"
    if request.method == "POST":
        if token != owner:
            return httpx.Response(401, json={"detail": "unauthorized"})
        return httpx.Response(200, json={"report_id": "0b9f7c1e-4d2a-4f6b-9a3e-2c1d0e9f8a7b"})
    if token == other or request.method == "DELETE":
        return httpx.Response(404, json={"detail": "Report not found"})
    return httpx.Response(200, json={"status": "completed", "evaluation_status": "completed",
                                     "markdown_content": "# report", "quality_score": 81})  # fmt: skip


class FakeIam:
    """Identity-policy simulation only: IAM refuses a resource policy for a role caller."""

    def __init__(self, allowed_elsewhere: frozenset[str] = frozenset()) -> None:
        self.allowed_elsewhere = allowed_elsewhere

    def simulate_principal_policy(self, *, PolicySourceArn, ActionNames, ResourceArns):
        own = "/reports/" in ResourceArns[0]
        return {"EvaluationResults": [
            {"EvalActionName": action,
             "EvalDecision": "allowed" if own or action in self.allowed_elsewhere
             else "implicitDeny"} for action in ActionNames]}  # fmt: skip


class FakeLogs:
    """TestMetricFilter, with the stand-in patterns as plain substrings."""

    def test_metric_filter(self, *, filterPattern, logEventMessages):
        # Numbered from 1 as CloudWatch numbers them; the kit matches on the message.
        return {"matches": [{"eventNumber": index + 1, "eventMessage": message}
                            for index, message in enumerate(logEventMessages)
                            if filterPattern in message]}  # fmt: skip


class FakeCloudWatch:
    def __init__(self) -> None:
        self.states: list[tuple[str, str]] = []

    def set_alarm_state(self, *, AlarmName, StateValue, StateReason):
        self.states.append((AlarmName, StateValue))


def write_07b_receipts(work: Path, plan_sha256: str) -> str:
    """A real AWS-07b chain for the target's plan; returns its head."""
    ledger = Ledger(work / "receipts", kit="aws-07b", plan_sha256=plan_sha256)
    documents = {
        "bootstrap": {"terraform": {"operator_role_arn":
                                    "arn:aws:iam::111122223333:role/sentry-staging-operator"}},
        "foundation": {"terraform": {"report_bucket": "sentry-staging-111122223333-reports",
                                     "report_bucket_policy": {"Version": "2012-10-17",
                                                              "Statement": [{"Effect": "Deny"}]},
                                     "worker_metric_filters": {
                                         "WorkerReadyReceipts": '"ready":true',
                                         "WorkerRuntimeErrors": '"error_code":"runtime_unavailable"',
                                         "WorkerDeadlineErrors": '_deadline_exceeded"'}}},
        "releases": {"terraform": {"current_release": "r0b9f7c1e", "releases": {"r0b9f7c1e": {
            "iam_role_names": {"worker-task": "sentry-staging-r0b9f7c1e-worker-task",
                               "api-task": "sentry-staging-r0b9f7c1e-api-task"}}}}},
        "run": {"run": {"state": "held_paused", "last_proven": "operational_verified"}},
    }  # fmt: skip
    digest = ""
    for step, outputs in documents.items():
        digest = ledger.write(step, {"result": "ok", "outputs": outputs})
    return digest


def test_platform_cases_observe_through_the_test_identities_and_record_no_token(tmp_path):
    target = aws_08a.load_target(platform_target(tmp_path))
    target.document["aws_07b_chain_head"] = write_07b_receipts(tmp_path / "work", "a" * 64)
    target.document["name_prefix"] = "sentry-staging"
    cloudwatch = FakeCloudWatch()
    typed = ["submit", "alert-delivery", "received"]
    platform = aws_08a.Platform(
        target, http=httpx.Client(base_url=target.document["endpoint"],
                                  transport=httpx.MockTransport(api)),
        clients=lambda service: {"iam": FakeIam(), "cloudwatch": cloudwatch,
                                 "logs": FakeLogs()}[service],
        prompt=lambda _text: typed.pop(0), aws_07b=tmp_path / "work")  # fmt: skip
    target.document["alert_alarm"] = "sentry-staging-runtime-no-cpu"
    out = io.StringIO()
    runner = aws_08a.Runner(target, tmp_path / "ledger", out=out, platform=platform)
    selected = ["auth-valid", "auth-invalid", "auth-expired", "auth-wrong-owner", "readback",
                "evaluation", "tls-runtime-hostname", "cross-prefix-s3-denial", "alert-delivery",
                "pitr-restore", "stale-fence"]  # fmt: skip
    code = runner.run(selected)
    records = {doc["step"]: doc for _, doc, _ in runner.ledger.receipts()}
    assert code == aws_08a.EXIT_OK, out.getvalue()
    for name in selected[:9]:
        assert records[name]["result"] == "passed", records[name]
        assert records[name]["identity"] == "isolated project aws-08a-isolated in fixture-auth"
    assert records["pitr-restore"]["result"] == "skip" and "restore receipt" in (
        records["pitr-restore"]["reason"]
    )
    assert records["stale-fence"]["result"] == "skip"
    assert cloudwatch.states == [("sentry-staging-runtime-no-cpu", "ALARM"),
                                 ("sentry-staging-runtime-no-cpu", "OK")]  # fmt: skip
    text = "".join(path.read_text() for path in (tmp_path / "ledger" / "receipts").iterdir())
    assert "token-value" not in text, "a test identity's token reached the ledger"


def test_runbook_lists_every_case_and_the_platform_only_proofs():
    text = (REPO / "deploy" / "aws-staging" / "aws-08a" / "README.md").read_text()
    for case in aws_08a.CASES:
        assert f"`{case.id}`" in text, case.id
    assert "## Proven on the platform only" in text


def test_platform_receipts_must_be_the_targets_own_chain(tmp_path):
    target = aws_08a.load_target(platform_target(tmp_path))
    write_07b_receipts(tmp_path / "work", "a" * 64)
    target.document["aws_07b_chain_head"] = "f" * 64
    platform = aws_08a.Platform(target, http=None, clients=lambda _s: None,
                                prompt=lambda _t: "", aws_07b=tmp_path / "work")  # fmt: skip
    with pytest.raises(aws_08a.Refused, match="aws_07b_chain_head"):
        platform.run(next(c for c in aws_08a.CASES if c.id == "tls-runtime-hostname"))


def test_no_report_is_created_on_the_platform_without_its_typed_confirmation(tmp_path):
    target = aws_08a.load_target(platform_target(tmp_path))
    sent = []

    def recording(request: httpx.Request) -> httpx.Response:
        sent.append((request.method, request.headers.get("Authorization", "")))
        return api(request)

    platform = aws_08a.Platform(
        target, http=httpx.Client(base_url=target.document["endpoint"],
                                  transport=httpx.MockTransport(recording)),
        clients=lambda _s: None, prompt=lambda _t: "no", aws_07b=None)  # fmt: skip
    runner = aws_08a.Runner(target, tmp_path / "ledger", out=io.StringIO(), platform=platform)
    runner.run(["auth-valid", "auth-invalid", "auth-expired", "auth-wrong-owner"])
    records = {doc["step"]: doc for _, doc, _ in runner.ledger.receipts()}
    assert {records[name]["result"] for name in records} == {"skip"}
    assert sent == [], "a request went out before the typed confirmation"


class FakeWorkerEcs:
    """One worker task; after the stop ECS starts a replacement."""

    def __init__(self, exit_code: int, drain_seconds: float) -> None:
        self.stopped: list[str] = []
        self.exit_code, self.drain_seconds = exit_code, drain_seconds

    def list_tasks(self, *, cluster, serviceName):
        assert serviceName == "sentry-staging-worker" and cluster.endswith(
            ":cluster/sentry-staging"
        )
        return {"taskArns": ["arn:task/new"] if self.stopped else ["arn:task/old"]}

    def stop_task(self, *, cluster, task, reason):
        self.stopped.append(task)

    def describe_tasks(self, *, cluster, tasks):
        from datetime import UTC, datetime, timedelta

        stopping = datetime(2026, 10, 17, tzinfo=UTC)
        executed = stopping + timedelta(seconds=self.drain_seconds)
        # STOPPED waits for the network interface to detach, well after the exit.
        return {"tasks": [{"taskArn": tasks[0], "stoppingAt": stopping,
                           "executionStoppedAt": executed,
                           "stoppedAt": executed + timedelta(seconds=40),
                           "containers": [{"name": "app", "exitCode": self.exit_code}]}]}  # fmt: skip


def worker_platform(tmp_path, ecs) -> aws_08a.Platform:
    target = aws_08a.load_target(platform_target(tmp_path))
    ledger = Ledger(tmp_path / "work" / "receipts", kit="aws-07b", plan_sha256="a" * 64)
    ledger.write(
        "services",
        {
            "result": "ok",
            "outputs": {
                "terraform": {
                    "service_arns": {
                        "worker": "arn:aws:ecs:us-east-1:111122223333:service/sentry-staging/sentry-staging-worker"
                    }
                }
            },
        },
    )
    target.document["aws_07b_chain_head"] = ledger.head()[1]
    polls = iter([{"status": "generating", "generation_stage": "research"}]
                 + [{"status": "completed", "evaluation_status": "completed"}] * 5)  # fmt: skip

    def reports(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(200, json={"report_id": "r-1"})
        return httpx.Response(200, json=next(polls))

    platform = aws_08a.Platform(
        target, http=httpx.Client(base_url=target.document["endpoint"],
                                  transport=httpx.MockTransport(reports)),
        clients=lambda _s: ecs, prompt=lambda text: text.split()[1], aws_07b=tmp_path / "work")  # fmt: skip
    platform.sleep = lambda _seconds: None
    return platform


@pytest.mark.parametrize("case_id, exit_code, drain, passed", [
    ("worker-death-before-publication", 137, 2, True),
    ("worker-death-before-publication", 124, 31, True),
    ("worker-death-before-publication", 0, 1, False),  # it finished the report itself
    ("termination-grace-and-replacement", 0, 5, True),
    ("termination-grace-and-replacement", 124, 31, True),
    ("termination-grace-and-replacement", 137, 61, False),  # killed, not drained
    ("termination-grace-and-replacement", 124, 31, True),  # STOPPED itself comes 40 s later
])  # fmt: skip
def test_the_worker_runners_judge_the_stop_by_what_the_worker_did(tmp_path, case_id, exit_code,
                                                                   drain, passed):  # fmt: skip
    ecs = FakeWorkerEcs(exit_code, drain)
    platform = worker_platform(tmp_path, ecs)
    observed = platform.run(next(c for c in aws_08a.CASES if c.id == case_id))
    assert observed["ok"] is passed, observed
    assert ecs.stopped == ["arn:task/old"] and observed["observed"]["replacement"] == "arn:task/new"
    assert observed["observed"]["stop_seconds"] == drain


def test_a_worker_case_asks_once_its_case_id_confirms_the_report(tmp_path):
    ecs = FakeWorkerEcs(124, 31)
    platform = worker_platform(tmp_path, ecs)
    asked: list[str] = []
    platform.prompt = lambda text: asked.append(text.split()[1]) or text.split()[1]
    platform.run(next(c for c in aws_08a.CASES if c.id == "worker-death-before-publication"))
    assert asked == ["worker-death-before-publication"]


def test_the_aws_07b_chain_is_checked_before_any_request(tmp_path):
    target = aws_08a.load_target(platform_target(tmp_path))
    write_07b_receipts(tmp_path / "work", "a" * 64)
    target.document["aws_07b_chain_head"] = "f" * 64
    sent = []
    platform = aws_08a.Platform(
        target, http=httpx.Client(base_url=target.document["endpoint"],
                                  transport=httpx.MockTransport(lambda r: sent.append(r) or api(r))),
        clients=lambda _s: None, prompt=lambda _t: "submit", aws_07b=tmp_path / "work")  # fmt: skip
    runner = aws_08a.Runner(target, tmp_path / "ledger", out=io.StringIO(), platform=platform)
    with pytest.raises(aws_08a.Refused, match="aws_07b_chain_head"):
        runner.run(["auth-valid", "tls-runtime-hostname"])
    assert sent == [] and runner.ledger.receipts() == []


def test_an_access_denial_is_recorded_as_one_not_as_a_platform_failure(tmp_path):
    from botocore.exceptions import ClientError

    class DeniedIam:
        def simulate_principal_policy(self, **_kwargs):
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "secret text"}},
                              "SimulatePrincipalPolicy")  # fmt: skip

    target = aws_08a.load_target(platform_target(tmp_path))
    target.document["aws_07b_chain_head"] = write_07b_receipts(tmp_path / "work", "a" * 64)
    platform = aws_08a.Platform(target, http=None, clients=lambda _s: DeniedIam(),
                                prompt=lambda _t: "", aws_07b=tmp_path / "work")  # fmt: skip
    runner = aws_08a.Runner(target, tmp_path / "ledger", out=io.StringIO(), platform=platform)
    assert runner.run(["cross-prefix-s3-denial"]) == aws_08a.EXIT_FAILED
    (record,) = [doc for _, doc, _ in runner.ledger.receipts()]
    assert record["reason"] == "access denied: the session may not call SimulatePrincipalPolicy"
    assert "secret text" not in json.dumps(record)


@pytest.mark.parametrize("elsewhere, policy, passed", [
    (frozenset(), [{"Effect": "Deny"}], True),
    (frozenset({"s3:PutObject"}), [{"Effect": "Deny"}], False),  # a write outside reports/
    (frozenset(), [{"Effect": "Deny"}, {"Effect": "Allow"}], False),  # the bucket grants too
])  # fmt: skip
def test_the_s3_case_checks_every_action_and_a_deny_only_bucket_policy(tmp_path, elsewhere,
                                                                       policy, passed):  # fmt: skip
    target = aws_08a.load_target(platform_target(tmp_path))
    target.document["aws_07b_chain_head"] = write_07b_receipts(tmp_path / "work", "a" * 64)
    platform = aws_08a.Platform(target, http=None, clients=lambda _s: FakeIam(elsewhere),
                                prompt=lambda _t: "", aws_07b=tmp_path / "work")  # fmt: skip
    receipts = platform._receipts()
    receipts["foundation"]["outputs"]["terraform"]["report_bucket_policy"]["Statement"] = policy
    platform._receipts = lambda: receipts  # ty: ignore[invalid-assignment]
    observed = platform.run(next(c for c in aws_08a.CASES if c.id == "cross-prefix-s3-denial"))
    assert observed["ok"] is passed, observed
    assert observed["observed"]["decisions"]["worker-task"]["own"] == {
        "s3:GetObject": "allowed",
        "s3:PutObject": "allowed",
    }


def _decision(action: str, decision: str = "implicitDeny", **extra: Any) -> dict[str, Any]:
    return {"EvalActionName": action, "EvalDecision": decision, **extra}


class PagedIam:
    """The reports/ simulation answers completely; the outside one answers with scripted pages."""

    def __init__(self, pages: list[Any], own: FakeIam | None = None) -> None:
        self.pages = pages
        self.own = own or FakeIam()
        self.markers: list[str | None] = []

    def simulate_principal_policy(self, *, PolicySourceArn, ActionNames, ResourceArns,
                                  Marker=None):  # fmt: skip
        if "/reports/" in ResourceArns[0]:
            return self.own.simulate_principal_policy(PolicySourceArn=PolicySourceArn,
                                                      ActionNames=ActionNames,
                                                      ResourceArns=ResourceArns)  # fmt: skip
        self.markers.append(Marker)
        return self.pages[0 if Marker is None else int(Marker.removeprefix("page-"))]


GET, PUT, DELETE = "s3:GetObject", "s3:PutObject", "s3:DeleteObject"
MORE = {"IsTruncated": True, "Marker": "page-1"}
LAST = {"IsTruncated": False}


@pytest.mark.parametrize("pages, reason", [
    # A real answer over two pages: the allowance on the second page is a failed proof.
    ([{"EvaluationResults": [_decision(GET)], **MORE},
      {"EvaluationResults": [_decision(PUT, "allowed"), _decision(DELETE)], **LAST}], None),
    ([{"EvaluationResults": [_decision(GET), _decision(PUT)], **LAST}],
     "no decision for s3:DeleteObject"),
    ([{"EvaluationResults": [_decision(GET), _decision(PUT), _decision(DELETE, "maybe")]}],
     "an unknown decision for s3:DeleteObject"),
    ([{"EvaluationResults": [_decision(GET), _decision(GET), _decision(PUT), _decision(DELETE)]}],
     "more than one decision for s3:GetObject"),
    ([{"EvaluationResults": [_decision(GET), _decision(PUT), _decision(DELETE)], **MORE},
      {"EvaluationResults": [_decision(PUT, "allowed")], **LAST}],
     "more than one decision for s3:PutObject"),
    ([{"EvaluationResults": [_decision(GET), _decision(PUT), _decision(DELETE),
                             _decision("s3:ListBucket")]}], "a decision for an action not requested"),
    ([{"EvaluationResults": [_decision(GET), _decision(PUT),
                             _decision(DELETE, EvalResourceName="arn:aws:s3:::other/x")]}],
     "a decision for s3:DeleteObject on another resource"),
    ([{"EvaluationResults": [_decision(GET)], "IsTruncated": True}],
     "a truncated answer without a marker"),
    ([{"EvaluationResults": [_decision(GET), _decision(PUT), _decision(DELETE)],
       "IsTruncated": "false"}], "an answer with no clear truncation flag"),
    ([{"IsTruncated": False}], "an answer without a list of evaluation results"),
    ([{"EvaluationResults": [None]}], "a malformed evaluation result"),
])  # fmt: skip
def test_the_s3_case_needs_one_known_decision_per_action_across_every_page(tmp_path, pages,
                                                                           reason):  # fmt: skip
    target = aws_08a.load_target(platform_target(tmp_path))
    target.document["aws_07b_chain_head"] = write_07b_receipts(tmp_path / "work", "a" * 64)
    iam = PagedIam(pages)
    platform = aws_08a.Platform(target, http=None, clients=lambda _s: iam,
                                prompt=lambda _t: "", aws_07b=tmp_path / "work")  # fmt: skip
    observed = platform.run(next(c for c in aws_08a.CASES if c.id == "cross-prefix-s3-denial"))
    assert observed["ok"] is False, observed
    if reason is None:
        assert "reason" not in observed
        assert observed["observed"]["decisions"]["worker-task"]["other"][PUT] == "allowed"
    else:
        prefix = "incomplete IAM simulation, worker-task outside reports/"
        assert observed["reason"] == f"{prefix}: {reason}"


def test_the_s3_case_passes_on_a_complete_answer_read_across_its_pages(tmp_path):
    target = aws_08a.load_target(platform_target(tmp_path))
    target.document["aws_07b_chain_head"] = write_07b_receipts(tmp_path / "work", "a" * 64)
    iam = PagedIam([{"EvaluationResults": [_decision(GET)], **MORE},
                    {"EvaluationResults": [_decision(PUT, "explicitDeny"), _decision(DELETE)],
                     **LAST}])  # fmt: skip
    platform = aws_08a.Platform(target, http=None, clients=lambda _s: iam,
                                prompt=lambda _t: "", aws_07b=tmp_path / "work")  # fmt: skip
    bucket = platform._receipts()["foundation"]["outputs"]["terraform"]["report_bucket"]
    # A result may name its resource; the one requested is accepted.
    iam.pages[0]["EvaluationResults"][0]["EvalResourceName"] = (
        f"arn:aws:s3:::{bucket}/aws-08a/outside")  # fmt: skip
    runner = aws_08a.Runner(target, tmp_path / "ledger", out=io.StringIO(), platform=platform)
    assert runner.run(["cross-prefix-s3-denial"]) == aws_08a.EXIT_OK
    (record,) = [doc for _, doc, _ in runner.ledger.receipts()]
    assert record["result"] == "passed", record
    assert record["observed"]["decisions"]["api-task"]["other"] == {
        GET: "implicitDeny", PUT: "explicitDeny", DELETE: "implicitDeny"}  # fmt: skip
    assert iam.markers == [None, "page-1", None, "page-1"]  # both roles, both pages


def test_an_endless_simulation_is_refused_after_a_bounded_number_of_pages(tmp_path):
    target = aws_08a.load_target(platform_target(tmp_path))
    target.document["aws_07b_chain_head"] = write_07b_receipts(tmp_path / "work", "a" * 64)
    iam = PagedIam([{"EvaluationResults": [], "IsTruncated": True, "Marker": f"page-{index + 1}"}
                    for index in range(aws_08a.SIMULATION_PAGES + 5)])  # fmt: skip
    platform = aws_08a.Platform(target, http=None, clients=lambda _s: iam,
                                prompt=lambda _t: "", aws_07b=tmp_path / "work")  # fmt: skip
    runner = aws_08a.Runner(target, tmp_path / "ledger", out=io.StringIO(), platform=platform)
    assert runner.run(["cross-prefix-s3-denial"]) == aws_08a.EXIT_FAILED
    (record,) = [doc for _, doc, _ in runner.ledger.receipts()]
    assert record["result"] == "failed"
    assert record["reason"] == ("incomplete IAM simulation, worker-task outside reports/: still "
                                f"truncated after {aws_08a.SIMULATION_PAGES} pages")  # fmt: skip
    assert len(iam.markers) == aws_08a.SIMULATION_PAGES


def test_an_incomplete_reports_answer_is_not_an_allowance(tmp_path):
    class Partial(FakeIam):
        def simulate_principal_policy(self, *, PolicySourceArn, ActionNames, ResourceArns):
            answer = super().simulate_principal_policy(PolicySourceArn=PolicySourceArn,
                                                       ActionNames=ActionNames,
                                                       ResourceArns=ResourceArns)  # fmt: skip
            return {"EvaluationResults": answer["EvaluationResults"][:1]}

    target = aws_08a.load_target(platform_target(tmp_path))
    target.document["aws_07b_chain_head"] = write_07b_receipts(tmp_path / "work", "a" * 64)
    platform = aws_08a.Platform(target, http=None, clients=lambda _s: Partial(),
                                prompt=lambda _t: "", aws_07b=tmp_path / "work")  # fmt: skip
    observed = platform.run(next(c for c in aws_08a.CASES if c.id == "cross-prefix-s3-denial"))
    assert observed["ok"] is False
    assert observed["reason"] == ("incomplete IAM simulation, worker-task under reports/: no "
                                  "decision for s3:PutObject")  # fmt: skip
