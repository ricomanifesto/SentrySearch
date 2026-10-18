"""AWS-08a: the end-to-end matrix against a target, as a hashed, redacted receipt ledger.

    python -m release_kits.aws_08a cases
    python -m release_kits.aws_08a run --target TARGET.json --ledger DIR [--case ID ...]

A target description (``sentry.aws-08a-target.v1``) names what is tested:

    {"schema": "sentry.aws-08a-target.v1", "name": "local-canary", "kind": "local",
     "platform": false, "endpoint": null, "deployer_session": null, "identities": null,
     "images": {"search": "sha256:...", "runtime": "sha256:...", "release_tools": "sha256:..."},
     "runtime_checkout": "/path/to/sentryruntime"}

``kind: local`` is the local canary topology: every case that does not need the
platform runs here, through the suites that prove it (``CASES``), and each case
that needs the platform is recorded ``skip`` with its reason. ``kind: platform``
names the API ``endpoint``, the ``deployer_session`` file, an isolated test
``identities`` file (never a production tenant or key), the AWS-07b work
directory (``aws_07b_work``) and plan, and runs the platform cases. Every record
names the identity kind used (the local test auth double, or the isolated project
the identities file names) and holds only identifiers, outcomes and hashes: no
token, credential, report content or log line. Logs stay beside the ledger and
only their SHA-256 enters it.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time
from typing import Any, Callable, Mapping, TextIO

from release_kits.ledger import ChainBroken, Ledger, utc_now
from release_kits.plan import PlanRefused, sha256

KIT = "aws-08a"
REPO = Path(__file__).resolve().parents[1]
TARGET_SCHEMA = "sentry.aws-08a-target.v1"
IDENTITIES_SCHEMA = "sentry.aws-08a-identities.v1"
EXIT_OK, EXIT_REFUSED, EXIT_FAILED = 0, 2, 3


# The Runtime's two operator events in the shape its slog JSON handler writes them.
# The shape is a line captured from a Runtime built from source on macOS, which
# printed microseconds with the local zone offset; these samples use UTC, and a Linux
# build may print up to nanoseconds. No filter reads the time. The Runtime's own tests
# pin each line's exact keys (sentryruntime internal/runtime/events_test.go); the
# alarm inventory and the alert-delivery case test filters on them.
RUNTIME_EVENT_SAMPLES = {
    "lease_expired": '{"time":"2026-10-18T03:03:57.964322Z","level":"INFO","msg":"lease_expired",'
    '"event":"lease_expired","run_id":"0b9f7c1e-4d2a-4f6b-9a3e-2c1d0e9f8a7b","attempt":2}',
    "retry_exhausted": '{"time":"2026-10-18T03:03:57.964322Z","level":"INFO","msg":"retry_exhausted",'
    '"event":"retry_exhausted","run_id":"0b9f7c1e-4d2a-4f6b-9a3e-2c1d0e9f8a7b","attempt":3,'
    '"max_attempts":3}',
}


class Refused(Exception):
    """The target or an input cannot be used; nothing ran."""


@dataclass(frozen=True)
class Proof:
    """One test that proves a case: a pytest node in a suite, or a Runtime Go test."""

    suite: str
    node: str


@dataclass(frozen=True)
class Case:
    id: str
    title: str
    proofs: tuple[Proof, ...] = ()
    # Why the case needs the platform; such a case is recorded skip on a local target.
    platform: str | None = None
    # How the platform run closes it (a runner below), when it has one.
    platform_runner: str | None = None


def unit(node: str) -> Proof:
    return Proof("unit", node)


def search(node: str) -> Proof:
    return Proof("service-images", node)


def consistency(node: str) -> Proof:
    return Proof("runtime-consistency", node)


def canary(node: str) -> Proof:
    return Proof("deterministic-canary", node)


def go(name: str) -> Proof:
    return Proof("runtime-integration", name)


E2E = canary("tests/deterministic_canary.py::"
             "test_authenticated_report_reaches_evaluation_artifact_and_readback")  # fmt: skip
CASES: tuple[Case, ...] = (
    Case("auth-valid", "A valid test identity's report is admitted", (E2E,),
         platform_runner="auth"),
    Case("auth-invalid", "An invalid token is refused before anything is reserved", (E2E,),
         platform_runner="auth"),
    Case("auth-expired", "An expired token is refused", (E2E,), platform_runner="auth"),
    Case("auth-wrong-owner", "Another identity cannot read or delete the report", (E2E,),
         platform_runner="auth"),
    Case("outbox-dispatch", "The accepted intent is dispatched from the outbox to the Runtime",
         (E2E, unit("tests/test_runtime_adapter.py::"
                    "test_dispatcher_marks_intent_submitted_after_idempotent_runtime_response")),
         platform_runner="report"),
    Case("runtime-claim", "A worker claims the run under a lease and heartbeats it",
         (E2E, go("TestConcurrentClaimersGrantOneLease"), go("TestHeartbeatExtendsTheCurrentLease"),
          unit("tests/test_runtime_adapter.py::test_worker_heartbeats_while_generation_is_running")),
         platform_runner="report"),
    Case("artifacts", "The report artifact is published under its content-addressed key",
         (E2E, unit("tests/test_artifact_keys.py::"
                    "test_different_content_never_overwrites_a_published_object")),
         platform_runner="report"),
    Case("evaluation", "The report is evaluated after generation", (E2E,),
         platform_runner="report"),
    Case("readback", "The owner reads the completed, evaluated report back", (E2E,),
         platform_runner="report"),
    Case("duplicate-submission", "A duplicate delivery maps to the existing run, once",
         (E2E, go("TestConcurrentIdempotentSubmissionsReturnOneRun"))),
    Case("worker-death-before-publication",
         "A worker lost mid-run: its lease expires and a replacement completes the run",
         (go("TestExpiredLeaseIsRecoveredAndStaleWorkerIsFenced"),
          search("tests/service_images.py::"
                 "test_busy_worker_drain_deadline_kills_child_and_restart_recovers_lease"),
          consistency("tests/runtime_postgres.py::test_replacement_attempt_fences_the_old_writer")),
         platform_runner="worker-death"),
    Case("worker-death-after-publication",
         "A worker lost after publishing: the replay is acknowledged without regeneration",
         (unit("tests/test_runtime_adapter.py::"
               "test_worker_acknowledges_completed_report_replay_without_regeneration"),
          consistency("tests/runtime_postgres.py::"
                      "test_terminal_observation_preserves_published_artifacts"),
          consistency("tests/runtime_postgres.py::"
                      "test_takeover_during_upload_preserves_the_winning_object"))),
    Case("stale-fence", "A stale writer is fenced and never classified as a generation failure",
         (go("TestExpiredLeaseIsRecoveredAndStaleWorkerIsFenced"),
          go("TestIllegalTransitionsAreFenced"),
          unit("tests/test_runtime_recovery.py::"
               "test_worker_does_not_classify_a_fence_as_a_generation_failure"),
          consistency("tests/runtime_postgres.py::"
                      "test_missing_and_durable_reports_reject_unfenced_writes"))),
    Case("evaluation-only-recovery",
         "An interrupted evaluation is recovered from saved evidence without regeneration",
         (consistency("tests/runtime_postgres.py::"
                      "test_recovered_evaluation_uses_saved_evidence_without_generation"),
          consistency("tests/runtime_postgres.py::"
                      "test_interrupted_evaluation_is_reclaimed_and_old_results_are_fenced"),
          consistency("tests/runtime_postgres.py::"
                      "test_evaluation_crash_recovery_has_a_budget_and_manual_retry"))),
    Case("dependency-outage",
         "A Runtime outage keeps accepted intents pending and they drain afterwards",
         (consistency("tests/runtime_postgres.py::"
                      "test_accepted_intent_survives_outage_and_drains_during_admission_pause"),
          unit("tests/test_runtime_adapter.py::"
               "test_dispatcher_keeps_intent_pending_when_runtime_is_unavailable"),
          unit("tests/test_runtime_recovery.py::"
               "test_reconciler_preserves_intents_when_the_runtime_cannot_be_read"))),
    Case("retry-exhaustion",
         "Retries are delayed and bounded; exhaustion is terminal and reconciled",
         (go("TestFailurePolicyDelaysRetriesAndExhaustsAttempts"),
          go("TestTerminalFailureCodeDoesNotConsumeRetryBudget"),
          consistency("tests/runtime_postgres.py::"
                      "test_runtime_failure_and_exhaustion_are_reconciled_without_regeneration"))),
    Case("cross-prefix-s3-denial",
         "A workload role cannot read or write another prefix of the report bucket", (),
         platform="IAM and bucket-policy evaluation exist only in the account",
         platform_runner="s3-prefix"),
    Case("tls-runtime-hostname",
         "Callers verify the Runtime's certificate and its runtime.<namespace> name",
         (unit("tests/test_runtime_transport.py::"
               "test_real_tls_rejects_untrusted_identity_and_redirects"),
          search("tests/service_images.py::test_untrusted_runtime_certificate_keeps_worker_unready"),
          search("tests/aws_08a_local.py::"
                 "test_certificate_rollover_needs_the_new_authority_trusted_first")),
         platform_runner="tls"),
    Case("secret-rotation", "Rotated Runtime tokens take over and the retired ones are refused",
         (search("tests/aws_08a_local.py::test_secret_rotation_retires_the_old_runtime_tokens"),)),
    Case("certificate-rollover",
         "A renewed Runtime certificate is trusted only once its authority is in the bundle",
         (search("tests/aws_08a_local.py::"
                 "test_certificate_rollover_needs_the_new_authority_trusted_first"),)),
    Case("termination-grace-and-replacement",
         "SIGTERM drains within its grace and a replacement task takes the work",
         (unit("tests/test_worker_supervisor.py::test_sigterm_drains_the_real_supervisor_process"),
          unit("tests/test_worker_loop.py::test_drain_does_not_start_the_next_work_phase"),
          search("tests/platform_fit.py::"
                 "test_busy_worker_drain_and_restart_recover_on_named_volumes")),
         platform_runner="worker-death"),
    Case("alert-delivery", "An alarm reaches the named recipient", (),
         platform="SNS delivery to a person's inbox exists only in the account",
         platform_runner="alert"),
    Case("pitr-restore",
         "A point-in-time restore into a new instance, its schema verified before any login",
         (), platform="RDS point-in-time restore exists only in the account",
         platform_runner="restore"),
)  # fmt: skip
REQUIRED = tuple(case.id for case in CASES)
SUITES = ("unit", "runtime-consistency", "deterministic-canary", "service-images",
          "runtime-integration")  # fmt: skip


@dataclass
class Target:
    path: Path
    document: dict[str, Any]
    sha256: str
    identities: dict[str, Any] | None = None
    secrets: list[str] = field(default_factory=list)

    @property
    def local(self) -> bool:
        return self.document["kind"] == "local"

    @property
    def identity_kind(self) -> str:
        if self.local:
            return "test auth double (local canary JWT fixture)"
        assert self.identities is not None
        return f"isolated project {self.identities['project']} in {self.identities['service']}"


def load_target(path: Path) -> Target:
    raw = path.read_bytes()
    document = json.loads(raw)
    keys = {"schema", "name", "kind", "platform", "endpoint", "deployer_session", "identities"}
    if not isinstance(document, dict) or document.get("schema") != TARGET_SCHEMA:
        raise Refused(f"the target is not a {TARGET_SCHEMA} document")
    if not keys <= set(document):
        raise Refused(f"the target needs {sorted(keys)}")
    if document["kind"] == "local":
        if (document["platform"] or document["endpoint"] or document["deployer_session"]
                or document["identities"]):  # fmt: skip
            raise Refused("a local target names no endpoint, session or platform")
        for name in ("images", "runtime_checkout"):
            if name not in document:
                raise Refused(f"a local target names {name}")
        return Target(path, document, sha256(raw))
    if document["kind"] != "platform" or document["platform"] is not True:
        raise Refused("kind is local or platform, and a platform target sets platform: true")
    endpoint = str(document["endpoint"] or "")
    if not endpoint.startswith("https://"):
        raise Refused("a platform endpoint is https")
    for name in ("deployer_session", "identities", "aws_07b_work", "aws_07b_chain_head", "plan",
                 "plan_sha256"):  # fmt: skip
        if not document.get(name):
            raise Refused(f"a platform target names {name} explicitly")
    identities = json.loads(Path(document["identities"]).read_bytes())
    if identities.get("schema") != IDENTITIES_SCHEMA:
        raise Refused(f"the identities file is not {IDENTITIES_SCHEMA}")
    if re.search(r"prod", str(identities.get("project")), re.I):
        raise Refused("the identities name a production project; use an isolated one")
    tokens = [Path(identities["tokens"][name]).read_text().strip()
              for name in ("owner", "other", "expired")]  # fmt: skip
    return Target(path, document, sha256(raw), identities, tokens)


# Local suites -------------------------------------------------------------------------


def suite_command(suite: str, target: Target, nodes: list[str]) -> tuple[list[str], Path,
                                                                          dict[str, str]]:  # fmt: skip
    """The command that runs a suite's selected proofs, its directory and extra settings."""
    images = target.document.get("images", {})
    runtime = str(target.document.get("runtime_checkout", ""))
    python = [sys.executable, "-B"]
    image_env = {"SENTRYSEARCH_TEST_IMAGE": images.get("search", ""),
                 "SENTRYRUNTIME_TEST_IMAGE": images.get("runtime", ""),
                 "RELEASE_TOOLS_TEST_IMAGE": images.get("release_tools", ""),
                 "SENTRYRUNTIME_TEST_REPO": runtime}  # fmt: skip
    if suite == "unit":
        return [*python, "-m", "pytest", "-p", "no:cacheprovider", "-v", *nodes], REPO, {}
    if suite == "service-images":
        return [*python, "-m", "pytest", "-p", "no:cacheprovider", "-v", *nodes], REPO, image_env
    if suite == "runtime-consistency":
        return [*python, "dev/check_runtime_consistency.py", "--runtime-repo", runtime], REPO, {}
    if suite == "deterministic-canary":
        return ([*python, "dev/check_deterministic_canary.py", "--runtime-repo", runtime,
                 "--skip-build", "--search-image", images.get("search", ""),
                 "--runtime-image", images.get("runtime", "")], REPO, {})  # fmt: skip
    pattern = "^(" + "|".join(sorted(nodes)) + ")$"
    return (["go", "test", "-tags", "integration", "-count=1", "-json", "-run", pattern,
             "./tests/integration/"], Path(runtime), {})  # fmt: skip


def junit_outcomes(path: Path) -> dict[str, str]:
    """Each test node's outcome from pytest's JUnit XML, parametrized cases folded.

    A node passes only if every one of its parametrized cases passed; any failure
    or error fails it; otherwise (all skipped) it is skipped.
    """
    from xml.etree import ElementTree

    if not path.is_file():
        return {}
    seen: dict[str, list[str]] = {}
    for case in ElementTree.parse(path).iter("testcase"):
        module = str(case.get("classname", "")).replace(".", "/")
        name = str(case.get("name", "")).split("[", 1)[0]
        node = f"{module}.py::{name}"
        kinds = {child.tag for child in case}
        outcome = ("failed" if kinds & {"failure", "error"} else
                   "skipped" if "skipped" in kinds else "passed")  # fmt: skip
        seen.setdefault(node, []).append(outcome)
    return {node: ("failed" if "failed" in outcomes else
                   "passed" if all(o == "passed" for o in outcomes) else "skipped")
            for node, outcomes in seen.items()}  # fmt: skip


def go_outcomes(output: str) -> dict[str, str]:
    """Top-level Go test outcomes from ``go test -json``."""
    found: dict[str, str] = {}
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        test = event.get("Test") if isinstance(event, dict) else None
        if test and "/" not in test and event.get("Action") in ("pass", "fail", "skip"):
            found[test] = {"pass": "passed", "fail": "failed", "skip": "skipped"}[event["Action"]]
    return found


def environment() -> dict[str, str]:
    """What suites inherit: the user's tool paths, never a credential or provider setting."""
    keep = ("PATH", "HOME", "USER", "LANG", "LC_ALL", "TMPDIR", "DOCKER_HOST", "GOPATH",
            "GOCACHE", "GOMODCACHE", "GOTOOLCHAIN", "GOFLAGS")  # fmt: skip
    return {key: value for key, value in os.environ.items() if key in keep} | {
        "PYTHON_DOTENV_DISABLED": "1", "PYTHONDONTWRITEBYTECODE": "1",
        "AWS_EC2_METADATA_DISABLED": "true"}  # fmt: skip


class Runner:
    """Runs a target's cases and writes one ledger record per case."""

    def __init__(self, target: Target, ledger_dir: Path, *, out: TextIO = sys.stdout,
                 prompt: Callable[[str], str] = input,
                 execute: Callable[..., subprocess.CompletedProcess] = subprocess.run,
                 platform: "Platform | None" = None) -> None:  # fmt: skip
        self.target = target
        self.directory = ledger_dir.resolve()
        self.out = out
        self.prompt = prompt
        self.execute = execute
        self.platform = platform
        self.ledger = Ledger(self.directory / "receipts", kit=KIT, plan_sha256=target.sha256)

    def say(self, text: str) -> None:
        print(text, file=self.out, flush=True)

    def run(self, selected: list[str] | None = None) -> int:
        cases = [case for case in CASES if not selected or case.id in selected]
        if selected and len(cases) != len(set(selected)):
            raise Refused(f"unknown cases: {sorted(set(selected) - set(REQUIRED))}")
        if self.ledger.receipts():
            raise Refused("this ledger directory already has records; use a new one")
        self.say(f"AWS-08a against {self.target.document['name']} ({self.target.document['kind']}),"
                 f" target {self.target.sha256}; identity: {self.target.identity_kind}")  # fmt: skip
        if self.target.local:
            outcomes, suites = self._local(cases)
        else:
            outcomes, suites = {}, {}
            if self.platform is not None and self.platform.aws_07b is not None:
                self.platform.receipts()  # the AWS-07b chain, before anything is sent
        failed, digest = 0, ""
        try:
            for case in cases:
                record = self._record(case, outcomes, suites)
                failed += record["result"] == "failed"
                digest = self.ledger.write(case.id, record, keep_out=self.target.secrets)
                self.say(f"  {case.id:<34} {record['result']}"
                         + (f" ({record['reason']})" if record.get("reason") else ""))  # fmt: skip
        finally:
            if digest:
                self.say(f"Ledger head {digest}: keep it; it is the only record of the last entry")
        return EXIT_FAILED if failed else EXIT_OK

    def _local(self, cases: list[Case]) -> tuple[dict[tuple[str, str], str], dict[str, Any]]:
        wanted: dict[str, list[str]] = {}
        for case in cases:
            if case.platform is None:
                for proof in case.proofs:
                    wanted.setdefault(proof.suite, [])
                    if proof.node not in wanted[proof.suite]:
                        wanted[proof.suite].append(proof.node)
        self._check_proofs(wanted)
        outcomes: dict[tuple[str, str], str] = {}
        suites: dict[str, Any] = {}
        logs = self.directory / "logs"
        logs.mkdir(parents=True, exist_ok=True, mode=0o700)
        for suite in SUITES:
            if suite not in wanted:
                continue
            command, cwd, extra = suite_command(suite, self.target, wanted[suite])
            junit = logs / f"{suite}.junit.xml"
            if suite != "runtime-integration":
                # Every pytest the suite starts writes its outcomes here (the dev runners
                # pass the environment on), so no outcome is read from console text.
                extra = {**extra, "PYTEST_ADDOPTS": f"--junitxml={junit}"}
            self.say(f"  $ {shlex.join(command)}")
            started = time.monotonic()
            result = self.execute(command, cwd=cwd, env=environment() | extra, text=True,
                                  capture_output=True, check=False)  # fmt: skip
            text = (result.stdout or "") + (result.stderr or "")
            path = logs / f"{suite}.log"
            with path.open("x") as stream:
                stream.write(text)
            found = (go_outcomes(result.stdout or "") if suite == "runtime-integration"
                     else junit_outcomes(junit))  # fmt: skip
            for node in wanted[suite]:
                outcomes[(suite, node)] = found.get(node, "missing")
            suites[suite] = {"command": command, "exit": result.returncode,
                             "seconds": round(time.monotonic() - started, 1),
                             "log": str(path), "log_sha256": sha256(text.encode())}  # fmt: skip
        return outcomes, suites

    def _check_proofs(self, wanted: dict[str, list[str]]) -> None:
        """Every proof names a test that exists, so a renamed test cannot pass as missing."""
        runtime = Path(str(self.target.document.get("runtime_checkout", "")))
        go_sources = "".join(path.read_text() for path in
                             sorted((runtime / "tests" / "integration").glob("*_test.go")))  # fmt: skip
        for suite, nodes in wanted.items():
            for node in nodes:
                if suite == "runtime-integration":
                    found = f"func {node}(t *testing.T)" in go_sources
                else:
                    path, _, name = node.partition("::")
                    found = (REPO / path).is_file() and f"def {name}(" in (REPO / path).read_text()
                if not found:
                    raise Refused(f"proof {suite} {node} names no test")

    def _record(self, case: Case, outcomes: dict[tuple[str, str], str],
                suites: dict[str, Any]) -> dict[str, Any]:  # fmt: skip
        base = {"title": case.title, "target": self.target.document["name"],
                "target_kind": self.target.document["kind"],
                "identity": self.target.identity_kind, "at": utc_now()}  # fmt: skip
        if self.target.local:
            if case.platform is not None:
                return {**base, "result": "skip", "reason": f"platform: {case.platform}",
                        "platform_runner": case.platform_runner}  # fmt: skip
            proofs = [{"suite": proof.suite, "node": proof.node,
                       "outcome": outcomes[(proof.suite, proof.node)],
                       "suite_exit": suites[proof.suite]["exit"],
                       "log_sha256": suites[proof.suite]["log_sha256"]}
                      for proof in case.proofs]  # fmt: skip
            # A node's pass is an observation; the case passes only if every suite its
            # proofs ran in also exited 0 (an unmapped failure or a failed teardown
            # holds it).
            failed_suites = sorted({proof["suite"] for proof in proofs if proof["suite_exit"] != 0})
            passed = all(proof["outcome"] == "passed" for proof in proofs) and not failed_suites
            record = {**base, "result": "passed" if passed else "failed", "proofs": proofs}
            if failed_suites:
                record["reason"] = "suite exited nonzero: " + ", ".join(
                    f"{suite} ({suites[suite]['exit']})" for suite in failed_suites
                )
            return record
        if case.platform_runner is None or self.platform is None:
            return {**base, "result": "skip",
                    "reason": "no platform runner: the local proofs stand for this case"}  # fmt: skip
        try:
            observed = self.platform.run(case)
        except PlatformSkipped as skipped:
            return {**base, "result": "skip", "reason": str(skipped)}
        except (Refused, ChainBroken):
            raise  # a refused input stops the run; it is not a failed observation
        except Exception as error:  # a failed observation, never its raw text
            code = str(getattr(error, "response", {}).get("Error", {}).get("Code", ""))
            if code in ACCESS_DENIED:
                # Not the platform failing the case: the session may not make this call.
                return {**base, "result": "failed", "reason": "access denied: the session may "
                        f"not call {getattr(error, 'operation_name', 'this API')}"}  # fmt: skip
            return {**base, "result": "failed", "reason": type(error).__name__}
        return {**base, "result": "passed" if observed.pop("ok") else "failed", **observed}


# Platform runners ---------------------------------------------------------------------

ACCESS_DENIED = ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation")


class PlatformSkipped(Exception):
    """A platform case whose input this run was not given."""


class Platform:
    """The platform cases: HTTP through the test identities, AWS through the explicit session."""

    def __init__(self, target: Target, *, http: Any, clients: Callable[[str], Any],
                 prompt: Callable[[str], str], aws_07b: Path | None) -> None:  # fmt: skip
        self.target = target
        self.http = http
        self.clients = clients
        self.prompt = prompt
        self.aws_07b = aws_07b
        self.cache: dict[str, Any] = {}
        self.sleep: Callable[[float], None] = time.sleep

    def token(self, name: str) -> str:
        assert self.target.identities is not None
        return Path(self.target.identities["tokens"][name]).read_text().strip()

    def request(self, method: str, path: str, token: str | None, body: Any = None) -> Any:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return self.http.request(method, path, headers=headers, json=body)

    def run(self, case: Case) -> dict[str, Any]:
        return getattr(self, "_" + str(case.platform_runner).replace("-", "_"))(case)

    def _confirm_submit(self) -> None:
        typed = self.prompt(f"Type submit to send reports to {self.target.document['endpoint']}"
                            " with the test identities (one is admitted and runs generation and"
                            " evaluation): ")  # fmt: skip
        if typed.strip() != "submit":
            raise PlatformSkipped("report creation not confirmed")

    def _submit(self, confirmed: bool = False) -> str | None:
        """Create one report with the owner identity, once confirmed; it runs for real."""
        if not confirmed:
            self._confirm_submit()
        body = {"tool_name": "AWS-08a isolated test target"}
        admitted = self.request("POST", "/api/reports", self.token("owner"), body)
        return admitted.json().get("report_id") if admitted.status_code == 200 else None

    def _poll(self, report: str, done: Callable[[dict[str, Any]], bool],
              seconds: float = 1800) -> dict[str, Any]:  # fmt: skip
        deadline = time.monotonic() + seconds
        seen: dict[str, Any] = {}
        while time.monotonic() < deadline:
            answer = self.request("GET", f"/api/reports/{report}", self.token("owner"))
            body = answer.json() if answer.status_code == 200 else {}
            seen = {"status": body.get("status"), "stage": body.get("generation_stage"),
                    "evaluation_status": body.get("evaluation_status"),
                    "artifact": bool(body.get("markdown_content")),
                    "quality_score_present": body.get("quality_score") is not None}  # fmt: skip
            if done(seen):
                return seen
            self.sleep(10)
        return seen

    def _auth(self, case: Case) -> dict[str, Any]:
        if self.cache.get("declined"):
            raise PlatformSkipped("report creation not confirmed")
        if "auth" not in self.cache:
            # Confirmed first: on a platform whose auth is broken, even the denial
            # probes would create reports.
            try:
                self._confirm_submit()
            except PlatformSkipped:
                self.cache["declined"] = True
                raise
            body = {"tool_name": "AWS-08a isolated test target"}
            denied = {name: self.request("POST", "/api/reports", token, body).status_code
                      for name, token in (("none", None), ("invalid", "not-a-token"),
                                          ("expired", self.token("expired")))}  # fmt: skip
            report = self._submit(confirmed=True)
            other = {method: self.request(method, f"/api/reports/{report}",
                                          self.token("other")).status_code
                     for method in ("GET", "DELETE")} if report else {}  # fmt: skip
            self.cache["auth"] = {"denied": denied, "report_id": report, "other": other}
        seen: dict[str, Any] = self.cache["auth"]
        denied: dict[str, int] = seen["denied"]
        checks = {"auth-valid": seen["report_id"] is not None,
                  "auth-invalid": denied["invalid"] == 401 and denied["none"] == 401,
                  "auth-expired": denied["expired"] == 401,
                  "auth-wrong-owner": seen["other"] == {"GET": 404, "DELETE": 404}}  # fmt: skip
        return {"ok": checks[case.id], "observed": {"denied": denied, "other": seen["other"],
                                                    "admitted": seen["report_id"] is not None}}  # fmt: skip

    def _report(self, case: Case) -> dict[str, Any]:
        if "report" not in self.cache:
            self._auth(CASES[0])
            report = self.cache["auth"]["report_id"]
            if report is None:
                raise PlatformSkipped("no report was admitted")
            self.cache["report"] = self._poll(
                report,
                lambda seen: seen["status"] in ("completed", "failed")
                and seen["evaluation_status"] in ("completed", "failed"),
            )
        seen = self.cache["report"]
        done = seen.get("status") == "completed"
        checks = {"outbox-dispatch": done, "runtime-claim": done, "artifacts": seen.get("artifact"),
                  "evaluation": seen.get("evaluation_status") == "completed",
                  "readback": done and seen.get("quality_score_present")}  # fmt: skip
        return {"ok": bool(checks[case.id]), "observed": seen}

    def receipts(self) -> dict[str, dict[str, Any]]:
        return self._receipts()

    def _receipts(self) -> dict[str, dict[str, Any]]:
        """The AWS-07b chain for this plan, ending at the head the target names."""
        if self.aws_07b is None:
            raise PlatformSkipped("needs the AWS-07b work directory")
        from release_kits.ledger import Ledger

        chain = Ledger(self.aws_07b / "receipts", kit="aws-07b",
                       plan_sha256=str(self.target.document.get("plan_sha256")))  # fmt: skip
        if chain.head()[1] != self.target.document.get("aws_07b_chain_head"):
            raise Refused("the AWS-07b receipts do not end at the target's aws_07b_chain_head")
        return chain.completed()

    def _tls(self, case: Case) -> dict[str, Any]:
        run = self._receipts().get("run")
        if run is None:
            raise PlatformSkipped("the AWS-07b run step has not succeeded")
        report = run["outputs"]["run"]
        # held_paused means the Runtime observer's receipt verified runtime.<namespace>
        # with the private authority (release-tools observe-runtime).
        return {"ok": report.get("state") == "held_paused",
                "observed": {"aws_07b_run_state": report.get("state"),
                             "last_proven": report.get("last_proven")}}  # fmt: skip

    def _s3_prefix(self, case: Case) -> dict[str, Any]:
        done = self._receipts()
        foundation = done["foundation"]["outputs"]["terraform"]
        release = done["releases"]["outputs"]["terraform"]
        key = release["current_release"]
        bucket = foundation["report_bucket"]
        account = done["bootstrap"]["outputs"]["terraform"]["operator_role_arn"].split(":")[4]
        names = release["releases"][key]["iam_role_names"]
        iam = self.clients("iam")
        # IAM simulates a resource policy only for a user caller, so each role's identity
        # policies are simulated alone. The bucket policy holds only Deny statements (checked
        # here on the applied policy), so it can only narrow what they allow.
        statements = foundation["report_bucket_policy"].get("Statement", [])
        deny_only = bool(statements) and all(item.get("Effect") == "Deny" for item in statements)
        decisions: dict[str, dict[str, dict[str, str]]] = {}
        observed = {"decisions": decisions, "bucket_policy_deny_only": deny_only,
                    "evaluated_by": "iam:SimulatePrincipalPolicy on each role's identity "
                                    "policies, every page of each answer; the bucket policy's "
                                    "conditional denies are not simulated"}  # fmt: skip
        for role_key, own in S3_OWN_ACTIONS.items():
            role = f"arn:aws:iam::{account}:role/{names[role_key]}"
            decisions[role_key] = {}
            for label, where, resource, actions in (
                ("own", "under reports/", f"arn:aws:s3:::{bucket}/reports/aws-08a/probe", own),
                ("other", "outside reports/", f"arn:aws:s3:::{bucket}/aws-08a/outside",
                 S3_OBJECT_ACTIONS),
            ):  # fmt: skip
                try:
                    decisions[role_key][label] = simulated_decisions(iam, role, resource, actions)
                except IncompleteSimulation as incomplete:
                    # Missing evidence is not a denial: the proof fails and says why.
                    return {"ok": False, "observed": observed,
                            "reason": f"incomplete IAM simulation, {role_key} {where}: {incomplete}"}  # fmt: skip
        # Each role's own actions are allowed under reports/, each one; outside reports/
        # nothing is allowed to either role.
        ok = deny_only and all(
            set(seen["own"]) == set(S3_OWN_ACTIONS[role_key])
            and all(decision == "allowed" for decision in seen["own"].values())
            and not any(decision == "allowed" for decision in seen["other"].values())
            for role_key, seen in decisions.items()
        )
        return {"ok": ok, "observed": observed}

    def _alert(self, case: Case) -> dict[str, Any]:
        alarm = str(self.target.document.get("alert_alarm") or "")
        prefix = str(self.target.document.get("name_prefix") or "")
        if not alarm or not prefix or not alarm.startswith(prefix + "-"):
            raise PlatformSkipped("the target names no alert_alarm of its own environment")
        filters = self._filter_matches()
        cloudwatch = self.clients("cloudwatch")
        typed = self.prompt(f"Type alert-delivery to set {alarm} to ALARM for one minute: ")
        if typed.strip() != "alert-delivery":
            raise PlatformSkipped("not confirmed")
        cloudwatch.set_alarm_state(AlarmName=alarm, StateValue="ALARM",
                                   StateReason="AWS-08a alert delivery test")  # fmt: skip
        try:
            received = self.prompt("Type received once the notification reached the recipient: ")
        finally:
            cloudwatch.set_alarm_state(AlarmName=alarm, StateValue="OK",
                                       StateReason="AWS-08a alert delivery test finished")  # fmt: skip
        return {"ok": received.strip() == "received" and all(filters.values()),
                "observed": {"alarm": alarm, "confirmed": received.strip() == "received",
                             "metric_filters_match_receipts": filters}}  # fmt: skip

    def _filter_matches(self) -> dict[str, bool]:
        """CloudWatch's own TestMetricFilter over the lines the filters count: receipts
        and metric events the worker's writer makes, and the Runtime's operator events.
        Every filter must match exactly its own samples among all of them."""
        import io

        from src.execution.readiness_receipts import RECEIPT_MARKER, ReadinessReceipts

        foundation = self._receipts()["foundation"]["outputs"]["terraform"]
        patterns = {**(foundation.get("worker_metric_filters") or {}),
                    **(foundation.get("event_metric_filters") or {})}  # fmt: skip

        def line(**snapshot: Any) -> str:
            sink = io.StringIO()
            receipts = ReadinessReceipts("00000000-0000-4000-8000-000000000000", sink)
            receipts.observe({"alive": True, "ready": False, "draining": False, "phase": "idle",
                              "phase_elapsed_seconds": 1.0, "phase_budget_seconds": 60.0,
                              "error_code": None, **snapshot})  # fmt: skip
            receipts.close({"alive": False, "ready": False, "phase": "stopped"}, timeout=1.0)
            return sink.getvalue().splitlines()[0]

        def metric(**fields: Any) -> str:
            sink = io.StringIO()
            receipts = ReadinessReceipts("00000000-0000-4000-8000-000000000000", sink,
                                         emit_metrics=True)  # fmt: skip
            receipts.observe_metrics(lambda: fields)
            receipts.close({"alive": False, "ready": False, "phase": "stopped"}, timeout=1.0)
            return next(text for text in sink.getvalue().splitlines()
                        if not text.startswith(RECEIPT_MARKER))  # fmt: skip

        samples = {"ready": line(ready=True), "unready": line(),
                   "runtime": line(error_code="runtime_unavailable"),
                   "deadline": line(error_code="generation_deadline_exceeded"),
                   "metric": metric(backlog_size=4, backlog_oldest_seconds=1200,
                                    runtime_certificate_days_left=0, reconcile_checked=3,
                                    reconcile_mismatches=1),
                   "metric-quiet": metric(backlog_size=0, backlog_oldest_seconds=None,
                                          runtime_certificate_days_left=None,
                                          reconcile_checked=3, reconcile_mismatches=0),
                   **RUNTIME_EVENT_SAMPLES}  # fmt: skip
        expected = {"WorkerReadyReceipts": {"ready"}, "WorkerRuntimeErrors": {"runtime"},
                    "WorkerDeadlineErrors": {"deadline"},
                    "WorkerBacklogOldestSeconds": {"metric"}, "WorkerReconcileMismatches": {"metric"},
                    "WorkerCertificateDaysLeft": {"metric"},
                    "RuntimeLeaseExpired": {"lease_expired"},
                    "RuntimeRetryExhausted": {"retry_exhausted"}}  # fmt: skip
        logs = self.clients("logs")
        found = {}
        for name, wanted in expected.items():
            if name not in patterns:
                found[name] = False
                continue
            answer = logs.test_metric_filter(filterPattern=patterns[name],
                                             logEventMessages=list(samples.values()))  # fmt: skip
            # Matched by message, not position: event numbering is the service's to define.
            matched = {match.get("eventMessage") for match in answer.get("matches", [])}
            hits = {label for label, message in samples.items() if message in matched}
            found[name] = hits == wanted
        return found

    def _worker_death(self, case: Case) -> dict[str, Any]:
        """Stop the worker mid-run; the report finishes on the task ECS starts in its place."""
        services = self._receipts()["services"]["outputs"]["terraform"]["service_arns"]
        prefix, _, rest = services["worker"].partition(":service/")
        cluster_name, service_name = rest.split("/")[0], rest.split("/")[-1]
        cluster = f"{prefix}:cluster/{cluster_name}"
        ecs = self.clients("ecs")
        tasks = ecs.list_tasks(cluster=cluster, serviceName=service_name)["taskArns"]
        if len(tasks) != 1:
            raise PlatformSkipped(f"expected one running worker task, found {len(tasks)}")
        typed = self.prompt(f"Type {case.id} to submit a report and stop worker task {tasks[0]} "
                            "while it runs: ")  # fmt: skip
        if typed.strip() != case.id:
            raise PlatformSkipped("not confirmed")
        report = self._submit(confirmed=True)  # typing the case id confirmed its one report
        if report is None:
            raise PlatformSkipped("no report was admitted")
        started = self._poll(report, lambda seen: seen["status"] == "generating"
                             and seen["stage"] not in (None, "queued"), seconds=600)  # fmt: skip
        if started.get("status") != "generating":
            raise PlatformSkipped("the report never started on the worker")
        ecs.stop_task(cluster=cluster, task=tasks[0], reason=f"AWS-08a {case.id}")
        finished = self._poll(report, lambda seen: seen["status"] in ("completed", "failed"))
        replaced: list[str] = []
        for _ in range(60):
            replaced = [arn for arn in ecs.list_tasks(cluster=cluster,
                                                      serviceName=service_name)["taskArns"]
                        if arn != tasks[0]]  # fmt: skip
            if replaced:
                break
            self.sleep(10)
        stopped = ecs.describe_tasks(cluster=cluster, tasks=[tasks[0]])["tasks"]
        exits = sorted({c.get("exitCode") for t in stopped for c in t.get("containers", [])
                        if c.get("name") == "app"}, key=str)  # fmt: skip
        timing = stopped[0] if stopped else {}
        ok = finished.get("status") == "completed" and bool(replaced)
        if case.id == "termination-grace-and-replacement":
            # The supervisor's own exit: 0 after a clean drain, 124 when the drain deadline
            # ends a generation. Either means it left before ECS's SIGKILL at the stop
            # timeout, which would have made it 137.
            ok = ok and exits in ([0], [124])
        else:
            # Lost mid-run: the replacement, not the stopped task, finished the report.
            ok = ok and exits in ([124], [137])
        return {"ok": ok, "observed": {"report": finished, "stopped_task": tasks[0],
                                       "app_exit_codes": exits,
                                       "stop_seconds": stop_seconds(timing),
                                       "replacement": replaced[0] if replaced else None}}  # fmt: skip

    def _restore(self, case: Case) -> dict[str, Any]:
        restored = self._receipts().get("restore")
        if restored is None:
            raise PlatformSkipped("needs an AWS-07b restore receipt (python -m "
                                  "release_kits.aws_07b restore)")  # fmt: skip
        # The restore itself is the 07b receipt. Verifying the new instance's schema with
        # the reconcile and proof jobs needs a release whose bundles name that instance;
        # no kit builds one yet, so this case cannot pass and says so.
        raise PlatformSkipped("the restored instance's schema verification is not built: it "
                              "needs a release whose bundles name the restored instance")  # fmt: skip


# Each workload role's own object actions under reports/ (deploy/aws-platform-fit/main.tf).
S3_OWN_ACTIONS = {"worker-task": ("s3:GetObject", "s3:PutObject"),
                  "api-task": ("s3:GetObject", "s3:DeleteObject")}  # fmt: skip
S3_OBJECT_ACTIONS = ("s3:GetObject", "s3:PutObject", "s3:DeleteObject")
SIMULATION_DECISIONS = frozenset({"allowed", "explicitDeny", "implicitDeny"})
# Each request names at most three actions; an answer still truncated after this many
# pages is not a usable one.
SIMULATION_PAGES = 10


class IncompleteSimulation(Exception):
    """An IAM simulation answer that does not decide each requested action exactly once."""


def simulated_decisions(iam: Any, role: str, resource: str,
                        actions: tuple[str, ...]) -> dict[str, str]:  # fmt: skip
    """Each requested action's decision on one resource, read across every page of the answer.

    IAM may truncate a simulation's results below the page size, so an answer is complete
    only when its last page says it is not truncated. A missing, unknown or repeated
    decision, or one for another action or resource, is refused, never read as a denial.
    """
    request: dict[str, Any] = {"PolicySourceArn": role, "ActionNames": list(actions),
                               "ResourceArns": [resource]}  # fmt: skip
    decisions: dict[str, str] = {}
    for _ in range(SIMULATION_PAGES):
        answer = iam.simulate_principal_policy(**request)
        results = answer.get("EvaluationResults") if isinstance(answer, dict) else None
        if not isinstance(results, list):
            raise IncompleteSimulation("an answer without a list of evaluation results")
        for item in results:
            if not isinstance(item, dict):
                raise IncompleteSimulation("a malformed evaluation result")
            action, decision = item.get("EvalActionName"), item.get("EvalDecision")
            if action not in actions:
                raise IncompleteSimulation("a decision for an action not requested")
            if not isinstance(decision, str) or decision not in SIMULATION_DECISIONS:
                raise IncompleteSimulation(f"an unknown decision for {action}")
            if item.get("EvalResourceName", resource) != resource:
                raise IncompleteSimulation(f"a decision for {action} on another resource")
            if action in decisions:
                raise IncompleteSimulation(f"more than one decision for {action}")
            decisions[action] = decision
        truncated = answer.get("IsTruncated", False)
        if not isinstance(truncated, bool):
            raise IncompleteSimulation("an answer with no clear truncation flag")
        if not truncated:
            break
        marker = answer.get("Marker")
        if not isinstance(marker, str) or not marker:
            raise IncompleteSimulation("a truncated answer without a marker")
        request = {**request, "Marker": marker}
    else:
        raise IncompleteSimulation(f"still truncated after {SIMULATION_PAGES} pages")
    missing = [action for action in actions if action not in decisions]
    if missing:
        raise IncompleteSimulation("no decision for " + ", ".join(missing))
    return decisions


def stop_seconds(task: Mapping[str, Any]) -> float | None:
    """From STOPPING to the end of the task's execution (not to STOPPED, which waits for
    the network interface to detach). Recorded as an observation only."""
    started, stopped = task.get("stoppingAt"), task.get("executionStoppedAt")
    if not isinstance(started, datetime) or not isinstance(stopped, datetime):
        return None
    return (stopped - started).total_seconds()


def main(argv: list[str] | None = None, *, out: TextIO = sys.stdout, **options: Any) -> int:
    parser = argparse.ArgumentParser(prog="python -m release_kits.aws_08a", allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("cases")
    run = commands.add_parser("run")
    run.add_argument("--target", type=Path, required=True)
    run.add_argument("--ledger", type=Path, required=True)
    run.add_argument("--case", action="append")
    args = parser.parse_args(argv)
    if args.command == "cases":
        for case in CASES:
            where = f"platform: {case.platform}" if case.platform else "local"
            print(f"{case.id:<34} {where}", file=out)
        return EXIT_OK
    try:
        target = load_target(args.target)
        platform = options.pop("platform", None)
        if platform is None and not target.local:
            platform = platform_for(target)
        return Runner(target, args.ledger, out=out, platform=platform, **options).run(args.case)
    except (Refused, PlanRefused, ChainBroken, KeyError, OSError) as error:
        print(f"aws_08a: refused: {error}", file=out)
        return EXIT_REFUSED


def platform_for(target: Target) -> Platform:
    """The platform runner: isolated HTTP client and clients from the explicit session."""
    import httpx

    from release_kits import session as sessions
    from release_kits.plan import load_plan

    plan = load_plan(Path(target.document["plan"]), target.document["plan_sha256"])
    try:
        loaded = sessions.load(target.document["deployer_session"], operator=plan.operator,
                               now=datetime.now(UTC))  # fmt: skip
    except sessions.SessionRefused as error:
        raise Refused(str(error)) from None
    caller = sessions.client(loaded, "sts", plan.region).get_caller_identity()
    if caller.get("Account") != plan.account_id:
        raise Refused("the session belongs to another account than the plan")
    operator_role = f":assumed-role/{plan.name_prefix}-operator/"
    if operator_role in str(caller.get("Arn", "")):
        raise Refused("give your deployer session: the operator role holds none of the platform "
                      "cases' permissions outside an AWS-07b attach window")  # fmt: skip
    target.document["name_prefix"] = plan.name_prefix
    ca = target.document.get("endpoint_ca")
    http = httpx.Client(base_url=target.document["endpoint"], trust_env=False, timeout=30,
                        verify=ca or True, follow_redirects=False)  # fmt: skip
    return Platform(target, http=http,
                    clients=lambda service: sessions.client(loaded, service, plan.region),
                    prompt=input, aws_07b=Path(target.document["aws_07b_work"]))  # fmt: skip


if __name__ == "__main__":
    raise SystemExit(main())
