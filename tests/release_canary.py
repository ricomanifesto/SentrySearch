"""Explicit integrated release canary; run with dev/check_release_canary.py (AWS-06).

``release_cli run`` drives a whole first deployment through the real adapters:
ECS and Logs requests are answered by the container-backed fakes in
``tests.release_canary_stack`` (real job, observer and service containers on an
internal network, their actual output as log events), and the journal and lock
live in an S3-compatible stand-in reached by the real store adapter. Manifest
expectations come from the images themselves: the release-tools SQL digests, the
Search schema revision and the verified image bindings.

Every environment is disposable: its databases, volumes, network and containers
carry one prefix and are removed afterwards. No AWS request is made.
"""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import socket
import subprocess
import tempfile
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from pathlib import Path
from typing import Any

import pytest
from botocore.config import Config

from release.journal import verify_chain
from release.manifest import load_approval, load_manifest
from release.ports import AmbiguousResponse
from release_tools.receipt import RECEIPT_MARKER
from release_cli import main as cli
from release_cli.clients import AwsClients, client_config, isolated_session
from release_cli.clock import MonotonicUtcClock
from release_cli.credentials import SessionCredentials
from tests.release_canary_stack import (
    CanaryAws,
    CanaryEcs,
    CanaryEnvironment,
    Images,
    TaskDefinitions,
    receipt_lines,
    wait_for,
    wall_window,
)
from tests.release_fakes import (
    ACCOUNT,
    OBSERVER_NAMESPACE,
    REGION,
    SimulatedCrash,
    approval_document,
    encode,
    forward_document,
    manifest_document,
    rollback_run_document,
)
from tests.test_release_cli import ASSUMED, ENVIRONMENT, OPERATOR, ROLE_ID, write_credentials

S3_ENDPOINT = os.environ.get("CANARY_S3_ENDPOINT", "")
# Releases created in each environment, saved with its evidence before teardown.
RELEASES: dict[int, list] = {}
BINDINGS = os.environ.get("CANARY_IMAGE_BINDINGS", "")
ARTIFACTS = os.environ.get("CANARY_ARTIFACTS", "")
REPO = Path(__file__).resolve().parents[1]
BUDGET_SECONDS = 900


def _images() -> tuple[Images, dict]:
    bindings = json.loads(Path(BINDINGS).read_text())
    images = Images(
        runtime=bindings["runtime"]["index"],
        search=bindings["search"]["index"],
        tools=bindings["release-tools"]["index"],
        digests={name: bindings[name]["platform_manifest"]
                 for name in ("runtime", "search", "release-tools")},
    )  # fmt: skip
    return images, bindings


def product_schema() -> str:
    from src.storage.schema import _revision

    version, checksum = _revision()
    return f"sentrysearch:{version}:{checksum[:16]}"


def canary_document(env: CanaryEnvironment, bindings: dict, *, release_id: str) -> dict:
    """A first deployment (bootstrap, empty_hold) whose expectations the images meet."""
    document = forward_document(bootstrap=True)
    document["release_id"] = release_id
    document["environment"]["name"] = ENVIRONMENT
    not_before, expires_at = wall_window()
    document["window"].update(not_before=_iso(not_before), expires_at=_iso(expires_at))
    # The fixture's risk decision expires seven days after its fixed start date. The
    # window here follows the wall clock, so the risk expiry does too (seven days past
    # the window), or every manifest is refused once the fixture date has passed.
    document["risk"]["expires_at"] = _iso(expires_at + timedelta(days=7))
    document["sources"] = {
        "runtime": bindings["runtime"]["source_revision"],
        "search": bindings["search"]["source_revision"],
        "release_tools": bindings["release-tools"]["source_revision"],
    }
    for name, key in (("runtime", "runtime"), ("search", "search"),
                      ("release_tools", "release-tools")):  # fmt: skip
        binding = bindings[key]
        document["images"][name].update(
            manifest_digest=binding["index"],
            arm64_digest=binding["platform_manifest"],
            provenance_sha256=binding["provenance_sha256"],
            sbom_sha256=binding["sbom_sha256"],
            scan_sha256=binding["scan_sha256"],
        )
    from release_tools.config import MAIN_SQL

    sql = env.pins["sql"]
    schemas = {"runtime": "goose:1,2,3", "product": product_schema()}
    for job in document["jobs"]:
        database = job["database"]
        if "schema" in job["expect"]:
            job["expect"]["schema"] = schemas[database]
        if job["phase"] == "grant":
            digest = sql[MAIN_SQL[("grant", database)]]
            job["expect"]["sql_digest"] = digest
            if database == "product":
                job["sql"]["sha256"] = digest
                job["sql"]["source_commit"] = document["sources"]["search"]
            else:
                # The reviewed Runtime grant pin; the image must carry exactly it.
                assert job["sql"]["sha256"] == digest, "release-tools image lacks the pinned grant"
    return document


def _iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Release:
    """One canary release: its documents on disk and the CLI wired to the canary."""

    env: CanaryEnvironment
    ecs: CanaryEcs
    aws: CanaryAws
    document: dict
    root: Path
    outputs: list[dict] = field(default_factory=list)
    counter: int = 0

    @property
    def paths(self) -> dict[str, str]:
        return {name: str(self.root / f"{name}.json") for name in ("manifest", "approval")} | {
            "credentials": str(self.root / "custody" / "session.json")
        }

    def write(self, **approval: Any) -> None:
        (self.root / "manifest.json").write_bytes(encode(self.document))
        loaded = load_manifest(encode(self.document))
        now = datetime.now(UTC).replace(microsecond=0)
        values = {"release_id": self.document["release_id"], "environment": ENVIRONMENT,
                  "not_before": _iso(now - timedelta(minutes=1)),
                  "not_after": _iso(now + timedelta(minutes=90)), **approval}  # fmt: skip
        (self.root / "approval.json").write_bytes(
            encode(approval_document(loaded.sha256, **values))
        )
        write_credentials(Path(self.paths["credentials"]),
                          expires_at=_iso(now + timedelta(hours=3)))  # fmt: skip

    def sts_identity(self, _params: dict) -> dict:
        date = format_datetime(datetime.now(UTC).replace(microsecond=0), usegmt=True)
        return {"UserId": f"{ROLE_ID}:{OPERATOR}", "Account": ACCOUNT, "Arn": ASSUMED,
                "ResponseMetadata": {"HTTPHeaders": {"date": date}}}  # fmt: skip

    def clients(self, credentials: SessionCredentials, region: str):
        release = self

        class Canary:
            def __init__(self) -> None:
                self.real = AwsClients(credentials, region)

            def client(self, service: str):
                if service == "s3":
                    return s3_client(credentials, region)
                return release.aws.bridge.attach(self.real.client(service))

        return Canary()

    def tokens(self) -> str:
        # Unique per release: the ECS fake's idempotency map spans the environment.
        self.counter += 1
        return f"canary{self.document['release_id'][:8]}{self.counter:04d}" + "0" * 18

    def cli(self, command: str, *extra: str, session: str = "canary-session-a",
            clock_factory=MonotonicUtcClock) -> tuple[int, dict]:  # fmt: skip
        out = io.StringIO()
        argv = [command, "--manifest", self.paths["manifest"], "--approval",
                self.paths["approval"], "--credentials", self.paths["credentials"], *extra]  # fmt: skip
        with loopback_only() as attempts:
            code = cli.main(argv, clients=self.clients, clock_factory=clock_factory,
                            tokens=self.tokens, session_ids=lambda: session, out=out,
                            environ={})  # fmt: skip
        assert not attempts, f"the CLI reached beyond loopback: {attempts}"
        report = json.loads(out.getvalue())
        self.outputs.append(report)
        return code, report


LOOPBACK = {"127.0.0.1", "::1", "localhost"}


@contextmanager
def loopback_only() -> Iterator[list[str]]:
    """Refuse and record any lookup or connection that is not to loopback.

    The ECS, Logs and STS clients are answered in process by the offline bridge and
    the S3 client reaches the stand-in on loopback, so an attempt here is a leak.
    """
    attempts: list[str] = []
    saved = (socket.socket.connect, socket.socket.connect_ex, socket.create_connection,
             socket.getaddrinfo)  # fmt: skip

    def allowed(address: Any) -> bool:
        # A Unix socket path is not network; a tuple's host must be loopback.
        return not isinstance(address, tuple) or str(address[0]) in LOOPBACK

    def connect(self: socket.socket, address: Any) -> Any:
        if not allowed(address):
            attempts.append(f"connect {address!r}")
            raise OSError("non-loopback connection refused by the canary")
        return saved[0](self, address)

    def connect_ex(self: socket.socket, address: Any) -> Any:
        if not allowed(address):
            attempts.append(f"connect_ex {address!r}")
            raise OSError("non-loopback connection refused by the canary")
        return saved[1](self, address)

    def create_connection(address: Any, *args: Any, **kwargs: Any) -> Any:
        if not allowed(address):
            attempts.append(f"create_connection {address!r}")
            raise OSError("non-loopback connection refused by the canary")
        return saved[2](address, *args, **kwargs)

    def getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
        if str(host) not in LOOPBACK:
            attempts.append(f"getaddrinfo {host!r}")
            raise OSError("non-loopback lookup refused by the canary")
        return saved[3](host, *args, **kwargs)

    socket.socket.connect = connect  # ty: ignore[invalid-assignment]
    socket.socket.connect_ex = connect_ex  # ty: ignore[invalid-assignment]
    socket.create_connection = create_connection  # ty: ignore[invalid-assignment]
    socket.getaddrinfo = getaddrinfo  # ty: ignore[invalid-assignment]
    try:
        yield attempts
    finally:
        socket.socket.connect, socket.socket.connect_ex = saved[0], saved[1]
        socket.create_connection, socket.getaddrinfo = saved[2], saved[3]


def s3_client(credentials: SessionCredentials, region: str) -> Any:
    """The CLI's S3 client settings, pointed at the stand-in with path-style addressing."""
    base = client_config()
    s3 = getattr(base, "s3", None) or {}
    config = base.merge(Config(s3={**s3, "addressing_style": "path"}))
    return isolated_session().create_client(
        "s3", region_name=region, endpoint_url=S3_ENDPOINT,
        aws_access_key_id=credentials.access_key_id,
        aws_secret_access_key=credentials.secret_access_key,
        aws_session_token=credentials.session_token, config=config,
    )  # fmt: skip


def admin_s3() -> Any:
    """The canary's own reader of the stand-in (not the operator's client)."""
    expires = datetime.now(UTC) + timedelta(hours=1)
    return s3_client(SessionCredentials("canary", "canary-admin", "canary", expires, OPERATOR),
                     REGION)  # fmt: skip


@pytest.fixture
def canary(request) -> Iterator[tuple[CanaryEnvironment, dict]]:
    if not S3_ENDPOINT or not BINDINGS:
        pytest.fail("CANARY_S3_ENDPOINT and CANARY_IMAGE_BINDINGS are required")
    images, bindings = _images()
    with tempfile.TemporaryDirectory(prefix="release-canary-") as directory:
        # Symlink-free, as the CLI requires of the credentials path.
        root = Path(directory).resolve()
        root.chmod(0o755)
        env = CanaryEnvironment(root, images)
        try:
            env.start()
            yield env, bindings
        finally:
            # Evidence first, pass or fail: the journal and every task's output.
            for index, release in enumerate(RELEASES.pop(id(env), [])):
                try:
                    save(release, f"{request.node.name}-{index}")
                except Exception as error:  # never mask the test's own outcome
                    print(f"evidence for release {index} not saved: {error!r}")
            env.stop()


def _window_end(document: dict) -> datetime:
    return datetime.fromisoformat(document["window"]["expires_at"].replace("Z", "+00:00"))


def new_release(env: CanaryEnvironment, bindings: dict, *, release_id: str | None = None,
                revisions_until: datetime | None = None) -> Release:  # fmt: skip
    """A first deployment. Its revisions' fixed deadline is its window's end unless given."""
    document = canary_document(env, bindings, release_id=release_id or str(uuid.uuid4()))
    definitions = TaskDefinitions(env)
    definitions.register(document, not_after=revisions_until or _window_end(document),
                         budget_seconds=BUDGET_SECONDS)  # fmt: skip
    ecs = CanaryEcs(env, definitions)
    ecs.configure(document)
    aws = CanaryAws(ecs, document)
    aws.bridge.handlers[("sts", "GetCallerIdentity")] = lambda p: release.sts_identity(p)
    root = env.root / f"release-{document['release_id'][:8]}"
    root.mkdir(mode=0o700)
    release = Release(env, ecs, aws, document, root)
    RELEASES.setdefault(id(env), []).append(release)
    reset_store()
    release.write()
    return release


def follow(previous: Release, document: dict) -> Release:
    """A later release in the same environment: the same tasks, services and streams.

    A forward release registers its own new revisions under its own deadline. A
    rollback run registers nothing: it launches the prior release's retained
    revisions, each with the deadline that release fixed.
    """
    definitions = previous.ecs.definitions
    if document["purpose"]["kind"] == "rollback":
        definitions.require_retained(document)
    else:
        definitions.register(document, not_after=_window_end(document),
                             budget_seconds=BUDGET_SECONDS)  # fmt: skip
    previous.ecs.learn(document)
    previous.aws.documents.append(document)
    root = previous.env.root / f"release-{document['release_id'][:8]}"
    root.mkdir(mode=0o700)
    release = Release(previous.env, previous.ecs, previous.aws, document, root)
    RELEASES.setdefault(id(previous.env), []).append(release)
    release.write()
    return release


def reset_store() -> None:
    """Each environment starts with an empty control bucket in the shared stand-in.

    A held release keeps its lock by design; the next environment must not inherit it.
    """
    bucket = f"{ENVIRONMENT}-{ACCOUNT}-control"
    client = admin_s3()
    try:
        client.create_bucket(Bucket=bucket)
    except Exception as error:  # an existing bucket from an earlier case in this stand-in
        if "BucketAlready" not in str(error):
            raise
    for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        for item in page.get("Contents", []):
            client.delete_object(Bucket=bucket, Key=item["Key"])


def stored(key: str) -> tuple[bytes, str] | None:
    try:
        found = admin_s3().get_object(Bucket=f"{ENVIRONMENT}-{ACCOUNT}-control", Key=key)
    except Exception as error:
        if "NoSuchKey" in str(error):
            return None
        raise
    return found["Body"].read(), found["ETag"]


def journal(release: Release) -> dict:
    found = stored(f"releases/{release.document['release_id']}/journal.json")
    assert found is not None
    return json.loads(found[0])


# Normalized projection ------------------------------------------------------------------

# Declared nondeterministic fields: wall times, the store's ETags, the hash chain
# that covers them, and the worker's boot id, receipt window and measured
# stability. The lock-release request covers the lock's ETag, so its request hash
# is volatile too; every launch's request hash is compared. The manifest and
# approval hashes cover the release window's wall times: they are masked only after
# ``assert_authority`` has matched each to its saved document, and the documents
# are compared with only their times masked. Deadlines and token expiries are kept
# as offsets from their own event's issue time. Everything else (task identities,
# addresses, tokens, receipt hashes, outcomes, holds, gate resets and lock release)
# is compared as written.
VOLATILE = {"at", "issued_at", "epoch_at", "lock_etag", "prior_sha256", "manifest_sha256",
            "approval_sha256", "boot_id", "first_sequence", "last_sequence",
            "stable_seconds"}  # fmt: skip
RELATIVE = ("deadline_at", "token_expires_at")
# The only fields of a saved manifest and approval that differ between two runs of
# one release: the release window's wall times and the risk expiry that follows
# them, and the approval's own window and its hash of the manifest that carries them.
MANIFEST_TIMES = (("window", "not_before"), ("window", "expires_at"), ("risk", "expires_at"))
APPROVAL_TIMES = (("not_before",), ("not_after",), ("manifest_sha256",))


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def normalized(document: dict) -> Any:
    def walk(value: Any) -> Any:
        if isinstance(value, dict):
            volatile = VOLATILE | (
                {"request_sha256"} if value.get("action") == "release_lock" else set()
            )
            anchor = value.get("issued_at") or value.get("epoch_at") or value.get("at")
            result = {}
            for key, item in value.items():
                if key in RELATIVE and isinstance(item, str) and anchor:
                    seconds = (_time(item) - _time(anchor)).total_seconds()
                    result[key] = f"+{seconds:g}s"
                elif key in volatile:
                    result[key] = "<volatile>"
                else:
                    result[key] = walk(item)
            return result
        if isinstance(value, list):
            return [walk(item) for item in value]
        return value

    return walk(copy.deepcopy(document))


def assert_authority(release: Release, raw: dict) -> None:
    """The journal's manifest and approval hashes are those of the saved documents."""
    manifest = load_manifest((release.root / "manifest.json").read_bytes())
    approval = load_approval((release.root / "approval.json").read_bytes())
    assert raw["manifest_sha256"] == manifest.sha256
    assert approval.approval.manifest_sha256 == manifest.sha256
    prepared = [e for e in raw["events"] if e.get("to") == "prepared"]
    assert [e["approval_sha256"] for e in prepared] == [approval.sha256]


def masked_document(path: Path, times: tuple[tuple[str, ...], ...]) -> Any:
    """A saved manifest or approval with exactly the named wall-time paths masked."""
    document = json.loads(path.read_bytes())
    for keys in times:
        target = document
        for key in keys[:-1]:
            target = target[key]
        assert keys[-1] in target, keys
        target[keys[-1]] = "<time>"
    return document


def save(release: Release, label: str) -> None:
    """Keep the raw journal and the CLI reports; the normalized projection is derived."""
    if not ARTIFACTS:
        return
    directory = Path(ARTIFACTS) / f"{label}-{release.document['release_id'][:8]}"
    directory.mkdir(parents=True, exist_ok=True)
    # Every task container's output, as the log streams carried it.
    outputs = {}
    for arn, task in release.ecs.tasks.items():
        outputs[arn.rsplit("/", 1)[1]] = {
            "job": task.tags.get("sentry:job-id") or task.group,
            "definition": task.task_definition,
            "lines": [line for _, line in release.ecs.lines(task)],
        }
    (directory / "task-output.json").write_text(json.dumps(outputs, indent=1))
    # The documents the journal's authority hashes cover; no credentials.
    for name in ("manifest", "approval"):
        (directory / f"{name}.json").write_bytes((release.root / f"{name}.json").read_bytes())
    if stored(f"releases/{release.document['release_id']}/journal.json") is None:
        return
    raw = journal(release)
    (directory / "journal.json").write_text(json.dumps(raw, indent=1, sort_keys=True))
    (directory / "journal-normalized.json").write_text(
        json.dumps(normalized(raw), indent=1, sort_keys=True)
    )
    (directory / "reports.json").write_text(json.dumps(release.outputs, indent=1))
    digest = hashlib.sha256(json.dumps(normalized(raw), sort_keys=True).encode()).hexdigest()
    (directory / "normalized.sha256").write_text(digest + "\n")


def transitions(release: Release) -> list[str]:
    return [e["to"] for e in journal(release)["events"] if e["kind"] == "transition"]


def launches(release: Release) -> dict[str, int]:
    counts: dict[str, int] = {}
    for task in release.ecs.tasks.values():
        job_id = task.tags.get("sentry:job-id")
        if job_id:
            counts[job_id] = counts.get(job_id, 0) + 1
    return counts


FORWARD = ["prepared", "locked", "quiesced", "migrated", "grants_verified",
           "services_started", "operational_verified", "held_paused"]  # fmt: skip
FIXED_RELEASE = "6a1d2c3b-4e5f-4a7b-8c9d-0e1f2a3b4c5d"


def assert_held_paused(release: Release, code: int, report: dict) -> None:
    assert "error" not in report, report
    assert (code, report["state"]) == (cli.EXIT_OK, "held_paused"), (report, transitions(release))
    raw = journal(release)
    verify_chain(raw)
    assert transitions(release) == FORWARD
    assert stored(f"locks/{ENVIRONMENT}.json") is None, "the lock is released"
    jobs = [job["id"] for job in release.document["jobs"]] + ["runtime-observe", "api-observe"]
    assert launches(release) == {job_id: 1 for job_id in jobs}


def assert_held(release: Release, code: int, report: dict, reason: str) -> None:
    assert "error" not in report, report
    assert (code, report["state"], report["reason"]) == (cli.EXIT_HELD, "hold", reason), report
    verify_chain(journal(release))
    assert "held_paused" not in transitions(release)
    lock = stored(f"locks/{ENVIRONMENT}.json")
    assert lock is not None, "a held release keeps its lock"
    assert json.loads(lock[0])["release_id"] == release.document["release_id"]


def assert_sent_once(release: Release, operation: str) -> None:
    """Every launch and deploy reached ECS once; the lost response was reconciled."""
    events = journal(release)["events"]
    assert not [e for e in events if e["kind"] == "intent" and "retry_of" in e]
    sent = [m[1]["clientToken"] for m in release.ecs.mutations if m[0] == "run_task"]
    journaled = [e["token"] for e in events if e.get("action") == "run_task"]
    assert sorted(sent) == sorted(journaled) and len(set(sent)) == len(sent), (sent, journaled)
    deployed = [m[1]["service"] for m in release.ecs.mutations
                if m[0] == "update_service" and m[1].get("taskDefinition")]  # fmt: skip
    services = release.document["environment"]["services"]
    assert sorted(deployed) == sorted(services.values()), deployed
    resolves = {"RunTask": "run_task", "UpdateService": "update_service"}[operation]
    assert [e["subject"] for e in events if e.get("reconciled") is True
            and e.get("resolves") == resolves], f"no reconciled {resolves} observation"  # fmt: skip


def forget(release: Release) -> None:
    """Remove a finished release's journal so a repeat can reuse its release id."""
    key = f"releases/{release.document['release_id']}/journal.json"
    found = stored(key)
    if found is not None:
        admin_s3().delete_object(Bucket=f"{ENVIRONMENT}-{ACCOUNT}-control", Key=key,
                                 IfMatch=found[1])  # fmt: skip


# The canary ------------------------------------------------------------------------------


def test_a_first_deployment_reaches_held_paused_through_real_containers(canary):
    env, bindings = canary
    release = new_release(env, bindings)
    code, report = release.cli("run")
    assert_held_paused(release, code, report)


def test_two_first_deployments_write_identical_normalized_journals():
    """Two fresh environments, the same release: only declared fields may differ."""
    projections = []
    documents: list[list[Any]] = []
    for run in ("a", "b"):
        images, bindings = _images()
        with tempfile.TemporaryDirectory(prefix="release-canary-") as directory:
            root = Path(directory).resolve()
            root.chmod(0o755)
            env = CanaryEnvironment(root, images, label=run)
            try:
                env.start()
                release = new_release(env, bindings, release_id=FIXED_RELEASE)
                code, report = release.cli("run")
                assert_held_paused(release, code, report)
                save(release, f"repeat-{run}")
                raw = journal(release)
                assert_authority(release, raw)
                documents.append([
                    masked_document(release.root / "manifest.json", MANIFEST_TIMES),
                    masked_document(release.root / "approval.json", APPROVAL_TIMES),
                ])  # fmt: skip
                projections.append(normalized(raw))
                forget(release)
            finally:
                env.stop()
    first, second = (projection["events"] for projection in projections)
    assert len(first) == len(second), (len(first), len(second))
    for index, (left, right) in enumerate(zip(first, second, strict=True)):
        differing = sorted(
            key for key in left.keys() | right.keys() if left.get(key) != right.get(key)
        )
        assert not differing, (
            index,
            left.get("kind"),
            {k: (left.get(k), right.get(k)) for k in differing},
        )
    assert projections[0] == projections[1]
    assert documents[0] == documents[1], "the two runs' manifests and approvals differ"


# Faults: each holds with its designed reason, then recovers or stays held ----------------


def lose_response(release: Release, service: str, operation: str) -> None:
    """The request is applied, then its response is lost once."""
    handler = release.aws.bridge.handlers[(service, operation)]
    state = {"left": 1}

    def lossy(params: dict) -> dict:
        result = handler(params)
        if state["left"]:
            state["left"] -= 1
            raise AmbiguousResponse("response lost after the request was applied")
        return result

    release.aws.bridge.handlers[(service, operation)] = lossy


def lock_etag() -> str:
    found = stored(f"locks/{ENVIRONMENT}.json")
    assert found is not None
    return found[1]


def test_fault_controller_crash_after_a_launch_recovers_to_one_task_each(canary):
    env, bindings = canary
    release = new_release(env, bindings)
    release.ecs.crash[("run_task", "after")] = 1
    with pytest.raises(SimulatedCrash):
        release.cli("run")
    code, report = release.cli(
        "recover", "--prior-session", "canary-session-a", "--lock-etag", lock_etag(),
        "--fence-evidence-sha256", hashlib.sha256(b"canary session a fenced").hexdigest(),
        "--authorized-by", "canary-operator", session="canary-session-b",
    )  # fmt: skip
    assert_held_paused(release, code, report)


@pytest.mark.parametrize("operation", ["RunTask", "UpdateService"])
def test_fault_a_lost_response_is_reconciled_without_a_second_send(canary, operation):
    env, bindings = canary
    release = new_release(env, bindings)
    lose_response(release, "ecs", operation)
    code, report = release.cli("run")
    assert_held_paused(release, code, report)
    assert_sent_once(release, operation)


VERSION_TABLE = (
    "CREATE TABLE IF NOT EXISTS sentrysearch_schema_migrations (version INTEGER PRIMARY KEY,"
    " checksum VARCHAR(64) NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW());"
    " ALTER TABLE sentrysearch_schema_migrations OWNER TO {owner}"
)
# Long enough for the product migration to have started on a loaded host, well
# inside its fifteen-minute job deadline.
EXPIRY_SECONDS = 300


def lock_version_table(env: CanaryEnvironment) -> subprocess.Popen:
    """Hold the product version table exclusively until ``unlock``."""
    database = env.databases["product"]
    container = env.database_container("product")
    env.sql(container, database.name, VERSION_TABLE.format(owner=database.owner))
    process = subprocess.Popen(
        ["docker", "exec", "-i", container, "psql", "-X", "-U", "postgres", "-d",
         database.name], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True,
    )  # fmt: skip
    assert process.stdin is not None
    process.stdin.write("BEGIN; LOCK TABLE sentrysearch_schema_migrations IN ACCESS"
                        " EXCLUSIVE MODE; SELECT 'locked';\n")  # fmt: skip
    process.stdin.flush()
    return process


def unlock(process: subprocess.Popen) -> None:
    assert process.stdin is not None
    process.stdin.write("ROLLBACK;\n")
    process.stdin.close()
    process.wait(timeout=30)


def freeze_blocked(env: CanaryEnvironment, tag: str, *, timeout: int = 60) -> str:
    """Stop the backend of the session tagged ``tag`` once it waits on a lock.

    The wait runs inside the database container, polling every 50 ms: from the host,
    each look costs a ``docker exec`` that a loaded host stretches past the job's
    three-second lock limit. A stopped backend leaves the statement running, so
    no server-side limit can end it; only the job's own deadline or a stop can.
    """
    query = (f"SELECT pid FROM pg_stat_activity WHERE application_name = '{tag}'"
             " AND wait_event_type = 'Lock' LIMIT 1")  # fmt: skip
    script = (f"end=$(( $(date +%s) + {timeout} )); while [ $(date +%s) -lt $end ]; do "
              f'pid=$(psql -X -U postgres -d postgres -tAc "{query}"); '
              'if [ -n "$pid" ]; then kill -STOP "$pid"; echo "$pid"; exit 0; fi; '
              "sleep 0.05; done; exit 1")  # fmt: skip
    result = subprocess.run(
        ["docker", "exec", env.database_container("product"), "sh", "-c", script],
        capture_output=True, text=True, timeout=timeout + 30, check=True,
    )  # fmt: skip
    return result.stdout.strip()


def thaw(env: CanaryEnvironment, pid: str) -> None:
    subprocess.run(["docker", "exec", env.database_container("product"), "kill", "-CONT", pid],
                   capture_output=True, check=False)  # fmt: skip


def assert_session_gone(env: CanaryEnvironment, tag: str) -> None:
    sessions = f"SELECT count(*) FROM pg_stat_activity WHERE application_name = '{tag}'"
    container = env.database_container("product")
    wait_for("the job's session gone", lambda: env.sql(container, "postgres", sessions) == "0",
             timeout=30)  # fmt: skip


def test_fault_a_job_killed_mid_sql_holds_with_its_outcome_unknown(canary):
    env, bindings = canary
    release = new_release(env, bindings)
    tag = f"release:{release.document['release_id']}:product-migrate"
    held: dict[str, Any] = {}

    def kill_mid_statement(task, _name) -> None:
        # Frozen first, so the job is still inside its statement when it dies.
        held["pid"] = freeze_blocked(env, tag)
        held["task"] = task
        release.ecs.kill(task.arn, "KILL")

    release.ecs.before_start["product-migrate"] = lambda _task: held.update(
        lock=lock_version_table(env)
    )
    release.ecs.after_start["product-migrate"] = kill_mid_statement
    try:
        code, report = release.cli("run")
    finally:
        if "pid" in held:
            thaw(env, held["pid"])
        if "lock" in held:
            unlock(held["lock"])
    # The killed job leaves no receipt: the nonzero exit holds, and the schema
    # outcome is unknown, so a rerun must reconcile first.
    assert_held(release, code, report, "job_container_failed")
    assert "reconcile_partial_migration_before_rerun" in report["rollback"]["actions"], report
    task = held["task"]
    assert (release.ecs._state(task) or {}).get("ExitCode") == 137
    assert not receipt_lines([line for _, line in release.ecs.lines(task)])
    assert_session_gone(env, tag)


def test_fault_approval_expiry_mid_window_holds_and_stops_its_jobs(canary):
    env, bindings = canary
    release = new_release(env, bindings)
    expires = datetime.now(UTC).replace(microsecond=0) + timedelta(seconds=EXPIRY_SECONDS)
    release.write(not_after=_iso(expires))
    tag = f"release:{release.document['release_id']}:product-migrate"
    held: dict[str, Any] = {}

    def keep_running(task, _name) -> None:
        # The migration stays inside its statement until something stops it.
        held["pid"] = freeze_blocked(env, tag)
        held["task"] = task

    release.ecs.before_start["product-migrate"] = lambda _task: held.update(
        lock=lock_version_table(env)
    )
    release.ecs.after_start["product-migrate"] = keep_running
    try:
        code, report = release.cli("run")
    finally:
        if "pid" in held:
            thaw(env, held["pid"])
        if "lock" in held:
            unlock(held["lock"])
    assert_held(release, code, report, "approval_expired")
    events = journal(release)["events"]
    task = held["task"]
    launched = [e for e in events if e.get("result") == "launched"
                and e["subject"] == "product-migrate"]  # fmt: skip
    assert len(launched) == 1 and _time(launched[0]["at"]) < expires, launched
    # The expiry stopped the running job: one StopTask, sent and confirmed.
    stops = [(e["subject"], e["task_arn"]) for e in events if e.get("action") == "stop_task"]
    confirmed = [(e["subject"], e["task_arn"]) for e in events
                 if e.get("result") == "stop_confirmed"]  # fmt: skip
    assert stops == confirmed == [("product-migrate", task.arn)], (stops, confirmed)
    assert [m for m in release.ecs.mutations if m[0] == "stop_task"] == [
        ("stop_task", {"task": task.arn, "reason": "release authorization window expired"})
    ]
    assert not [e for e in events if e.get("action") == "run_task"
                and e["sequence"] > launched[0]["sequence"]], "nothing launched after"  # fmt: skip
    assert (release.ecs._state(task) or {}).get("ExitCode") == 143, "SIGTERM ended the job"
    assert_session_gone(env, tag)
    running = [t for t in release.ecs.tasks.values() if t.tags.get("sentry:job-id")
               and release.ecs._status(t) != "STOPPED"]  # fmt: skip
    assert not running, "expiry cleanup stops the release's own jobs"


def test_fault_clock_regression_holds(canary):
    env, bindings = canary
    release = new_release(env, bindings)
    started = time.monotonic()

    def regressing_wall() -> float:
        # Thirty seconds in, the wall clock steps back ten minutes.
        return time.time() - (600 if time.monotonic() - started > 30 else 0)

    code, report = release.cli("run", clock_factory=lambda: MonotonicUtcClock(wall=regressing_wall))
    # The adapter refuses the wall clock's step back (``wall_clock_regression``)
    # and stays untrusted, so the controller holds.
    assert_held(release, code, report, "controller_clock_untrusted")


def test_fault_drifted_service_settings_hold_before_any_deploy(canary):
    env, bindings = canary
    release = new_release(env, bindings)
    api = release.document["environment"]["services"]["api"]
    release.ecs.services[api].settings["enableExecuteCommand"] = True
    code, report = release.cli("run")
    assert_held(release, code, report, "service_settings_drift")
    assert not [m for m in release.ecs.mutations if m[0] == "update_service"
                and m[1].get("taskDefinition")]  # fmt: skip


def test_fault_a_replaced_worker_task_holds_the_gate(canary):
    env, bindings = canary
    release = new_release(env, bindings)

    def replace(task) -> None:
        # The gate's worker task dies; ECS would start another in its place.
        release.ecs.kill(task.arn, "KILL")

    release.aws.canary_logs.before_read = replace
    code, report = release.cli("run")
    assert_held(release, code, report, "task_replaced")
    assert "operational_verified" not in transitions(release)


@pytest.mark.parametrize(
    ("forgery", "reason"),
    [("appended", "observation_ambiguous"), ("substituted", "operational_peer_mismatch")],
)
def test_fault_a_forged_observer_receipt_holds(canary, forgery, reason):
    env, bindings = canary
    release = new_release(env, bindings)
    if forgery == "appended":
        # A second receipt in the observer's stream, naming another task.
        forged = {
            "schema": "sentry.operational.v1", "release_id": release.document["release_id"],
            "check_id": "runtime-observe",
            "task_arn": f"arn:aws:ecs:{REGION}:{ACCOUNT}:task/sentry-staging/" + "f" * 32,
            "status": "passed",
            "result": {"target": "runtime", "host": f"runtime.{OBSERVER_NAMESPACE}",
                       "peer": "169.254.170.250", "port": "8443", "tls": "verified",
                       "checks": "healthz,readyz"},
        }  # fmt: skip
        release.aws.appended["runtime-observe"] = [
            f"{RECEIPT_MARKER} {json.dumps(forged, separators=(',', ':'), sort_keys=True)}"
        ]
    else:
        # The observer's own receipt, with the address it connected to replaced by
        # one that is not the recorded Runtime task's.
        release.aws.rewritten["runtime-observe"] = lambda receipt: {
            **receipt, "result": {**receipt["result"], "peer": "169.254.170.250"}
        }  # fmt: skip
    code, report = release.cli("run")
    assert_held(release, code, report, reason)
    assert "operational_verified" not in transitions(release)


# Rollback canary: a retained prior pair restored after a failed upgrade -------------------

ROLLBACK = ["prepared", "locked", "quiesced", "reconciled", "proven", "services_started",
            "operational_verified", "held_paused"]  # fmt: skip


def _revised(spec: dict, revision: int) -> dict:
    spec = copy.deepcopy(spec)
    family = spec["task_definition"].rsplit(":", 1)[0]
    spec["task_definition"] = f"{family}:{revision}"
    return spec


def upgrade_document(env: CanaryEnvironment, bindings: dict, prior: dict, *, release_id: str
                     ) -> dict:  # fmt: skip
    """A forward upgrade to new revisions whose fallback is the retained prior pair."""
    document = canary_document(env, bindings, release_id=release_id)
    document["jobs"] = [job for job in document["jobs"] if job["phase"] != "bootstrap"]
    for job in document["jobs"]:
        job["task"] = _revised(job["task"], 8)
    for check in document["operational_checks"]:
        if "task" in check:
            check["task"] = _revised(check["task"], 8)
    document["services"] = {name: _revised(spec, 8) for name, spec in document["services"].items()}
    fallback = manifest_document(rollback="compatible_release")["rollback"]
    fallback.update(
        release_id=prior["release_id"],
        images={name: {"repository": prior["images"][name]["repository"],
                       "arm64_digest": prior["images"][name]["arm64_digest"]}
                for name in ("runtime", "search")},
        services=copy.deepcopy(prior["services"]),
        compatible_schemas={"runtime": ["goose:1,2,3"], "product": [product_schema()]},
    )  # fmt: skip
    document["rollback"] = fallback
    return document


def rollback_document(prior: dict, failed: dict, *, release_id: str) -> dict:
    """The rollback run: the prior pair's revisions over the stated actual schemas."""
    document = rollback_run_document()
    document["release_id"] = release_id
    document["environment"] = copy.deepcopy(failed["environment"])
    document["window"] = copy.deepcopy(failed["window"])
    # The prior release's own risk decision, as the rollback kit renders it.
    document["risk"] = copy.deepcopy(prior["risk"])
    document["sources"] = copy.deepcopy(prior["sources"])
    document["images"] = copy.deepcopy(prior["images"])
    document["rollback"] = copy.deepcopy(failed["rollback"])
    document["services"] = copy.deepcopy(prior["services"])
    document["operational_checks"] = copy.deepcopy(prior["operational_checks"])
    schemas = {"runtime": "goose:1,2,3", "product": product_schema()}
    document["purpose"] = {
        "kind": "rollback",
        "failed_release_id": failed["release_id"],
        "failed_services": {name: spec["task_definition"]
                            for name, spec in failed["services"].items()},
        "actual_schemas": schemas,
    }  # fmt: skip
    for job in document["jobs"]:
        job["expect"]["schema"] = schemas[job["database"]]
    return document


def failed_upgrade(env: CanaryEnvironment, bindings: dict, prior: Release) -> Release:
    """An upgrade from the deployed prior release that holds after starting its services."""
    failed = follow(prior, upgrade_document(env, bindings, prior.document,
                                            release_id=str(uuid.uuid4())))  # fmt: skip
    forged = {"schema": "sentry.operational.v1", "release_id": failed.document["release_id"],
              "check_id": "runtime-observe",
              "task_arn": f"arn:aws:ecs:{REGION}:{ACCOUNT}:task/sentry-staging/" + "f" * 32,
              "status": "passed", "result": {"target": "runtime"}}  # fmt: skip
    failed.aws.appended["runtime-observe"] = [
        f"{RECEIPT_MARKER} {json.dumps(forged, separators=(',', ':'), sort_keys=True)}"
    ]
    code, report = failed.cli("run", session="canary-session-f")
    assert_held(failed, code, report, "observation_ambiguous")
    assert "services_started" in transitions(failed), "the failed upgrade deployed its services"
    failed.aws.appended.clear()
    return failed


def run_rollback(prior: Release, failed: Release) -> tuple[Release, int, dict]:
    """A rollback run over the prior release's retained revisions, under a fenced handoff."""
    rollback = follow(prior, rollback_document(prior.document, failed.document,
                                               release_id=str(uuid.uuid4())))  # fmt: skip
    code, report = rollback.cli(
        "run", "--failed-session", "canary-session-f", "--failed-lock-etag", lock_etag(),
        "--fence-evidence-sha256", hashlib.sha256(b"failed session fenced").hexdigest(),
        "--authorized-by", "canary-operator", session="canary-session-r",
    )  # fmt: skip
    return rollback, code, report


def launched_by(release: Release) -> list[str]:
    """The jobs and observers this release's own launch tokens started, in order."""
    own = f"canary{release.document['release_id'][:8]}"
    return [str(task.tags.get("sentry:job-id")) for task in release.ecs.tasks.values()
            if task.started_by.startswith(own)]  # fmt: skip


def test_a_rollback_restores_the_retained_prior_pair_after_a_failed_upgrade(canary):
    env, bindings = canary
    prior = new_release(env, bindings)
    code, report = prior.cli("run", session="canary-session-p")
    assert_held_paused(prior, code, report)
    failed = failed_upgrade(env, bindings, prior)
    rollback, code, report = run_rollback(prior, failed)
    assert "error" not in report, report
    assert (code, report["state"]) == (cli.EXIT_OK, "held_paused"), (report, transitions(rollback))
    verify_chain(journal(rollback))
    assert transitions(rollback) == ROLLBACK
    assert stored(f"locks/{ENVIRONMENT}.json") is None
    for name, arn in rollback.document["environment"]["services"].items():
        assert (
            rollback.ecs.services[arn].task_definition
            == prior.document["services"][name]["task_definition"]
        )
    # The run launches only reconcile, proof and the observers: never a migration,
    # grant or bootstrap.
    assert sorted(launched_by(rollback)) == sorted(
        ["runtime-reconcile", "product-reconcile", "runtime-proof", "product-proof",
         "runtime-observe", "api-observe"]
    )  # fmt: skip
    # Each ran as the prior release's own revision, under the deadline that release
    # fixed, not this run's window.
    deadline = _iso(_window_end(prior.document))
    for task in rollback.ecs.tasks.values():
        if task.started_by.startswith(f"canary{rollback.document['release_id'][:8]}"):
            spec = rollback.ecs.definitions.spec(task.task_definition, task.arn.rsplit("/", 1)[1])
            assert task.task_definition.endswith(":7")
            assert spec.environment["RELEASE_NOT_AFTER"] == deadline
            assert spec.environment["RELEASE_ID"] == prior.document["release_id"]


# How long the prior release's revisions stay valid in the expiry case. It must
# cover that release's own first deployment; a slower host can raise it.
RETAINED_MINUTES = int(os.environ.get("CANARY_RETAINED_MINUTES", "12"))


def test_a_rollback_after_the_retained_revisions_expired_holds_at_its_first_job(canary):
    # The prior release's reconcile, proof and observer revisions keep the deadline
    # its plan fixed. A rollback run approved for a later window does not extend
    # it: its first job refuses to start work, and the run holds. A rollback then
    # needs a new release planned from the prior pair's images.
    env, bindings = canary
    until = datetime.now(UTC).replace(microsecond=0) + timedelta(minutes=RETAINED_MINUTES)
    prior = new_release(env, bindings, revisions_until=until)
    code, report = prior.cli("run", session="canary-session-p")
    assert_held_paused(prior, code, report)
    assert datetime.now(UTC) < until, "the prior release must deploy inside its own deadline"
    failed = failed_upgrade(env, bindings, prior)
    time.sleep(max(0.0, (until - datetime.now(UTC)).total_seconds()) + 2)

    sent_before = len(prior.ecs.mutations)
    rollback, code, report = run_rollback(prior, failed)
    assert _window_end(rollback.document) > until, "the run's own window is still open"
    assert_held(rollback, code, report, "job_container_failed")
    assert transitions(rollback) == ["prepared", "locked", "quiesced", "hold"]
    # Only the first reconcile job was launched; it reported its own expiry.
    assert launched_by(rollback) == ["runtime-reconcile"]
    [task] = [t for t in rollback.ecs.tasks.values()
              if t.tags.get("sentry:job-id") == "runtime-reconcile"]  # fmt: skip
    spec = rollback.ecs.definitions.spec(task.task_definition, task.arn.rsplit("/", 1)[1])
    assert spec.environment["RELEASE_NOT_AFTER"] == _iso(until)
    # It stopped before reaching the database, so it wrote no receipt, only why.
    output = [text for _, text in rollback.ecs.lines(task)]
    assert not receipt_lines(output), output
    assert any("deadline_expired" in text for text in output), output
    # Nothing was proven or started: every service stays at zero on the revision
    # the failed upgrade left, and the run deployed nothing.
    assert not [m for m in rollback.ecs.mutations[sent_before:]
                if m[0] == "update_service" and m[1].get("taskDefinition")]  # fmt: skip
    for name, arn in rollback.document["environment"]["services"].items():
        service = rollback.ecs.services[arn]
        assert service.desired == 0, name
        assert service.task_definition == failed.document["services"][name]["task_definition"]
