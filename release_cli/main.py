"""Attended release operator CLI and the release controller's only composition root.

``validate`` checks a manifest and approval locally: no clients, credentials,
clock reference or network. Every other command first reads the custodian's
session file, builds the isolated clients, and proves the operator's identity
and the Clock's reference through the preflight; only then does it touch the
control bucket or ECS.

- ``status`` reads the journal and lock and changes nothing.
- ``run`` starts a new release session. A journal owned by another session is a
  conflict; nothing here can name or resume an existing session.
- ``recover`` records the break-glass takeover of a lost session's exact lock,
  then continues the release under this process's new session.
- ``cleanup`` records the same takeover, stops the release's own unfinished job
  tasks and holds. It never launches, deploys or scales.

Output is one JSON document on stdout, with no credential, token or response
text. Exit codes: 0 success, 2 refused before any release action, 3 the release
holds, 4 the controller halted.
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
import uuid
from collections.abc import Callable, Sequence
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Protocol, TextIO

from release.controller import Outcome, RecoveryAuthorization, ReleaseController, ReleaseHalted
from release.journal import Journal, ObjectStore, journal_key, lock_key
from release.manifest import (
    LoadedApproval,
    LoadedManifest,
    Manifest,
    ReleaseRejected,
    load_approval,
    load_manifest,
    verify_approval_binding,
)
from release.ports import AmbiguousResponse, ClockUntrusted
from release_aws.ecs import EcsAdapter
from release_aws.errors import AwsRequestRejected
from release_aws.evidence import LogEvidence
from release_aws.logs import CloudWatchLogs
from release_aws.store import S3ObjectStore
from release_cli.clients import AwsClients
from release_cli.clock import MonotonicUtcClock
from release_cli.credentials import (
    REQUIRED_MARGIN,
    CredentialsRefused,
    SessionCredentials,
    load_session_credentials,
)
from release_cli.preflight import OperatorIdentity, PreflightRefused, verify_operator

EXIT_OK = 0
EXIT_REFUSED = 2
EXIT_HELD = 3
EXIT_HALTED = 4
MAX_INPUT_BYTES = 1024 * 1024


class ClientSource(Protocol):
    def client(self, service: str) -> Any: ...


ClientsFactory = Callable[[SessionCredentials, str], ClientSource]


class Refused(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class ReadOnlyStore:
    """The control bucket for ``status``: reads pass through, every write is refused."""

    def __init__(self, store: ObjectStore) -> None:
        self._store = store

    def read(self, key: str) -> tuple[bytes, str] | None:
        return self._store.read(key)

    def create(self, key: str, body: bytes) -> str:
        raise PermissionError("status never writes")

    def replace(self, key: str, body: bytes, *, if_match: str) -> str:
        raise PermissionError("status never writes")

    def delete(self, key: str, *, if_match: str) -> None:
        raise PermissionError("status never writes")


def control_bucket(manifest: Manifest) -> str:
    """The bootstrap root's control bucket, derived as Terraform names it."""
    environment = manifest.environment
    return f"{environment.name}-{environment.account_id}-control"


def _read_input(path: str) -> bytes:
    try:
        with Path(path).open("rb") as handle:
            data = handle.read(MAX_INPUT_BYTES + 1)
    except OSError:
        raise Refused("input_unreadable", path) from None
    if len(data) > MAX_INPUT_BYTES:
        raise Refused("input_too_large", path)
    return data


def _manifest(path: str) -> LoadedManifest:
    return load_manifest(_read_input(path))


def _approval(path: str, loaded: LoadedManifest) -> LoadedApproval:
    approval = load_approval(_read_input(path))
    verify_approval_binding(loaded, approval)
    return approval


def _required_until(manifest: Manifest, now: datetime) -> datetime:
    window = manifest.window
    return min(now + timedelta(seconds=window.total_seconds), window.expires_at)


def _operator_clients(
    args: argparse.Namespace,
    manifest: Manifest,
    clock: MonotonicUtcClock,
    clients: ClientsFactory,
) -> ClientSource:
    """Credentials file, isolated clients, then identity and time proven by preflight."""
    identity = OperatorIdentity(
        account_id=manifest.environment.account_id,
        role_arn=args.operator_role,
        session_name=manifest.operator,
    )
    now = clock.now()
    credentials = load_session_credentials(
        args.credentials,
        operator=manifest.operator,
        now=now,
        required_until=_required_until(manifest, now),
    )
    source = clients(credentials, manifest.environment.region)
    verify_operator(source.client("sts"), identity, clock)
    # Recheck the custodian's lifetime against the now-referenced clock.
    if credentials.expires_at < _required_until(manifest, clock.now()) + REQUIRED_MARGIN:
        raise CredentialsRefused("session_expires_too_soon")
    return source


def _store(source: ClientSource, manifest: Manifest) -> S3ObjectStore:
    environment = manifest.environment
    return S3ObjectStore(
        source.client("s3"),
        region=environment.region,
        bucket=control_bucket(manifest),
        expected_owner=environment.account_id,
    )


def _controller(
    loaded: LoadedManifest,
    approval: LoadedApproval,
    source: ClientSource,
    clock: MonotonicUtcClock,
    *,
    tokens: Callable[[], str],
    session_id: str,
) -> ReleaseController:
    manifest = loaded.manifest
    region = manifest.environment.region
    logs = CloudWatchLogs(source.client("logs"), region=region)
    return ReleaseController(
        loaded,
        approval,
        store=_store(source, manifest),
        ecs=EcsAdapter(
            source.client("ecs"), region=region, cluster_arn=manifest.environment.cluster_arn
        ),
        evidence=LogEvidence(logs, manifest),
        logs=logs,
        clock=clock,
        tokens=tokens,
        session_id=session_id,
    )


def _outcome(command: str, session_id: str, outcome: Outcome) -> tuple[int, dict[str, Any]]:
    document = {
        "command": command,
        "session_id": session_id,
        "state": outcome.state,
        "reason": outcome.reason,
        "last_proven": outcome.last_proven,
        "admission": outcome.admission,
        "rollback": outcome.rollback,
    }
    return (EXIT_OK if outcome.state == "held_paused" else EXIT_HELD), document


def _status(loaded: LoadedManifest, source: ClientSource) -> dict[str, Any]:
    manifest = loaded.manifest
    store = ReadOnlyStore(_store(source, manifest))
    journal = Journal(store, journal_key(manifest.release_id))
    summary: dict[str, Any] = {"command": "status", "release_id": manifest.release_id}
    if not journal.load():
        summary["journal"] = None
    else:
        document = journal.document
        if document.get("manifest_sha256") != loaded.sha256:
            raise Refused("journal_manifest_mismatch")
        transitions = [e for e in journal.events if e["kind"] == "transition"]
        latest: dict[tuple[str, str], dict[str, Any]] = {}
        for event in journal.events:
            if event["kind"] == "intent":
                latest[(event["action"], event["subject"])] = event
            elif event["kind"] == "observation" and event.get("resolves"):
                latest.pop((event["resolves"], event["subject"]), None)
        summary["journal"] = {
            "session_id": document.get("session_id"),
            "state": transitions[-1]["to"],
            "reason": transitions[-1].get("reason"),
            "events": len(journal.events),
            "last_event_at": journal.events[-1]["at"],
            "outstanding": [
                {"action": e["action"], "subject": e["subject"], "sequence": e["sequence"]}
                for e in sorted(latest.values(), key=lambda item: item["sequence"])
            ],
            "clock_untrusted_events": sum(1 for e in journal.events if e.get("clock_untrusted")),
        }
    found = store.read(lock_key(manifest.environment.name))
    if found is None:
        summary["lock"] = None
    else:
        try:
            body = json.loads(found[0])
        except ValueError:
            body = {}
        body = body if isinstance(body, dict) else {}
        summary["lock"] = {
            "release_id": body.get("release_id"),
            "session_id": body.get("session_id"),
            "etag": found[1],
        }
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m release_cli", allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate", allow_abbrev=False)
    validate.add_argument("--manifest", required=True)
    validate.add_argument("--approval", required=True)
    for name in ("status", "run", "recover", "cleanup"):
        command = commands.add_parser(name, allow_abbrev=False)
        command.add_argument("--manifest", required=True)
        if name != "status":
            command.add_argument("--approval", required=True)
        command.add_argument("--credentials", required=True)
        command.add_argument("--operator-role", required=True)
        if name in ("recover", "cleanup"):
            command.add_argument("--prior-session", required=True)
            command.add_argument("--lock-etag", required=True)
            command.add_argument("--fence-evidence-sha256", required=True)
            command.add_argument("--authorized-by", required=True)
    return parser


def _dispatch(
    args: argparse.Namespace,
    *,
    clients: ClientsFactory,
    clock_factory: Callable[[], MonotonicUtcClock],
    tokens: Callable[[], str],
    session_id: str,
) -> tuple[int, dict[str, Any]]:
    loaded = _manifest(args.manifest)
    if args.command == "validate":
        approval = _approval(args.approval, loaded)
        manifest = loaded.manifest
        return EXIT_OK, {
            "command": "validate",
            "result": "valid",
            "release_id": manifest.release_id,
            "execution": manifest.execution,
            "manifest_sha256": loaded.sha256,
            "approval_sha256": approval.sha256,
            "environment": manifest.environment.name,
            "account_id": manifest.environment.account_id,
            "region": manifest.environment.region,
            "operator": manifest.operator,
            "approval_not_before": approval.approval.not_before.isoformat(),
            "approval_not_after": approval.approval.not_after.isoformat(),
            "jobs": [job.id for job in manifest.jobs],
        }
    approval = None if args.command == "status" else _approval(args.approval, loaded)
    clock = clock_factory()
    source = _operator_clients(args, loaded.manifest, clock, clients)
    if not clock.reference_bound:
        raise Refused("clock_reference_unbound")
    if args.command == "status":
        return EXIT_OK, _status(loaded, source)
    assert approval is not None
    controller = _controller(loaded, approval, source, clock, tokens=tokens, session_id=session_id)
    if args.command == "run":
        return _outcome("run", session_id, controller.run())
    controller.recover(
        RecoveryAuthorization(
            prior_session_id=args.prior_session,
            lock_etag=args.lock_etag,
            fence_evidence_sha256=args.fence_evidence_sha256,
            authorized_by=args.authorized_by,
        )
    )
    if args.command == "recover":
        return _outcome("recover", session_id, controller.run())
    return _outcome("cleanup", session_id, controller.abort())


def _token() -> str:
    return secrets.token_urlsafe(24)


def main(
    argv: Sequence[str] | None = None,
    *,
    clients: ClientsFactory = AwsClients,
    clock_factory: Callable[[], MonotonicUtcClock] = MonotonicUtcClock,
    tokens: Callable[[], str] = _token,
    session_ids: Callable[[], str] = lambda: uuid.uuid4().hex,
    out: TextIO | None = None,
) -> int:
    """Run one command; ``clients`` is the only way an SDK client is obtained."""
    stream = out if out is not None else sys.stdout
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    session_id = session_ids()
    code: int
    document: dict[str, Any]
    try:
        code, document = _dispatch(
            args, clients=clients, clock_factory=clock_factory, tokens=tokens, session_id=session_id
        )
    except ReleaseRejected as error:
        code, document = EXIT_REFUSED, {"error": error.code, "detail": error.detail}
    except Refused as error:
        code, document = EXIT_REFUSED, {"error": error.code, "detail": error.detail}
    except CredentialsRefused as error:
        code, document = EXIT_REFUSED, {"error": error.reason}
    except PreflightRefused as error:
        code, document = EXIT_REFUSED, {"error": error.reason}
    except ClockUntrusted as error:
        code, document = EXIT_REFUSED, {"error": "clock_untrusted", "detail": str(error)}
    except ReleaseHalted as error:
        code, document = EXIT_HALTED, {"error": "halted", "detail": error.code}
    except (AmbiguousResponse, AwsRequestRejected) as error:
        # Only a read (status) or a client check reaches here; the class says enough.
        code, document = EXIT_HALTED, {"error": "aws_unconfirmed", "detail": type(error).__name__}
    document = {"command": args.command, **document}
    stream.write(json.dumps(document, sort_keys=True) + "\n")
    stream.flush()
    return code
