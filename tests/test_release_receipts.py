"""Typed release receipts: one strict codec per kind, aligned across languages.

The migration golden lines are byte-identical to the Runtime repository's
``cmd/migrate/testdata`` fixtures, which its Go producer must reproduce. Both
repositories pin the same SHA256s so neither side can drift alone.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from release.machine import evaluate_job
from release.manifest import MIGRATION_RECEIPT_SCHEMA, load_manifest
from release_tools import receipt
from release_tools.receipt import ReceiptAmbiguous, parse_receipt, receipt_line
from tests.release_fakes import encode, manifest_document

FIXTURES = Path(__file__).parent / "fixtures" / "release_receipts"
GOLDEN = {
    "migration-receipt-succeeded.golden": (
        "1f1a493800452bf7b40e2c508a3a7b037424ecc4e51408030289bf303a15a676"
    ),
    "migration-receipt-failed.golden": (
        "7d7820c6a3ab119ac794189bda8bc6a0f295e2f0af0750a07dfc906d2f1a1a4a"
    ),
}
RELEASE = "0b9f7c1e-4d2a-4f6b-9a3e-2c1d0e9f8a7b"
TASK = "arn:aws:ecs:us-east-1:111122223333:task/sentry-staging/0123456789abcdef0123456789abcdef"


def golden(name: str) -> str:
    data = (FIXTURES / name).read_bytes()
    assert hashlib.sha256(data).hexdigest() == GOLDEN[name], "update both repositories together"
    return data.decode().removesuffix("\n")


def test_python_producer_writes_the_runtime_golden_bytes():
    assert MIGRATION_RECEIPT_SCHEMA == receipt.MIGRATION_SCHEMA
    succeeded = receipt_line(
        "migration", release_id=RELEASE, subject="runtime-migrate", task_arn=TASK,
        status="succeeded",
        result={"database": "runtime_db", "principal": "runtime_owner", "schema": "goose:1,2,3"},
    )  # fmt: skip
    failed = receipt_line(
        "migration", release_id=RELEASE, subject="runtime-migrate", task_arn=TASK,
        status="failed", result={"reason": "deadline_exceeded", "sql_outcome": "unknown"},
    )  # fmt: skip
    assert succeeded == golden("migration-receipt-succeeded.golden")
    assert failed == golden("migration-receipt-failed.golden")


def test_the_controller_accepts_the_go_producers_success_receipt_exactly():
    document = manifest_document()
    document["release_id"] = RELEASE
    loaded = load_manifest(encode(document))
    job = loaded.manifest.jobs[0]
    parsed = parse_receipt([golden("migration-receipt-succeeded.golden")], "migration")
    assert parsed is not None
    digests = {name: image["arm64_digest"] for name, image in document["images"].items()}
    containers = [
        {"name": c.name, "imageDigest": digests[c.image], "exitCode": 0}
        for c in job.task.containers
    ]
    task = {
        "taskArn": TASK,
        "taskDefinitionArn": job.task.task_definition,
        "lastStatus": "STOPPED",
        "startedBy": "token",
        "stopCode": "EssentialContainerExited",
        "containers": containers,
        "overrides": {"containerOverrides": [{"name": c["name"]} for c in containers]},
        "enableExecuteCommand": False,
    }
    verdict = evaluate_job(job, digests, release_id=RELEASE, token="token", task=task,
                           receipt=parsed)  # fmt: skip
    assert verdict is None
    failed = parse_receipt([golden("migration-receipt-failed.golden")], "migration")
    assert evaluate_job(job, digests, release_id=RELEASE, token="token", task=task,
                        receipt=failed) == "job_receipt_mismatch"  # fmt: skip


@pytest.mark.parametrize("kind", ["tools", "operational"])
def test_another_kinds_parser_never_accepts_a_migration_receipt(kind):
    with pytest.raises(ReceiptAmbiguous):
        parse_receipt([golden("migration-receipt-succeeded.golden")], kind)


def envelope(**changes) -> str:
    document = json.loads(golden("migration-receipt-succeeded.golden").split(" ", 1)[1])
    for key, value in changes.items():
        if value is None:
            document.pop(key, None)
        else:
            document[key] = value
    return "SENTRY_RELEASE_RECEIPT " + json.dumps(document)


@pytest.mark.parametrize(
    "line",
    [
        envelope(schema="sentry.release-tools.job.v1"),
        envelope(job_id=None, check_id="runtime-migrate"),
        envelope(extra="x"),
        envelope(task_arn=None),
        envelope(status="passed"),
        envelope(release_id=7),
        envelope(result={"database": "runtime_db", "schema": 3}),
        envelope(result={}),
        envelope(result={"database": "a b"}),
        envelope(result=["database"]),
        envelope(status="failed", result={"reason": "x"}),
        envelope(status="failed", result={"reason": "x", "sql_outcome": "none", "more": "y"}),
        "SENTRY_RELEASE_RECEIPT{}",
        "SENTRY_RELEASE_RECEIPT not-json",
    ],
)
def test_a_migration_envelope_other_than_exactly_its_own_is_ambiguous(line):
    with pytest.raises(ReceiptAmbiguous):
        parse_receipt([line], "migration")


def test_absent_or_duplicated_receipts():
    assert parse_receipt(['{"event":"job_started"}'], "migration") is None
    line = golden("migration-receipt-succeeded.golden")
    with pytest.raises(ReceiptAmbiguous):
        parse_receipt([line, line], "migration")


def test_producers_refuse_values_outside_the_allowlist_and_wrong_failure_fields():
    with pytest.raises(ValueError):
        receipt_line("migration", release_id=RELEASE, subject="m", task_arn=TASK,
                     status="succeeded", result={"schema": "has space"})  # fmt: skip
    with pytest.raises(ValueError):
        receipt_line("operational", release_id=RELEASE, subject="c", task_arn=TASK,
                     status="succeeded", result={"target": "api"})  # fmt: skip
    with pytest.raises(ValueError):
        receipt_line("migration", release_id=RELEASE, subject="m", task_arn=TASK,
                     status="failed", result={"reason": "x"})  # fmt: skip
    line = receipt_line("operational", release_id=RELEASE, subject="api-observe", task_arn=TASK,
                        status="passed", result={"target": "api"})  # fmt: skip
    parsed = parse_receipt([line], "operational")
    assert parsed is not None and parsed["check_id"] == "api-observe" and "job_id" not in parsed


@pytest.mark.parametrize(
    "kind, subject_field, status, result",
    [
        ("tools", "job_id", "succeeded", '{"database":"product_db","principal":"product_owner"}'),
        ("migration", "job_id", "succeeded",
         '{"database":"product_db","principal":"product_owner","schema":"goose:1"}'),
        ("operational", "check_id", "passed", '{"target":"api"}'),
    ],
)  # fmt: skip
def test_a_repeated_key_is_ambiguous_never_last_wins(kind, subject_field, status, result):
    schema = receipt.KINDS[kind][0]
    envelope = (
        f'{{"release_id":"{RELEASE}","{subject_field}":"x","schema":"{schema}",'
        f'"status":"failed","status":"{status}","task_arn":"{TASK}","result":{result}}}'
    )
    with pytest.raises(ReceiptAmbiguous):
        parse_receipt([f"{receipt.RECEIPT_MARKER} {envelope}"], kind)
    nested = (
        f'{{"release_id":"{RELEASE}","{subject_field}":"x","schema":"{schema}",'
        f'"status":"{status}","task_arn":"{TASK}",'
        f'"result":{{"database":"a","database":"b"}}}}'
    )
    with pytest.raises(ReceiptAmbiguous):
        parse_receipt([f"{receipt.RECEIPT_MARKER} {nested}"], kind)
