"""Release tools on Cloudflare: platform selection, JobRunner identity and the receipt post."""

from __future__ import annotations

import json
import time

import pytest

from release_tools import jobs, receipt
from tests.test_release_tools import (  # noqa: F401 - fixtures are used by name
    NOW,
    RELEASE_ID,
    environment,
    fake_psql,
    metadata,
)

OBJECT_ID = "d" * 64
NONCE = "e" * 32
GRANT_RESULT = "result|database|sentryruntime\nresult|principal|runtime_owner\n"


class Exchange:
    """A scripted HTTPConnection stand-in; ``plan`` is consumed one entry per attempt."""

    def __init__(self, plan):
        self.plan = list(plan)
        self.attempts = []

    def __call__(self, host, port, timeout):
        exchange = self

        class Connection:
            sock = None

            def request(self, method, path, body, headers):
                step = exchange.plan.pop(0) if exchange.plan else 204
                exchange.attempts.append((host, port, method, path, body, headers, timeout))
                if isinstance(step, float):
                    time.sleep(step)
                    raise OSError("timed out")
                if isinstance(step, Exception):
                    raise step
                self.status = step

            def getresponse(self):
                status = self.status

                class Response:
                    def read(self, limit):
                        return b""

                response = Response()
                response.status = status
                return response

            def close(self):
                pass

        return Connection()


def cloudflare(kind="grant", database="runtime", **overrides):
    env = environment(kind, database, **overrides)
    env.pop("ECS_CONTAINER_METADATA_URI_V4")
    env.update(
        RELEASE_PLATFORM="cloudflare",
        CLOUDFLARE_DURABLE_OBJECT_ID=OBJECT_ID,
        SENTRY_LAUNCH_NONCE=NONCE,
    )
    env.update(overrides)
    return env


@pytest.fixture
def posted(monkeypatch):
    exchange = Exchange([])
    original = receipt.post_cloudflare_receipt

    def post(envelope, **kwargs):
        return original(envelope, connection=exchange, **kwargs)

    monkeypatch.setattr(receipt, "post_cloudflare_receipt", post)
    return exchange


def logs(captured) -> list[dict]:
    return [json.loads(line) for line in captured.err.splitlines() if line.startswith("{")]


@pytest.mark.parametrize("value", ["gcp", "ECS", "", "cloudflare "])
def test_an_unknown_platform_fails_before_any_connection(fake_psql, capsys, value):
    _, recorded = fake_psql
    code = jobs.main(["grant"], cloudflare(RELEASE_PLATFORM=value), now=lambda: NOW)
    assert code == jobs.EXIT_CONFIG
    assert logs(capsys.readouterr())[-1]["reason"] == "release_platform_invalid"
    assert recorded() == []


@pytest.mark.parametrize(
    "override",
    [
        {"CLOUDFLARE_DURABLE_OBJECT_ID": ""},
        {"CLOUDFLARE_DURABLE_OBJECT_ID": "D" * 64},
        {"CLOUDFLARE_DURABLE_OBJECT_ID": "d" * 63},
        {"SENTRY_LAUNCH_NONCE": ""},
        {"SENTRY_LAUNCH_NONCE": "e" * 33},
    ],
)
def test_the_jobrunner_identity_is_required_before_any_connection(fake_psql, capsys, override):
    _, recorded = fake_psql
    code = jobs.main(["grant"], cloudflare(**override), now=lambda: NOW)
    assert code == jobs.EXIT_TASK_IDENTITY
    assert logs(capsys.readouterr())[-1]["reason"] == "instance_identity_unavailable"
    assert recorded() == []


def test_a_cloudflare_job_posts_only_the_separately_versioned_envelope(fake_psql, capsys, posted):
    reply, _ = fake_psql
    reply(stdout=GRANT_RESULT)
    code = jobs.main(["grant"], cloudflare(), now=lambda: NOW)
    captured = capsys.readouterr()
    assert code == jobs.EXIT_OK
    assert receipt.RECEIPT_MARKER not in captured.out
    [(host, port, method, path, body, headers, _)] = posted.attempts
    assert (host, port, method, path) == ("evidence.internal", 80, "POST", "/v1/job-receipt")
    assert headers == {"Content-Type": "application/json"}
    document = json.loads(body)
    assert document == {
        "schema": "sentry.release-tools.job.cloudflare.v1",
        "release_id": RELEASE_ID,
        "job_id": "runtime-grant",
        "durable_object_id": OBJECT_ID,
        "launch_nonce": NONCE,
        "status": "succeeded",
        "result": document["result"],
    }
    assert "task_arn" not in document and set(document["result"]) == {
        "database",
        "principal",
        "service_role",
        "sql_digest",
    }


def test_a_failed_cloudflare_job_posts_its_failure(fake_psql, capsys, posted):
    reply, _ = fake_psql
    reply(stdout="result|database|sentrysearch\nresult|principal|runtime_owner\n")
    code = jobs.main(["grant"], cloudflare(), now=lambda: NOW)
    assert code != jobs.EXIT_OK
    document = json.loads(posted.attempts[0][4])
    assert document["status"] == "failed"
    assert document["result"] == {"reason": "observation_mismatch", "sql_outcome": "unknown"}


def test_a_lost_receipt_never_changes_the_jobs_result(fake_psql, capsys, posted):
    reply, _ = fake_psql
    reply(stdout=GRANT_RESULT)
    posted.plan = [OSError("refused")] * receipt.POST_ATTEMPTS
    code = jobs.main(["grant"], cloudflare(), now=lambda: NOW)
    events = [entry["event"] for entry in logs(capsys.readouterr())]
    assert code == jobs.EXIT_OK
    assert "receipt_unsent" in events and events[-1] == "job_succeeded"
    assert len(posted.attempts) == receipt.POST_ATTEMPTS


def envelope(**changes):
    document = receipt.cloudflare_envelope(
        release_id=RELEASE_ID,
        job_id="runtime-grant",
        durable_object_id=OBJECT_ID,
        launch_nonce=NONCE,
        status="succeeded",
        result={"database": "sentryruntime"},
    )
    document.update(changes)
    return document


def test_a_failed_exchange_is_retried_with_the_identical_body_until_accepted():
    exchange = Exchange([OSError("reset"), 503, 204])
    assert receipt.post_cloudflare_receipt(envelope(), connection=exchange, sleep=lambda _: None)
    bodies = {attempt[4] for attempt in exchange.attempts}
    assert len(exchange.attempts) == 3 and len(bodies) == 1


@pytest.mark.parametrize("status", [400, 403, 409, 413, 422])
def test_a_refusal_is_final(status):
    exchange = Exchange([status, 204])
    assert not receipt.post_cloudflare_receipt(
        envelope(), connection=exchange, sleep=lambda _: None
    )
    assert len(exchange.attempts) == 1


def test_attempts_are_bounded():
    exchange = Exchange([503] * 10)
    assert not receipt.post_cloudflare_receipt(
        envelope(), connection=exchange, sleep=lambda _: None
    )
    assert len(exchange.attempts) == receipt.POST_ATTEMPTS


def test_one_deadline_bounds_every_attempt_including_a_hung_exchange():
    exchange = Exchange([5.0, 5.0, 5.0])
    started = time.monotonic()
    assert not receipt.post_cloudflare_receipt(
        envelope(), deadline_seconds=0.5, connection=exchange
    )
    assert time.monotonic() - started < 1.5


def test_a_hung_name_lookup_is_inside_the_deadline():
    def connection(host, port, timeout):
        time.sleep(5)  # stands in for a blocked getaddrinfo before any socket exists
        raise OSError("unreachable")

    started = time.monotonic()
    assert not receipt.post_cloudflare_receipt(
        envelope(), deadline_seconds=0.3, connection=connection
    )
    assert time.monotonic() - started < 1.0


@pytest.mark.parametrize(
    "change",
    [
        {"task_arn": "arn:aws:ecs:x"},
        {"result": {"blob": "x" * 2100}},
    ],
)
def test_the_envelope_is_exact_and_bounded(change):
    with pytest.raises(ValueError):
        receipt.post_cloudflare_receipt(envelope(**change), connection=Exchange([]))


@pytest.mark.parametrize(
    "identity",
    [{"durable_object_id": "x" * 64}, {"launch_nonce": "E" * 32}, {"status": "maybe"}],
)
def test_the_envelope_identity_and_status_are_validated(identity):
    arguments = {
        "release_id": RELEASE_ID,
        "job_id": "runtime-grant",
        "durable_object_id": OBJECT_ID,
        "launch_nonce": NONCE,
        "status": "succeeded",
        "result": {},
        **identity,
    }
    with pytest.raises(ValueError):
        receipt.cloudflare_envelope(**arguments)


def test_explicit_ecs_is_the_unchanged_default_path(fake_psql, metadata, capsys):
    reply, _ = fake_psql
    reply(stdout=GRANT_RESULT)
    env = environment("grant", "runtime", ECS_CONTAINER_METADATA_URI_V4=metadata)
    env["RELEASE_PLATFORM"] = "ecs"
    assert jobs.main(["grant"], env, now=lambda: NOW) == jobs.EXIT_OK
    out = capsys.readouterr().out
    [line] = [line for line in out.splitlines() if line.startswith(receipt.RECEIPT_MARKER)]
    assert set(json.loads(line.split(" ", 1)[1])) == receipt.ENVELOPE_FIELDS
