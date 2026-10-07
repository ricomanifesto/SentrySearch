"""Real local pipeline with deterministic test-only external service boundaries.

Explicit Docker suite: use dev/check_deterministic_canary.py, not ordinary pytest.
"""

import hashlib
import json
from pathlib import Path
import time
import uuid

import jwt

from tests.canary_services import OTHER_USER, USER
from tests.platform_fit import VolumeStack, stack  # noqa: F401
from tests.service_images import (
    API,
    SEARCH_IMAGE,
    docker,
    local_probe,
    logs,
    stop,
    wait_for,
)

FIXTURE_MOUNT = ("-v", f"{Path(__file__).resolve().parent}:/fixtures/tests:ro")
REQUEST = """
import http.client,json,sys
request=json.load(sys.stdin)
client=http.client.HTTPConnection('127.0.0.1',8000,timeout=5)
headers={'Content-Type':'application/json'}
if request.get('token'): headers['Authorization']='Bearer '+request['token']
client.request(request['method'],request['path'],json.dumps(request['body']) if request.get('body') else None,headers)
response=client.getresponse()
print(json.dumps([response.status,json.loads(response.read(2097153))]))
client.close()
"""


def request(api, method, path, token=None, body=None):
    result = docker(
        "exec",
        "-i",
        api,
        "python",
        "-c",
        REQUEST,
        stdin=json.dumps({"method": method, "path": path, "token": token, "body": body}),
    )
    return json.loads(result.stdout)


def test_authenticated_report_reaches_evaluation_artifact_and_readback(stack: VolumeStack):
    # The network itself, not just endpoint settings, denies outside providers.
    assert (
        docker("network", "inspect", "--format", "{{.Internal}}", stack.network).stdout.strip()
        == "true"
    )
    key = stack.secrets["provider"]

    def token(user=USER, expiry=None):
        value = jwt.encode(
            {
                "sub": user,
                "aud": "authenticated",
                "iss": "local-canary",
                "exp": int(time.time()) + 600 if expiry is None else expiry,
            },
            key,
            algorithm="HS256",
        )
        stack.secrets[f"canary-{user}-{expiry}"] = value
        return value

    valid, other, expired = token(), token(OTHER_USER), token(expiry=1)
    fixtures = stack.name("canary-fixtures")
    stack.run(
        SEARCH_IMAGE,
        fixtures,
        {"CANARY_AUTH_KEY": key, "PYTHONPATH": "/fixtures:/app"},
        ["python", "-m", "tests.canary_services"],
        detach=True,
        options=(*FIXTURE_MOUNT, "--network-alias", "canary-fixtures"),
    )
    wait_for(
        "fixture services", lambda: "canary fixture listening" in logs(fixtures), container=fixtures
    )
    env = stack.product_env() | {
        "PORT": "8000",
        "NEXT_PUBLIC_SUPABASE_URL": "http://canary-fixtures:9001",
        "SUPABASE_SERVICE_ROLE_KEY": stack.secrets["producer"],
        "AWS_ENDPOINT_URL_S3": "http://canary-fixtures:9001",
        "AWS_REQUEST_CHECKSUM_CALCULATION": "when_required",
        "AWS_RESPONSE_CHECKSUM_VALIDATION": "when_required",
    }
    paused = stack.name("canary-paused-api")
    stack.run(
        SEARCH_IMAGE, paused, env | {"SENTRYSEARCH_EXECUTION_MODE": "paused"}, API, detach=True
    )
    wait_for("paused API", lambda: "Uvicorn running" in logs(paused), container=paused)
    assert request(paused, "POST", "/api/reports", valid, {"tool_name": "Example Threat"})[0] == 503
    assert stack.psql("sentrysearch", "SELECT count(*) FROM reports") == "0"
    assert stop(paused)[0] == 143

    api = stack.name("canary-api")
    stack.run(SEARCH_IMAGE, api, env, API, detach=True)
    wait_for("API", lambda: "Uvicorn running" in logs(api), container=api)
    for denied in (None, "invalid-fixture-token", expired):
        assert (
            request(api, "POST", "/api/reports", denied, {"tool_name": "Example Threat"})[0] == 401
        )
    assert stack.psql("sentrysearch", "SELECT count(*) FROM reports") == "0"

    status, admitted = request(api, "POST", "/api/reports", valid, {"tool_name": "Example Threat"})
    assert status == 200, admitted
    report_id = str(uuid.UUID(admitted["report_id"]))
    assert (
        stack.psql(
            "sentrysearch",
            f"SELECT state FROM report_runtime_dispatches WHERE report_id='{report_id}'",
        )
        == "pending"
    )
    assert request(api, "GET", f"/api/reports/{report_id}", other)[0] == 404

    worker = stack.name("canary-worker")
    worker_env = stack.worker_env() | {
        "PYTHONPATH": "/fixtures:/app",
        "AWS_ENDPOINT_URL_S3": "http://canary-fixtures:9001",
        "AWS_REQUEST_CHECKSUM_CALCULATION": "when_required",
        "AWS_RESPONSE_CHECKSUM_VALIDATION": "when_required",
    }
    stack.run(
        SEARCH_IMAGE,
        worker,
        worker_env,
        ["python", "-m", "tests.canary_process", "--health-port", "8081", "--poll-seconds", "1"],
        detach=True,
        options=FIXTURE_MOUNT,
    )

    def completed():
        return (
            stack.psql(
                "sentrysearch",
                f"SELECT status || ':' || evaluation_status FROM reports WHERE id='{report_id}'",
            )
            == "completed:completed"
        )

    wait_for("generation and evaluation", completed, timeout=90, container=worker)
    probe = docker("exec", worker, "python", "-m", "dev.check_worker_readiness", check=False)
    assert probe.returncode == 0, probe.stdout
    assert json.loads(probe.stdout)["ready"] is True
    assert local_probe(worker, "/healthz")[0] == 200
    status, report = request(api, "GET", f"/api/reports/{report_id}", valid)
    assert status == 200, report
    assert report["status"] == "completed" and report["evaluation_status"] == "completed"
    assert report["quality_score"] > 0 and report["quality_assessment"]["section_validations"]
    assert report["claim_attributions"] and report["markdown_content"]
    assert report["web_sources"] and report["evaluation_route"]
    assert {source["evidence_snapshot_sha256"] for source in report["web_sources"]} == {
        "6208dd694a0c7a30e9d97f45d9815be0caa97dcce704860d01904f2c5a09900d"
    }
    row = stack.psql("sentrysearch", f"SELECT markdown_s3_key FROM reports WHERE id='{report_id}'")
    assert (
        row
        == f"reports/{report_id}/artifacts/{hashlib.sha256(report['markdown_content'].encode()).hexdigest()}.md"
    )
    run_id = str(
        uuid.UUID(
            stack.psql(
                "sentrysearch",
                f"SELECT runtime_run_id FROM report_runtime_dispatches WHERE report_id='{report_id}'",
            )
        )
    )
    runtime_status, run = stack.runtime_get(f"/v1/runs/{run_id}")
    assert runtime_status == 200 and run["state"] == "succeeded" and run["attempt"] == 1, run
    # A duplicate outbox delivery must map to the existing terminal run.
    stack.psql(
        "sentrysearch",
        f"UPDATE report_runtime_dispatches SET state='pending' WHERE report_id='{report_id}'",
    )
    wait_for(
        "idempotent redispatch",
        lambda: stack.psql(
            "sentrysearch",
            f"SELECT state FROM report_runtime_dispatches WHERE report_id='{report_id}'",
        )
        == "succeeded",
        container=worker,
    )
    assert stack.runtime_get(f"/v1/runs/{run_id}")[1]["attempt"] == 1
    assert (
        stack.psql("sentrysearch", f"SELECT markdown_s3_key FROM reports WHERE id='{report_id}'")
        == row
    )
    assert request(api, "GET", f"/api/reports/{report_id}", other)[0] == 404
    assert request(api, "GET", f"/api/reports/{report_id}", expired)[0] == 401
    assert request(api, "DELETE", f"/api/reports/{report_id}", other)[0] == 404
    assert request(api, "GET", f"/api/reports/{report_id}", valid)[0] == 200
    assert request(api, "DELETE", f"/api/reports/{report_id}", valid)[0] == 200
    assert request(api, "GET", f"/api/reports/{report_id}", valid)[0] == 404
    assert stack.psql("sentrysearch", f"SELECT count(*) FROM reports WHERE id='{report_id}'") == "0"
    removed = docker(
        "exec",
        fixtures,
        "python",
        "-c",
        "import http.client,sys; c=http.client.HTTPConnection('127.0.0.1',9001,timeout=3); "
        "c.request('GET',sys.argv[1]); assert c.getresponse().status == 404; c.close()",
        f"/image-check-bucket/{row}",
        check=False,
    )
    assert removed.returncode == 0, removed.stderr
    assert stop(worker)[0] == 0
    fixture_receipt = json.loads(
        logs(worker).split("Canary fixture receipt: ", 1)[1].splitlines()[0]
    )
    assert fixture_receipt == {
        "model_requests": {"research": 3, "synthesis": 1, "section": 7, "consistency": 1},
        "source_requests": 1,
    }
    assert stop(api)[0] == 143
    for name in (api, paused, worker, fixtures):
        stack.assert_no_secrets(logs(name))
    print(
        json.dumps(
            {
                "proof": "local-fixture-e2e",
                "state": run["state"],
                "evaluation": report["evaluation_status"],
                "artifact_sha256": row.rsplit("/", 1)[1][:-3],
                "auth_denials": True,
                "duplicate_dispatch": True,
                "worker_ready": True,
            }
        )
    )
