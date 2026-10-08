"""R2 report artifact backend against the offline R2 model."""

from __future__ import annotations

import importlib
import json
import os
from pathlib import Path
from typing import Any, cast
from urllib.parse import parse_qs, urlsplit

import botocore.session
from botocore.exceptions import ClientError
from botocore.loaders import Loader
import pytest

from release_cloudflare.r2_client import R2ClientRejected, R2Target, endpoint_for
from src.storage.artifact_store import MAX_PRESIGN_SECONDS, artifact_key
from src.storage.r2_artifacts import (
    ArtifactDeletionIncomplete,
    R2ArtifactStore,
    R2Credentials,
    build_client,
    client_config,
)
from src.storage.s3_manager import S3StorageManager
from tests.r2_fakes import ACCOUNT_ID, Fault, R2Backend

ARTIFACTS = R2Target(account_id=ACCOUNT_ID, bucket="sentry-staging-artifacts")
CREDENTIALS = R2Credentials("fixture-artifact-key-id", "fixture-artifact-secret")


def store_for(backend: R2Backend, **kwargs: Any) -> R2ArtifactStore:
    def factory():
        client = build_client(ARTIFACTS, CREDENTIALS, ca_bundle=None)
        client.meta.events.register("before-send.s3", backend.handle)
        return client

    return R2ArtifactStore(ARTIFACTS, CREDENTIALS, client_factory=factory, **kwargs)


def artifacts_backend(**kwargs: Any) -> R2Backend:
    return R2Backend(target=ARTIFACTS, **kwargs)


def test_keys_match_the_s3_backend_for_the_same_bytes():
    objects: dict[str, bytes] = {}

    class Client:
        def put_object(self, **kwargs):
            objects[kwargs["Key"]] = kwargs["Body"]

    s3 = S3StorageManager()
    s3.s3_client = cast(Any, Client())
    s3._initialized = True
    r2 = store_for(artifacts_backend())
    assert r2.upload_markdown_report("report-1", "winner") == s3.upload_markdown_report(
        "report-1", "winner"
    )
    trace = {"attempt": 1, "nested": {"b": 2, "a": 1}}
    assert r2.upload_trace_data("report-1", trace) == s3.upload_trace_data("report-1", trace)
    assert artifact_key("report-1", b"winner", "md").startswith("reports/report-1/artifacts/")


def test_upload_is_content_addressed_and_round_trips_without_checksum_trailers():
    backend = artifacts_backend()
    store = store_for(backend)
    first = store.upload_markdown_report("report-1", "winner")
    second = store.upload_markdown_report("report-1", "late writer")
    assert first != second
    assert store.upload_markdown_report("report-1", "winner") == first
    assert store.download_content(first) == "winner"
    assert backend.raw(first) == b"winner"
    for entry in backend.requests("PUT"):
        assert entry.status == 200
        assert entry.headers["content-type"] in ("text/markdown", "application/json")
        assert not any(name.startswith("x-amz-checksum-") for name in entry.headers)
        assert "aws-chunked" not in entry.headers.get("content-encoding", "")


def test_download_errors_surface_like_the_s3_backend():
    store = store_for(artifacts_backend())
    with pytest.raises(ClientError):
        store.download_content("reports/report-1/artifacts/" + "0" * 64 + ".md")


@pytest.mark.parametrize(
    "key",
    [
        "other/report-1/x.md",
        "reports//x.md",
        "reports/report-1/../../escape.md",
        "reports/report-1/./x.md",
        "reports/report-1",
        "",
    ],
)
def test_keys_outside_the_report_namespace_are_refused(key):
    store = store_for(artifacts_backend())
    with pytest.raises(ValueError):
        store.download_content(key)
    with pytest.raises(ValueError):
        store.get_presigned_url(key)


@pytest.mark.parametrize("report_id", ["", "a/b", "../x", "-leading", "x" * 129, "has space"])
def test_report_ids_cannot_escape_their_prefix(report_id):
    store = store_for(artifacts_backend())
    with pytest.raises(ValueError):
        store.upload_markdown_report(report_id, "x")
    with pytest.raises(ValueError):
        store.delete_report_files(report_id)


def test_presigned_urls_are_on_the_s3_domain_and_capped_at_seven_days():
    store = store_for(artifacts_backend())
    key = "reports/report-1/artifacts/" + "0" * 64 + ".md"
    url = store.get_presigned_url(key)
    parts = urlsplit(url)
    assert parts.hostname == f"{ACCOUNT_ID}.r2.cloudflarestorage.com"
    assert parts.path == f"/{ARTIFACTS.bucket}/{key}"
    query = parse_qs(parts.query)
    assert query["X-Amz-Expires"] == ["3600"] and query["X-Amz-Algorithm"] == ["AWS4-HMAC-SHA256"]
    assert parse_qs(urlsplit(store.get_presigned_url(key, MAX_PRESIGN_SECONDS)).query)[
        "X-Amz-Expires"
    ] == [str(MAX_PRESIGN_SECONDS)]
    for bad in (0, -1, MAX_PRESIGN_SECONDS + 1, True):
        with pytest.raises(ValueError):
            store.get_presigned_url(key, bad)


def test_deletion_pages_through_the_prefix_and_never_touches_a_neighbour():
    backend = artifacts_backend(page_size=2)
    store = store_for(backend)
    mine = [store.upload_markdown_report("report-1", f"body {n}") for n in range(5)]
    neighbour = store.upload_markdown_report("report-10", "neighbour")
    assert sorted(store.list_report_files("report-1")) == sorted(mine)
    store.delete_report_files("report-1")
    assert backend.keys("reports/report-1/") == []
    assert backend.keys("reports/report-10/") == [neighbour]
    lists = [entry for entry in backend.requests("GET") if entry.key == ""]
    assert len(lists) >= 3, "the listing was paginated"
    assert all(entry.status == 204 for entry in backend.requests("DELETE"))


def test_a_failed_key_is_reported_after_every_key_is_attempted():
    backend = artifacts_backend()
    store = store_for(backend)
    keys = [store.upload_markdown_report("report-1", f"body {n}") for n in range(3)]
    backend.faults.append(Fault("DELETE", keys[1], "http_500", count=3))
    with pytest.raises(ArtifactDeletionIncomplete, match="1 of 3"):
        store.delete_report_files("report-1")
    assert backend.keys("reports/report-1/") == [keys[1]]


def test_empty_report_deletes_nothing():
    backend = artifacts_backend()
    store = store_for(backend)
    store.delete_report_files("report-1")
    assert backend.requests("DELETE") == []
    assert store.list_report_files("report-1") == []


def test_transient_failures_are_retried_for_idempotent_calls_only_within_the_bound():
    backend = artifacts_backend()
    store = store_for(backend)
    backend.faults.append(Fault("PUT", "reports/.*", "http_500", count=2))
    key = store.upload_markdown_report("report-1", "eventually")
    assert backend.raw(key) == b"eventually"
    backend.faults.append(Fault("PUT", "reports/.*", "http_500", count=3))
    with pytest.raises(ClientError):
        store.upload_markdown_report("report-1", "never")


def test_require_available_builds_an_isolated_client(monkeypatch):
    poisoned = {
        "AWS_PROFILE": "poisoned",
        "AWS_ACCESS_KEY_ID": "poisoned",
        "AWS_SECRET_ACCESS_KEY": "poisoned",
        "AWS_ENDPOINT_URL": "https://ambient.invalid",
        "AWS_ENDPOINT_URL_S3": "https://ambient.invalid",
        "AWS_CONFIG_FILE": "/nonexistent/config",
        "AWS_SHARED_CREDENTIALS_FILE": "/nonexistent/credentials",
        "AWS_CA_BUNDLE": "/nonexistent/ca.pem",
        "REQUESTS_CA_BUNDLE": "/nonexistent/requests-ca.pem",
        "HTTPS_PROXY": "http://192.0.2.1:9",
        "HTTP_PROXY": "http://192.0.2.1:9",
        "AWS_REQUEST_CHECKSUM_CALCULATION": "when_supported",
    }
    for name, value in poisoned.items():
        monkeypatch.setenv(name, value)
    store = R2ArtifactStore(ARTIFACTS, CREDENTIALS)
    store.require_available()
    client = store._client
    assert client.meta.endpoint_url == f"https://{ACCOUNT_ID}.r2.cloudflarestorage.com"
    assert client._get_credentials().method == "explicit"
    assert client._get_credentials().access_key == "fixture-artifact-key-id"
    assert client._endpoint.http_session._proxy_config._proxies == {}
    assert client.meta.config.request_checksum_calculation == "when_required"


def test_unusable_clients_and_credentials_fail_closed_without_echoing_values():
    with pytest.raises(ValueError):
        R2Credentials("", "secret")
    with pytest.raises(ValueError):
        R2Credentials("id", "has space")
    assert "secret-value" not in repr(R2Credentials("id", "secret-value"))
    store = R2ArtifactStore(ARTIFACTS, CREDENTIALS, client_factory=lambda: object())
    with pytest.raises(RuntimeError, match="Artifact storage unavailable") as error:
        store.require_available()
    assert error.value.__cause__ is None


def test_attempt_bounds_differ_only_where_every_operation_is_idempotent():
    from release_cloudflare.r2_client import R2ClientRejected, validate_client
    from release_cloudflare.r2_store import R2ObjectStore
    from tests.r2_fakes import CONTROL, make_client

    three: dict[str, Any] = {"retries": {"mode": "standard", "total_max_attempts": 3}}
    artifact_client = build_client(ARTIFACTS, CREDENTIALS, ca_bundle=None)
    validate_client(artifact_client, ARTIFACTS, max_attempts=3)
    with pytest.raises(R2ClientRejected):
        validate_client(artifact_client, ARTIFACTS)
    with pytest.raises(R2ClientRejected):
        R2ObjectStore(make_client(R2Backend(), **three), CONTROL)
    for bad in (0, 4, True):
        with pytest.raises(R2ClientRejected) as error:
            validate_client(artifact_client, ARTIFACTS, max_attempts=bad)
        assert error.value.reason == "max_attempts"
    legacy = make_client(R2Backend(), retries={"mode": "standard", "max_attempts": 0})
    validate_client(legacy, CONTROL)
    with pytest.raises(R2ClientRejected) as error:
        validate_client(make_client(R2Backend(), retries={"total_max_attempts": True}), CONTROL)
    assert error.value.reason == "retries"


def test_a_configured_ca_bundle_is_the_only_bundle_accepted(tmp_path):
    bundle = tmp_path / "r2-ca.pem"
    bundle.write_text("placeholder")
    store = R2ArtifactStore(ARTIFACTS, CREDENTIALS, ca_bundle=str(bundle))
    store.require_available()
    assert store._client._endpoint.http_session._verify == str(bundle)
    mismatched = R2ArtifactStore(
        ARTIFACTS,
        CREDENTIALS,
        ca_bundle=str(bundle),
        client_factory=lambda: build_client(ARTIFACTS, CREDENTIALS, ca_bundle=None),
    )
    with pytest.raises(RuntimeError, match="Artifact storage unavailable"):
        mismatched.require_available()
    # An empty bundle name would turn certificate checking off in botocore.
    empty = R2ArtifactStore(ARTIFACTS, CREDENTIALS, ca_bundle="")
    with pytest.raises(RuntimeError, match="Artifact storage unavailable"):
        empty.require_available()


def _redirecting_ruleset(root: Path, url: str) -> None:
    """Plant an S3 endpoint ruleset that resolves every request to ``url``."""
    path = root / "s3" / "2006-03-01"
    path.mkdir(parents=True)
    endpoint = {
        "url": url,
        "properties": {
            "authSchemes": [
                {
                    "name": "sigv4",
                    "signingName": "s3",
                    "signingRegion": "auto",
                    "disableDoubleEncoding": True,
                }
            ]
        },
        "headers": {},
    }
    ruleset = {
        "version": "1.0",
        "parameters": {
            "Region": {"builtIn": "AWS::Region", "required": False, "type": "String"},
            "Bucket": {"required": False, "type": "String"},
            "Endpoint": {"builtIn": "SDK::Endpoint", "required": False, "type": "String"},
        },
        "rules": [{"conditions": [], "endpoint": endpoint, "type": "endpoint"}],
    }
    (path / "endpoint-rule-set-1.json").write_text(json.dumps(ruleset))


def test_ambient_botocore_models_and_plugins_do_not_reach_the_client(tmp_path, monkeypatch):
    _redirecting_ruleset(tmp_path / "data", "https://attacker.invalid")
    _redirecting_ruleset(tmp_path / "customer", "https://attacker.invalid")
    monkeypatch.setenv("AWS_DATA_PATH", str(tmp_path / "data"))
    monkeypatch.setattr(Loader, "CUSTOMER_DATA_PATH", str(tmp_path / "customer"))
    (tmp_path / "cf03_plugin_probe.py").write_text(
        "LOADED = []\n\ndef initialize_client_plugin(client):\n    LOADED.append(client)\n"
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.setenv("BOTOCORE_EXPERIMENTAL__PLUGINS", "probe=cf03_plugin_probe")
    cf03_plugin_probe = importlib.import_module("cf03_plugin_probe")

    # The planted ruleset and plugin are live for an ordinary botocore session.
    ordinary = botocore.session.Session().create_client(
        "s3",
        region_name="auto",
        endpoint_url=endpoint_for(ARTIFACTS),
        aws_access_key_id="fixture",
        aws_secret_access_key="fixture",
    )
    assert cf03_plugin_probe.LOADED == [ordinary]
    url = ordinary.generate_presigned_url(
        "get_object", Params={"Bucket": ARTIFACTS.bucket, "Key": "reports/r/a.md"}
    )
    assert urlsplit(url).hostname == "attacker.invalid"

    backend = artifacts_backend()
    store = store_for(backend)
    key = store.upload_markdown_report("report-1", "private body")
    # The offline model refuses any other host, so a stored object proves the target.
    assert backend.raw(key) == b"private body"
    assert cf03_plugin_probe.LOADED == [ordinary]


def test_requests_resolved_off_the_target_are_refused_before_sending(tmp_path, monkeypatch):
    _redirecting_ruleset(tmp_path, "https://attacker.invalid")
    monkeypatch.setenv("AWS_DATA_PATH", str(tmp_path))
    backend = artifacts_backend()

    def unrestricted_client():
        session = botocore.session.Session(
            session_vars={
                "profile": (None, None, None, None),
                "config_file": (None, None, os.devnull, None),
                "credentials_file": (None, None, os.devnull, None),
            }
        )
        client = session.create_client(
            "s3",
            region_name="auto",
            endpoint_url=endpoint_for(ARTIFACTS),
            aws_access_key_id=CREDENTIALS.access_key_id,
            aws_secret_access_key=CREDENTIALS.secret_access_key,
            verify=True,
            config=client_config(),
        )
        client.meta.events.register("before-send.s3", backend.handle)
        return client

    store = R2ArtifactStore(ARTIFACTS, CREDENTIALS, client_factory=unrestricted_client)
    store.require_available()  # the endpoint it was given is still exact
    with pytest.raises(R2ClientRejected) as error:
        store.upload_markdown_report("report-1", "private body")
    assert error.value.reason == "request_endpoint"
    assert backend.log == []


def test_a_listing_with_an_invalid_key_deletes_nothing():
    backend = artifacts_backend()
    store = store_for(backend)
    store.upload_markdown_report("report-1", "kept")
    backend.put_raw(f"reports/report-1/../report-2/artifacts/{'c' * 64}.md", b"x", '"1"')
    with pytest.raises(RuntimeError, match="invalid artifact key"):
        store.delete_report_files("report-1")
    with pytest.raises(RuntimeError, match="invalid artifact key"):
        store.list_report_files("report-1")
    assert backend.deleting_requests() == []


def test_a_listing_that_does_not_state_completeness_deletes_nothing():
    backend = artifacts_backend(omit_is_truncated=True)
    store = store_for(backend)
    store.upload_markdown_report("report-1", "kept")
    with pytest.raises(RuntimeError, match="complete"):
        store.delete_report_files("report-1")
    assert backend.deleting_requests() == []


def test_downloads_are_checked_against_their_content_address():
    backend = artifacts_backend()
    store = store_for(backend)
    key = store.upload_markdown_report("report-1", "original")
    backend.put_raw(key, b"# tampered\n", backend.etag(key))
    with pytest.raises(ValueError, match="does not match"):
        store.download_content(key)
    legacy = "reports/report-1/report.md"
    backend.put_raw(legacy, b"legacy body", '"2"')
    assert store.download_content(legacy) == "legacy body"
