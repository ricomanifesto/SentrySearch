"""Offline configuration, credential-chain and process-boundary proofs."""

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import boto3
import pytest

from src.storage import database
from src.storage.s3_manager import S3StorageManager


@pytest.fixture
def storage_env(monkeypatch, tmp_path):
    import os

    for key in os.environ:
        if key.startswith(("DB_", "AWS_")) or key in {"ENVIRONMENT", "PGHOSTADDR", "PGSERVICE"}:
            monkeypatch.delenv(key)
    monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "1")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "absent-credentials"))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "absent-config"))
    return monkeypatch


def test_database_preserves_reserved_credentials_and_hides_parameters(storage_env):
    storage_env.setenv("DB_USER", "user@tenant")
    storage_env.setenv("DB_PASSWORD", "test:@/secret?#%")
    manager = database.DatabaseManager()
    try:
        assert manager.engine.url.username == "user@tenant"
        assert manager.engine.url.password == "test:@/secret?#%"
        assert manager.engine.url.host == "localhost"
        assert manager.engine.hide_parameters is True
        assert manager.engine.url.query["connect_timeout"] == "5"
    finally:
        manager.engine.dispose()


@pytest.mark.parametrize("host", ["db.example.test", "10.0.0.2", "localhost,evil.test", ""])
def test_remote_or_ambiguous_database_cannot_default_to_plaintext(storage_env, host):
    storage_env.setenv("DB_HOST", host)
    with pytest.raises(ValueError):
        database.DatabaseManager()


@pytest.mark.parametrize("mode", ["prefer", "require", "verify-ca", "disable", ""])
def test_remote_database_rejects_unverified_tls(storage_env, mode):
    storage_env.setenv("DB_HOST", "db.example.test")
    storage_env.setenv("DB_SSLMODE", mode)
    with pytest.raises(ValueError):
        database.DatabaseManager()


def test_remote_database_requires_ca_then_constructs_verified_url(storage_env, tmp_path):
    storage_env.setenv("DB_HOST", "db.example.test")
    storage_env.setenv("DB_SSLMODE", "verify-full")
    with pytest.raises(ValueError):
        database.DatabaseManager()
    # Parsing is offline; libpq verifies PEM contents at connection time.
    ca = tmp_path / "test-ca.pem"
    ca.write_text("fixture")
    storage_env.setenv("DB_SSLROOTCERT", str(ca))
    manager = database.DatabaseManager()
    assert manager.engine.url.query["sslmode"] == "verify-full"
    assert manager.engine.url.query["sslrootcert"] == str(ca)
    assert manager.engine.url.query["gssencmode"] == "disable"
    manager.engine.dispose()


@pytest.mark.parametrize("key", ["PGHOSTADDR", "PGSERVICE"])
def test_ambient_libpq_routing_cannot_override_explicit_database_host(storage_env, key):
    storage_env.setenv(key, "private-routing-override")
    with pytest.raises(ValueError) as error:
        database.DatabaseManager()
    assert "private-routing-override" not in str(error.value)


def test_deployment_requires_explicit_database_config(storage_env):
    storage_env.setenv("ENVIRONMENT", "production")
    with pytest.raises(ValueError):
        database.DatabaseManager()


def test_s3_uses_sdk_session_credentials_including_session_token(storage_env):
    storage_env.setenv("AWS_ACCESS_KEY_ID", "fixture-access")
    storage_env.setenv("AWS_SECRET_ACCESS_KEY", "fixture-secret")
    storage_env.setenv("AWS_SESSION_TOKEN", "fixture-session")
    store = S3StorageManager()
    store.require_available()
    assert store.s3_client is not None
    credentials = store.s3_client._request_signer._credentials
    assert credentials.method == "env"
    assert credentials.token == "fixture-session"
    store.s3_client.close()


def test_s3_supports_shared_profile_without_static_environment_keys(storage_env, tmp_path):
    credentials_file = tmp_path / "credentials"
    credentials_file.write_text(
        "[default]\naws_access_key_id=fixture-access\n"
        "aws_secret_access_key=fixture-secret\naws_session_token=fixture-profile-token\n"
    )
    storage_env.setenv("AWS_SHARED_CREDENTIALS_FILE", str(credentials_file))
    store = S3StorageManager()
    store.require_available()
    assert store.s3_client is not None
    assert store.s3_client._request_signer._credentials.method == "shared-credentials-file"
    assert store.s3_client._request_signer._credentials.token == "fixture-profile-token"
    store.s3_client.close()


def test_s3_does_not_pass_frozen_role_credentials_to_client(storage_env):
    session = Mock()
    storage_env.setattr(boto3, "Session", lambda: session)
    store = S3StorageManager()
    store.require_available()
    args, kwargs = session.client.call_args
    assert args == ("s3",)
    assert not any(key.startswith("aws_") for key in kwargs)
    assert store.s3_client is session.client.return_value


def test_deferred_role_credentials_must_resolve_before_ready(storage_env):
    session = Mock()
    session.get_credentials.return_value.get_frozen_credentials.side_effect = RuntimeError(
        "private-token-file"
    )
    storage_env.setattr(boto3, "Session", lambda: session)
    with pytest.raises(RuntimeError, match="Artifact storage unavailable"):
        S3StorageManager().require_available()
    session.client.assert_not_called()


def test_sdk_client_keeps_refreshable_credentials_after_initial_resolution(storage_env):
    from botocore.credentials import DeferredRefreshableCredentials

    refreshes = []

    def refresh():
        refreshes.append(True)
        return {
            "access_key": "fixture-access",
            "secret_key": "fixture-secret",
            "token": f"fixture-session-{len(refreshes)}",
            "expiry_time": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        }

    credentials = DeferredRefreshableCredentials(refresh_using=refresh, method="assume-role")
    session = boto3.Session()
    session._session._credentials = credentials
    storage_env.setattr(boto3, "Session", lambda: session)
    store = S3StorageManager()
    store.require_available()
    assert len(refreshes) == 1
    assert store.s3_client is not None
    assert store.s3_client._request_signer._credentials is credentials
    credentials._expiry_time = datetime.now(timezone.utc) - timedelta(seconds=1)
    assert (
        store.s3_client._request_signer._credentials.get_frozen_credentials().token
        == "fixture-session-2"
    )
    assert len(refreshes) == 2
    store.s3_client.close()


@pytest.mark.parametrize(
    "key,value",
    [
        ("DB_PORT", "0"),
        ("DB_PORT", "65536"),
        ("DB_PORT", "private-not-port"),
        ("ENVIRONMENT", "prodution"),
    ],
)
def test_invalid_database_settings_are_rejected_safely(storage_env, key, value):
    storage_env.setenv(key, value)
    with pytest.raises(ValueError) as error:
        database.DatabaseManager()
    assert value not in str(error.value)


def test_database_connection_failure_does_not_log_driver_details(storage_env, caplog):
    manager = database.DatabaseManager()
    engine = manager.engine
    manager.engine = Mock()
    manager.engine.connect.side_effect = RuntimeError("private-db-password")
    assert manager.test_connection() is False
    assert "private-db-password" not in caplog.text
    engine.dispose()


def test_failed_api_schema_check_stops_startup(monkeypatch):
    from src.api import main as api

    def fail():
        raise RuntimeError("schema incompatible")

    monkeypatch.setattr(api.db_manager, "require_schema", fail)

    async def run():
        async with api.lifespan(api.app):
            pytest.fail("API served without schema")

    with pytest.raises(RuntimeError, match="schema incompatible"):
        asyncio.run(run())


def test_deployed_api_requires_artifact_credentials_before_serving(monkeypatch):
    from src.api import main as api

    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setattr(api.db_manager, "require_schema", lambda: None)
    monkeypatch.setattr(
        api.report_service.s3_manager,
        "require_available",
        Mock(side_effect=RuntimeError("artifacts unavailable")),
    )

    async def run():
        async with api.lifespan(api.app):
            pytest.fail("API served without credentials")

    with pytest.raises(RuntimeError, match="artifacts unavailable"):
        asyncio.run(run())


@pytest.mark.parametrize("partial", [False, True])
def test_s3_missing_or_partial_credentials_fail_without_leaking(storage_env, caplog, partial):
    if partial:
        storage_env.setenv("AWS_ACCESS_KEY_ID", "private-fixture-key")
    store = S3StorageManager()
    with caplog.at_level(logging.WARNING):
        with pytest.raises(RuntimeError, match="Artifact storage unavailable") as error:
            store.upload_markdown_report("fixture", "must not be skipped")
    assert "private-fixture" not in str(error.value) + caplog.text
    assert store._initialized is False


def test_production_artifact_bucket_must_be_explicit(storage_env):
    storage_env.setenv("ENVIRONMENT", "production")
    with pytest.raises(RuntimeError, match="Artifact storage unavailable"):
        S3StorageManager().require_available()


def test_api_startup_checks_storage_without_migration_or_reader_writes(monkeypatch):
    from src.api import main as api

    calls = []
    monkeypatch.setattr(
        api.db_manager, "require_schema", lambda: calls.append("schema"), raising=False
    )
    monkeypatch.setattr(api.db_manager, "migrate_schema", lambda: pytest.fail("startup DDL"))
    monkeypatch.setattr(
        api.report_service, "reconcile_reader_state", lambda: pytest.fail("startup backfill")
    )
    monkeypatch.setenv("ENVIRONMENT", "development")

    async def run():
        async with api.lifespan(api.app):
            pass

    asyncio.run(run())
    assert calls == ["schema"]


def test_worker_checks_required_persistence_before_returning_jobs(monkeypatch):
    from dev.run_runtime_worker import load_jobs
    from src.storage.report_service import report_service

    calls = []
    monkeypatch.setattr(
        report_service.db_manager, "require_schema", lambda: calls.append("schema"), raising=False
    )
    monkeypatch.setattr(
        report_service.s3_manager,
        "require_available",
        lambda: calls.append("artifacts"),
        raising=False,
    )
    load_jobs()
    assert calls == ["schema", "artifacts"]
