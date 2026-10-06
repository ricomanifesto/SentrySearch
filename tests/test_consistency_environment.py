"""The disposable consistency runner must not inherit provider authority."""

import os
from unittest.mock import patch

import boto3

from dev.check_runtime_consistency import isolated_environment


def test_consistency_environment_blocks_host_credentials_and_provider_endpoints(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "host-key-must-not-survive")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/host/credentials")
    monkeypatch.setenv("AWS_CONFIG_FILE", "/host/config")
    monkeypatch.setenv("AWS_PROFILE", "production")
    monkeypatch.setenv("AWS_ENDPOINT_URL_S3", "https://production.example")
    monkeypatch.setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://production.example")
    monkeypatch.setenv("OPENROUTER_API_KEY", "host-provider-key")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "host-product-key")
    monkeypatch.setenv("DATABASE_URL", "postgres://production.example/live")
    monkeypatch.setenv("HTTPS_PROXY", "http://production.example:8080")
    monkeypatch.setenv("http_proxy", "http://production.example:8080")
    monkeypatch.setenv("ALL_PROXY", "socks5://production.example:1080")
    monkeypatch.setenv("NO_PROXY", "production.example")
    env = isolated_environment()
    assert env["AWS_SHARED_CREDENTIALS_FILE"] == os.devnull
    assert env["AWS_CONFIG_FILE"] == os.devnull
    assert env["AWS_EC2_METADATA_DISABLED"] == "true"
    assert env["PYTHON_DOTENV_DISABLED"] == "1"
    assert not {"AWS_PROFILE", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "DATABASE_URL"} & env.keys()
    assert not {"OPENROUTER_API_KEY", "SUPABASE_SERVICE_ROLE_KEY"} & env.keys()
    assert not {"HTTPS_PROXY", "http_proxy", "ALL_PROXY"} & env.keys()
    assert env["NO_PROXY"] == env["no_proxy"] == "*"
    with patch.dict(os.environ, env, clear=True):
        session = boto3.Session()
        credentials = session.get_credentials()
        assert credentials is not None
        assert credentials.get_frozen_credentials().access_key == "disposable-test-key"
        assert session.client("s3").meta.endpoint_url == "http://127.0.0.1:9"
