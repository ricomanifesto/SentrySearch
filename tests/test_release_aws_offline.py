"""Whole releases through the AWS adapters in a poisoned environment with no network."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]


def test_adapter_releases_ignore_the_ambient_aws_environment_and_never_touch_the_network(
    tmp_path,
):
    poisoned = {
        "AWS_ACCESS_KEY_ID": "poisoned-adapter-test",
        "AWS_SECRET_ACCESS_KEY": "poisoned-adapter-test",
        "AWS_SESSION_TOKEN": "poisoned-adapter-test",
        "AWS_PROFILE": "poisoned-adapter-test",
        "AWS_DEFAULT_PROFILE": "poisoned-adapter-test",
        "AWS_REGION": "poisoned-1",
        "AWS_DEFAULT_REGION": "poisoned-1",
        "AWS_CONFIG_FILE": str(tmp_path / "missing-config"),
        "AWS_SHARED_CREDENTIALS_FILE": str(tmp_path / "missing-credentials"),
        "AWS_ENDPOINT_URL": "http://192.0.2.1:9",
        "AWS_ENDPOINT_URL_ECS": "http://192.0.2.1:9",
        "AWS_ENDPOINT_URL_S3": "http://192.0.2.1:9",
        "AWS_USE_FIPS_ENDPOINT": "true",
        "AWS_MAX_ATTEMPTS": "9",
        "AWS_RETRY_MODE": "adaptive",
        "AWS_CA_BUNDLE": str(tmp_path / "missing-ca"),
        "AWS_EC2_METADATA_SERVICE_ENDPOINT": "http://192.0.2.1",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://192.0.2.1/poisoned",
        "AWS_WEB_IDENTITY_TOKEN_FILE": str(tmp_path / "missing-token"),
        "HTTPS_PROXY": "http://192.0.2.1:9",
        "HTTP_PROXY": "http://192.0.2.1:9",
        "PYTHON_DOTENV_DISABLED": "1",
    }
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("AWS_", "HTTP", "http", "PYTHON"))
    }
    env.update(poisoned)
    result = subprocess.run(
        [sys.executable, "-B", str(REPO / "tests" / "release_aws_process.py")],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["results"] == [
        {"state": "held_paused", "reason": None},
        # Runtime and API observers do not exist yet: their checks stay unproven.
        {"state": "hold", "reason": "operational_evidence_missing"},
    ]
    assert receipt["socket_attempts"] == []
    assert receipt["endpoints"] == [
        "https://ecs.us-east-1.amazonaws.com",
        "https://logs.us-east-1.amazonaws.com",
        "https://s3.amazonaws.com",
    ]
    assert receipt["sdk_calls"] > 100
    assert "poisoned" not in result.stdout + result.stderr
