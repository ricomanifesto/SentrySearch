"""The offline release controller never needs AWS credentials, SDKs or a network."""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]
ALLOWED_IMPORTS = {
    "__future__",
    "collections",
    "dataclasses",
    "datetime",
    "enum",
    "hashlib",
    "json",
    "re",
    "typing",
    "pydantic",
    "release",
}


def test_release_package_imports_no_sdk_transport_or_process_modules():
    for path in sorted((REPO / "release").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""] if node.level == 0 else ["release"]
            else:
                continue
            for name in names:
                assert name.split(".")[0] in ALLOWED_IMPORTS, f"{path.name} imports {name}"


def test_full_release_runs_with_poisoned_aws_environment_and_denied_network(tmp_path):
    poisoned = {
        "AWS_ACCESS_KEY_ID": "poisoned-offline-test",
        "AWS_SECRET_ACCESS_KEY": "poisoned-offline-test",
        "AWS_SESSION_TOKEN": "poisoned-offline-test",
        "AWS_PROFILE": "poisoned-offline-test",
        "AWS_REGION": "poisoned-1",
        "AWS_DEFAULT_REGION": "poisoned-1",
        "AWS_CONFIG_FILE": str(tmp_path / "missing-config"),
        "AWS_SHARED_CREDENTIALS_FILE": str(tmp_path / "missing-credentials"),
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
        [sys.executable, "-B", str(REPO / "tests" / "release_offline_process.py")],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["results"] == [
        {"state": "held_paused", "reason": None},
        {"state": "hold", "reason": "job_container_failed"},
    ]
    assert receipt["socket_attempts"] == []
    assert receipt["loaded_sdk_or_http_modules"] == []
    assert "poisoned-offline-test" not in result.stdout + result.stderr
