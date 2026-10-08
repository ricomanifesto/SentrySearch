"""Credential- and network-isolation proof for the R2 release-control store."""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]
R2_MODULES = (
    "release_cloudflare/__init__.py",
    "release_cloudflare/r2_client.py",
    "release_cloudflare/r2_store.py",
)
ALLOWED_THIRD_PARTY = {"botocore", "release", "release_cloudflare"}
FORBIDDEN_ATTRIBUTES = {"environ", "getenv", "putenv", "Session", "delete_object", "delete_objects"}
FORBIDDEN_NAMES = {"Session", "load_dotenv", "getenv"}


def test_r2_modules_never_build_sessions_read_the_environment_or_delete():
    for relative in R2_MODULES:
        tree = ast.parse((REPO / relative).read_text(encoding="utf-8"), relative)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                assert node.level == 0, f"{relative} uses a relative import"
                names = [node.module or ""]
            else:
                names = []
            for name in names:
                root = name.split(".")[0]
                assert root != "os", f"{relative} imports os"
                assert (
                    root in sys.stdlib_module_names or root in ALLOWED_THIRD_PARTY
                ), f"{relative} imports {name}"
            if isinstance(node, ast.Attribute):
                assert node.attr not in FORBIDDEN_ATTRIBUTES, f"{relative} uses .{node.attr}"
            if isinstance(node, ast.Name):
                assert node.id not in FORBIDDEN_NAMES, f"{relative} uses {node.id}"


def test_full_r2_release_runs_with_poisoned_environment_and_denied_network(tmp_path):
    home = tmp_path / "home"
    xdg = tmp_path / "xdg"
    work = tmp_path / "work"
    for directory in (home, xdg, work):
        directory.mkdir()
    missing = tmp_path / "missing"
    poisoned = {
        # boto3/botocore chain (R2 through the S3 API keeps every AWS channel relevant)
        "AWS_ACCESS_KEY_ID": "poisoned-offline-test",
        "AWS_SECRET_ACCESS_KEY": "poisoned-offline-test",
        "AWS_SESSION_TOKEN": "poisoned-offline-test",
        "AWS_PROFILE": "poisoned-offline-test",
        "AWS_REGION": "poisoned-1",
        "AWS_DEFAULT_REGION": "poisoned-1",
        "AWS_CONFIG_FILE": str(missing / "config"),
        "AWS_SHARED_CREDENTIALS_FILE": str(missing / "credentials"),
        "AWS_WEB_IDENTITY_TOKEN_FILE": str(missing / "token"),
        "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_EC2_METADATA_SERVICE_ENDPOINT": "http://192.0.2.1",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://192.0.2.1/poisoned",
        "AWS_ENDPOINT_URL": "https://ambient-endpoint.invalid",
        "AWS_ENDPOINT_URL_S3": "https://ambient-endpoint.invalid",
        "AWS_REQUEST_CHECKSUM_CALCULATION": "when_supported",
        # Cloudflare and Wrangler channels (no Wrangler runs; defence in depth)
        "CLOUDFLARE_API_BASE_URL": "http://192.0.2.1/poisoned",
        "CLOUDFLARE_API_TOKEN": "poisoned-offline-test",
        "CLOUDFLARE_ACCOUNT_ID": "00000000000000000000000000000000",
        "WRANGLER_SEND_METRICS": "false",
        "WRANGLER_SEND_ERROR_REPORTS": "false",
        "CLOUDFLARE_CF_FETCH_ENABLED": "false",
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(xdg),
        # proxies and dotenv
        "HTTPS_PROXY": "http://192.0.2.1:9",
        "HTTP_PROXY": "http://192.0.2.1:9",
        "PYTHON_DOTENV_DISABLED": "1",
    }
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(
            ("AWS_", "CLOUDFLARE_", "WRANGLER_", "MINIFLARE_", "DOCKER_", "HTTP", "http", "PYTHON")
        )
        and key not in ("NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy", "HOME", "XDG_CONFIG_HOME")
    }
    env.update(poisoned)
    result = subprocess.run(
        [sys.executable, "-B", str(REPO / "tests" / "release_r2_offline_process.py")],
        cwd=work,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["socket_attempts"] == []
    assert receipt["loaded_http_modules"] == []
    happy, failed = receipt["results"]
    assert happy["state"] == "held_paused" and happy["lock_state"] == "released"
    assert failed["state"] == "hold" and failed["lock_state"] == "held"
    for outcome in receipt["results"]:
        assert outcome["endpoint"] == receipt["expected_endpoint"]
        assert outcome["credential_method"] == "explicit"
        assert outcome["delete_requests"] == 0 and outcome["requests"] > 0
    assert list(work.iterdir()) == [] and list(home.iterdir()) == []
