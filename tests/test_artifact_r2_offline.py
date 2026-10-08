"""Isolation proof for the R2 artifact backend on the API and worker import paths."""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]
ACCOUNT = "0123456789abcdef0123456789abcdef"
MODULES = {
    # Each new module's own responsibility sets its allowlist.
    "src/storage/artifact_store.py": {"hashlib", "typing", "__future__"},
    "src/storage/r2_artifacts.py": {
        "__future__",
        "dataclasses",
        "datetime",
        "hashlib",
        "json",
        "logging",
        "os",
        "re",
        "typing",
        "urllib",
        "botocore",
        "release_cloudflare",
        "artifact_store",
    },
    "src/storage/artifacts.py": {
        "__future__",
        "collections",
        "os",
        "pathlib",
        "release_cloudflare",
        "artifact_store",
        "r2_artifacts",
        "s3_manager",
    },
}


def test_new_artifact_modules_import_only_what_their_role_needs():
    for relative, allowed in MODULES.items():
        tree = ast.parse((REPO / relative).read_text(encoding="utf-8"), relative)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                roots = [(node.module or "").split(".")[0]]
            else:
                roots = []
            for root in roots:
                assert root in allowed, f"{relative} imports {root}"
            if isinstance(node, ast.Name):
                assert node.id not in ("load_dotenv", "boto3"), relative
            if isinstance(node, ast.Attribute) and relative != "src/storage/artifacts.py":
                # Only the selection module reads configuration.
                assert node.attr not in ("environ", "getenv"), f"{relative} reads the environment"
    assert "proxies={}" in (REPO / "src/storage/r2_artifacts.py").read_text(encoding="utf-8")


def test_cloudflare_entrypoint_imports_and_uses_r2_with_denied_network(tmp_path):
    home, work, missing = tmp_path / "home", tmp_path / "work", tmp_path / "missing"
    home.mkdir()
    work.mkdir()
    poisoned = {
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
        "AWS_CA_BUNDLE": str(missing / "ca.pem"),
        "REQUESTS_CA_BUNDLE": str(missing / "requests-ca.pem"),
        "AWS_S3_BUCKET": "poisoned-s3-bucket",
        "CLOUDFLARE_API_BASE_URL": "http://192.0.2.1/poisoned",
        "CLOUDFLARE_API_TOKEN": "poisoned-offline-test",
        "WRANGLER_SEND_METRICS": "false",
        "WRANGLER_SEND_ERROR_REPORTS": "false",
        "CLOUDFLARE_CF_FETCH_ENABLED": "false",
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home),
        "HTTPS_PROXY": "http://192.0.2.1:9",
        "HTTP_PROXY": "http://192.0.2.1:9",
        "PYTHON_DOTENV_DISABLED": "1",
        "ENVIRONMENT": "test",
        "SENTRYSEARCH_PLATFORM": "cloudflare",
        "ARTIFACT_BACKEND": "r2",
        "R2_ACCOUNT_ID": ACCOUNT,
        "R2_ARTIFACT_BUCKET": "sentry-staging-artifacts",
        "R2_ACCESS_KEY_ID": "fixture-artifact-key-id",
        "R2_SECRET_ACCESS_KEY": "fixture-artifact-secret",
    }
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(
            (
                "AWS_",
                "CLOUDFLARE_",
                "WRANGLER_",
                "R2_",
                "DB_",
                "PG",
                "SENTRY",
                "SUPABASE",
                "OPENROUTER",
                "HTTP",
                "http",
                "PYTHON",
            )
        )
        and key not in ("NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy", "HOME")
    }
    env.update(poisoned)
    result = subprocess.run(
        [sys.executable, "-B", str(REPO / "tests" / "artifact_r2_offline_process.py")],
        cwd=work,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stderr[-3000:]
    receipt = json.loads(result.stdout.strip().splitlines()[-1])
    assert receipt["socket_attempts"] == []
    assert receipt["artifacts"] == "R2ArtifactStore"
    assert receipt["endpoint"] == f"https://{ACCOUNT}.r2.cloudflarestorage.com"
    assert receipt["credential_method"] == "explicit"
    assert receipt["proxies"] == {}
    assert receipt["round_trip"] == "offline body"
    assert receipt["presign_host"] == f"{ACCOUNT}.r2.cloudflarestorage.com"
    assert receipt["remaining"] == []
    assert receipt["s3_initialized"] is False
    assert receipt["requests"] and all(status in (200, 204) for _, status in receipt["requests"])
    assert list(work.iterdir()) == []
