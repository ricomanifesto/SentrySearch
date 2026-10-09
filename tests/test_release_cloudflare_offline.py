"""A whole Cloudflare release offline: poisoned environment, sockets denied."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]


def test_cloudflare_releases_run_with_a_poisoned_environment_and_denied_network(tmp_path):
    home, xdg, work = (tmp_path / name for name in ("home", "xdg", "work"))
    for directory in (home, xdg, work):
        directory.mkdir()
    missing = tmp_path / "missing"
    poisoned = {
        "CLOUDFLARE_API_BASE_URL": "http://192.0.2.1/poisoned",
        "CLOUDFLARE_API_TOKEN": "poisoned-offline-test",
        "CLOUDFLARE_API_KEY": "poisoned-offline-test",
        "CLOUDFLARE_EMAIL": "poisoned@offline.invalid",
        "CLOUDFLARE_ACCOUNT_ID": "00000000000000000000000000000000",
        "CLOUDFLARE_DURABLE_OBJECT_ID": "0" * 64,
        "WRANGLER_SEND_METRICS": "false",
        "WRANGLER_SEND_ERROR_REPORTS": "false",
        "CLOUDFLARE_CF_FETCH_ENABLED": "false",
        "AWS_ACCESS_KEY_ID": "poisoned-offline-test",
        "AWS_SECRET_ACCESS_KEY": "poisoned-offline-test",
        "AWS_PROFILE": "poisoned-offline-test",
        "AWS_CONFIG_FILE": str(missing / "config"),
        "AWS_SHARED_CREDENTIALS_FILE": str(missing / "credentials"),
        "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_ENDPOINT_URL": "https://ambient-endpoint.invalid",
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(xdg),
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
        [sys.executable, "-B", str(REPO / "tests" / "release_cloudflare_offline_process.py")],
        cwd=work,
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["socket_attempts"] == []
    assert receipt["loaded_http_modules"] == []
    first, unwired, unobserved = receipt["results"]
    assert (first["state"], first["lock_state"]) == ("held_paused", "released")
    assert first["unsigned_or_refused"] == [] and first["deployments"] == 5
    assert (unwired["state"], unwired["reason"]) == ("hold", "launch_failed")
    assert unwired["lock_state"] == "held"
    assert (unobserved["state"], unobserved["reason"]) == ("hold", "operational_evidence_missing")
    assert list(work.iterdir()) == [] and list(home.iterdir()) == []
