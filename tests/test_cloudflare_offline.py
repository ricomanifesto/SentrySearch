"""Isolation proof for the Cloudflare entrypoint, runtime tunnel and receipt sink."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

from dev.tls_fixtures import create_certificates

REPO = Path(__file__).resolve().parents[1]


def test_cloudflare_paths_reach_only_the_intercepted_hosts_with_denied_network(tmp_path):
    certs = create_certificates(tmp_path / "certs", hostname="runtime.test")
    home, missing = tmp_path / "home", tmp_path / "missing"
    home.mkdir()
    poisoned = {
        "AWS_ACCESS_KEY_ID": "poisoned-offline-test",
        "AWS_SECRET_ACCESS_KEY": "poisoned-offline-test",
        "AWS_PROFILE": "poisoned-offline-test",
        "AWS_CONFIG_FILE": str(missing / "config"),
        "AWS_SHARED_CREDENTIALS_FILE": str(missing / "credentials"),
        "AWS_EC2_METADATA_SERVICE_ENDPOINT": "http://192.0.2.1",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://192.0.2.1/poisoned",
        "CLOUDFLARE_API_BASE_URL": "http://192.0.2.1/poisoned",
        "CLOUDFLARE_API_TOKEN": "poisoned-offline-test",
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home),
        "HTTPS_PROXY": "http://192.0.2.1:9",
        "HTTP_PROXY": "http://192.0.2.1:9",
        "ALL_PROXY": "http://192.0.2.1:9",
        "https_proxy": "http://192.0.2.1:9",
        "http_proxy": "http://192.0.2.1:9",
        "all_proxy": "http://192.0.2.1:9",
        "NO_PROXY": "",
        "SSL_CERT_FILE": str(missing / "ca.pem"),
        "PYTHON_DOTENV_DISABLED": "1",
        "ENVIRONMENT": "test",
    }
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("AWS_", "CLOUDFLARE_", "WRANGLER_", "R2_"))
        and key.lower() not in {"https_proxy", "http_proxy", "all_proxy", "no_proxy"}
    }
    env.update(poisoned)
    result = subprocess.run(
        [
            sys.executable,
            "-B",
            str(REPO / "tests" / "cloudflare_offline_process.py"),
            str(certs.ca),
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    receipt = json.loads(result.stdout)
    assert receipt["cfinit_profiles"] == ["runtime-release", "search", "search-release"]
    assert receipt["attempts_at_import"] == []
    assert receipt["attempts_at_construction"] == []
    # The tunnel and the receipt sink each tried exactly their intercepted host:
    # never a proxy, never DNS for anything else, and both failed closed.
    assert receipt["attempts"] == [
        ["create_connection", repr(("runtime.internal", 80))],
        ["create_connection", repr(("evidence.internal", 80))],
    ]
    assert receipt["results"]["runtime"] != "reached"
    assert receipt["results"]["receipt"] == "OSError"
