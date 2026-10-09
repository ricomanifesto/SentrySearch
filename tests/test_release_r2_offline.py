"""Credential- and network-isolation proof for the R2 release-control store."""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

REPO = Path(__file__).resolve().parents[1]
PACKAGE = REPO / "release_cloudflare"
# Every module in the package needs an explicit allowlist of the exact modules
# it may import; an unlisted module fails until its role is reviewed.
MODULE_IMPORTS: dict[str, set[str]] = {
    "__init__.py": set(),
    "r2_client.py": {"__future__", "dataclasses", "re", "typing"},
    "r2_store.py": {
        "__future__",
        "hashlib",
        "json",
        "re",
        "typing",
        "uuid",
        "botocore.exceptions",
        "release.journal",
        "release_cloudflare.r2_client",
    },
    # CF-05: pure manifest parsing, the signed control client (the transport
    # and the key object are injected; cryptography only signs) and port types.
    "manifest.py": {
        "__future__",
        "dataclasses",
        "datetime",
        "re",
        "typing",
        "pydantic",
        "release.manifest",
        "release.readiness",
    },
    "control_client.py": {
        "__future__",
        "base64",
        "collections.abc",
        "dataclasses",
        "datetime",
        "hashlib",
        "json",
        "re",
        "typing",
        "cryptography.hazmat.primitives.asymmetric.ed25519",
    },
    "ports.py": {
        "__future__",
        "collections.abc",
        "dataclasses",
        "datetime",
        "typing",
        "release_cloudflare.control_client",
    },
}
FORBIDDEN_MODULE_ROOTS = {
    "os",
    "socket",
    "http",
    "urllib",
    "subprocess",
    "importlib",
    "dotenv",
    "boto3",
    "requests",
    "httpx",
    "shutil",
    "pathlib",
    "io",
}
FORBIDDEN_MODULES = {"botocore.session", "botocore.credentials", "botocore.client"}
FORBIDDEN_ATTRIBUTES = {
    "environ",
    "getenv",
    "putenv",
    "Session",
    "get_session",
    "create_client",
    "create_credential_resolver",
    "EnvProvider",
    "delete_object",
    "delete_objects",
    "_make_api_call",
    "getproxies",
    "urlopen",
}
FORBIDDEN_NAMES = {"open", "exec", "eval", "compile", "__import__", "load_dotenv", "getenv"}


def violations(source: str, allowed: set[str], name: str = "<module>") -> list[str]:
    """Static findings for one module of the release adapter package."""
    found = []
    for node in ast.walk(ast.parse(source, name)):
        if isinstance(node, ast.Import):
            modules = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                found.append("relative import")
            modules = [node.module or ""]
            modules += [f"{node.module}.{alias.name}" for alias in node.names]
        else:
            modules = []
        for module in modules:
            if module.split(".")[0] in FORBIDDEN_MODULE_ROOTS or module in FORBIDDEN_MODULES:
                found.append(f"imports {module}")
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            base = (
                [alias.name for alias in node.names]
                if isinstance(node, ast.Import)
                else [node.module or ""]
            )
            found += [f"imports unlisted {module}" for module in base if module not in allowed]
        if isinstance(node, ast.Attribute) and node.attr in FORBIDDEN_ATTRIBUTES:
            found.append(f"uses .{node.attr}")
        if isinstance(node, ast.Name) and node.id in FORBIDDEN_NAMES:
            found.append(f"uses {node.id}")
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if node.value in (".env", ".dev.vars") or node.value.startswith(("DeleteObject",)):
                found.append(f"names {node.value!r}")
    return found


def test_every_module_in_the_package_has_a_reviewed_import_allowlist():
    modules = sorted(path.relative_to(PACKAGE).as_posix() for path in PACKAGE.rglob("*.py"))
    assert modules == sorted(MODULE_IMPORTS), "a new module needs its own allowlist"
    for relative, allowed in MODULE_IMPORTS.items():
        source = (PACKAGE / relative).read_text(encoding="utf-8")
        assert violations(source, allowed, relative) == [], relative


@pytest.mark.parametrize(
    "snippet",
    [
        "import os\nos.environ['X']",
        "import botocore.session\nbotocore.session.get_session()",
        "from botocore.credentials import EnvProvider\nEnvProvider().load()",
        "from botocore.credentials import create_credential_resolver",
        "open('.env').read()",
        "from pathlib import Path\nPath('.dev.vars').read_text()",
        "import urllib.request\nurllib.request.getproxies()",
        "import socket\nsocket.create_connection(('x', 1))",
        "import http.client\nhttp.client.HTTPSConnection('x')",
        "from urllib.request import urlopen\nurlopen('https://x')",
        "import subprocess\nsubprocess.run(['env'])",
        "import importlib\nimportlib.import_module('dotenv')",
        "__import__('os')",
        "client._make_api_call('DeleteObject', {})",
        "client.delete_objects(Bucket='b', Delete={})",
        "import json",
    ],
)
def test_the_static_guard_detects_each_violation(snippet):
    allowed = MODULE_IMPORTS["r2_store.py"] - {"json"}
    assert violations(snippet, allowed), snippet


def test_the_static_guard_accepts_the_reviewed_modules_unchanged():
    source = (PACKAGE / "r2_store.py").read_text(encoding="utf-8")
    assert violations(source, MODULE_IMPORTS["r2_store.py"]) == []
    assert violations(source, MODULE_IMPORTS["r2_store.py"] - {"uuid"})


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
        assert outcome["deleting_requests"] == 0 and outcome["requests"] > 0
    assert list(work.iterdir()) == [] and list(home.iterdir()) == []
