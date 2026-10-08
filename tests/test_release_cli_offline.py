"""The operator CLI ignores every ambient AWS input and never touches the network."""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]
RELEASE_PACKAGES = ("release", "release_aws", "release_cli")


def poisoned_environment(root: Path) -> dict[str, str]:
    """Every ambient input botocore could otherwise consult, each pointing somewhere real."""
    home = root / "home"
    aws = home / ".aws"
    (aws / "models" / "ecs" / "2014-11-13").mkdir(parents=True)
    (aws / "models" / "ecs" / "2014-11-13" / "service-2.json").write_text("{}")
    marker = root / "credential-process-ran"
    (aws / "config").write_text(
        "[default]\nregion = poisoned-1\nendpoint_url = http://192.0.2.1:9\n"
        f"credential_process = /usr/bin/touch {marker}\nca_bundle = {root / 'ca.pem'}\n"
        "max_attempts = 9\nretry_mode = adaptive\n[profile poisoned]\nregion = poisoned-1\n"
    )
    (aws / "credentials").write_text(
        "[default]\naws_access_key_id = AKIAPOISONEDPOISONED\n"
        "aws_secret_access_key = poisoned-cli-test\n"
    )
    (root / "ca.pem").write_text("not a certificate\n")
    (root / "token").write_text("poisoned-web-identity-token")
    (root / "models").mkdir()
    return {
        "HOME": str(home),
        "AWS_ACCESS_KEY_ID": "AKIAPOISONEDCLITEST0",
        "AWS_SECRET_ACCESS_KEY": "poisoned-cli-test",
        "AWS_SESSION_TOKEN": "poisoned-cli-test",
        "AWS_PROFILE": "poisoned",
        "AWS_DEFAULT_PROFILE": "poisoned",
        "AWS_REGION": "poisoned-1",
        "AWS_DEFAULT_REGION": "poisoned-1",
        "AWS_CONFIG_FILE": str(aws / "config"),
        "AWS_SHARED_CREDENTIALS_FILE": str(aws / "credentials"),
        "AWS_DATA_PATH": str(root / "models"),
        "AWS_CA_BUNDLE": str(root / "ca.pem"),
        "AWS_ENDPOINT_URL": "http://192.0.2.1:9",
        "AWS_ENDPOINT_URL_ECS": "http://192.0.2.1:9",
        "AWS_ENDPOINT_URL_S3": "http://192.0.2.1:9",
        "AWS_ENDPOINT_URL_STS": "http://192.0.2.1:9",
        "AWS_USE_FIPS_ENDPOINT": "true",
        "AWS_USE_DUALSTACK_ENDPOINT": "true",
        "AWS_STS_REGIONAL_ENDPOINTS": "legacy",
        "AWS_DEFAULTS_MODE": "cross-region",
        "AWS_MAX_ATTEMPTS": "9",
        "AWS_RETRY_MODE": "adaptive",
        "AWS_EC2_METADATA_SERVICE_ENDPOINT": "http://192.0.2.1",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://192.0.2.1/poisoned",
        "AWS_CONTAINER_AUTHORIZATION_TOKEN": "poisoned-cli-test",
        "AWS_WEB_IDENTITY_TOKEN_FILE": str(root / "token"),
        "AWS_ROLE_ARN": "arn:aws:iam::999999999999:role/poisoned",
        "AWS_ROLE_SESSION_NAME": "poisoned",
        "HTTPS_PROXY": "http://192.0.2.1:9",
        "HTTP_PROXY": "http://192.0.2.1:9",
        "https_proxy": "http://192.0.2.1:9",
        "ALL_PROXY": "http://192.0.2.1:9",
        "NO_PROXY": "",
        "REQUESTS_CA_BUNDLE": str(root / "ca.pem"),
        # Read by the SDK directly rather than through session variables.
        "AWS_S3_US_EAST_1_REGIONAL_ENDPOINT": "legacy",
        "AWS_S3_USE_ARN_REGION": "true",
        "AWS_S3_DISABLE_MULTIREGION_ACCESS_POINTS": "false",
        "AWS_EXECUTION_ENV": "poisoned-execution-env",
        "AWS_LAMBDA_FUNCTION_NAME": "poisoned-function",
        "_X_AMZN_TRACE_ID": "Root=1-poisoned",
        "PYTHON_DOTENV_DISABLED": "1",
    }


def test_cli_ignores_poisoned_environment_profiles_models_proxies_and_providers(tmp_path):
    root = tmp_path.resolve() / "poison"
    root.mkdir()
    work = tmp_path.resolve() / "work"
    work.mkdir()
    receipt, result = run_poisoned(root, work, poisoned_environment(root))
    assert receipt["events"] == [], "an ambient file, process or socket was used"
    assert not (root / "credential-process-ran").exists()
    assert receipt["run"]["code"] == 0 and receipt["run"]["state"] == "held_paused"
    assert receipt["bridge_services"] == ["ecs", "logs", "s3", "sts"]
    for service, built in receipt["clients"].items():
        assert built["region"] == "us-east-1"
        assert built["retries"] == {"total_max_attempts": 1, "mode": "standard"}
        assert built["proxies"] == {}
        assert built["verify_default"] is True
        assert built["credential_method"] == "explicit" and built["explicit_key"] is True
        assert built["s3"]["us_east_1_regional_endpoint"] == "regional"
        assert built["s3"]["use_arn_region"] is False
        assert built["s3"]["s3_disable_multiregion_access_points"] is True
        assert built["user_agent"] == "sentry-release-cli/1"
    # A real prepared request carries the fixed user agent and no Lambda trace header.
    assert receipt["headers"] == {"User-Agent": "sentry-release-cli/1"}
    assert {service: built["endpoint"] for service, built in receipt["clients"].items()} == {
        "ecs": "https://ecs.us-east-1.amazonaws.com",
        "logs": "https://logs.us-east-1.amazonaws.com",
        "s3": "https://s3.us-east-1.amazonaws.com",
        "sts": "https://sts.us-east-1.amazonaws.com",
    }
    assert "poisoned" not in result.stdout + result.stderr


def run_poisoned(
    root: Path, work: Path, poison: dict[str, str]
) -> tuple[dict, subprocess.CompletedProcess[str]]:
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("AWS_", "HTTP", "http", "ALL_PROXY", "NO_PROXY", "PYTHON",
                               "REQUESTS_CA", "SSLKEYLOG", "_X_AMZN"))
    }  # fmt: skip
    env.update(poison)
    env.update({"SENTRY_CLI_POISON_ROOT": str(root), "SENTRY_CLI_WORK": str(work)})
    result = subprocess.run(
        [sys.executable, "-B", str(REPO / "tests" / "release_cli_process.py")],
        cwd=work,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout), result


def test_a_tls_key_log_variable_refuses_the_run_before_any_client_exists(tmp_path):
    root = tmp_path.resolve() / "poison"
    root.mkdir()
    work = tmp_path.resolve() / "work"
    work.mkdir()
    log = root / "tls-keys.log"
    receipt, result = run_poisoned(
        root, work, {"SSLKEYLOGFILE": str(log), "SENTRY_CLI_MODE": "refusal"}
    )
    assert receipt["run"]["error"] == "unsafe_environment"
    assert receipt["run"]["detail"] == "SSLKEYLOGFILE"
    assert receipt["bridge_services"] == [] and receipt["events"] == []
    assert not log.exists()


def _names(path: Path) -> tuple[set[str], set[str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules, attributes = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            modules.add(node.module or "")
        elif isinstance(node, ast.Attribute):
            attributes.add(node.attr)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            attributes.add(node.func.id)
    return modules, attributes


def test_only_the_cli_client_module_builds_sessions_or_clients():
    builders = {"create_client", "Session", "get_credentials", "client"}
    for package in RELEASE_PACKAGES:
        for path in sorted((REPO / package).glob("*.py")):
            modules, attributes = _names(path)
            relative = path.relative_to(REPO).as_posix()
            assert "boto3" not in {m.split(".")[0] for m in modules}, relative
            assert "dotenv" not in {m.split(".")[0] for m in modules}, relative
            if relative == "release_cli/clients.py":
                continue
            assert "botocore.session" not in modules, relative
            assert not {"create_client", "Session", "get_credentials"} & attributes, relative
    assert builders


def test_the_cli_reads_the_environment_only_to_refuse_unsafe_variables_and_never_changes_it():
    """The one read is ``main``'s default for the refusal check; nothing writes it."""
    for path in sorted((REPO / "release_cli").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        functions = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
        inside = {id(n): f.name for f in functions for n in ast.walk(f)}
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in {
                "environ", "getenv", "putenv", "unsetenv", "environb"
            }:  # fmt: skip
                where = inside.get(id(node))
                assert (path.name, where, node.attr) == ("main.py", "main", "environ"), path.name
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in {"putenv", "unsetenv", "environb"}:
                raise AssertionError(path.name)
