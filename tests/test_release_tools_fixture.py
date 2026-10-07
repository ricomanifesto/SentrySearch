"""Guard the portable, isolated release-tools container fixture."""

import subprocess
from unittest.mock import Mock

import pytest

from tests import release_tools_images as images
from dev import check_release_tools as runner


@pytest.fixture
def stack(tmp_path):
    value = images.Stack(
        network="fixture-test",
        root=tmp_path,
        secrets={"postgres": "fixture", "runtime_owner": "fixture", "search_owner": "fixture"},
    )
    value.material = {"runtime": "runtime-material", "product": "product-material"}
    return value


@pytest.mark.parametrize("ssl", [True, False])
def test_fixture_does_not_publish_database_ports(monkeypatch, stack, ssl):
    run = Mock(return_value=subprocess.CompletedProcess([], 0, "", ""))
    monkeypatch.setattr(images, "docker", run)
    monkeypatch.setattr(images, "wait_for", lambda *args, **kwargs: None)
    images._start_postgres(stack, name="fixture-postgres", ssl=ssl, ip=None, alias="postgres")
    args = run.call_args.args
    assert "--publish" not in args and "-p" not in args
    assert args[args.index("--network") + 1] == stack.network


def test_both_real_migration_commands_run_in_isolated_readonly_containers(monkeypatch, stack):
    run = Mock(return_value=subprocess.CompletedProcess([], 0, "Storage schema ready\n", ""))
    monkeypatch.setattr(images, "docker", run)
    monkeypatch.setattr(images, "SEARCH_IMAGE", "sha256:product-fixture", raising=False)
    monkeypatch.setattr(images, "RUNTIME_IMAGE", "sha256:runtime-fixture")
    images._migrate(stack)
    assert run.call_count == 2
    runtime, product = [call.args for call in run.call_args_list]
    assert runtime[-2:] == ("sha256:runtime-fixture", "/app/migrate")
    assert product[-4:] == ("sha256:product-fixture", "python", "-m", "dev.migrate_storage")
    for args, uid, material in (
        (runtime, "65532:65532", "runtime-material"),
        (product, "10001:10001", "product-material"),
    ):
        assert args[:2] == ("run", "--rm")
        assert "--read-only" in args
        assert args[args.index("--network") + 1] == stack.network
        assert args[args.index("--cap-drop") + 1] == "ALL"
        assert args[args.index("--user") + 1] == uid
        assert args[args.index("--mount") + 1] == (
            f"type=volume,source={material},target=/run/material,readonly,volume-nocopy"
        )
    settings = dict(
        line.split("=", 1) for line in (stack.root / "product-migrate.env").read_text().splitlines()
    )
    assert settings == {
        "ENVIRONMENT": "production",
        "DB_HOST": "postgres",
        "DB_PORT": "5432",
        "DB_NAME": "sentrysearch",
        "DB_USER": "search_owner",
        "DB_PASSWORD": "fixture",
        "DB_SSLMODE": "verify-full",
        "DB_SSLROOTCERT": "/run/material/postgres-ca.pem",
    }
    assert (stack.root / "product-migrate.env").stat().st_mode & 0o777 == 0o600


def test_runner_supplies_all_three_built_image_identities_without_host_aws(monkeypatch, tmp_path):
    identities = [f"sha256:{number:064x}" for number in (1, 2, 3)]
    build = Mock(side_effect=identities)
    run = Mock()
    monkeypatch.setattr(runner, "build", build)
    monkeypatch.setattr(runner.subprocess, "run", run)
    monkeypatch.setattr(
        runner.sys, "argv", ["check_release_tools", "--runtime-repo", str(tmp_path)]
    )
    monkeypatch.setenv("AWS_PROFILE", "must-not-reach-tests")
    monkeypatch.setenv("SENTRYSEARCH_TEST_IMAGE", "stale-image")
    runner.main()
    assert build.call_count == 3
    assert build.call_args_list[0].args[0] == tmp_path
    assert build.call_args_list[2].args[2].name == "Dockerfile"
    env = run.call_args.kwargs["env"]
    assert env["SENTRYRUNTIME_TEST_IMAGE"] == identities[0]
    assert env["RELEASE_TOOLS_TEST_IMAGE"] == identities[1]
    assert env["SENTRYSEARCH_TEST_IMAGE"] == identities[2]
    assert not any(key.startswith("AWS_") for key in env)
