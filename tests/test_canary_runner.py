from dev.check_deterministic_canary import canary_environment, immutable_local_image

import pytest


def test_canary_environment_excludes_host_authority(monkeypatch):
    for name in (
        "NEXT_PUBLIC_SUPABASE_URL",
        "SUPABASE_SERVICE_ROLE_KEY",
        "AWS_PROFILE",
        "OPENROUTER_API_KEY",
        "SENTRYRUNTIME_WORKER_TOKEN",
        "DATABASE_URL",
    ):
        monkeypatch.setenv(name, "must-not-inherit")
    env = canary_environment()
    assert "must-not-inherit" not in env.values()
    assert env["PYTHON_DOTENV_DISABLED"] == "1"
    assert env["AWS_SHARED_CREDENTIALS_FILE"] == "/dev/null"


def test_image_identity_is_resolved_and_rejects_non_digest(monkeypatch):
    from types import SimpleNamespace
    from dev import check_deterministic_canary as runner

    monkeypatch.setattr(
        runner.subprocess, "run", lambda *a, **kw: SimpleNamespace(stdout="latest\n")
    )
    with pytest.raises(ValueError):
        immutable_local_image("some-tag")
    digest = "sha256:" + "a" * 64
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **kw: SimpleNamespace(stdout=digest))
    assert immutable_local_image("some-tag") == digest
