"""Bootstrap contracts use disposable certificates and stubbed AWS responses only."""

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from types import SimpleNamespace

import boto3
from botocore.stub import Stubber
import pytest

from dev import prepare_service_volumes as bootstrap
from dev.tls_fixtures import create_certificates


@pytest.fixture
def materials(tmp_path):
    certs = create_certificates(tmp_path / "certs", hostname="runtime.test")
    return {
        "server-cert.pem": certs.certificate.read_text(),
        "server-key.pem": certs.key.read_text(),
        "runtime-ca.pem": certs.ca.read_text(),
        "postgres-ca.pem": certs.ca.read_text(),
        "probe-token": "disposable-probe-token-0123456789",
    }


def test_runtime_validates_and_writes_fixed_private_files(tmp_path, materials, monkeypatch):
    destination = tmp_path / "material"
    destination.mkdir()
    ownership = []
    monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: ownership.append((uid, gid)))
    bootstrap.prepare("runtime", json.dumps(materials), destination)
    assert {path.name for path in destination.iterdir()} == set(materials)
    assert stat.S_IMODE(destination.stat().st_mode) == 0o700
    for name, value in materials.items():
        assert (destination / name).read_text() == value
        assert stat.S_IMODE((destination / name).stat().st_mode) == 0o400
    assert ownership == [(65532, 65532)] * (len(materials) + 1)


def test_search_initializes_all_named_volume_roots(tmp_path, materials, monkeypatch):
    roots = [tmp_path / name for name in ("material", "tmp", "work")]
    for root in roots:
        root.mkdir()
    ownership = []
    monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: ownership.append((uid, gid)))
    payload = {key: materials[key] for key in ("runtime-ca.pem", "postgres-ca.pem")}
    bootstrap.prepare("search", json.dumps(payload), roots[0], roots[1], roots[2])
    assert ownership == [(10001, 10001)] * 5
    assert all(stat.S_IMODE(root.stat().st_mode) == 0o700 for root in roots)
    assert list(roots[1].iterdir()) == list(roots[2].iterdir()) == []


@pytest.mark.parametrize("profile,uid", [("runtime-release", 65532), ("search-release", 10001)])
def test_release_profile_writes_only_database_ca(tmp_path, materials, monkeypatch, profile, uid):
    destination = tmp_path / "material"
    destination.mkdir()
    ownership = []
    monkeypatch.setattr(os, "fchown", lambda fd, user, group: ownership.append((user, group)))
    payload = {"postgres-ca.pem": materials["postgres-ca.pem"]}
    bootstrap.prepare(profile, json.dumps(payload), destination)
    assert [path.name for path in destination.iterdir()] == ["postgres-ca.pem"]
    assert (destination / "postgres-ca.pem").read_text() == payload["postgres-ca.pem"]
    assert stat.S_IMODE((destination / "postgres-ca.pem").stat().st_mode) == 0o400
    assert stat.S_IMODE(destination.stat().st_mode) == 0o700
    assert ownership == [(uid, uid), (uid, uid)]


@pytest.mark.parametrize("profile", ["runtime-release", "search-release"])
@pytest.mark.parametrize("extra", ["runtime-ca.pem", "server-key.pem", "probe-token"])
def test_release_profiles_reject_unneeded_material(tmp_path, materials, profile, extra):
    destination = tmp_path / "material"
    destination.mkdir()
    payload = {"postgres-ca.pem": materials["postgres-ca.pem"], extra: materials[extra]}
    with pytest.raises(ValueError):
        bootstrap.prepare(profile, json.dumps(payload), destination)
    assert list(destination.iterdir()) == []


@pytest.mark.parametrize("profile", ["runtime-release", "search-release"])
@pytest.mark.parametrize("scratch", ["tmp", "work"])
def test_release_profiles_reject_scratch_before_writes(tmp_path, materials, profile, scratch):
    destination = tmp_path / "material"
    destination.mkdir()
    scratch_root = tmp_path / "scratch"
    scratch_root.mkdir()
    with pytest.raises(ValueError):
        bootstrap.prepare(
            profile,
            json.dumps({"postgres-ca.pem": materials["postgres-ca.pem"]}),
            destination,
            tmp_dir=scratch_root if scratch == "tmp" else None,
            work_dir=scratch_root if scratch == "work" else None,
        )
    assert list(destination.iterdir()) == list(scratch_root.iterdir()) == []


@pytest.mark.parametrize(
    "mutation", ["missing", "extra", "bad-ca", "bad-token", "oversize", "duplicate"]
)
def test_bad_payload_is_rejected_before_writes(tmp_path, materials, mutation):
    destination = tmp_path / "material"
    destination.mkdir()
    if mutation == "missing":
        del materials["probe-token"]
    elif mutation == "extra":
        materials["../escape"] = "unsafe"
    elif mutation == "bad-ca":
        materials["runtime-ca.pem"] = "not a certificate"
    elif mutation == "bad-token":
        materials["probe-token"] = "secret\nheader"
    elif mutation == "oversize":
        materials["probe-token"] = "x" * 65537
    payload = json.dumps(materials)
    if mutation == "duplicate":
        payload = payload[:-1] + ', "probe-token": "duplicate"}'
    with pytest.raises(ValueError):
        bootstrap.prepare("runtime", payload, destination)
    assert list(destination.iterdir()) == []


def test_symlink_or_nonempty_root_rejected_before_any_writes(tmp_path, materials):
    material, scratch, work = (tmp_path / name for name in ("material", "scratch", "work"))
    for root in (material, scratch, work):
        root.mkdir()
    (work / "existing").write_text("preserve")
    payload = json.dumps({key: materials[key] for key in ("runtime-ca.pem", "postgres-ca.pem")})
    with pytest.raises(ValueError):
        bootstrap.prepare("search", payload, material, scratch, work)
    assert list(material.iterdir()) == []
    link = tmp_path / "link"
    link.symlink_to(material, target_is_directory=True)
    with pytest.raises((ValueError, OSError)):
        bootstrap.prepare("runtime", json.dumps(materials), link)
    nested = tmp_path / "nested"
    nested.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises((ValueError, OSError)):
        bootstrap.prepare("runtime", json.dumps(materials), nested / "material")


def test_nonmatching_key_fails_closed_and_cannot_retry_same_volume(tmp_path, materials):
    another = create_certificates(tmp_path / "another", hostname="runtime.test")
    materials["server-key.pem"] = another.key.read_text()
    destination = tmp_path / "material"
    destination.mkdir()
    with pytest.raises(ValueError):
        bootstrap.prepare("runtime", json.dumps(materials), destination)
    # A failed partial init is never reusable or reported ready.
    with pytest.raises(ValueError):
        bootstrap.prepare("runtime", json.dumps(materials), destination)


def test_encrypted_traditional_key_never_prompts_or_prints_material(tmp_path, materials):
    encrypted = subprocess.run(
        ["openssl", "rsa", "-traditional", "-aes256", "-passout", "pass:disposable"],
        input=materials["server-key.pem"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert "BEGIN RSA PRIVATE KEY" in encrypted and "Proc-Type: 4,ENCRYPTED" in encrypted
    materials["server-key.pem"] = encrypted
    destination = tmp_path / "material"
    destination.mkdir()
    # Exercise prepare directly so actual ownership remains the host user's.
    script = (
        "import sys;from pathlib import Path;from dev import prepare_service_volumes as b;"
        "\ntry:b.prepare('runtime',sys.stdin.read(),Path(sys.argv[1]))"
        "\nexcept Exception:print('Service volume initialization failed',file=sys.stderr);raise SystemExit(1)"
    )
    result = subprocess.run(
        [sys.executable, "-c", script, str(destination)],
        input=json.dumps(materials),
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 1 and result.stdout == ""
    assert result.stderr == "Service volume initialization failed\n"


def test_same_volume_inode_cannot_alias_secret_and_writable_scratch(
    tmp_path, materials, monkeypatch
):
    roots = [tmp_path / name for name in ("material", "tmp", "work")]
    for root in roots:
        root.mkdir()
    monkeypatch.setattr(
        os, "fstat", lambda fd: SimpleNamespace(st_uid=os.geteuid(), st_dev=1, st_ino=1)
    )
    payload = {key: materials[key] for key in ("runtime-ca.pem", "postgres-ca.pem")}
    with pytest.raises(ValueError, match="distinct"):
        bootstrap.prepare("search", json.dumps(payload), *roots)
    assert all(list(root.iterdir()) == [] for root in roots)


@pytest.mark.parametrize("version", ["AWSCURRENT", "", "x" * 32, "0" * 64])
def test_non_uuid_version_rejected_before_sdk_call(version):
    class NoClient:
        def get_secret_value(self, **kwargs):
            raise AssertionError("invalid version reached SDK")

    with pytest.raises(ValueError, match="UUID"):
        bootstrap.fetch_secret(NoClient(), "fixture", version)


def test_loads_only_explicit_secret_version_without_network(materials):
    client = boto3.client(
        "secretsmanager",
        region_name="us-east-1",
        aws_access_key_id="fixture",
        aws_secret_access_key="fixture",
        aws_session_token="fixture",
    )
    arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:fixture-AbCdEf"
    version = "01234567-89ab-cdef-0123-456789abcdef"
    with Stubber(client) as stub:
        stub.add_response(
            "get_secret_value",
            {"SecretString": json.dumps(materials), "VersionId": version},
            {"SecretId": arn, "VersionId": version},
        )
        assert bootstrap.fetch_secret(client, arn, version) == json.dumps(materials)
        stub.assert_no_pending_responses()


def test_rejects_wrong_secret_version_without_accepting_body():
    client = boto3.client(
        "secretsmanager",
        region_name="us-east-1",
        aws_access_key_id="fixture",
        aws_secret_access_key="fixture",
    )
    version = "01234567-89ab-cdef-0123-456789abcdef"
    with Stubber(client) as stub:
        stub.add_response(
            "get_secret_value",
            {"SecretString": "do-not-print", "VersionId": "x" * 32},
            {"SecretId": "fixture", "VersionId": version},
        )
        with pytest.raises(ValueError):
            bootstrap.fetch_secret(client, "fixture", version)


def test_cli_failure_is_redacted(monkeypatch, capsys):
    monkeypatch.setattr(
        bootstrap, "prepare", lambda *args: (_ for _ in ()).throw(ValueError("do-not-print"))
    )
    monkeypatch.setattr(bootstrap.sys, "stdin", __import__("io").StringIO("do-not-print"))
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    assert (
        bootstrap.main(
            ["--profile", "runtime", "--material-dir", "/run/material", "--fixture-stdin"]
        )
        == 1
    )
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "Service volume initialization failed\n"


def _digest(payload: str) -> str:
    import hashlib

    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def test_environment_source_requires_the_recorded_digest(materials):
    payload = json.dumps({key: materials[key] for key in ("runtime-ca.pem", "postgres-ca.pem")})
    environ = {"CFINIT_MATERIAL": payload, "CFINIT_MATERIAL_SHA256": _digest(payload)}
    assert bootstrap.payload_from_environment(environ) == payload
    for broken in (
        {**environ, "CFINIT_MATERIAL_SHA256": "0" * 64},
        {**environ, "CFINIT_MATERIAL_SHA256": _digest(payload).upper()},
        {"CFINIT_MATERIAL": payload},
        {"CFINIT_MATERIAL_SHA256": _digest("")},
        {"CFINIT_MATERIAL": "", "CFINIT_MATERIAL_SHA256": _digest("")},
    ):
        with pytest.raises(ValueError) as error:
            bootstrap.payload_from_environment(broken)
        assert "BEGIN" not in str(error.value)
    oversized = " " * (bootstrap.MAX_BYTES + 1)
    with pytest.raises(ValueError):
        bootstrap.payload_from_environment(
            {"CFINIT_MATERIAL": oversized, "CFINIT_MATERIAL_SHA256": _digest(oversized)}
        )


def test_cli_environment_source_prepares_and_excludes_other_sources(materials, monkeypatch):
    payload = json.dumps({key: materials[key] for key in ("runtime-ca.pem", "postgres-ca.pem")})
    monkeypatch.setenv("CFINIT_MATERIAL", payload)
    monkeypatch.setenv("CFINIT_MATERIAL_SHA256", _digest(payload))
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    calls = []
    monkeypatch.setattr(bootstrap, "prepare", lambda *args: calls.append(args))
    argv = [
        "--profile",
        "search-release",
        "--material-dir",
        "/run/material",
        "--environment-source",
    ]
    assert bootstrap.main(argv) == 0
    assert calls == [("search-release", payload, Path("/run/material"), None, None)]
    assert bootstrap.main([*argv, "--region", "us-east-1"]) == 1
    with pytest.raises(SystemExit):
        bootstrap.main([*argv, "--fixture-stdin"])
    monkeypatch.setenv("CFINIT_MATERIAL_SHA256", "0" * 64)
    assert bootstrap.main(argv) == 1 and len(calls) == 1


def test_material_logic_imports_without_the_aws_sdk():
    script = (
        "import sys; sys.modules['boto3'] = None; "
        "import dev.prepare_service_volumes as m; print(m.payload_from_environment.__name__)"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0 and result.stdout.strip() == "payload_from_environment"
