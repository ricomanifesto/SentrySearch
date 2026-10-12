"""The read-only account inspection kit, run against a stand-in ``aws`` program.

Nothing here reaches AWS or reads a credential: the kit finds ``aws`` on PATH,
and PATH holds only a recording stand-in. Each case runs under the bash that
ships with macOS when present, since that is where the operator runs it.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess

import pytest

REPO = Path(__file__).resolve().parents[1]
KIT = REPO / "deploy" / "aws-staging" / "inspect" / "aws-07a-inspect.sh"
BASH = "/bin/bash" if Path("/bin/bash").exists() else shutil.which("bash")
ACCOUNT = "111122223333"

# The stand-in records its arguments and the credential-bearing environment it
# was given, answers the identity call, and fails the operator-role lookup the
# way IAM does for a role that does not exist.
STAND_IN = """#!/bin/sh
{
  printf 'ARGS'
  for argument in "$@"; do printf '\\t%s' "$argument"; done
  printf '\\n'
  env | grep -E '^AWS_' | sort | sed 's/^/ENV\\t/'
} >> "$KIT_TEST_LOG"
case " $* " in
  *" sts get-caller-identity "*)
    if [ -n "$KIT_TEST_NO_IDENTITY" ]; then echo 'ExpiredToken' >&2; exit 254; fi
    printf '{"UserId": "AROAEXAMPLE:operator", "Account": "%s", "Arn": "arn:aws:sts::%s:assumed-role/x/operator"}\\n' "$KIT_TEST_ACCOUNT" "$KIT_TEST_ACCOUNT" ;;
  *" iam get-role "*)
    echo 'An error occurred (NoSuchEntity) when calling the GetRole operation: not found' >&2
    exit 254 ;;
  *) printf '[]\\n' ;;
esac
"""

READS = [
    ["sts", "get-caller-identity"],
    ["ec2", "describe-availability-zones", "--filters", "Name=state,Values=available",
     "--query", "AvailabilityZones[].ZoneName"],
    ["rds", "describe-db-engine-versions", "--engine", "postgres", "--query",
     "DBEngineVersions[?starts_with(EngineVersion, `16.`)].EngineVersion"],
    ["rds", "describe-orderable-db-instance-options", "--engine", "postgres",
     "--db-instance-class", "db.t4g.micro", "--query",
     "OrderableDBInstanceOptions[?starts_with(EngineVersion, `16.`)]"
     ".[EngineVersion,StorageType,MultiAZCapable]"],
    ["service-quotas", "list-service-quotas", "--service-code", "fargate", "--query",
     "Quotas[].[QuotaName,Value]"],
    ["service-quotas", "list-service-quotas", "--service-code", "vpc", "--query",
     "Quotas[?contains(QuotaName, `endpoint`)].[QuotaName,Value]"],
    ["ec2", "describe-vpcs", "--query", "Vpcs[].[VpcId,CidrBlock,IsDefault]"],
    ["ecr", "describe-repositories", "--query",
     "repositories[?starts_with(repositoryName, `sentry-staging/`)].repositoryName"],
    ["logs", "describe-log-groups", "--log-group-name-prefix", "/sentry-staging/", "--query",
     "logGroups[].logGroupName"],
    ["secretsmanager", "list-secrets", "--filters", "Key=name,Values=sentry-staging/",
     "--query", "SecretList[].Name"],
    ["ecs", "list-clusters"],
    ["iam", "get-role", "--role-name", "sentry-staging-operator"],
    ["budgets", "describe-budgets", "--account-id", ACCOUNT],
]  # fmt: skip
LOCATION = "Type=TERM_MATCH,Field=location,Value=US East (N. Virginia)"
PRICES = [
    ["pricing", "get-products", "--service-code", "AmazonVPC", "--filters", LOCATION,
     "Type=TERM_MATCH,Field=productFamily,Value=VpcEndpoint"],
    ["pricing", "get-products", "--service-code", "AmazonRDS", "--filters", LOCATION,
     "Type=TERM_MATCH,Field=instanceType,Value=db.t4g.micro",
     "Type=TERM_MATCH,Field=databaseEngine,Value=PostgreSQL",
     "Type=TERM_MATCH,Field=deploymentOption,Value=Single-AZ"],
    ["pricing", "get-products", "--service-code", "AmazonRDS", "--filters", LOCATION,
     "Type=TERM_MATCH,Field=productFamily,Value=Database Storage",
     "Type=TERM_MATCH,Field=deploymentOption,Value=Single-AZ"],
    ["pricing", "get-products", "--service-code", "AmazonECS", "--filters", LOCATION],
    ["pricing", "get-products", "--service-code", "AWSSecretsManager", "--filters", LOCATION],
]  # fmt: skip
GLOBAL = ["--output", "json", "--no-cli-pager", "--cli-connect-timeout", "10",
          "--cli-read-timeout", "60"]  # fmt: skip


def run(tmp_path: Path, *arguments: str, kit: Path = KIT, **environment: str):
    tools = tmp_path / "bin"
    tools.mkdir(exist_ok=True)
    stand_in = tools / "aws"
    stand_in.write_text(STAND_IN)
    stand_in.chmod(stand_in.stat().st_mode | stat.S_IXUSR)
    log = tmp_path / "aws.log"
    env = {
        "PATH": f"{tools}:/usr/bin:/bin",
        "HOME": str(tmp_path / "home"),
        "KIT_TEST_LOG": str(log),
        "KIT_TEST_ACCOUNT": ACCOUNT,
        "KIT_TEST_NO_IDENTITY": "",
        **environment,
    }
    result = subprocess.run([BASH, str(kit), *arguments], env=env, text=True,
                            capture_output=True, timeout=60)  # fmt: skip
    lines = log.read_text().splitlines() if log.exists() else []
    calls = [line.split("\t")[1:] for line in lines if line.startswith("ARGS")]
    inherited = sorted({line.split("\t", 1)[1] for line in lines if line.startswith("ENV")})
    return result, calls, inherited


def sent(region: str, command: list[str]) -> list[str]:
    return ["--profile", "staging-inspect", "--region", region, *GLOBAL, *command]


def test_it_sends_exactly_the_reviewed_reads_identity_first(tmp_path):
    out = tmp_path / "bundle"
    result, calls, inherited = run(
        tmp_path, "--profile", "staging-inspect", "--region", "us-east-1", "--out", str(out),
        # Ambient credentials and settings must not reach the CLI.
        AWS_ACCESS_KEY_ID="AKIAAMBIENT", AWS_SECRET_ACCESS_KEY="ambient", AWS_SESSION_TOKEN="t",
        AWS_PROFILE="default", AWS_DEFAULT_REGION="eu-west-1", AWS_ENDPOINT_URL="http://x",
        AWS_CA_BUNDLE="/tmp/ca",
    )  # fmt: skip
    assert result.returncode == 0, result.stderr
    assert calls == [sent("us-east-1", command) for command in READS + PRICES]
    assert calls[0][-2:] == ["sts", "get-caller-identity"]
    assert inherited == ["AWS_PAGER="]
    assert "Nothing in the account was created, changed or deleted." in result.stdout

    manifest = json.loads((out / "manifest.json").read_text())
    assert (manifest["kit"], manifest["region"], manifest["account_id"]) == (
        "aws-07a-inspect", "us-east-1", ACCOUNT
    )  # fmt: skip
    assert manifest["kit_sha256"] == hashlib.sha256(KIT.read_bytes()).hexdigest()
    assert manifest["skipped"] == [] and len(manifest["commands"]) == 18
    names = [entry["name"] for entry in manifest["commands"]]
    assert names == sorted(names) and names[0] == "01-sts-caller-identity"
    # One answer file per command, hashed; the files are everything in the bundle.
    expected_files = {"manifest.json"}
    for entry in manifest["commands"]:
        for stream in ("stdout", "stderr"):
            path = out / entry[stream]
            assert hashlib.sha256(path.read_bytes()).hexdigest() == entry[f"{stream}_sha256"]
            expected_files.add(entry[stream])
        assert entry["command"].startswith("aws ") and "--profile" not in entry["command"]
    assert {path.name for path in out.iterdir()} == expected_files
    codes = {entry["name"]: entry["exit_code"] for entry in manifest["commands"]}
    # A role that does not exist is an answer, not a reason to stop.
    assert codes.pop("12-iam-operator-role") == 254 and set(codes.values()) == {0}
    assert "NoSuchEntity" in (out / "12-iam-operator-role.stderr.txt").read_text()
    assert stat.S_IMODE(out.stat().st_mode) == 0o700
    assert stat.S_IMODE((out / "manifest.json").stat().st_mode) == 0o600


def test_list_prints_the_allowlist_without_running_anything(tmp_path):
    result, calls, _ = run(tmp_path, "--list")
    assert result.returncode == 0 and calls == []
    lines = result.stdout.splitlines()
    assert len(lines) == 18 and lines[0] == "01-sts-caller-identity\taws sts get-caller-identity"
    operations = [line.split("\t")[1].split()[1:3] for line in lines]
    assert operations == [command[:2] for command in READS + PRICES]


def test_prices_are_skipped_and_recorded_for_a_region_without_a_reviewed_location(tmp_path):
    out = tmp_path / "bundle"
    result, calls, _ = run(tmp_path, "--profile", "p", "--region", "eu-central-1", "--out",
                           str(out))  # fmt: skip
    assert result.returncode == 0, result.stderr
    assert [call[-2:] for call in calls if "pricing" in call] == []
    assert len(calls) == len(READS) and all(call[3] == "eu-central-1" for call in calls)
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["skipped"] == [f"{n}-price-{name}" for n, name in [
        (14, "vpc-endpoints"), (15, "rds-instance"), (16, "rds-storage"), (17, "fargate"),
        (18, "secrets-manager"),
    ]]  # fmt: skip


def mutated(tmp_path: Path, line: str) -> Path:
    """A copy of the kit with one more allowlist line."""
    text = KIT.read_text()
    anchor = "  inspect 11-ecs-clusters ecs list-clusters\n"
    assert text.count(anchor) == 1
    copy = tmp_path / "mutated.sh"
    copy.write_text(text.replace(anchor, anchor + f"  {line}\n"))
    return copy


@pytest.mark.parametrize(
    "line, reason",
    [
        ("inspect 19-ecs-delete ecs delete-cluster --cluster sentry-staging", "not a read"),
        ("inspect 19-ecs-update ecs update-service --service x --desired-count 0", "not a read"),
        ("inspect 19-run ecs run-task --task-definition x", "not a read"),
        # A read-looking name that still carries a mutating verb.
        ("inspect 19-get-put s3api get-put-thing", "mutating verb 'put'"),
        ("inspect 19-list-delete ecr list-delete-candidates", "mutating verb 'delete'"),
        ("price 19-price pricing describe-create-products", "mutating verb 'create'"),
        ("inspect 19-endpoint ecs list-clusters --endpoint-url http://127.0.0.1", "argument"),
        ("inspect 19-file iam get-role --cli-input-json file:///tmp/x", "argument"),
        ("inspect 19-url s3api get-object --bucket b --key k https://example.invalid/x", "URL"),
        ("inspect 19-profile ecs list-clusters --profile other", "argument --profile"),
        ("inspect 19-debug sts get-caller-identity --debug", "argument --debug"),
    ],
)
def test_any_command_that_is_not_a_plain_read_refuses_before_anything_runs(tmp_path, line, reason):
    kit = mutated(tmp_path, line)
    for arguments in (["--profile", "p", "--region", "us-east-1", "--out", str(tmp_path / "o")],
                      ["--list"]):  # fmt: skip
        result, calls, _ = run(tmp_path, *arguments, kit=kit)
        assert result.returncode == 2, result.stdout
        assert "refusing" in result.stderr and reason in result.stderr, result.stderr
        assert calls == [] and not (tmp_path / "o").exists()


def test_the_identity_check_must_stay_first(tmp_path):
    text = KIT.read_text()
    first = "  inspect 01-sts-caller-identity sts get-caller-identity\n"
    assert text.count(first) == 1
    kit = tmp_path / "reordered.sh"
    kit.write_text(text.replace(first, "  inspect 01-ecs-clusters ecs list-clusters\n" + first))
    result, calls, _ = run(tmp_path, "--profile", "p", "--region", "us-east-1", kit=kit)
    assert result.returncode == 2 and "identity check is not first" in result.stderr
    assert calls == []


def test_without_an_identity_nothing_else_is_asked(tmp_path):
    out = tmp_path / "bundle"
    result, calls, _ = run(tmp_path, "--profile", "p", "--region", "us-east-1", "--out", str(out),
                           KIT_TEST_NO_IDENTITY="1")  # fmt: skip
    assert result.returncode == 2 and "identity could not be read" in result.stderr
    assert [call[-2:] for call in calls] == [["sts", "get-caller-identity"]]
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["account_id"] == "" and len(manifest["commands"]) == 1
    assert manifest["commands"][0]["exit_code"] == 254


@pytest.mark.parametrize(
    "arguments, message",
    [
        (["--region", "us-east-1"], "--profile is required"),
        (["--profile", "p"], "--region is required"),
        (["--profile", "p", "--region", "us-east-1; rm -rf /"], "--region is required"),
        (["--profile", "p q", "--region", "us-east-1"], "not a profile name"),
        (["--profile", "p", "--region", "us-east-1", "--apply"], "unknown argument"),
    ],
)
def test_arguments_are_explicit_and_checked(tmp_path, arguments, message):
    result, calls, _ = run(tmp_path, *arguments)
    assert result.returncode == 2 and message in result.stderr and calls == []


def test_an_existing_bundle_is_never_overwritten_and_the_default_is_dated(tmp_path):
    out = tmp_path / "bundle"
    out.mkdir()
    (out / "manifest.json").write_text("{}")
    result, calls, _ = run(tmp_path, "--profile", "p", "--region", "us-east-1", "--out", str(out))
    assert result.returncode == 2 and "not empty" in result.stderr and calls == []
    assert (out / "manifest.json").read_text() == "{}"
    result, calls, _ = run(tmp_path, "--profile", "p", "--region", "us-east-1")
    assert result.returncode == 0, result.stderr
    [dated] = (tmp_path / "home" / "Documents" / "Codex").iterdir()
    assert len(dated.name) == 10 and (dated / "aws-07a-inspection" / "manifest.json").is_file()


def test_the_script_parses_and_passes_shellcheck():
    assert subprocess.run([BASH, "-n", str(KIT)], capture_output=True).returncode == 0
    assert os.access(KIT, os.X_OK)
    shellcheck = shutil.which("shellcheck")
    if shellcheck is None:
        pytest.skip("shellcheck is not installed")
    result = subprocess.run([shellcheck, str(KIT)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout
