"""The offline account-plan assembler, against synthetic inspection bundles.

Every bundle here is made up in a temporary directory. Sockets are refused for
the whole module: the assembler reads files and writes files, nothing else.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess

import pytest

from dev import assemble_account_plan as plan
from release.manifest import ReleaseRejected, load_manifest

ACCOUNT, REGION, PREFIX = "111122223333", "us-east-1", "sentry-staging"
REPO = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def no_sockets(monkeypatch):
    def refused(*_args, **_kwargs):
        raise AssertionError("the assembler must not open a socket")

    monkeypatch.setattr(socket, "socket", refused)
    monkeypatch.setattr(socket, "create_connection", refused)
    monkeypatch.setattr(socket, "getaddrinfo", refused)


def product(usagetype: str, unit: str, usd: str) -> str:
    """One Price List record, as get-products returns it: a JSON string."""
    return json.dumps({
        "product": {"attributes": {"usagetype": usagetype}},
        "terms": {"OnDemand": {"T": {"priceDimensions": {"D": {
            "unit": unit, "pricePerUnit": {"USD": usd}}}}}},
    })  # fmt: skip


def answers() -> dict[str, object]:
    """A clean account: nothing exists yet, quotas suffice, prices equal the estimate."""
    return {
        "01-sts-caller-identity": {"UserId": "AROAEXAMPLE:op", "Account": ACCOUNT,
                                   "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/x/op"},
        "02-ec2-availability-zones": ["us-east-1c", "us-east-1a", "us-east-1b"],
        "03-rds-postgres-16-versions": ["16.4", "16.8", "16.10"],
        "04-rds-orderable-t4g-micro": [["16.4", "gp2", True], ["16.8", "gp3", True],
                                       ["16.10", "gp3", True], ["16.10", "io1", True]],
        "05-quotas-fargate": [["Fargate On-Demand vCPU resource count", 6.0],
                              ["Fargate Spot vCPU resource count", 6.0]],
        "06-quotas-vpc-endpoints": [["Interface VPC endpoints per VPC", 50.0],
                                    ["Gateway VPC endpoints per Region", 20.0]],
        "07-ec2-vpcs": [["vpc-0default", "172.31.0.0/16", True], ["vpc-0other", "10.64.0.0/16", False]],
        "08-ecr-repositories": [],
        "09-logs-log-groups": [],
        "10-secretsmanager-secrets": [],
        "11-ecs-clusters": {"clusterArns": [f"arn:aws:ecs:{REGION}:{ACCOUNT}:cluster/other"]},
        "13-budgets": {"Budgets": []},
        "14-price-vpc-endpoints": {"PriceList": [
            product("USE1-VpcEndpoint-Hours", "Hrs", "0.0100000000"),
            product("USE1-VpcEndpoint-Bytes", "GB", "0.0100000000")]},
        "15-price-rds-instance": {"PriceList": [
            product("InstanceUsage:db.t4g.micro", "Hrs", "0.0160000000")]},
        "16-price-rds-storage": {"PriceList": [
            product("RDS:GP3-Storage", "GB-Mo", "0.1150000000"),
            product("RDS:GP2-Storage", "GB-Mo", "0.1150000000")]},
        "17-price-fargate": {"PriceList": [
            product("USE1-Fargate-ARM-vCPU-Hours:perCPU", "hours", "0.0323798400"),
            product("USE1-Fargate-ARM-GB-Hours", "hours", "0.0035600400"),
            product("USE1-Fargate-vCPU-Hours:perCPU", "hours", "0.0404800000")]},
        "18-price-secrets-manager": {"PriceList": [
            product("USE1-AWSSecretsManager-Secrets", "Secrets", "0.4000000000"),
            product("USE1-AWSSecretsManager-APIRequest", "API Requests", "0.0000050000")]},
    }  # fmt: skip


def write_bundle(root: Path, found: dict[str, object] | None = None, *,
                 failures: dict[str, tuple[int, str]] | None = None,
                 skipped: tuple[str, ...] = (), region: str = REGION) -> Path:  # fmt: skip
    """A bundle as the kit writes it: one answer and one error file per command."""
    found = answers() if found is None else found
    failures = {"12-iam-operator-role": (254, "An error occurred (NoSuchEntity) when calling "
                                              "the GetRole operation"), **(failures or {})}  # fmt: skip
    root.mkdir()
    commands = []
    for name in (*plan.READS, *plan.PRICES):
        if name in skipped:
            continue
        code, error = failures.get(name, (0, ""))
        text = "" if code else json.dumps(found[name], indent=4) + "\n"
        (root / f"{name}.json").write_text(text)
        (root / f"{name}.stderr.txt").write_text(error)
        commands.append({
            "name": name, "command": f"aws {name}", "region": region, "exit_code": code,
            "stdout": f"{name}.json", "stdout_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "stderr": f"{name}.stderr.txt",
            "stderr_sha256": hashlib.sha256(error.encode()).hexdigest(),
        })  # fmt: skip
    (root / "manifest.json").write_text(json.dumps({
        "kit": "aws-07a-inspect", "kit_sha256": "0" * 64, "started_at": "2026-10-12T15:00:00Z",
        "finished_at": "2026-10-12T15:01:00Z", "region": region, "name_prefix": PREFIX,
        "account_id": ACCOUNT, "skipped": list(skipped), "commands": commands,
    }, indent=2))  # fmt: skip
    return root


def decisions(**changes: object) -> dict[str, object]:
    chosen: dict[str, object] = {
        "account_id": ACCOUNT, "region": REGION, "name_prefix": PREFIX,
        "availability_zones": ["us-east-1a", "us-east-1b"], "vpc_cidr": "10.96.0.0/20",
        "private_dns_namespace": "sentry-staging.internal", "postgres_engine_version": "16.10",
        "operator": "fixture-operator",
        "operator_trust": {"principal_arn": f"arn:aws:iam::{ACCOUNT}:role/release-issuer",
                           "external_id": "fixture-external-id-0001", "session_seconds": 14400},
        "notifications": {"email": "alerts@example.com", "monthly_budget_usd": 200},
        "lifetime_days": 7,
    }  # fmt: skip
    chosen.update(changes)
    return chosen


def statuses(result: dict) -> dict[str, str]:
    return {item["id"]: item["status"] for item in result["checklist"]}


# The bundle ------------------------------------------------------------------------


def test_a_bundle_whose_files_match_its_manifest_is_read(tmp_path):
    bundle = plan.Bundle(write_bundle(tmp_path / "bundle"))
    assert (bundle.account_id, bundle.region, bundle.name_prefix) == (ACCOUNT, REGION, PREFIX)
    assert bundle.answer("02-ec2-availability-zones") == ["us-east-1c", "us-east-1a", "us-east-1b"]
    assert bundle.answer("12-iam-operator-role") is None
    assert "NoSuchEntity" in bundle.error("12-iam-operator-role")
    assert plan.main(["verify", "--bundle", str(tmp_path / "bundle")]) == 0


@pytest.mark.parametrize(
    "tamper, message",
    [
        (lambda root: (root / "07-ec2-vpcs.json").write_text("[]\n"), "does not match"),
        (lambda root: (root / "12-iam-operator-role.stderr.txt").write_text("AccessDenied"),
         "does not match"),
        (lambda root: (root / "notes.txt").write_text("edited by hand"), "does not list"),
        (lambda root: (root / "08-ecr-repositories.json").unlink(), "not a regular file"),
        (lambda root: ((root / "09-logs-log-groups.json").unlink(),
                       (root / "09-logs-log-groups.json").symlink_to("08-ecr-repositories.json")),
         "not a regular file"),
        (lambda root: (root / "manifest.json").write_text("{}"), "inspection kit"),
        (lambda root: (root / "manifest.json").unlink(), "no readable manifest"),
    ],
)  # fmt: skip
def test_a_bundle_that_does_not_verify_is_unusable_and_writes_nothing(tmp_path, tamper, message):
    root = write_bundle(tmp_path / "bundle")
    tamper(root)
    with pytest.raises(plan.Unusable, match=message):
        plan.Bundle(root)
    (tmp_path / "decisions.json").write_text(json.dumps(decisions()))
    code = plan.main(["assemble", "--bundle", str(root), "--decisions",
                      str(tmp_path / "decisions.json"), "--out", str(tmp_path / "out")])  # fmt: skip
    assert code == 2 and not (tmp_path / "out").exists()


def edited_manifest(root: Path, change) -> None:
    manifest = json.loads((root / "manifest.json").read_text())
    change(manifest)
    (root / "manifest.json").write_text(json.dumps(manifest))


@pytest.mark.parametrize(
    "change, message",
    [
        (lambda m: m["commands"].pop(6), "does not list"),
        (lambda m: m["commands"].insert(0, m["commands"].pop(1)), "identity check"),
        (lambda m: m["commands"][0].update(exit_code=254), "identity check"),
        (lambda m: m.update(account_id="999999999999"), "different accounts"),
        (lambda m: m["commands"][2].update(stdout="../outside.json"), "does not name a file"),
        (lambda m: m["commands"].append(dict(m["commands"][3])), "malformed"),
    ],
)
def test_a_manifest_that_is_incomplete_or_inconsistent_is_unusable(tmp_path, change, message):
    root = write_bundle(tmp_path / "bundle")
    edited_manifest(root, change)
    with pytest.raises(plan.Unusable, match=message):
        plan.Bundle(root)


def test_a_bundle_missing_a_required_read_is_unusable_but_skipped_prices_are_not(tmp_path):
    root = write_bundle(tmp_path / "bundle")
    for suffix in ("json", "stderr.txt"):
        (root / f"07-ec2-vpcs.{suffix}").unlink()
    edited_manifest(root, lambda m: m["commands"].pop(6))
    with pytest.raises(plan.Unusable, match="commands missing"):
        plan.Bundle(root)
    skipped = write_bundle(tmp_path / "skipped", skipped=plan.PRICES)
    assert plan.Bundle(skipped).answer("17-price-fargate") is None


# Draft -------------------------------------------------------------------------------


def test_a_draft_proposes_what_the_inspection_can_and_leaves_the_rest_to_a_person(tmp_path):
    root = write_bundle(tmp_path / "bundle")
    assert plan.main(["draft", "--bundle", str(root), "--out", str(tmp_path / "d.json")]) == 0
    drafted = json.loads((tmp_path / "d.json").read_text())
    basis = drafted.pop("basis")
    assert drafted == {
        "account_id": ACCOUNT, "region": REGION, "name_prefix": PREFIX,
        "availability_zones": ["us-east-1a", "us-east-1b"],
        # 10.64.0.0/20 would overlap the account's 10.64.0.0/16.
        "vpc_cidr": "10.96.0.0/20",
        "private_dns_namespace": "sentry-staging.internal",
        "postgres_engine_version": "16.10",
        "operator": None, "operator_trust": None, "notifications": None, "lifetime_days": 7,
    }  # fmt: skip
    assert set(basis) == set(drafted)
    # Completed with the operator alone, the draft is usable as it stands.
    result = plan.assemble(plan.Bundle(root), {**drafted, "basis": basis})
    assert set(statuses(result).values()) == {"met"}
    assert plan.main(["draft", "--bundle", str(root), "--out", str(tmp_path / "d.json")]) == 2


# Assemble ----------------------------------------------------------------------------


def test_a_clean_account_yields_each_roots_known_inputs_and_an_all_met_checklist(tmp_path):
    root = write_bundle(tmp_path / "bundle")
    (tmp_path / "decisions.json").write_text(json.dumps(decisions()))
    out = tmp_path / "out"
    assert plan.main(["assemble", "--bundle", str(root), "--decisions",
                      str(tmp_path / "decisions.json"), "--out", str(out)]) == 0  # fmt: skip
    common = {"account_id": ACCOUNT, "region": REGION, "name_prefix": PREFIX}
    inputs = {name: json.loads((out / name / "account.auto.tfvars.json").read_text())
              for name in plan.ROOTS}  # fmt: skip
    assert inputs == {
        "bootstrap": {**common, "operator_trust": {
            "principal_arn": f"arn:aws:iam::{ACCOUNT}:role/release-issuer",
            "external_id": "fixture-external-id-0001", "session_seconds": 14400,
            "operator": "fixture-operator"}},
        "foundation": {**common, "availability_zones": ["us-east-1a", "us-east-1b"],
                       "vpc_cidr": "10.96.0.0/20",
                       "private_dns_namespace": "sentry-staging.internal",
                       "postgres_engine_version": "16.10",
                       "notifications": {"email": "alerts@example.com",
                                         "monthly_budget_usd": 200}},
        "releases": {**common, "private_dns_namespace": "sentry-staging.internal"},
        "services": common,
    }  # fmt: skip
    record = json.loads((out / "account-plan.json").read_text())
    assert statuses(record) == dict.fromkeys(
        ["identity", "zones", "postgres", "fargate_quota", "endpoint_quota", "vpc_range",
         "repositories", "log_groups", "secrets", "cluster", "operator_role", "prices"], "met"
    )  # fmt: skip
    assert record["pending_inputs"]["bootstrap"] == {} == record["pending_inputs"]["foundation"]
    assert set(record["pending_inputs"]["releases"]) == {"releases", "observer_security_group_ids"}
    assert set(record["pending_inputs"]["services"]) == {
        "task_subnet_ids", "security_group_ids", "discovery_service_arns", "task_definition_arns"
    }  # fmt: skip
    page = (out / "account-plan.md").read_text()
    assert (
        record["plan_sha256"] in page and "| The identity is the intended account | met |" in page
    )
    assert sorted(path.name for path in out.iterdir()) == [
        "account-plan.json", "account-plan.md", "bootstrap", "foundation",
        "manifest.skeleton.json", "releases", "services",
    ]  # fmt: skip
    # Nothing is overwritten on a second run.
    assert plan.main(["assemble", "--bundle", str(root), "--decisions",
                      str(tmp_path / "decisions.json"), "--out", str(out)]) == 2  # fmt: skip


def test_the_prices_reproduce_the_estimate_when_the_rates_are_unchanged(tmp_path):
    result = plan.assemble(plan.Bundle(write_bundle(tmp_path / "bundle")), decisions())
    prices = result["prices"]
    assert {entry["status"] for entry in prices["rates"].values()} == {"unchanged"}
    assert prices["monthly_estimate"] == prices["monthly_refreshed"]
    monthly = prices["monthly_refreshed"]
    # The estimate's own lines: 32.73, 58.40, 27.96 and 5.20 to 6.80.
    assert (monthly["fargate"], monthly["endpoints"], monthly["rds"]) == (32.73, 58.40, 27.96)
    assert (monthly["secrets_low"], monthly["secrets_high"]) == (5.20, 6.80)
    assert (monthly["total_low"], monthly["total_high"]) == (125.79, 134.39)
    assert result["lifetime"] == {"days": 7, "cost_low": 28.95, "cost_high": 30.93}


def test_a_changed_rate_revises_the_estimate_and_a_missing_one_is_unknown(tmp_path):
    found = answers()
    found["14-price-vpc-endpoints"] = {"PriceList": [
        product("USE1-VpcEndpoint-Hours", "Hrs", "0.0110000000")]}  # fmt: skip
    result = plan.assemble(plan.Bundle(write_bundle(tmp_path / "changed", found)), decisions())
    assert result["prices"]["changed"] == ["endpoint_hour"]
    assert result["prices"]["monthly_refreshed"]["endpoints"] == 64.24
    [item] = [item for item in result["checklist"] if item["id"] == "prices"]
    assert item["status"] == "met" and "estimate revised" in item["evidence"]

    # Two different prices for one rate, a failed query and a skipped one: no answer.
    found = answers()
    found["15-price-rds-instance"] = {"PriceList": [
        product("InstanceUsage:db.t4g.micro", "Hrs", "0.0160000000"),
        product("USW2-InstanceUsage:db.t4g.micro", "Hrs", "0.0170000000")]}  # fmt: skip
    root = write_bundle(tmp_path / "unknown", found,
                        failures={"17-price-fargate": (255, "AccessDeniedException")},
                        skipped=("18-price-secrets-manager",))  # fmt: skip
    result = plan.assemble(plan.Bundle(root), decisions())
    assert result["prices"]["unknown"] == [
        "fargate_gb_hour", "fargate_vcpu_hour", "rds_instance_hour", "secret_month"
    ]  # fmt: skip
    assert statuses(result)["prices"] == "unknown"
    # An unknown rate keeps the estimate's value in the refreshed column.
    assert result["prices"]["monthly_refreshed"] == result["prices"]["monthly_estimate"]


@pytest.mark.parametrize(
    "name, value, item, status",
    [
        ("08-ecr-repositories", ["sentry-staging/runtime"], "repositories", "unmet"),
        ("09-logs-log-groups", ["/sentry-staging/api"], "log_groups", "unmet"),
        ("10-secretsmanager-secrets", ["sentry-staging/runtime-env"], "secrets", "unmet"),
        ("11-ecs-clusters", {"clusterArns": [f"arn:aws:ecs:{REGION}:{ACCOUNT}:cluster/{PREFIX}"]},
         "cluster", "unmet"),
        ("11-ecs-clusters", {"clusters": []}, "cluster", "unknown"),
        ("02-ec2-availability-zones", ["us-east-1a"], "zones", "unmet"),
        ("02-ec2-availability-zones", ["us-east-1a", "us-east-1c"], "zones", "unmet"),
        ("04-rds-orderable-t4g-micro", [["16.10", "gp2", True]], "postgres", "unmet"),
        ("04-rds-orderable-t4g-micro", [["16.8", "gp3", True]], "postgres", "unmet"),
        ("05-quotas-fargate", [["Fargate On-Demand vCPU resource count", 1.0]],
         "fargate_quota", "unmet"),
        ("05-quotas-fargate", [["Something else", 100.0]], "fargate_quota", "unknown"),
        ("06-quotas-vpc-endpoints", [["Interface VPC endpoints per VPC", 3.0],
                                     ["Gateway VPC endpoints per Region", 20.0]],
         "endpoint_quota", "unmet"),
        ("06-quotas-vpc-endpoints", [["Interface VPC endpoints per VPC", 50.0]],
         "endpoint_quota", "unknown"),
        ("07-ec2-vpcs", [["vpc-0clash", "10.96.8.0/22", False]], "vpc_range", "unmet"),
        ("07-ec2-vpcs", [["vpc-0odd", "not-a-range", False]], "vpc_range", "unknown"),
    ],
)  # fmt: skip
def test_each_check_reports_what_the_account_showed(tmp_path, name, value, item, status):
    found = answers()
    found[name] = value
    result = plan.assemble(plan.Bundle(write_bundle(tmp_path / "bundle", found)), decisions())
    seen = statuses(result)
    assert seen[item] == status
    assert [key for key, state in seen.items() if state != "met"] == [item]


@pytest.mark.parametrize(
    "failure, status",
    [
        (None, "unmet"),  # the lookup succeeded: the role exists
        ((254, "An error occurred (AccessDenied) when calling the GetRole operation"), "unknown"),
        ((255, "Could not connect to the endpoint URL"), "unknown"),
    ],
)
def test_only_iams_own_not_found_means_no_operator_role(tmp_path, failure, status):
    found = answers()
    found["12-iam-operator-role"] = {"Role": {"RoleName": "sentry-staging-operator"}}
    failures = {"12-iam-operator-role": failure or (0, "")}
    root = write_bundle(tmp_path / "bundle", found, failures=failures)
    assert statuses(plan.assemble(plan.Bundle(root), decisions()))["operator_role"] == status


def test_a_failed_read_is_unknown_never_met(tmp_path):
    failures = {name: (255, "AccessDenied") for name in plan.READS[1:11]}
    root = write_bundle(tmp_path / "bundle", failures=failures)
    seen = statuses(plan.assemble(plan.Bundle(root), decisions()))
    assert {key for key, state in seen.items() if state == "met"} == {
        "identity", "operator_role", "prices"
    }  # fmt: skip
    assert "unmet" not in seen.values()


def test_another_prefix_than_the_one_inspected_is_unknown(tmp_path):
    root = write_bundle(tmp_path / "bundle")
    seen = statuses(plan.assemble(plan.Bundle(root), decisions(name_prefix="other-staging")))
    assert {seen[key] for key in ("repositories", "log_groups", "secrets", "cluster",
                                  "operator_role")} == {"unknown"}  # fmt: skip


@pytest.mark.parametrize(
    "changes, message",
    [
        ({"account_id": "999999999999"}, "another account"),
        ({"region": "us-west-2", "availability_zones": ["us-west-2a", "us-west-2b"]},
         "another region"),
        ({"account_id": "12345"}, "12-digit"),
        ({"name_prefix": "staging"}, "name_prefix"),
        ({"availability_zones": ["us-east-1a", "us-east-1a"]}, "two distinct zones"),
        ({"availability_zones": ["us-west-2a", "us-west-2b"]}, "two distinct zones"),
        ({"vpc_cidr": "10.96.0.1/20"}, "aligned RFC 1918"),
        ({"vpc_cidr": "8.8.8.0/24"}, "aligned RFC 1918"),
        ({"vpc_cidr": "10.0.0.0/8"}, "aligned RFC 1918"),
        ({"private_dns_namespace": "internal"}, "multi-label"),
        ({"postgres_engine_version": "17.2"}, "16.x"),
        ({"operator_trust": {"principal_arn": f"arn:aws:iam::{ACCOUNT}:root",
                             "external_id": "fixture-external-id-0001",
                             "session_seconds": 14400}}, "one IAM user or role"),
        ({"operator_trust": {"principal_arn": f"arn:aws:iam::{ACCOUNT}:role/issuer",
                             "external_id": "short", "session_seconds": 14400}}, "external_id"),
        ({"operator_trust": {"principal_arn": f"arn:aws:iam::{ACCOUNT}:role/issuer",
                             "external_id": "fixture-external-id-0001",
                             "session_seconds": 86400}}, "session_seconds"),
        ({"operator": None}, "needs an operator"),
        ({"notifications": {"email": "not-an-address", "monthly_budget_usd": 200}}, "one address"),
        ({"notifications": {"email": "a@example.com", "monthly_budget_usd": 0}}, "whole dollars"),
        ({"spend_cap": 100}, "unknown keys"),
    ],
)  # fmt: skip
def test_decisions_that_break_a_roots_rules_or_name_another_account_are_refused(
    tmp_path, changes, message
):
    bundle = plan.Bundle(write_bundle(tmp_path / "bundle"))
    with pytest.raises(plan.Unusable, match=message):
        plan.assemble(bundle, decisions(**changes))


def test_optional_inputs_left_out_are_listed_as_pending_not_invented(tmp_path):
    bundle = plan.Bundle(write_bundle(tmp_path / "bundle"))
    result = plan.assemble(bundle, decisions(operator=None, operator_trust=None,
                                             notifications=None))  # fmt: skip
    assert "operator_trust" not in result["inputs"]["bootstrap"]
    assert "notifications" not in result["inputs"]["foundation"]
    assert "operator_trust" in result["pending_inputs"]["bootstrap"]
    assert "notifications" in result["pending_inputs"]["foundation"]
    assert result["manifest_skeleton"]["operator"] == "TBD(the named operator)"


def test_the_plan_hash_covers_the_inputs_the_bundle_and_the_decisions(tmp_path):
    bundle = plan.Bundle(write_bundle(tmp_path / "bundle"))
    first = plan.assemble(bundle, decisions())
    assert first["plan_sha256"] == plan.assemble(bundle, copy.deepcopy(decisions()))["plan_sha256"]
    assert (
        first["plan_sha256"]
        != plan.assemble(bundle, decisions(vpc_cidr="172.24.0.0/20"))["plan_sha256"]
    )
    assert first["plan_sha256"] != plan.assemble(bundle, decisions(lifetime_days=14))["plan_sha256"]
    found = answers()
    found["13-budgets"] = {"Budgets": [{"BudgetName": "existing"}]}
    other = plan.Bundle(write_bundle(tmp_path / "other", found))
    assert first["plan_sha256"] != plan.assemble(other, decisions())["plan_sha256"]


def test_the_skeleton_names_this_accounts_identities_and_is_not_yet_a_manifest(tmp_path):
    bundle = plan.Bundle(write_bundle(tmp_path / "bundle"))
    skeleton = plan.assemble(bundle, decisions())["manifest_skeleton"]
    assert skeleton["schema_version"] == 2 and skeleton["purpose"] == {"kind": "forward"}
    assert skeleton["environment"] == {
        "name": PREFIX, "account_id": ACCOUNT, "region": REGION,
        "cluster_arn": f"arn:aws:ecs:{REGION}:{ACCOUNT}:cluster/{PREFIX}",
        "services": {name: f"arn:aws:ecs:{REGION}:{ACCOUNT}:service/{PREFIX}/{PREFIX}-{name}"
                     for name in ("runtime", "api", "worker")},
    }  # fmt: skip
    assert skeleton["operator_role"] == f"arn:aws:iam::{ACCOUNT}:role/{PREFIX}-operator"
    assert skeleton["operator"] == "fixture-operator"
    pending = [key for key, value in skeleton.items()
               if isinstance(value, str) and value.startswith("TBD(")]  # fmt: skip
    assert pending == ["release_id", "window", "sources", "images", "risk", "plan_sha256",
                       "services", "jobs", "operational_checks"]  # fmt: skip
    # Its keys are exactly a schema-2 manifest's, and it cannot be mistaken for one.
    from tests.release_fakes import forward_document

    assert set(skeleton) == set(forward_document())
    with pytest.raises(ReleaseRejected):
        load_manifest(json.dumps(skeleton).encode())


# The emitted inputs against the real roots -------------------------------------------

TERRAFORM = os.environ.get("ACCOUNT_PLAN_TERRAFORM", "")
PLUGINS = os.environ.get("ACCOUNT_PLAN_TERRAFORM_PLUGIN_DIR", "")
PENDING_FIXTURES = {
    "bootstrap": "",
    "foundation": "",
    # Inputs a later apply produces: the roots' own test fixtures stand in for them.
    "releases": "releases",
    "services": "task_subnet_ids security_group_ids discovery_service_arns task_definition_arns",
}


def fixture_variables(root: str, names: str) -> str:
    """The named variables' blocks from the root's own test file."""
    if not names:
        return ""
    text = (REPO / "deploy/aws-staging" / root / "tests" / f"{root}.tftest.hcl").read_text()
    start = text.index("\nvariables {\n") + 1
    depth, end = 0, start
    for end, char in enumerate(text[start:], start):
        depth += (char == "{") - (char == "}")
        if char == "}" and depth == 0:
            break
    body, kept, keep, depth = text[start:end].splitlines()[1:], [], False, 0
    for line in body:
        if depth == 0:
            keep = line.split("=")[0].strip() in names.split()
        depth += line.count("{") + line.count("[") - line.count("}") - line.count("]")
        if keep:
            kept.append(line)
    return "variables {\n" + "\n".join(kept) + "\n}\n"


@pytest.mark.skipif(not (TERRAFORM and PLUGINS), reason="needs ACCOUNT_PLAN_TERRAFORM and "
                    "ACCOUNT_PLAN_TERRAFORM_PLUGIN_DIR (a pinned binary and a provider mirror)")  # fmt: skip
@pytest.mark.parametrize("root", plan.ROOTS)
def test_the_emitted_inputs_pass_each_roots_own_variable_validation(tmp_path, monkeypatch, root):
    monkeypatch.undo()  # Terraform runs as a subprocess; this process still opens no socket.
    bundle = plan.Bundle(write_bundle(tmp_path / "bundle"))
    out = tmp_path / "out"
    plan.write_outputs(plan.assemble(bundle, decisions()), out)
    work = tmp_path / "deploy"
    shutil.copytree(REPO / "deploy", work, ignore=shutil.ignore_patterns(".terraform", "tests"))
    directory = work / "aws-staging" / root
    (directory / "tests").mkdir()
    (directory / "tests" / "account_inputs.tftest.hcl").write_text(
        'mock_provider "aws" {}\n' + fixture_variables(root, PENDING_FIXTURES[root])
        + 'run "assembled_account_inputs_are_accepted" {\n  command = plan\n}\n'
    )  # fmt: skip
    env = {"HOME": str(tmp_path / "home"), "PATH": "/usr/bin:/bin", "TF_IN_AUTOMATION": "1",
           "CHECKPOINT_DISABLE": "1"}  # fmt: skip
    for arguments in (
        ["init", "-backend=false", "-input=false", "-lockfile=readonly", f"-plugin-dir={PLUGINS}"],
        ["validate", "-no-color"],
        ["test", "-no-color", f"-var-file={out / root / 'account.auto.tfvars.json'}"],
    ):
        result = subprocess.run([TERRAFORM, *arguments], cwd=directory, env=env, text=True,
                                capture_output=True, timeout=600)  # fmt: skip
        assert result.returncode == 0, result.stdout + result.stderr
    assert "1 passed, 0 failed" in result.stdout
