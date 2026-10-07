"""Static guards for staging Terraform contracts that a mocked plan cannot show.

Backend settings, lifecycle meta-arguments and absent resource types are not
visible in ``terraform test`` plans. These checks read the formatted sources
without running Terraform, contacting AWS or reading any state.
"""

import re
from pathlib import Path

import pytest

from release.ports import EcsPort, EvidencePort, LogPort
from release.readiness import WORKER_CONTAINER, WORKER_LOG_STREAM_PREFIX, worker_stream
from src.execution.readiness_receipts import release_id_from_environment

DEPLOY = Path(__file__).resolve().parents[1] / "deploy"
STAGING = DEPLOY / "aws-staging"
ROOTS = ("bootstrap", "foundation", "releases", "services")
REMOTE_ROOTS = ("foundation", "releases", "services")
TASK_MODULE = DEPLOY / "aws-platform-fit"
REVIEWED_DEFAULTS = {"rds_ca_identifier", "log_retention_days", "report_retention_days"}
# Resource types (regular expressions) with no place in the private staging roots.
FORBIDDEN_RESOURCES = (
    r"aws_internet_gateway\w*",
    r"aws_egress_only_internet_gateway",
    r"aws_nat_gateway",
    r"aws_eip\w*",
    r"aws_route",
    r"aws_vpc_peering_connection\w*",
    r"aws_ec2_transit_gateway\w*",
    r"aws_vpn_\w+",
    r"aws_customer_gateway",
    r"aws_ec2_client_vpn_\w+",
    r"aws_vpc_ipv6_cidr_block_association",
    r"aws_instance",
    r"aws_network_interface\w*",
    r"aws_lb\w*",
    r"aws_alb\w*",
    r"aws_appautoscaling_\w+",
    r"aws_service_discovery_public_dns_namespace",
    r"aws_route53_zone",
    r"aws_secretsmanager_secret_version",
    r"aws_dynamodb_table",
    r"aws_iam_user\w*",
    r"aws_iam_access_key",
    r"aws_ecr_lifecycle_policy",
    r"aws_security_group_rule",
)
FORBIDDEN_SETTINGS = (
    r"password",
    r"password_wo",
    r"secret_string",
    r"secret_binary",
    r"dynamodb_table",
    r"cidr_ipv4",
    r"cidr_ipv6",
    r"cidr_blocks",
    r"associate_public_ip_address",
    r"execute_command_configuration",
    r"ipv6_cidr_block",
    r"map_public_ip_on_launch\s*=\s*true",
    r"assign_public_ip\s*=\s*true",
    r"assign_generated_ipv6_cidr_block\s*=\s*true",
    r"enable_execute_command\s*=\s*true",
    r"publicly_accessible\s*=\s*true",
    r"force_destroy\s*=\s*true",
    r"force_delete\s*=\s*true",
    r"skip_final_snapshot\s*=\s*true",
    r"deletion_protection\s*=\s*false",
    r"prevent_destroy\s*=\s*false",
    r"skip_destroy\s*=\s*false",
)


def configuration(directory: Path) -> str:
    return "\n".join(path.read_text() for path in sorted(directory.glob("*.tf")))


def all_configuration() -> str:
    directories = [STAGING / root for root in ROOTS] + [STAGING / "modules" / "naming", TASK_MODULE]
    return "\n".join(configuration(directory) for directory in directories)


def code_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if not line.lstrip().startswith(("#", "//"))]


def block(text: str, header: str) -> str:
    """Return the body of the block opened by ``header {`` (terraform fmt layout)."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.strip() == f"{header.strip()} {{":
            closing = line[: len(line) - len(line.lstrip())] + "}"
            body: list[str] = []
            for inner in lines[index + 1 :]:
                if inner == closing:
                    return "\n".join(body)
                body.append(inner)
    raise AssertionError(f"missing block: {header}")


def settings(body: str) -> dict[str, str]:
    """``name = value`` lines at a block body's own indentation, excluding nested blocks."""
    lines = [line for line in body.splitlines() if line.strip()]
    indent = min(len(line) - len(line.lstrip()) for line in lines)
    pairs = (re.fullmatch(rf" {{{indent}}}([a-z_]+)\s*=\s*(.+)", line) for line in lines)
    return {match[1]: match[2] for match in pairs if match}


@pytest.mark.parametrize("root", ROOTS)
def test_roots_pin_terraform_provider_and_lockfile(root):
    text = configuration(STAGING / root)
    assert 'required_version = ">= 1.16.5, < 1.17.0"' in text
    assert re.search(r'source\s*=\s*"hashicorp/aws"\n\s*version\s*=\s*"6\.65\.0"', text)
    lock = (STAGING / root / ".terraform.lock.hcl").read_text()
    assert 'version     = "6.65.0"' in lock
    assert len(re.findall(r'"h1:', lock)) >= 4


@pytest.mark.parametrize("root", REMOTE_ROOTS)
def test_environment_roots_use_native_s3_lockfile_backend(root):
    text = configuration(STAGING / root)
    assert settings(block(text, 'backend "s3"')) == {
        "key": f'"state/{root}.tfstate"',
        "encrypt": "true",
        "use_lockfile": "true",
    }
    assert "dynamodb" not in text


def test_bootstrap_state_starts_local():
    text = configuration(STAGING / "bootstrap")
    assert '  backend "local" {}' in text
    assert 'backend "s3"' not in text


@pytest.mark.parametrize("root", ROOTS)
def test_root_provider_guards_the_explicit_account(root):
    assert settings(block(configuration(STAGING / root), 'provider "aws"')) == {
        "region": "var.region",
        "allowed_account_ids": "[var.account_id]",
    }


def test_reusable_modules_leave_provider_configuration_to_roots():
    for directory in (TASK_MODULE, STAGING / "modules" / "naming"):
        assert 'provider "aws"' not in configuration(directory)


@pytest.mark.parametrize("root", ROOTS)
def test_only_reviewed_tunables_have_defaults(root):
    text = configuration(STAGING / root)
    for name in re.findall(r'^variable "([a-z_]+)" \{$', text, re.MULTILINE):
        if "default" in settings(block(text, f'variable "{name}"')):
            assert name in REVIEWED_DEFAULTS, name


def test_no_lookups_internet_paths_secret_values_or_unreviewed_services():
    text = all_configuration()
    assert not re.search(r'^data "', text, re.MULTILINE)
    for resource in FORBIDDEN_RESOURCES:
        assert not re.search(rf'^resource "{resource}" ', text, re.MULTILINE), resource
    for line in code_lines(text):
        for pattern in FORBIDDEN_SETTINGS:
            assert not re.match(rf"\s*{pattern}\b", line), line


@pytest.mark.parametrize(
    ("root", "header"),
    [
        ("bootstrap", 'resource "aws_s3_bucket" "control"'),
        ("foundation", 'resource "aws_s3_bucket" "reports"'),
        ("foundation", 'resource "aws_db_instance" "this"'),
        ("foundation", 'resource "aws_ecr_repository" "this"'),
    ],
)
def test_state_and_data_resources_prevent_destroy(root, header):
    resource = block(configuration(STAGING / root), header)
    assert block(resource, "lifecycle").strip() == "prevent_destroy = true"


@pytest.mark.parametrize(
    "header",
    [
        f'resource "{kind}" "{name}"'
        for kind in ("aws_iam_role", "aws_iam_role_policy")
        for name in ("task", "execution", "release_task", "release_execution", "tools_execution")
    ]
    + [
        'resource "aws_ecs_task_definition" "service"',
        'resource "aws_ecs_task_definition" "release"',
        'resource "aws_ecs_task_definition" "tools"',
    ],
)
def test_retained_release_identities_and_revisions_cannot_be_replaced(header):
    resource = block(configuration(TASK_MODULE), header)
    assert block(resource, "lifecycle").strip() == "prevent_destroy = true"
    if "aws_ecs_task_definition" in header:
        assert "skip_destroy" in settings(resource)


def test_release_controller_alone_owns_service_revision_and_count():
    services = block(configuration(STAGING / "services"), 'resource "aws_ecs_service" "this"')
    assert re.search(r"^  desired_count\s+= 0$", services, re.MULTILINE)
    assert block(services, "lifecycle").strip() == (
        "ignore_changes = [task_definition, desired_count]"
    )
    assert all_configuration().count("ignore_changes") == 1


@pytest.mark.parametrize(
    "header",
    [
        'resource "aws_route_table" "task"',
        'resource "aws_route_table" "db"',
        'resource "aws_default_route_table" "this"',
    ],
)
def test_route_tables_pin_empty_routes_and_propagation(header):
    # Mocked plans fill unset computed attributes, so pin the configuration itself.
    table = settings(block(configuration(STAGING / "foundation"), header))
    assert table["route"] == "[]"
    assert table["propagating_vgws"] == "[]"


def test_security_group_rules_are_only_the_reviewed_pairs():
    text = configuration(STAGING / "foundation")
    group = block(text, 'resource "aws_security_group" "this"')
    assert not re.search(r"^\s+(ingress|egress)\b", group, re.MULTILINE)
    rules = re.findall(r'^resource "(aws_vpc_security_group_\w+_rule)" "(\w+)"', text, re.MULTILINE)
    assert sorted(rules) == [
        ("aws_vpc_security_group_egress_rule", "peer"),
        ("aws_vpc_security_group_egress_rule", "s3"),
        ("aws_vpc_security_group_ingress_rule", "peer"),
    ]


@pytest.mark.parametrize("directory", [STAGING / root for root in ROOTS] + [TASK_MODULE])
def test_contract_tests_are_mocked_plans(directory):
    tests = sorted((directory / "tests").glob("*.tftest.hcl"))
    assert tests
    for path in tests:
        text = path.read_text()
        assert text.startswith('mock_provider "aws" {}\n')
        assert not re.search(r"command\s*=\s*apply", text)
        assert text.count("\n  command = plan\n") == text.count('\nrun "') > 0


def test_local_state_plans_and_inputs_are_ignored():
    ignored = (STAGING / ".gitignore").read_text().splitlines()
    for pattern in (".terraform/", "*.tfstate", "*.tfstate.*", "*.tfplan", "*.tfvars"):
        assert pattern in ignored


# Each controller ECS call and the IAM actions it needs. RunTask carries release
# tags, so it also needs launch-time ecs:TagResource.
LAUNCHER_ACTIONS = {
    "run_task": ("ecs:RunTask", "ecs:TagResource", "iam:PassRole"),
    "describe_tasks": ("ecs:DescribeTasks",),
    "list_tasks": ("ecs:ListTasks",),
    "update_service": ("ecs:UpdateService", "iam:PassRole"),
    "describe_services": ("ecs:DescribeServices",),
    "stop_task": ("ecs:StopTask",),
}


# Job receipts are read from the observed task's own log stream. Runtime and API
# operational receipts still await their own observers; worker readiness is read
# through LogPort from the worker app container's stream.
EVIDENCE_ACTIONS = {"job_receipt": ("logs:GetLogEvents",), "operational_receipt": ()}
LOG_ACTIONS = {"get_log_events": ("logs:GetLogEvents",)}


def test_launcher_policy_covers_every_controller_ecs_call():
    """Tie each port call to the Allow set the mocked plan asserts on rendered policies."""
    assert {name for name in vars(EcsPort) if not name.startswith("_")} == set(LAUNCHER_ACTIONS)
    assert {name for name in vars(EvidencePort) if not name.startswith("_")} == set(
        EVIDENCE_ACTIONS
    )
    assert {name for name in vars(LogPort) if not name.startswith("_")} == set(LOG_ACTIONS)
    plan_test = (STAGING / "releases" / "tests" / "releases.tftest.hcl").read_text()
    allowed = re.search(
        r'statement\.Effect == "Allow"\]\]\)\) == toset\(\[(.*?)\]\)', plan_test, re.DOTALL
    )
    assert allowed
    asserted = set(re.findall(r'"([a-z]+:[A-Za-z]+)"', allowed[1]))
    assert asserted == {
        action
        for actions in (
            *LAUNCHER_ACTIONS.values(),
            *EVIDENCE_ACTIONS.values(),
            *LOG_ACTIONS.values(),
        )
        for action in actions
    }
    # Scale-to-zero updates omit taskDefinition; deploys must name a retained revision.
    services = block(configuration(STAGING / "releases"), "services =")
    assert (
        'ArnEqualsIfExists = { "ecs:task-definition" = local.service_revisions[name] }' in services
    )


def between(text: str, start: str, end: str) -> str:
    return text[text.index(start) : text.index(end, text.index(start))]


def test_readiness_observer_reads_the_worker_stream_terraform_configures():
    """The controller derives the stream; Terraform must configure exactly that one."""
    task_module = configuration(TASK_MODULE)
    naming = configuration(STAGING / "modules" / "naming")
    releases = configuration(STAGING / "releases")
    # awslogs names streams <prefix>/<container>/<task-id>; the prefix is the role key.
    assert WORKER_LOG_STREAM_PREFIX == "worker" and WORKER_CONTAINER == "app"
    assert re.search(r"^ +worker += \{ uid = ", task_module, re.MULTILINE)
    logs = between(task_module, "  log_configuration = {", "  task_contracts = {")
    assert "awslogs-stream-prefix = name\n" in logs
    app = between(task_module, "  task_contracts = {", "  assume_task_role =").split("},\n", 1)[1]
    assert f'name                   = "{WORKER_CONTAINER}"' in app
    # The group is the naming module's /<prefix>/worker; manifests name the prefix.
    assert 'name => "/${local.prefix}/${name}"' in block(naming, 'output "log_groups"')
    task = "arn:aws:ecs:us-east-1:111122223333:task/c/" + "a" * 32
    assert worker_stream("sentry-staging", task) == (
        "/sentry-staging/worker",
        "worker/app/" + "a" * 32,
    )
    stream = block(task_module, 'output "readiness_log_stream"')
    assert 'local.log_configuration.worker.options["awslogs-stream-prefix"]' in stream
    assert "local.task_contracts.worker[1].name" in stream
    assert "Resource = [local.current.readiness_log_stream]" in releases
    # The worker revision fixes the identity its supervisor reads, explicitly non-blocking.
    assert "{ SENTRYSEARCH_RELEASE_ID = var.release_id }" in task_module
    uuid = "0b9f7c1e-4d2a-4f6b-9a3e-2c1d0e9f8a7b"
    assert release_id_from_environment({"SENTRYSEARCH_RELEASE_ID": uuid}) == uuid
    assert 'worker_log_options = { mode = "non-blocking", max-buffer-size = "4m" }' in task_module
    assert "release_id          = each.value.release_id" in releases
