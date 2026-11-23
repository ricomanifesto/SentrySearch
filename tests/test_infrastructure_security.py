"""Offline security contracts for infrastructure source and deployment tooling."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class InfrastructureSourceTests(unittest.TestCase):
    def test_database_has_no_implicit_public_network(self) -> None:
        main = (ROOT / "terraform/main.tf").read_text()
        variables = (ROOT / "terraform/variables.tf").read_text()
        self.assertRegex(main, r"publicly_accessible\s*=\s*false")
        self.assertNotIn('cidr_blocks = ["0.0.0.0/0"]', main)
        self.assertNotIn('data "aws_vpc" "default"', main)
        self.assertIn("vpc_id      = var.database_vpc_id", main)
        self.assertIn("subnet_ids = var.database_subnet_ids", main)
        self.assertIn("ingress = [for group_id in var.database_client_security_group_ids", main)
        for name in ("database_vpc_id", "database_subnet_ids"):
            block = variables.split(f'variable "{name}" {{', 1)[1].split("\n}", 1)[0]
            self.assertNotIn("default", block)

    def test_deletion_requires_protection_and_a_named_final_snapshot(self) -> None:
        main = (ROOT / "terraform/main.tf").read_text()
        variables = (ROOT / "terraform/variables.tf").read_text()
        self.assertRegex(main, r"deletion_protection\s*=\s*var.enable_deletion_protection")
        self.assertRegex(main, r"skip_final_snapshot\s*=\s*false")
        self.assertRegex(main, r"final_snapshot_identifier\s*=\s*var.db_final_snapshot_identifier")
        protection = variables.split('variable "enable_deletion_protection" {', 1)[1]
        self.assertRegex(protection.split("\n}", 1)[0], r"default\s*=\s*true")
        self.assertIn('variable "db_final_snapshot_identifier"', variables)

    def test_wildcard_permissions_are_read_only(self) -> None:
        policy = json.loads((ROOT / "terraform/terraform-permissions.json").read_text())
        wildcard_actions = set()
        for statement in policy["Statement"]:
            resources = statement["Resource"]
            resources = [resources] if isinstance(resources, str) else resources
            if "*" in resources:
                wildcard_actions.update(statement["Action"])
        self.assertEqual(
            wildcard_actions,
            {
                "ec2:DescribeVpcs",
                "ec2:DescribeSubnets",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeAvailabilityZones",
                "rds:DescribeDBInstances",
                "rds:DescribeDBSubnetGroups",
                "logs:DescribeLogGroups",
            },
        )
        for statement in policy["Statement"]:
            if "iam:PassRole" in statement["Action"]:
                self.assertEqual(
                    statement["Condition"]["StringEquals"]["iam:PassedToService"],
                    "monitoring.rds.amazonaws.com",
                )
            if "ec2:DeleteSecurityGroup" in statement["Action"]:
                self.assertEqual(
                    statement["Condition"]["StringEquals"]["aws:ResourceTag/Project"],
                    "sentrysearch",
                )

    def test_monitoring_role_deletion_can_read_instance_profiles(self) -> None:
        # deleteRole lists profiles even when none are attached:
        # https://github.com/hashicorp/terraform-provider-aws/blob/v5.100.0/internal/service/iam/role.go#L520-L580
        policy = json.loads((ROOT / "terraform/terraform-permissions.json").read_text())
        role = next(s for s in policy["Statement"] if s["Sid"] == "MonitoringRoleManagement")
        self.assertIn("iam:ListInstanceProfilesForRole", role["Action"])
        self.assertEqual(
            role["Resource"], "arn:aws:iam::<ACCOUNT_ID>:role/sentrysearch-rds-monitoring-role"
        )
        all_actions = {
            action for statement in policy["Statement"] for action in statement["Action"]
        }
        self.assertNotIn("iam:RemoveRoleFromInstanceProfile", all_actions)
        self.assertNotIn("iam:DeleteInstanceProfile", all_actions)

    def test_bucket_refresh_reads_remain_bucket_scoped(self) -> None:
        # AWS provider v5.100.0 reads these even when their settings are omitted:
        # https://github.com/hashicorp/terraform-provider-aws/blob/v5.100.0/internal/service/s3/bucket.go#L783-L1141
        # HeadBucket -> ListBucket; helper API names map to the IAM actions below.
        refresh_reads = {
            "s3:ListBucket",
            "s3:GetBucketPolicy",
            "s3:GetBucketAcl",
            "s3:GetBucketCORS",
            "s3:GetBucketWebsite",
            "s3:GetBucketVersioning",
            "s3:GetAccelerateConfiguration",
            "s3:GetBucketRequestPayment",
            "s3:GetBucketLogging",
            "s3:GetLifecycleConfiguration",
            "s3:GetReplicationConfiguration",
            "s3:GetEncryptionConfiguration",
            "s3:GetBucketObjectLockConfiguration",
            "s3:GetBucketLocation",
            "s3:GetBucketTagging",
        }
        policy = json.loads((ROOT / "terraform/terraform-permissions.json").read_text())
        bucket = next(s for s in policy["Statement"] if s["Sid"] == "ReportBucketManagement")
        self.assertTrue(
            refresh_reads <= set(bucket["Action"]), refresh_reads - set(bucket["Action"])
        )
        self.assertEqual(bucket["Resource"], "arn:aws:s3:::sentrysearch-reports-*")
        for statement in policy["Statement"]:
            for action in statement["Action"]:
                if action.startswith("s3:"):
                    self.assertEqual(statement["Resource"], bucket["Resource"])
                    self.assertNotIn("*", action)
                    self.assertNotIn(action, {"s3:GetObject", "s3:PutObject", "s3:DeleteObject"})

    def test_vercel_uses_the_committed_lockfile(self) -> None:
        config = json.loads((ROOT / "vercel.json").read_text())
        self.assertEqual(config["installCommand"], "npm ci")
        self.assertTrue((ROOT / "frontend/package-lock.json").is_file())

    def test_elan_release_is_verified_before_it_is_executed(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        install = workflow.split("      - name: Install elan\n", 1)[1].split("      - name:", 1)[0]
        self.assertIn("releases/download/v4.2.4/elan-x86_64-unknown-linux-gnu.tar.gz", install)
        self.assertIn("42b94d4244e8353142c456ec0e4ca6528fd898a6c604d4059f494e706e431f63", install)
        self.assertLess(install.index("sha256sum --check"), install.index("tar -xzf"))
        self.assertLess(install.index("tar -xzf"), install.index('"$elan_dir/elan-init"'))
        self.assertNotIn("elan-init.sh", install)


class DeployScriptTests(unittest.TestCase):
    def run_deploy(self, failure: str = "", answer: str = "y\n") -> tuple:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            module = base / "module"
            module.mkdir()
            shutil.copy(ROOT / "terraform/deploy.sh", module / "deploy.sh")
            (module / "terraform.tfvars").write_text(
                'aws_region = "us-east-1"\nproject_name = "sentrysearch"\n'
            )
            tools = base / "bin"
            tools.mkdir()
            mock = tools / "terraform"
            mock.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, pathlib, stat, sys\n"
                "args = sys.argv[1:]\n"
                "record = {'args': args, 'cwd': os.getcwd()}\n"
                "if args[0] == 'plan':\n"
                "    plan = pathlib.Path(next(a[5:] for a in args if a.startswith('-out=')))\n"
                "    plan.write_text('sensitive-plan-fixture')\n"
                "    record.update(plan=str(plan.resolve()), mode=stat.S_IMODE(plan.stat().st_mode), directory_mode=stat.S_IMODE(plan.parent.stat().st_mode))\n"
                "with open(os.environ['MOCK_CALLS'], 'a') as f:\n"
                "    f.write(json.dumps(record) + '\\n')\n"
                "if args[0] == 'plan':\n"
                "    print('reviewed-plan-marker')\n"
                "if args[0] == 'apply':\n"
                "    print('apply-marker')\n"
                "if args[0] == 'output':\n"
                "    print('credential-output-sentinel' if args[-1] == 'aws_secret_access_key' else '{}')\n"
                "sys.exit(19 if args[0] == os.environ.get('MOCK_FAIL_COMMAND') else 0)\n"
            )
            mock.chmod(0o700)
            aws = tools / "aws"
            aws.write_text("#!/bin/sh\nprintf '{}\\n'\n")
            aws.chmod(0o700)
            calls = base / "calls.jsonl"
            env = os.environ.copy()
            env.update(
                PATH=f"{tools}:{os.environ['PATH']}",
                TF_VAR_db_password="password-fixture-do-not-print",
                MOCK_CALLS=str(calls),
                MOCK_FAIL_COMMAND=failure,
                TMPDIR=str(base),
            )
            result = subprocess.run(
                ["bash", "-x", str(module / "deploy.sh")],
                input=answer,
                text=True,
                capture_output=True,
                cwd=module,
                env=env,
                check=False,
            )
            recorded = [json.loads(line) for line in calls.read_text().splitlines()]
            plans = [record for record in recorded if record["args"][0] == "plan"]
            plan = plans[0]
            plan_removed = not Path(plan["plan"]).exists()
            return result, recorded, plan, plan_removed

    def test_success_never_prints_credentials_and_removes_private_plan(self) -> None:
        result, calls, plan, removed = self.run_deploy()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("credential-output-sentinel", result.stdout + result.stderr)
        self.assertNotIn("password-fixture-do-not-print", result.stdout + result.stderr)
        self.assertEqual(plan["mode"], 0o600)
        self.assertEqual(plan["directory_mode"], 0o700)
        self.assertTrue(removed)
        self.assertTrue(any(call["args"][0] == "apply" for call in calls))
        self.assertLess(
            result.stdout.index("reviewed-plan-marker"),
            result.stdout.index("Apply this reviewed plan"),
        )
        self.assertLess(
            result.stdout.index("Apply this reviewed plan"), result.stdout.index("apply-marker")
        )

    def test_plan_and_apply_failures_remove_saved_plan(self) -> None:
        for command in ("plan", "apply"):
            with self.subTest(command=command):
                result, calls, _, removed = self.run_deploy(failure=command)
                self.assertEqual(result.returncode, 19)
                self.assertTrue(removed)
                if command == "plan":
                    self.assertFalse(any(call["args"][0] == "apply" for call in calls))

    def test_declining_reviewed_plan_never_applies(self) -> None:
        result, calls, _, removed = self.run_deploy(answer="n\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call["args"][0] == "apply" for call in calls))
        self.assertTrue(removed)


if __name__ == "__main__":
    unittest.main()
