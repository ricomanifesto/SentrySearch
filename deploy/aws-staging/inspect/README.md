# Read-only account inspection

`aws-07a-inspect.sh` reads the facts a staging plan depends on from the account
and region you choose, and saves them as a bundle of files with a manifest. It
does not create, change or delete anything, and it is the only step here that
touches an AWS account. You run it yourself, in a terminal where you have
authenticated the profile; nothing else in this repository runs it for you.

```bash
deploy/aws-staging/inspect/aws-07a-inspect.sh --profile <profile> --region <region>
```

- `--profile` is the AWS CLI profile you authenticated. Only that profile
  supplies credentials: each call runs the CLI in a new environment that holds
  `HOME`, `PATH`, the locale, time zone and temporary-directory variables and
  nothing else. No inherited `AWS_*` setting reaches it (credentials, profile,
  region, endpoints, config-file locations, CA bundle), and neither does a
  proxy variable. The profile therefore has to live in the default
  `~/.aws/config`, and a profile that needs a proxy will fail here.
- `--region` is the commercial region to inspect, for example `us-east-1`.
- `--out <directory>` is optional. The default is
  `~/Documents/Codex/<UTC date>/aws-07a-inspection/`. The script refuses a
  directory that is not empty, so an earlier bundle is never overwritten.
- `--list` prints every command it would send and exits without sending any.

When it finishes it prints the bundle's location and the SHA-256 of
`manifest.json`. Keep that line: it is the only record of the manifest that does
not sit in the bundle itself.

It needs `bash`, the AWS CLI and `shasum` or `sha256sum`. It works with the
bash 3.2 that ships with macOS.

## What it reads

Eighteen commands, in this order. `--list` prints their exact arguments.

| # | Reads | Used to check |
| --- | --- | --- |
| 01 | `sts get-caller-identity` | this is the intended account; nothing else runs if it fails |
| 02 | `ec2 describe-availability-zones` | two zones are available |
| 03 | `rds describe-db-engine-versions` (PostgreSQL 16) | a 16.x minor exists |
| 04 | `rds describe-orderable-db-instance-options` (`db.t4g.micro`) | that minor supports the instance class with gp3 |
| 05 | `service-quotas list-service-quotas` (Fargate) | Fargate quota covers three small services and one job |
| 06 | `service-quotas list-service-quotas` (VPC endpoints) | endpoint quotas cover four interface endpoints and one gateway |
| 07 | `ec2 describe-vpcs` | the planned range overlaps no range of an existing VPC, first or associated later |
| 08 | `ecr describe-repositories` | no `sentry-staging/` repository exists yet |
| 09 | `logs describe-log-groups` | no `/sentry-staging/` log group exists yet |
| 10 | `secretsmanager list-secrets` | no `sentry-staging/` secret exists yet (names only, never values) |
| 11 | `ecs list-clusters` | no `sentry-staging` cluster exists yet |
| 12 | `iam get-role` (`sentry-staging-operator`) | no operator role exists yet; "not found" is the expected answer |
| 13 | `budgets describe-budgets` | existing budgets, for the spend review |
| 14–18 | `pricing get-products` for VPC endpoints, RDS instance and storage, Fargate and Secrets Manager | current public prices for the plan's four priced services |

Prices come from the Price List endpoint in `us-east-1` and are filtered by the
region's location name. The script knows that name for `us-east-1`, `us-east-2`
and `us-west-2`; for any other region it skips the five price queries and says
so in the manifest.

## What it writes

```text
<out>/manifest.json                 what ran: command text, exit code, SHA-256 of each file
<out>/NN-<name>.json                each command's answer, exactly as the CLI printed it
<out>/NN-<name>.stderr.txt          each command's error output (usually empty)
```

The directory is created owner-only. It holds account identifiers, VPC ranges
and resource names, but no credential and no secret value. A command that fails
is recorded with its exit code and the run continues; only a failed identity
check stops it. The manifest also records the SHA-256 of the script that ran.

## From a bundle to account inputs

`dev/assemble_account_plan.py` reads a bundle offline: no AWS call, credential,
network or Terraform run. It first checks every file against the manifest's
hashes and refuses a bundle that does not verify, has a file the manifest does
not list, does not start with a successful identity check, or records an answer
under any command other than the read this kit runs for it. A bundle is never
repaired by hand.

```bash
python -m dev.assemble_account_plan verify   --bundle <bundle> --manifest-sha256 <printed hash>
python -m dev.assemble_account_plan draft    --bundle <bundle> --out decisions.json
python -m dev.assemble_account_plan assemble --bundle <bundle> --manifest-sha256 <printed hash> --decisions decisions.json --out <directory>
```

Those checks compare the bundle with its own manifest, so an answer and its
manifest entry edited together still pass them. `--manifest-sha256` closes that:
give it the hash the kit printed, and a manifest changed since then is refused.
Without it the plan reports "The manifest is the one the kit printed" as
`unknown`. The plan also reports whether the kit that wrote the bundle is the
one in this checkout, by the script hash the manifest records.

`draft` writes a `decisions.json` with what the inspection can suggest: the
inspected account and region, the first two zones, the highest PostgreSQL 16
minor orderable with gp3, and the first of four candidate ranges that overlaps
no existing VPC. The operator, the operator's trust and the alert recipient stay
`null` for a person to fill in, and so does `account_confirmed_by`. `basis`
says where each value came from. Edit the file freely; nothing in it is a
decision until someone confirms it.

| Key | Meaning |
| --- | --- |
| `account_id`, `region` | must equal the bundle's, or nothing is written |
| `account_confirmed_by` | who confirmed that the inspected account is the intended one; while `null`, that check is `unknown` |
| `name_prefix` | the environment prefix; the kit inspected `sentry-staging` |
| `availability_zones` | two zones of the region |
| `vpc_cidr` | an aligned RFC 1918 network between /16 and /24 |
| `private_dns_namespace` | the private name the Runtime certificate is issued for |
| `postgres_engine_version` | an exact 16.x minor |
| `operator`, `operator_trust` | the release operator and the principal that issues the operator role's sessions; optional |
| `notifications` | alert recipient and whole-dollar monthly review threshold; optional |
| `lifetime_days` | how long the environment is planned to live; 7 if omitted |
| `log_gb_month` | assumed monthly log volume in GB for the cost model: a number or a `[low, high]` pair; `[1, 10]` if omitted |
| `lifetime_crosses_month_boundary` | whether the run crosses into another calendar month (one more hosted-zone month); unknown if omitted, and then both figures are shown |

`assemble` applies the roots' own input rules to those values, then writes into
an empty directory:

- `<root>/account.auto.tfvars.json` for `bootstrap`, `foundation`, `releases`
  and `services`: exactly the inputs known before anything is applied. Inputs a
  later step produces (foundation outputs, pushed image digests, secret
  versions) are listed as pending, never invented.
- `manifest.skeleton.json`: a schema-2 first-deployment manifest with this
  account's cluster, service and operator-role identities, and `TBD(...)` for
  everything a later step supplies. It is not loadable as a manifest until
  those are filled.
- `account-plan.json` and `account-plan.md`: the checklist above with each item
  `met`, `unmet` or `unknown` and what was seen; the price table with the
  estimate's rates beside the bundle's; the pending inputs; and `plan_sha256`,
  one hash over the inputs, the skeleton, the bundle's manifest and the
  decisions.

A check is `unknown` whenever its answer is missing, failed or unreadable; a
failed read is never counted as "nothing found". The operator role counts as
absent only when IAM itself answered `NoSuchEntity`. A price is refreshed only
when the bundle holds exactly one positive price for that rate; otherwise the
rate is `unknown` and the estimate's value is kept in the refreshed column.

`tests/test_assemble_account_plan.py` builds synthetic bundles and runs with
sockets refused. With `ACCOUNT_PLAN_TERRAFORM` (a pinned Terraform binary) and
`ACCOUNT_PLAN_TERRAFORM_PLUGIN_DIR` (a provider mirror) set, it also plans each
root with a mocked provider and the emitted file as `-var-file`, so the roots'
own variable validation judges the emitted values.

## Why it can only read

The commands are a fixed list inside the script. Before it parses its
arguments, and so before it can send anything, the script checks every listed
command and exits if any one:

- is not a `get-`, `describe-` or `list-` operation;
- has a word in its operation name that names a change (`create`, `delete`,
  `put`, `update`, `run`, `attach` and the rest of the list in the script);
- carries any option other than the eight the listed commands use (`--filters`,
  `--query`, `--engine`, `--db-instance-class`, `--service-code`,
  `--log-group-name-prefix`, `--role-name`, `--account-id`), spelled exactly.
  So nothing that could redirect the request, read a local file, weaken TLS or
  change the credentials gets through, joined to its value or not
  (`--endpoint-url`, `--endpoint-url=...`, `--no-verify-ssl`,
  `--cli-input-json`, `--profile`, `--debug`);
- carries a `file://` or URL value.

The identity check must also be the first command. There is no flag that adds
a command, and the same check runs again on each command immediately before it
is sent. This limits what the script asks for; what the profile is allowed to
do is still decided by its IAM policy, so a read-only policy is the stronger
guarantee.

## Tests

`tests/test_aws_inspection_kit.py` runs the script against a recording stand-in
for the AWS CLI, with no network and no credentials. It checks the exact
commands and their order, the whole environment the CLI receives, the manifest,
its hashes and the printed manifest hash, the refusal of eighteen altered
allowlists before anything is sent, a failed identity check, argument checking,
and `bash -n` and `shellcheck`.

The script has not been run against an AWS account. The price queries' filters
and the shape of their answers are written from the Price List API's
documentation and are unverified until a real bundle exists.
