# AWS-07b: publication, apply and the first attended release

This is the operator's runbook for `python -m release_kits.aws_07b`. The kit runs
the staging deployment sequence one step at a time: the four Terraform roots, the
credential custodian's secrets, the image push, the launcher attachments, the
operator session, and the first attended release. **It has run only in
rehearsal** (moto stand-ins, a mocked Terraform provider and the container-backed
release fakes; see [Rehearsal](#rehearsal)). Nothing here has touched an AWS
account, and running any step against one is a separate approval for each step.

Every step:

1. re-verifies the account plan (`--plan` and the hash the assembler printed,
   `--plan-sha256`; the hash covers the inspection checklist) and the receipt
   chain in the work directory, whose newest receipt must be the one whose hash
   the last step printed (`--chain-head`);
2. refuses unless the step before it has a successful receipt;
3. prints its exact commands and the plan hash;
4. waits for you to type the step's identifier (anything else stops it and
   changes nothing; a step with a session first makes the read-only
   `GetCallerIdentity` check);
5. runs, and writes a receipt chained to the previous one, and prints that
   receipt's hash for the next command.

A step that fails after something ran (an SDK error, a refused plan, a partial
push) still writes a failed receipt: the kit's own reason, or only the error's
class for anything else, and what was already done (`partial`). A retry sends the
same requests again: the custodian's secret versions are fixed by plan, release
and purpose, so a secret this step already created is recognized by its version;
an image already stored at its digest counts once it reads back unchanged.
`detach` runs after any `attach` attempt, failed or not, and removes every policy
the attach step names wherever it is attached. A step whose receipt would hold a
secret value writes instead a failed receipt that keeps only the step's
description, commands and times, and the step fails with it: it prints `FAILED`
and that receipt's hash (the `--chain-head` for a retry), no next-command line,
and exits `3`.

Every value it uses (account, region, names, digests, ARNs, VersionIds) comes from
the plan or from an earlier receipt; you type only step identifiers. A step that
touches the account needs `--session FILE`: a session file in the release CLI's
format (`sentry.operator-session.v1`, mode 0400, outside any repository, session
name equal to the plan's operator). The kit never reads an environment variable,
profile, configuration file or instance metadata for credentials. Terraform runs
with an environment built from that file alone, with every other credential
source switched off.

## Before you start

- An account plan from the read-only inspection:
  `python -m dev.assemble_account_plan assemble --bundle B --decisions D --out PLAN`
  prints the plan hash. Every checklist item must be `met` (an unconfirmed
  account or unknown item stops the kit), and the decisions must name the
  operator and the operator trust.
- The verified image bindings of the build (`verified-image-bindings.json`): each
  image's local index, platform manifest, evidence hashes and the OCI archive
  the scan read, with its SHA-256.
- Your risk decision on the images' retained findings as a
  `sentry.risk-decision.v1` document (`decision_id`, `decided_by`, `decided_at`,
  `expires_at`, `retained_findings`, and `images` naming the three platform
  manifests). The kit records its hash in the manifest and decides nothing.
- The pinned Terraform 1.16.5 binary, a Runtime checkout that has the Runtime
  image's source commit, and this Search checkout at the reviewed head.
- A new, empty work directory outside any repository, mode 0700 (the kit refuses
  otherwise). It holds the receipts,
  rendered inputs, plan files, the bootstrap root's local state and logs. Keep it
  on an encrypted disk; it holds no secret value.

## Commands

```bash
python -m release_kits.aws_07b init --plan PLAN --plan-sha256 HASH --work WORK \
    --image-bindings BINDINGS --risk-decision RISK --runtime-checkout RUNTIME \
    --terraform /path/to/terraform-1.16.5 [--provider-canary PROVIDER_APPROVAL]
python -m release_kits.aws_07b status --plan PLAN --plan-sha256 HASH --work WORK
python -m release_kits.aws_07b step bootstrap --plan PLAN --plan-sha256 HASH --work WORK \
    --session DEPLOYER.json --chain-head LAST_RECEIPT_HASH
```

`init` fixes the release record before anything touches the account: a new
release UUID; the three images (each archive is read and its platform manifest
verified); the release-tools image's tools and SQL digests, read from the image
itself (`docker run --pull never --network none <index> digest`), which must
carry the reviewed Runtime grant pin; the Runtime schema (its migrations at the
image's source commit) and the product schema (version and migration checksum
at the Search image's source commit); the risk decision; and the fixed job
budgets, deadline, database identities and window.

`--provider-canary` is only for a capped real-provider canary. Its file is a
`sentry.provider-canary-approval.v1` document naming `plan_sha256`, the image
bindings' `image_bindings_sha256`, `decided_by`, `decided_at` (UTC), and the
canary: `canary_id`, `canary_manifest` (the `sentry.provider-canary.v1` JSON),
`canary_manifest_sha256` and an https `base_url` whose host the manifest names
for `openrouter`. `init` checks it as the worker will check its settings, shows
the whole canary before you confirm, and fixes it into the record. Without it a
release has no provider: the worker keeps the disabled scaffold and the custodian
step refuses a provider key.

Exit codes: `0` done, `2` refused before anything ran (nothing written), `3`
the step ran and failed or held (its receipt says why).

## Steps

The section column is the operational proposal's section each step implements.

| Step | Section | Session | What it does | Receipt records |
| --- | --- | --- | --- | --- |
| `bootstrap` | 7.1 | deployer | `bootstrap/`: init (local state in the work directory), plan, check, apply | plan file and hash, outputs (control bucket, operator role) |
| `foundation` | 7.2 | deployer | `foundation/`: init with the control bucket, plan, check, apply | outputs (subnets, groups, repositories, databases, admin secret ARNs) |
| `custodian` | 7.3 | deployer | creates the 17 section 4 secrets (18 when the record names a provider canary) from `--custodian DIR`, reads the two RDS-managed administrator secrets' current versions | ARN and VersionId of each, never a value |
| `images` | 7.4 | deployer | pushes the three platform manifests by digest from their archives | registry digests; fails if a digest would change |
| `releases` | 7.5 | deployer | `releases/`: renders one `current` release (with observers and bootstrap), plan, check, apply | rendered input, outputs |
| `services` | 7.6 | deployer | `services/`: three services at desired count zero | outputs, the four plan files' combined hash |
| `attach` | 7.7 | deployer | attaches exactly the attended set, `release-evidence` and the bootstrap launcher to the operator role | the attached set, checked exact |
| `session` | 7.8 | operator | checks the custodian's operator session file and its identity | session name, expiry and caller, never a key |
| `validate` | 7.9 | none | renders the manifest and approval, then `python -m release_cli validate` | both files and hashes, the CLI report |
| `run` | 7.10 | operator | `python -m release_cli run`, then `status` | the run's state; ok only for `held_paused` with the lock released |
| `detach` | 7.11 | deployer | detaches everything `attach` attached; runs after any `run` outcome | detached and remaining policies |
| `restore` | 8 | deployer | a separate command: restores one database by point in time into a new instance | the new instance; schema verification pending |
| `teardown` | 8 | deployer | a separate command: scale to zero, detach, then remove the services root only | what was removed and what is kept |

### Terraform steps

Each Terraform step writes the root's inputs from the verified plan in memory
into the work directory (a plan file edited after it was loaded is never what
Terraform reads), refuses a root directory holding any variable file Terraform
would load by itself, and initializes the root with `-backend-config` from the plan
(the control bucket `<prefix>-<account>-control`, the root's fixed state key
and the region; `bootstrap/` keeps local state in `WORK/state/`), writes a plan
file, reads it with `terraform show -json` and checks it before anything is
applied: Terraform 1.16.5, exactly the variables the kit rendered, only
`create`, `read` or `no-op` changes, and for `releases/` nothing created outside
the current release's module and the launcher policies. You then type the
identifier a second time to apply exactly that plan file; its SHA-256 is taken
at the check and verified again before the apply. Any other plan stops
the step with a failed receipt; nothing is applied.

### The custodian directory

`--custodian DIR` holds one JSON object per bundle, `DIR/<purpose>.json`, each
owner-only (0400 or 0600) and outside any repository. The kit checks each file
holds exactly its keys and never prints a value. Secrets are created as
`<prefix>/<purpose>` with the AWS-managed key; the request token is the version
id the receipt records.

| Purpose | Keys |
| --- | --- |
| `environment/runtime` | `DATABASE_URL`, `SENTRYRUNTIME_AUTH_CREDENTIALS` |
| `environment/api` | `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD` |
| `environment/worker` | the `DB_*` keys, `SENTRYRUNTIME_PRODUCER_TOKEN`, `SENTRYRUNTIME_WORKER_TOKEN` |
| `material/runtime` | `server-cert.pem`, `server-key.pem`, `runtime-ca.pem`, `postgres-ca.pem`, `probe-token` |
| `material/api`, `material/worker` | `runtime-ca.pem`, `postgres-ca.pem` |
| `owner-environment/runtime`, `proof-environment/runtime` | `DATABASE_URL` |
| `owner-environment/product`, `proof-environment/product` | the `DB_*` keys |
| `owner-material/runtime`, `owner-material/product` | `postgres-ca.pem` |
| `observer-material/runtime` | `runtime-ca.pem`, `probe-token` |
| `bootstrap-credentials/runtime`, `bootstrap-credentials/product` | `RELEASE_OWNER_PASSWORD`, `RELEASE_SERVICE_PASSWORD` |
| `bootstrap-ca/runtime`, `bootstrap-ca/product` | `postgres-ca.pem` |
| `provider-key/worker` | `OPENROUTER_API_KEY`; only for a release whose record names a provider canary, refused otherwise, and never blank or the disabled placeholder |

The logins are fixed: `runtime_db` owned by `runtime_owner` with service login
`runtime_service`, and `product_db`, `product_owner`, `product_service`; the
administrators are the instances' `runtime_admin` and `product_admin`.

### Sessions

The deployer session (Terraform, secrets, images, IAM) is yours, issued outside
the kit with the permissions those steps need; that principal is a separate
approval. The operator session (steps `session` and `run`) is the custodian's
short-lived session for `<prefix>-operator`, with session name and source
identity equal to the operator. `run` refuses any other session than the one
`session` checked. Delete both files after the window.

### Restore and teardown

Both refuse without their own approval document, bound to the plan hash and the
receipt chain's current head and approved by the operator:

- `sentry.restore-approval.v1`: `database` (`runtime` or `product`),
  `target_identifier` (`<prefix>-<database>-db-restore-<label>`, a new instance),
  `restore_time` (`latest` or a UTC time), `not_after`. The restore never touches
  the original instance and is created with deletion protection.
- `sentry.teardown-approval.v1`: `remove` naming exactly the three
  `aws_ecs_service.this[...]` addresses, `not_after`. It scales the services to
  zero, detaches every launcher policy, and destroys only the services root
  after checking the destroy plan removes exactly those three. Releases are
  retired by `terraform state rm` and deregistration, and the foundation needs a
  reviewed change lifting `prevent_destroy`; both are separate approvals, and
  snapshots and images are kept.

## Rehearsal

`dev/rehearse_aws_07b.py` runs `init` and all eleven steps here, typed
identifiers supplied by the rehearsal driver:

- moto 5.2.3 in server mode on loopback answers ECR, S3, Secrets Manager, STS and
  IAM. moto does not implement ECR's layer-upload operations, so a loopback shim
  in front of it implements those four and verifies every uploaded blob's digest;
  everything else goes to moto unchanged.
- Each Terraform step's plan half runs the pinned 1.16.5 binary with
  `-backend=false` and the mocked provider (`terraform test`, `command = plan`)
  against the kit's rendered variables. **Apply is not rehearsed**: the outputs
  each apply would report are stand-ins derived from the rendered inputs, and the
  resources later steps call (control bucket, repositories, policies, operator
  role, administrator secrets) are created in moto by the rehearsal itself.
- The run step drives `release_cli run` in process through the container-backed
  ECS and Logs fakes with the real images, the journal and lock in moto S3, and
  the operator's identity from a moto STS session of the operator role. It ends
  `held_paused` with the lock released.

## Proven on the platform only

Nothing below can be shown here; the kit's account run writes the receipts that
close each item:

- every Terraform apply, the S3 backend and its lockfile, and the real plan's
  JSON (the diff check is tested on fixture plan documents);
- IAM evaluation of the attached policies, the operator role's trust, and that the
  deployer session can do what each step asks;
- ECR's own layer and manifest handling (the shim stands in for it), and Fargate
  pulling the pushed digests through the endpoints;
- Secrets Manager's version handling and the RDS-managed administrator secrets;
- the release's ECS and Logs behaviour on Fargate (timing, listing delay), and the
  RDS point-in-time restore itself; verifying the restored instance's schema with
  the reconcile and proof jobs needs a release whose bundles name it, which is
  not built yet (the AWS-08a `pitr-restore` case says so).
