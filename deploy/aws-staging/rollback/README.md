# Rollback: the retained prior pair after a failed release

This is the runbook for `python -m release_kits.rollback`. It restores the
retained prior release after a failed upgrade, as the controller's rollback runs
define it ([release controller](../../../docs/release-controller.md#rollback-runs)).
It has run only against the in-memory release fakes and has never touched an
account. A rollback against the account is its own approval.

The steps use the AWS-07b kit's mechanics: each re-verifies the account plan
and the receipt chain, prints its exact commands and the plan hash, waits for its
identifier to be typed, and writes a receipt chained to the previous one. The
re-plan types its identifier twice, the second time to apply exactly the checked
plan file.

```bash
python -m release_kits.rollback init --plan PLAN --plan-sha256 HASH --work NEW_WORK \
    --prior-work AWS07B_WORK --failed-manifest FAILED.json \
    --failed-release-input FAILED_RELEASE.json --decision DECISION.json \
    --prior-chain-head PRIOR_LAST_RECEIPT_HASH
python -m release_kits.rollback step replan   --plan PLAN --plan-sha256 HASH --work NEW_WORK --session DEPLOYER.json --chain-head HASH
python -m release_kits.rollback step attach   --plan PLAN --plan-sha256 HASH --work NEW_WORK --session DEPLOYER.json --chain-head HASH
python -m release_kits.rollback step render   --plan PLAN --plan-sha256 HASH --work NEW_WORK --chain-head HASH
python -m release_kits.rollback step validate --plan PLAN --plan-sha256 HASH --work NEW_WORK --chain-head HASH
python -m release_kits.rollback step run      --plan PLAN --plan-sha256 HASH --work NEW_WORK --session OPERATOR.json --chain-head HASH
python -m release_kits.rollback step check    --plan PLAN --plan-sha256 HASH --work NEW_WORK --session OPERATOR.json --chain-head HASH
python -m release_kits.rollback step detach   --plan PLAN --plan-sha256 HASH --work NEW_WORK --session DEPLOYER.json --chain-head HASH
```

## Inputs

- `--prior-work`: the AWS-07b work directory of the retained prior release. Its
  chain must verify against the same plan and end with a successful run; its
  receipts give the prior manifest, bundles, security groups, revisions and the
  pinned Terraform binary. `--prior-chain-head` is its last receipt's hash, and
  every later step refuses if that chain has changed since.
- `--failed-manifest`: the failed release's manifest. Its fallback must be
  `compatible_release` naming the prior release and the prior release's own
  services.
- `--failed-release-input`: the failed release's entry of the releases root's
  `releases` input as it was applied (one key, `r` plus eight hex digits).
- `--decision`: a `sentry.rollback-decision.v1` document from whoever decides the
  rollback: `failed_release_id`, `failed_session` and `failed_lock_etag` (from
  `release_cli status` on the failed release), `fence_evidence_sha256` (the
  evidence that the failed operator process is stopped and its session revoked or
  expired), `actual_schemas` for both databases (each must be one of the
  fallback's compatible schemas), `authorized_by` and `decided_at`. The kit
  decides none of these.

## Steps

| Step | Section | Session | What it does |
| --- | --- | --- | --- |
| `replan` | 9.1 | deployer | `releases/` with the prior release `current` and the failed one `rollback`. The plan may change nothing inside either release module and only update launcher policies; the jobs, observe and receipts policies must be known at plan time and name nothing of the failed release; the prior release's `definitions_sha256` must be unchanged after apply |
| `attach` | 7.7 | deployer | attaches the attended set the re-plan rendered (now the prior release's) and `release-evidence` to the operator role, checked exact; refuses if anything is already attached |
| `render` | 9.2 | none | the rollback manifest: the prior pair's services, images, observers and proof jobs, its reconcile jobs expecting the decided schemas with no release or owner session, the failed release's revisions as `failed_services`, and its fallback; then the approval bound to it |
| `validate` | 9.2 | none | `python -m release_cli validate`; it must report a rollback execution of exactly this manifest |
| `run` | 9.3 | operator | `python -m release_cli run` with the decision's handoff: pause and drain the services, sweep every launch the failed release journaled, reconcile and prove the stated schemas, start the prior pair, prove it operational and release the lock |
| `check` | 9.4 | operator | `release_cli status` (journal `held_paused`, nothing outstanding, lock free) and ECS: every service on the prior release's revision, and no task anywhere in the cluster, running or still stopping, on any revision but the prior pair's services and this rollback's own jobs and observers |
| `detach` | 7.11 | deployer | detaches every policy `attach` names wherever it is attached; runs after any `attach` attempt and any `run` outcome; fails, naming them, if the operator role still has policies no step attached |

If `attach` finds the operator role already holding policies (a failed
release's window that was never closed), it fails and attaches nothing. `detach`
then removes the policies of the set it names and fails, naming whatever else is
still attached; removing those is a separate, reviewed action, and `attach`
refuses until the role is empty.

A run that holds is recorded `held` with its reason; nothing is retried. The
controller's rules for a held rollback (the next attempt names the held run as
the failed release) are **not a kit path yet**: a held rollback has no releases
root entry of its own, so this kit cannot re-plan for it. `render` also refuses
if the prior or failed manifest changed since it was validated or recorded. If the prior release's revisions have passed the
deadline they were planned with, the run holds at its first job and a rollback
needs a new release key planned from the prior pair's images, a separate
approval.

## Proven on the platform only

- The re-plan against the real releases state (the slot swap as a real plan,
  and IAM accepting the updated launcher policies).
- ECS quiesce, drain and restart timing on Fargate, and how long ECS keeps
  describing stopped tasks.
- The handoff against the real S3 lock's conditional semantics.
- The holds the controller cannot clear (AWS-F061) on the platform.
