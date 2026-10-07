# Release controller AWS adapters

`release_aws/` implements the [release controller's](release-controller.md) ports
over AWS SDK clients. Each port call becomes one SDK request, or a bounded set of
complete pages and descriptions. `release/` stays SDK-free; a static test and a
poisoned-environment process test enforce that.

**Evidence level.** The adapters have been exercised only against stubbed SDK
responses and in-process fakes, with the network denied. Nothing has called AWS,
launched a task, changed a service, read a real log or written to S3. No CLI
builds these clients yet, and no IAM policy is attached.

## Injected clients

Every adapter takes a client the caller built. The package never creates a
session, resolves credentials, reads dotenv or environment variables, or picks an
endpoint. It refuses a client unless all of the following hold:

- it targets the expected service and the manifest's region;
- SDK retries are disabled (`total_max_attempts` is 1) in legacy or standard
  mode, because the controller owns every retry and an SDK retry of
  `UpdateService` could create a second deployment. Adaptive mode is refused:
  its client-side rate limiter can delay even a first attempt;
- connect and read timeouts are explicit and at most 30 seconds.

The timeout bounds each connect and each socket read, not a whole call: DNS
resolution and multi-read responses are outside it. Deadlines are checked between
calls, so a stalled call can delay noticing one.

The tests build clients from a botocore session that ignores every AWS
environment variable and configuration file, including profiles, endpoint URLs,
retry mode, FIPS and the CA bundle. They use explicit fixture credentials. A
future operator CLI needs the same isolation.

## Outcomes and errors

| SDK result | Port result |
| --- | --- |
| Throttling codes, HTTP 5xx, connection loss, timeouts, unparseable responses | `AmbiguousResponse`: the request may have applied; the controller reconciles or holds |
| Other 4xx (access denied, invalid parameter, client error) | `AwsRequestRejected` carrying only the AWS error code |
| S3 412/409 on a conditional write; 404 on a conditional replace/delete | `PreconditionFailed` |
| S3 404 on read | absent (`None`); 403 is a refusal, never "absent" |
| Logs `ResourceNotFoundException` | `LogStreamMissing` |

Provider error messages are never repeated: they can quote request content. Each
replacement exception is raised outside the handler, so it carries no
`__context__` or `__cause__` back to the SDK error. The same applies to receipt
parsing errors, which quote the raw line. The controller journals and raises its
own holds outside its handlers too. No exception that escapes a release therefore
chains to provider or log content.

## Adapters

**`EcsAdapter`** (one cluster):
- **Requests.** `RunTask` accepts only the controller's exact launch shape:
  - one Fargate task, Exec off, public IP disabled;
  - the client token as `startedBy`;
  - tags.

  Overrides, placement, capacity providers, groups and volume configuration are
  refused before anything is sent. `UpdateService` accepts only scale-to-zero, or
  a single-task forced deploy of a named revision. Deployment settings, Exec and
  networking belong to Terraform (see the [ownership
  contract](../deploy/aws-staging/README.md)).
- **Enumeration.** Listings follow `nextToken` to the end. Any of the following
  raises `AmbiguousResponse`; an incomplete listing is never returned as a short
  one:
  - a failed page;
  - a page without its task list;
  - more than 20 pages;
  - a description that omits a requested resource.

  `DescribeTasks` and `DescribeServices` work in API-sized batches.
- **Listing semantics.**
  - **Launch token.** The service model allows `startedBy` only as the sole
    filter, which lists tasks ECS still intends to run. Tasks that already
    exited are added by describing the cluster's desired-`STOPPED` tasks and
    matching their `startedBy`. A job that ran and exited is therefore found
    without resending `RunTask`.
  - **Cluster-wide quiesce check.** It includes every described stopped-desired
    task whose last status is not yet `STOPPED`. A requested stop flips the
    desired status at once while the process may run for up to the stop
    timeout.
  - **Ambiguity.** A desired-`STOPPED` task that cannot be described makes
    either listing ambiguous.
- **Observed tasks.** The controller, not IAM, rejects launched, reconciled,
  completed or service tasks that report any override or Exec. A reconciled
  launch is described and verified like a direct one, and a refused launch is
  never relaunched, even if its hold was never journaled. Quiesce waits until
  every listed task has stopped and holds on any task ECS still intends to run.

**`CloudWatchLogs`** (`LogPort`). One `GetLogEvents` call per port call:
- `startFromHead=true`, which is required when following forward tokens;
- `unmask=false`;
- the caller's bounds, limit and token passed through unchanged.

It does no internal paging, retry or filtering. A page without a forward token is
ambiguous.

**`LogEvidence`** (`EvidencePort`):
- **Stream.** It reads a job's receipt only from the stream Terraform configures
  for the observed task:
  - log group `/<prefix>/<database>-release`;
  - stream `<database>-release/migration/<task-id>` for migrations;
  - stream `<database>-<phase>/<phase>/<task-id>` for grants and proofs.
- **Reading.** It reads from the head to the stream end within the manifest's
  fixed window, bounded to 20 pages and 256 KiB. Overflow is ambiguous.
- **Parsing.** It parses with `release_tools.receipt.extract_receipt`. It
  returns only the parsed receipt. Ordinary application lines (report IDs,
  request lines, tracebacks) are read but never returned or put into an
  exception.
- **Outcomes.** A missing stream or receipt is missing evidence, so the
  controller waits until its deadline. Duplicate or malformed receipts are
  ambiguous.
- **Missing producers.** The migration images emit no receipts, and Runtime and
  API operational observers do not exist. Those checks therefore stay unproven:
  `operational_receipt` always returns `None`, and a manifest that requires them
  holds with `operational_evidence_missing`.

**`S3ObjectStore`** (`ObjectStore`) on the control bucket:
- **Keys.** It accepts only `releases/<uuid>/journal.json` and
  `locks/<environment>.json`.
- **Writes.**
  - Create uses `If-None-Match: *`.
  - Replace and delete use `If-Match` with the read ETag.
  - Every request names `ExpectedBucketOwner`.
- **Reads.** A read must return exactly its declared length, at most 4 MiB. A
  full read lets botocore verify that length and any checksum. A missing bucket
  is a refusal; only a missing key on a conditional write is a lost race.
- **Unknown write outcomes.** If a write's outcome is unknown, the controller's
  next conditional write fails when the earlier write landed. The run then halts
  with `journal_conflict` instead of forking, and the action whose intent was
  being written is never sent. A recovered session reconciles that intent.

## Tests

- `tests/test_release_aws.py` uses botocore's `Stubber` for exact request
  parameters and error mapping.
- The same file also runs whole releases through the real adapters and botocore
  request validation, answered by the controller fakes (`tests/aws_offline.py`),
  with every socket call denied. These runs cover:
  - throttling;
  - lost `RunTask` and S3 responses;
  - a competing journal writer and a held lock;
  - duplicate receipts;
  - denied, missing, incomplete, empty, slow and throttled log reads;
  - stale receipts;
  - controller clock regression during the readiness gate.
- `tests/test_release_aws_offline.py` repeats complete releases in a separate
  interpreter with poisoned AWS variables, proxies and endpoints and with sockets
  denied.

## Unverified against AWS

- IAM evaluation of the unattached launcher policies, and whether each request
  above is allowed.
- `ListTasks` with `startedBy`: whether it is truly the sole permitted filter,
  and how long stopped tasks stay listed and describable. A stopped task that
  ages out between listing and description makes the listing ambiguous: a
  fail-closed hold, not a guess.
- Whether `DescribeTasks` always reports `overrides` and `enableExecuteCommand`.
  If it omits them, the controller holds.
- `GetLogEvents` token behavior as `endTime` advances, and its throttling under
  the 5 s poll.
- S3 conditional delete and `409` behavior on the versioned control bucket.
- Partial `deploymentConfiguration` semantics. They no longer matter, because
  the controller never sends one.
- A Clock adapter that enforces non-regression and a bounded UTC offset is not
  implemented. The readiness gate detects regression it observes; other steps
  read the clock unchecked.

**Known liveness costs, all fail-closed:**
- An ambiguous lock create holds even if the lock landed, which then needs a
  recorded recovery.
- A throttled job-receipt read is a terminal hold, unlike readiness reads,
  which only clear stability.
