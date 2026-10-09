"""Strict Cloudflare release manifest and external approval receipt, schema version 1.

The Cloudflare counterpart of ``release.manifest``: pure parsing and validation
with the same JSON strictness (duplicate keys, non-integer numbers and any
``override`` key are refused before hashing), the same canonical hash and the
same window, risk, job-plan and approval rules. It shares the provider-neutral
submodels and adds Cloudflare's own identities: account and zone, the Worker
script names and the version-id tuple a release deploys, Durable Object
namespaces, container applications and their approved settings, AMD64 image
digests in the account's registry, buckets, placement, per-Worker secret
digests, the operator key and the minimum Wrangler version.

The document says ``"platform": "cloudflare"``; the AWS loader refuses it as an
unknown field and this loader refuses an AWS document as missing it. The
approval's ``kind`` differs from the AWS approval's for the same reason.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import re
from typing import Annotated, Any, Literal

from pydantic import Field

from release.manifest import (
    JOB_ORDER,
    MAX_VALIDITY,
    PHASES,
    PRODUCT_GRANT_PATH,
    RELEASE_TOOLS_RESULT_KEYS,
    RUNTIME_GRANT_PIN,
    CompatibleSchemas,
    Digest,
    EmptyHold,
    Expectation,
    ExpectValue,
    LoadedManifest,
    Name,
    OperationalCheck,
    ReleaseRejected,
    Risk,
    SchemaId,
    Sha256,
    Sources,
    SqlPin,
    Strict,
    Text,
    UtcTime,
    Uuid,
    Window,
    _document,
    _pattern,
    _validated,
    canonical_sha256,
)
from release.readiness import WORKER_READINESS_CHECK, WORKER_RECEIPT_KIND

SCHEMA_VERSION = 1
PLATFORM = "cloudflare"
REGISTRY = "registry.cloudflare.com"
# Grant and proof jobs post this separately versioned receipt from the JobRunner;
# the AWS v1 envelope (task_arn) is never reused for a Cloudflare identity.
CLOUDFLARE_JOB_RECEIPT_SCHEMA = "sentry.release-tools.job.cloudflare.v1"
WORKERS = ("edge", "api", "worker", "runtime", "jobs")
# Service key -> the Worker script and Durable Object name that run it.
SERVICE_WORKERS = {"runtime": "runtime", "api": "api", "worker": "worker"}
OBJECT_NAMES = {"runtime": "runtime-0", "api": "api-0", "worker": "worker-0"}
CONTAINER_WORKERS = ("api", "worker", "runtime", "jobs")
# Each container application's image map, fixed by the Worker scripts.
APPLICATION_IMAGES = {
    "api": ("search",),
    "worker": ("search",),
    "runtime": ("runtime",),
    "jobs": ("release_tools", "runtime", "search"),
}
MIGRATION_IMAGES = {"runtime": "runtime", "product": "search"}
RECEIPT_CONTROL_FIELDS = frozenset(
    {
        "release_id",
        "job_id",
        "durable_object_id",
        "launch_nonce",
        "task_arn",
        "status",
        "result",
        "receipt_schema",
        "schema_version",
    }
)
WRANGLER_FLOOR = (4, 0, 0)

Hex32 = _pattern(r"[0-9a-f]{32}")
ScriptName = _pattern(r"[a-z0-9][a-z0-9-]{0,62}")
ApplicationId = Uuid
SecretName = _pattern(r"[A-Z][A-Z0-9_]{0,63}")
BucketName = _pattern(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]")
RegionCode = _pattern(r"[A-Z]{2,6}")
SemVer = _pattern(r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}")
BackupRef = _pattern(r"[A-Za-z0-9][A-Za-z0-9:_./-]{0,254}")
ImageKey = Literal["runtime", "search", "release_tools"]
# "basic" is not accepted by start() under the durable_object policy.
InstanceType = Literal["lite", "standard-1", "standard-2", "standard-3", "standard-4"]


class Workers(Strict):
    edge: ScriptName
    api: ScriptName
    worker: ScriptName
    runtime: ScriptName
    jobs: ScriptName


class Versions(Strict):
    """One Worker version id per script: the tuple a release deploys at 100%."""

    edge: Uuid
    api: Uuid
    worker: Uuid
    runtime: Uuid
    jobs: Uuid


class Namespaces(Strict):
    api: Hex32
    worker: Hex32
    runtime: Hex32
    jobs: Hex32


class Environment(Strict):
    name: Name
    account_id: Hex32
    zone_id: Hex32
    workers: Workers
    namespaces: Namespaces
    # The versions the one-time bootstrap deploy left current: an empty-hold
    # release may move forward only from exactly these.
    bootstrap_versions: Versions


class Application(Strict):
    """A container application and the settings the release requires of it."""

    id: ApplicationId
    scheduling_policy: Literal["durable_object"]
    instance_type: InstanceType
    ssh_enabled: Literal[False]
    logs_enabled: Literal[False]
    images: tuple[ImageKey, ...] = Field(min_length=1, max_length=3)


class Applications(Strict):
    api: Application
    worker: Application
    runtime: Application
    jobs: Application


class Image(Strict):
    repository: str
    amd64_digest: Digest
    provenance_sha256: Sha256
    sbom_sha256: Sha256
    scan_sha256: Sha256


class Images(Strict):
    runtime: Image
    search: Image
    release_tools: Image


class Storage(Strict):
    artifacts_bucket: BucketName
    control_bucket: BucketName
    jurisdiction: Literal["default", "eu", "fedramp"]


class Placement(Strict):
    regions: tuple[RegionCode, ...] = Field(min_length=1, max_length=8)


class Secret(Strict):
    name: SecretName
    sha256: Sha256


class Secrets(Strict):
    edge: tuple[Secret, ...] = Field(max_length=16)
    api: tuple[Secret, ...] = Field(min_length=1, max_length=16)
    worker: tuple[Secret, ...] = Field(min_length=1, max_length=16)
    runtime: tuple[Secret, ...] = Field(min_length=1, max_length=16)
    jobs: tuple[Secret, ...] = Field(min_length=1, max_length=16)


class Job(Strict):
    id: Name
    phase: Literal["migrate", "grant", "proof"]
    database: Literal["runtime", "product"]
    image: ImageKey
    deadline_seconds: int = Field(ge=60, le=3600)
    stop_grace_seconds: int = Field(ge=1, le=120)
    receipt_schema: SchemaId
    expect: Expectation = Field(min_length=1, max_length=16)
    sql: SqlPin | None = None


class PriorImage(Strict):
    repository: str
    amd64_digest: Digest


class PriorImages(Strict):
    runtime: PriorImage
    search: PriorImage


class Backups(Strict):
    runtime: BackupRef
    product: BackupRef


class CompatibleRelease(Strict):
    """Upgrade: the exact retained prior release and the versions it deployed."""

    kind: Literal["compatible_release"]
    release_id: Uuid
    versions: Versions
    images: PriorImages
    trust_sha256: Sha256
    compatible_schemas: CompatibleSchemas
    backups: Backups


class Manifest(Strict):
    schema_version: Literal[1]
    platform: Literal["cloudflare"]
    release_id: Uuid
    milestone: Literal["operational-paused"]
    environment: Environment
    operator: Text
    window: Window
    sources: Sources
    images: Images
    risk: Risk
    plan_sha256: Sha256
    versions: Versions
    applications: Applications
    storage: Storage
    placement: Placement
    secrets: Secrets
    operator_key_id: Sha256
    wrangler_min_version: SemVer
    jobs: tuple[Job, ...] = Field(min_length=1, max_length=12)
    operational_checks: tuple[OperationalCheck, ...] = Field(min_length=1, max_length=16)
    rollback: Annotated[EmptyHold | CompatibleRelease, Field(discriminator="kind")]


class Approval(Strict):
    schema_version: Literal[1]
    kind: Literal["cloudflare-release-approval"]
    release_id: Uuid
    manifest_sha256: Sha256
    environment: Name
    account_id: Hex32
    zone_id: Hex32
    milestone: Literal["operational-paused"]
    approved_by: Text
    not_before: UtcTime
    not_after: UtcTime


@dataclass(frozen=True)
class LoadedApproval:
    approval: Approval
    sha256: str


def load_manifest(raw: bytes) -> LoadedManifest:
    document = _document(raw)
    manifest = _validated(Manifest, document)
    _check_manifest(manifest)
    return LoadedManifest(manifest, canonical_sha256(document))


def load_approval(raw: bytes) -> LoadedApproval:
    document = _document(raw)
    return LoadedApproval(_validated(Approval, document), canonical_sha256(document))


def verify_approval(loaded: LoadedManifest, receipt: Any, now: datetime) -> None:
    """Raise unless this receipt authorizes exactly this Cloudflare manifest at ``now``."""
    manifest, approval = loaded.manifest, receipt.approval
    if not isinstance(manifest, Manifest) or not isinstance(approval, Approval):
        raise ReleaseRejected("approval_platform_mismatch")
    if approval.manifest_sha256 != loaded.sha256:
        raise ReleaseRejected("approval_manifest_mismatch")
    environment = manifest.environment
    scope = (approval.release_id, approval.environment, approval.account_id, approval.zone_id)
    wanted = (manifest.release_id, environment.name, environment.account_id, environment.zone_id)
    if scope != wanted:
        raise ReleaseRejected("approval_scope_mismatch")
    if approval.not_before >= approval.not_after:
        raise ReleaseRejected("approval_interval_invalid")
    if approval.not_after > manifest.window.expires_at:
        raise ReleaseRejected("approval_outlives_manifest")
    if now < approval.not_before or now < manifest.window.not_before:
        raise ReleaseRejected("approval_not_yet_valid")
    if now >= approval.not_after:
        raise ReleaseRejected("approval_expired")


def expected_job_receipt(
    job: Job, release_id: str, object_id: str, launch_nonce: str
) -> dict[str, Any]:
    """The exact receipt a successful Cloudflare job posts for its own start."""
    return {
        "schema": job.receipt_schema,
        "release_id": release_id,
        "job_id": job.id,
        "durable_object_id": object_id,
        "launch_nonce": launch_nonce,
        "status": "succeeded",
        # Result data never replaces the envelope: result.schema is the database
        # revision, not the receipt schema.
        "result": dict(job.expect),
    }


def _check_manifest(manifest: Manifest) -> None:
    window = manifest.window
    if not window.not_before < window.expires_at <= window.not_before + MAX_VALIDITY:
        raise ReleaseRejected("window_invalid", "window")
    if manifest.risk.expires_at < window.expires_at:
        raise ReleaseRejected("risk_expires_before_release", "risk.expires_at")
    version = tuple(int(part) for part in manifest.wrangler_min_version.split("."))
    if version < WRANGLER_FLOOR:
        raise ReleaseRejected("invalid_field", "wrangler_min_version")
    _check_scope(manifest)
    _check_versions(manifest)
    _check_applications(manifest)
    _check_jobs(manifest)
    _check_release_tools_jobs(manifest)
    _check_secret_separation(manifest)
    _check_operational(manifest)
    rollback = manifest.rollback
    if isinstance(rollback, CompatibleRelease) and rollback.release_id == manifest.release_id:
        raise ReleaseRejected("rollback_not_prior_release", "rollback.release_id")


def _distinct(values: list[str], code: str, detail: str) -> None:
    if len(set(values)) != len(values):
        raise ReleaseRejected(code, detail)


def _repository(value: str, account: str, detail: str) -> None:
    """An image repository in this account's registry, with no tag or digest."""
    prefix = f"{REGISTRY}/{account}/"
    if not value.startswith(prefix):
        raise ReleaseRejected("resource_scope_mismatch", detail)
    if re.fullmatch(r"[a-z0-9][a-z0-9._/-]{0,255}", value[len(prefix) :]) is None:
        raise ReleaseRejected("mutable_reference", detail)


def _check_scope(manifest: Manifest) -> None:
    environment = manifest.environment
    account = environment.account_id
    for name in ("runtime", "search", "release_tools"):
        _repository(getattr(manifest.images, name).repository, account, f"images.{name}")
    rollback = manifest.rollback
    if isinstance(rollback, CompatibleRelease):
        for name in ("runtime", "search"):
            _repository(getattr(rollback.images, name).repository, account, "rollback.images")
    _distinct([getattr(environment.workers, w) for w in WORKERS], "invalid_field", "workers")
    namespaces = [getattr(environment.namespaces, w) for w in CONTAINER_WORKERS]
    _distinct(namespaces, "invalid_field", "environment.namespaces")
    storage = manifest.storage
    if storage.artifacts_bucket == storage.control_bucket:
        raise ReleaseRejected("invalid_field", "storage")
    _distinct(list(manifest.placement.regions), "invalid_field", "placement.regions")


def _check_versions(manifest: Manifest) -> None:
    """Every Worker gets a new version; none is reused from the prior state."""
    versions = [getattr(manifest.versions, w) for w in WORKERS]
    _distinct(versions, "invalid_field", "versions")
    prior = [getattr(manifest.environment.bootstrap_versions, w) for w in WORKERS]
    _distinct(prior, "invalid_field", "environment.bootstrap_versions")
    rollback = manifest.rollback
    if isinstance(rollback, CompatibleRelease):
        prior += [getattr(rollback.versions, w) for w in WORKERS]
        _distinct(prior[len(WORKERS) :], "invalid_field", "rollback.versions")
    if set(versions) & set(prior):
        raise ReleaseRejected("version_reused", "versions")


def _check_applications(manifest: Manifest) -> None:
    ids = [getattr(manifest.applications, w).id for w in CONTAINER_WORKERS]
    _distinct(ids, "invalid_field", "applications")
    for worker in CONTAINER_WORKERS:
        if getattr(manifest.applications, worker).images != APPLICATION_IMAGES[worker]:
            raise ReleaseRejected("application_images_invalid", f"applications.{worker}")


def _check_jobs(manifest: Manifest) -> None:
    jobs = manifest.jobs
    if tuple((job.phase, job.database) for job in jobs) != JOB_ORDER:
        raise ReleaseRejected("job_plan_invalid", "jobs")
    if len({job.id for job in jobs}) != len(jobs):
        raise ReleaseRejected("job_plan_invalid", "jobs")
    for job in jobs:
        if RECEIPT_CONTROL_FIELDS & job.expect.keys():
            raise ReleaseRejected("job_expectation_reserved", f"jobs.{job.id}.expect")
        required = {"database", "principal"} | ({"schema"} if job.phase == "migrate" else set())
        if not required <= job.expect.keys():
            raise ReleaseRejected("job_expectation_incomplete", f"jobs.{job.id}.expect")
        if job.phase == "migrate" and job.image != MIGRATION_IMAGES[job.database]:
            raise ReleaseRejected("job_image_invalid", f"jobs.{job.id}.image")
        if job.phase != "grant":
            if job.sql is not None:
                raise ReleaseRejected("unexpected_sql", f"jobs.{job.id}.sql")
            continue
        if job.sql is None:
            raise ReleaseRejected("grant_sql_required", f"jobs.{job.id}.sql")
        if job.database == "runtime" and job.sql.model_dump() != RUNTIME_GRANT_PIN:
            raise ReleaseRejected("grant_pin_mismatch", f"jobs.{job.id}.sql")
        if job.database == "product" and job.sql.source_commit != manifest.sources.search:
            raise ReleaseRejected("grant_pin_mismatch", f"jobs.{job.id}.sql")


def _check_release_tools_jobs(manifest: Manifest) -> None:
    """Grant and proof jobs run the tools image and agree with the migrated identity."""
    jobs = {(job.phase, job.database): job for job in manifest.jobs}
    for job in manifest.jobs:
        if job.phase == "migrate":
            continue
        where = f"jobs.{job.id}"
        if job.id != f"{job.database}-{job.phase}":
            raise ReleaseRejected("job_id_invalid", where)
        if job.receipt_schema != CLOUDFLARE_JOB_RECEIPT_SCHEMA:
            raise ReleaseRejected("job_receipt_schema_invalid", where)
        if job.image != "release_tools":
            raise ReleaseRejected("job_image_invalid", f"{where}.image")
        if set(job.expect) != RELEASE_TOOLS_RESULT_KEYS[job.phase]:
            raise ReleaseRejected("job_expectation_invalid", f"{where}.expect")
        if job.sql is None:
            continue
        if job.expect["sql_digest"] != job.sql.sha256:
            raise ReleaseRejected("grant_pin_mismatch", f"{where}.sql")
        if job.database == "product" and (
            job.sql.path != PRODUCT_GRANT_PATH
            or job.sql.source_commit != manifest.sources.release_tools
        ):
            raise ReleaseRejected("grant_pin_mismatch", f"{where}.sql")
    for database in ("runtime", "product"):
        migrate, grant, proof = (jobs[(phase, database)].expect for phase in PHASES)
        if (
            grant["database"] != migrate["database"]
            or proof["database"] != migrate["database"]
            or grant["principal"] != migrate["principal"]
            or grant["service_role"] != proof["principal"]
            or proof["principal"] == migrate["principal"]
            or proof["schema"] != migrate["schema"]
        ):
            raise ReleaseRejected("job_expectation_inconsistent", f"jobs.{database}")


def _check_secret_separation(manifest: Manifest) -> None:
    """Secret values (by digest) never repeat across service Workers or into the jobs Worker.

    Names are unique within a Worker; a value bound to one service Worker is
    never bound to another, and job administrator material is never a service's.
    """
    seen: set[str] = set()
    for worker in WORKERS:
        secrets = getattr(manifest.secrets, worker)
        _distinct([item.name for item in secrets], "invalid_field", f"secrets.{worker}")
        digests = {item.sha256 for item in secrets}
        if len(digests) != len(secrets) or digests & seen:
            raise ReleaseRejected("shared_secret_bundle", f"secrets.{worker}")
        seen |= digests


def _check_operational(manifest: Manifest) -> None:
    """The controller proves worker readiness from the worker object's receipt store."""
    checks = manifest.operational_checks
    if len({check.id for check in checks}) != len(checks):
        raise ReleaseRejected("invalid_field", "operational_checks")
    if WORKER_READINESS_CHECK not in {check.id for check in checks} or any(
        (check.id == WORKER_READINESS_CHECK) != (check.receipt_schema == WORKER_RECEIPT_KIND)
        for check in checks
    ):
        raise ReleaseRejected("worker_readiness_check_invalid", "operational_checks")


__all__ = [
    "APPLICATION_IMAGES",
    "CLOUDFLARE_JOB_RECEIPT_SCHEMA",
    "CONTAINER_WORKERS",
    "OBJECT_NAMES",
    "SERVICE_WORKERS",
    "WORKERS",
    "Approval",
    "CompatibleRelease",
    "ExpectValue",
    "Job",
    "LoadedApproval",
    "Manifest",
    "expected_job_receipt",
    "load_approval",
    "load_manifest",
    "verify_approval",
]
