"""Strict release manifest and external approval receipt, schema version 1.

Pure parsing and validation: no clock, file system, SDK or network access. One
manifest is one immutable candidate identified by the SHA-256 of its canonical
JSON. Approval is a separate receipt bound to that hash, never a manifest field.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from types import MappingProxyType
from typing import Annotated, Any, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    PlainSerializer,
    StringConstraints,
    ValidationError,
)

SCHEMA_VERSION = 1
MILESTONE = "operational-paused"
# The reviewed Runtime service-grant script. Change only after reviewing new source.
RUNTIME_GRANT_PIN = {
    "path": "db/roles/service.sql",
    "source_commit": "bb6e523da3c6f4bb186a548f3be696a40798fae9",
    "sha256": "02a2b55161506254b1977f26351ec3bbba4de7c94a54b3b697153d622ae02aa0",
}
# Grant and proof jobs run the release-tools image. Its receipt schema, the product
# grant script path and the result keys each job reports are fixed here; the
# tools emit exactly these keys, so an expectation must name all of them.
RELEASE_TOOLS_RECEIPT_SCHEMA = "sentry.release-tools.job.v1"
PRODUCT_GRANT_PATH = "release_tools/sql/product/grants.sql"
RELEASE_TOOLS_RESULT_KEYS = {
    "grant": frozenset({"database", "principal", "service_role", "sql_digest"}),
    "proof": frozenset({"database", "principal", "schema"}),
}
MAX_VALIDITY = timedelta(days=7)
JOB_ORDER = (
    ("migrate", "runtime"),
    ("migrate", "product"),
    ("grant", "runtime"),
    ("grant", "product"),
    ("proof", "runtime"),
    ("proof", "product"),
)
PHASES = ("migrate", "grant", "proof")
RECEIPT_CONTROL_FIELDS = frozenset(
    {"release_id", "job_id", "task_arn", "status", "result", "receipt_schema", "schema_version"}
)


class ReleaseRejected(ValueError):
    """Input or observation that must not advance a release. Codes are bounded."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def _pattern(expression: str, max_length: int = 2048):
    return Annotated[str, StringConstraints(pattern=f"^{expression}$", max_length=max_length)]


def _utc(value: datetime) -> datetime:
    if value.utcoffset() != timedelta(0):
        raise ValueError("timestamps must be UTC")
    return value.astimezone(timezone.utc)


Text = Annotated[str, StringConstraints(min_length=1, max_length=256)]
Name = _pattern(r"[a-z0-9][a-z0-9-]{0,62}")
SchemaId = _pattern(r"[a-z0-9][a-z0-9.-]{0,127}")
AccountId = _pattern(r"[0-9]{12}")
Region = _pattern(r"[a-z]{2}-[a-z]+-[0-9]")
Uuid = _pattern(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
Sha256 = _pattern(r"[0-9a-f]{64}")
Digest = _pattern(r"sha256:[0-9a-f]{64}")
Commit = _pattern(r"[0-9a-f]{40}")
Subnet = _pattern(r"subnet-[0-9a-f]{8,17}")
SecurityGroup = _pattern(r"sg-[0-9a-f]{8,17}")
PlatformVersion = _pattern(r"[0-9]+\.[0-9]+\.[0-9]+")
ExpectKey = _pattern(r"[a-z][a-z_]{0,31}")
SqlPath = _pattern(r"[A-Za-z0-9_./-]{1,200}")
ExpectValue = _pattern(r"[A-Za-z0-9_.:,/-]{1,256}")


def _immutable_expectation(value: Mapping[str, str]) -> Mapping[str, str]:
    # Frozen models do not freeze nested dictionaries. Copy before wrapping so
    # neither the parser's input nor any caller can edit an approved candidate.
    return MappingProxyType(dict(value))


Expectation = Annotated[
    Mapping[ExpectKey, ExpectValue],
    AfterValidator(_immutable_expectation),
    PlainSerializer(lambda value: dict(value), return_type=dict[str, str]),
]
UtcTime = Annotated[datetime, AfterValidator(_utc)]
ImageKey = Literal["runtime", "search", "release_tools"]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class ServiceArns(Strict):
    runtime: str
    api: str
    worker: str


class Environment(Strict):
    name: Name
    account_id: AccountId
    region: Region
    cluster_arn: str
    services: ServiceArns


class Window(Strict):
    not_before: UtcTime
    expires_at: UtcTime
    total_seconds: int = Field(ge=60, le=4 * 3600)
    poll_seconds: int = Field(ge=1, le=60)
    service_start_seconds: int = Field(ge=30, le=1800)


class Sources(Strict):
    runtime: Commit
    search: Commit
    release_tools: Commit


class Image(Strict):
    repository: str
    manifest_digest: Digest
    arm64_digest: Digest
    provenance_sha256: Sha256
    sbom_sha256: Sha256
    scan_sha256: Sha256


class Images(Strict):
    runtime: Image
    search: Image
    release_tools: Image


class Risk(Strict):
    decision_id: Name
    decision_sha256: Sha256
    decided_by: Text
    expires_at: UtcTime
    retained_findings: int = Field(ge=0)


class Network(Strict):
    subnets: tuple[Subnet, ...] = Field(min_length=2, max_length=4)
    assign_public_ip: Literal["DISABLED"]
    platform_version: PlatformVersion


class SecretVersion(Strict):
    arn: str
    version_id: Uuid


class Container(Strict):
    name: Name
    image: ImageKey


class TaskSpec(Strict):
    task_definition: str
    task_role: str
    execution_role: str
    secrets: tuple[SecretVersion, ...] = Field(min_length=1, max_length=8)
    security_groups: tuple[SecurityGroup, ...] = Field(min_length=1, max_length=5)
    containers: tuple[Container, ...] = Field(min_length=2, max_length=4)


class Services(Strict):
    runtime: TaskSpec
    api: TaskSpec
    worker: TaskSpec


class SqlPin(Strict):
    path: SqlPath
    source_commit: Commit
    sha256: Sha256


class Job(Strict):
    id: Name
    phase: Literal["migrate", "grant", "proof"]
    database: Literal["runtime", "product"]
    task: TaskSpec
    deadline_seconds: int = Field(ge=60, le=3600)
    stop_grace_seconds: int = Field(ge=1, le=120)
    receipt_schema: SchemaId
    expect: Expectation = Field(min_length=1, max_length=16)
    sql: SqlPin | None = None


class OperationalCheck(Strict):
    id: Name
    receipt_schema: SchemaId


class EmptyHold(Strict):
    """First release: no prior binary exists, so failure keeps services at zero."""

    kind: Literal["empty_hold"]


class PriorImage(Strict):
    repository: str
    arm64_digest: Digest


class PriorImages(Strict):
    runtime: PriorImage
    search: PriorImage


class CompatibleSchemas(Strict):
    runtime: tuple[ExpectValue, ...] = Field(min_length=1)
    product: tuple[ExpectValue, ...] = Field(min_length=1)


class Backups(Strict):
    runtime: str
    product: str


class CompatibleRelease(Strict):
    """Upgrade: exact retained prior release that is compatible with actual schemas."""

    kind: Literal["compatible_release"]
    release_id: Uuid
    images: PriorImages
    services: Services
    trust_sha256: Sha256
    compatible_schemas: CompatibleSchemas
    backups: Backups


class Manifest(Strict):
    schema_version: Literal[1]
    release_id: Uuid
    milestone: Literal["operational-paused"]
    environment: Environment
    operator: Text
    window: Window
    sources: Sources
    images: Images
    risk: Risk
    plan_sha256: Sha256
    network: Network
    services: Services
    jobs: tuple[Job, ...] = Field(min_length=1, max_length=12)
    operational_checks: tuple[OperationalCheck, ...] = Field(min_length=1, max_length=16)
    rollback: Annotated[EmptyHold | CompatibleRelease, Field(discriminator="kind")]


class Approval(Strict):
    schema_version: Literal[1]
    kind: Literal["release-approval"]
    release_id: Uuid
    manifest_sha256: Sha256
    environment: Name
    account_id: AccountId
    region: Region
    milestone: Literal["operational-paused"]
    approved_by: Text
    not_before: UtcTime
    not_after: UtcTime


@dataclass(frozen=True)
class LoadedManifest:
    manifest: Manifest
    sha256: str


@dataclass(frozen=True)
class LoadedApproval:
    approval: Approval
    sha256: str


def canonical_sha256(document: Any) -> str:
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseRejected("duplicate_key")
        result[key] = value
    return result


def _no_float(_text: str) -> None:
    raise ReleaseRejected("non_integer_number")


def _reject_overrides(value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if "override" in key.lower():
                raise ReleaseRejected("override_rejected")
            _reject_overrides(item)
    elif isinstance(value, list):
        for item in value:
            _reject_overrides(item)


def _document(raw: bytes) -> dict[str, Any]:
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_float=_no_float,
            parse_constant=_no_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ReleaseRejected("invalid_json") from None
    if not isinstance(document, dict):
        raise ReleaseRejected("invalid_json")
    _reject_overrides(document)
    return document


def _validated(model: type[Strict], document: dict[str, Any]) -> Any:
    try:
        return model.model_validate_json(json.dumps(document), strict=True)
    except ValidationError as error:
        first = error.errors()[0]
        detail = ".".join(str(part) for part in first["loc"])
        code = {"missing": "missing_field", "extra_forbidden": "unknown_field"}.get(
            first["type"], "invalid_field"
        )
        # Pydantic messages may echo input values; keep only the location.
        raise ReleaseRejected(code, detail) from None


def load_manifest(raw: bytes) -> LoadedManifest:
    document = _document(raw)
    manifest = _validated(Manifest, document)
    _check_manifest(manifest)
    return LoadedManifest(manifest, canonical_sha256(document))


def load_approval(raw: bytes) -> LoadedApproval:
    document = _document(raw)
    return LoadedApproval(_validated(Approval, document), canonical_sha256(document))


def verify_approval(loaded: LoadedManifest, receipt: LoadedApproval, now: datetime) -> None:
    """Raise unless this receipt authorizes exactly this manifest at ``now``."""
    manifest, approval = loaded.manifest, receipt.approval
    if approval.manifest_sha256 != loaded.sha256:
        raise ReleaseRejected("approval_manifest_mismatch")
    environment = manifest.environment
    if (approval.release_id, approval.environment, approval.account_id, approval.region) != (
        manifest.release_id,
        environment.name,
        environment.account_id,
        environment.region,
    ):
        raise ReleaseRejected("approval_scope_mismatch")
    if approval.not_before >= approval.not_after:
        raise ReleaseRejected("approval_interval_invalid")
    if approval.not_after > manifest.window.expires_at:
        raise ReleaseRejected("approval_outlives_manifest")
    if now < approval.not_before or now < manifest.window.not_before:
        raise ReleaseRejected("approval_not_yet_valid")
    if now >= approval.not_after:
        raise ReleaseRejected("approval_expired")


def _check_manifest(manifest: Manifest) -> None:
    window = manifest.window
    if not window.not_before < window.expires_at <= window.not_before + MAX_VALIDITY:
        raise ReleaseRejected("window_invalid", "window")
    if manifest.risk.expires_at < window.expires_at:
        raise ReleaseRejected("risk_expires_before_release", "risk.expires_at")
    if tuple(int(part) for part in manifest.network.platform_version.split(".")) < (1, 4, 0):
        raise ReleaseRejected("invalid_field", "network.platform_version")
    _check_scope(manifest)
    _check_jobs(manifest)
    _check_release_tools_jobs(manifest)
    _check_secret_separation(manifest)
    if len({check.id for check in manifest.operational_checks}) != len(manifest.operational_checks):
        raise ReleaseRejected("invalid_field", "operational_checks")
    rollback = manifest.rollback
    if isinstance(rollback, CompatibleRelease) and rollback.release_id == manifest.release_id:
        raise ReleaseRejected("rollback_not_prior_release", "rollback.release_id")


def _scoped(value: str, prefix: str, structure: str, detail: str) -> None:
    """Reject other accounts/regions first, then floating or ambiguous references."""
    if not value.startswith(prefix):
        raise ReleaseRejected("resource_scope_mismatch", detail)
    if re.fullmatch(structure, value[len(prefix) :]) is None:
        raise ReleaseRejected("mutable_reference", detail)


def _check_task(spec: TaskSpec, prefixes: dict[str, str], detail: str) -> None:
    _scoped(
        spec.task_definition,
        prefixes["ecs"] + "task-definition/",
        r"[A-Za-z0-9_-]{1,255}:[1-9][0-9]{0,8}",
        detail + ".task_definition",
    )
    for field in ("task_role", "execution_role"):
        _scoped(getattr(spec, field), prefixes["iam"], r"[A-Za-z0-9+=,.@_/-]{1,512}", detail)
    for item in spec.secrets:
        _scoped(item.arn, prefixes["secret"], r"[A-Za-z0-9/_+=.@-]+-[A-Za-z0-9]{6}", detail)
    names = [container.name for container in spec.containers]
    if len(set(names)) != len(names) or "init" not in names:
        raise ReleaseRejected("invalid_field", detail + ".containers")


def _check_scope(manifest: Manifest) -> None:
    environment = manifest.environment
    account, region = environment.account_id, environment.region
    prefixes = {
        "ecs": f"arn:aws:ecs:{region}:{account}:",
        "iam": f"arn:aws:iam::{account}:role/",
        "secret": f"arn:aws:secretsmanager:{region}:{account}:secret:",
        "ecr": f"{account}.dkr.ecr.{region}.amazonaws.com/",
        "rds": f"arn:aws:rds:{region}:{account}:",
    }
    _scoped(
        environment.cluster_arn, prefixes["ecs"] + "cluster/", r"[A-Za-z0-9_-]{1,255}", "cluster"
    )
    cluster = environment.cluster_arn.rsplit("/", 1)[1]
    for name in ("runtime", "api", "worker"):
        _scoped(
            getattr(environment.services, name),
            f"{prefixes['ecs']}service/{cluster}/",
            r"[A-Za-z0-9_-]{1,255}",
            f"environment.services.{name}",
        )
    repository = r"[a-z0-9][a-z0-9._/-]{0,255}"
    for name in ("runtime", "search", "release_tools"):
        _scoped(getattr(manifest.images, name).repository, prefixes["ecr"], repository, "images")
    for name in ("runtime", "api", "worker"):
        _check_task(getattr(manifest.services, name), prefixes, f"services.{name}")
    for job in manifest.jobs:
        _check_task(job.task, prefixes, f"jobs.{job.id}.task")
    rollback = manifest.rollback
    if isinstance(rollback, CompatibleRelease):
        for name in ("runtime", "search"):
            _scoped(
                getattr(rollback.images, name).repository, prefixes["ecr"], repository, "rollback"
            )
        for name in ("runtime", "api", "worker"):
            _check_task(getattr(rollback.services, name), prefixes, f"rollback.services.{name}")
        snapshot = r"(snapshot|cluster-snapshot):[A-Za-z0-9-]{1,255}"
        for name in ("runtime", "product"):
            _scoped(getattr(rollback.backups, name), prefixes["rds"], snapshot, "rollback.backups")


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
    """Grant/proof jobs run the tools image and agree with the migrated identity.

    A grant receipt echoes the SQL digest the image verified before connecting, so
    the expectation binds the executed script to the reviewed pin.
    """
    jobs = {(job.phase, job.database): job for job in manifest.jobs}
    for job in manifest.jobs:
        if job.phase == "migrate":
            continue
        where = f"jobs.{job.id}"
        # The task definition fixes RELEASE_JOB_ID; the receipt echoes it.
        if job.id != f"{job.database}-{job.phase}":
            raise ReleaseRejected("job_id_invalid", where)
        if job.receipt_schema != RELEASE_TOOLS_RECEIPT_SCHEMA:
            raise ReleaseRejected("job_receipt_schema_invalid", where)
        if any(c.image != "release_tools" for c in job.task.containers if c.name != "init"):
            raise ReleaseRejected("job_image_invalid", f"{where}.task.containers")
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
    """Service bundles are pairwise disjoint; owner jobs never reuse a service bundle."""
    seen: set[str] = set()
    for name in ("runtime", "api", "worker"):
        arns = {item.arn for item in getattr(manifest.services, name).secrets}
        if arns & seen:
            raise ReleaseRejected("shared_secret_bundle", f"services.{name}")
        seen |= arns
    for job in manifest.jobs:
        if job.phase in {"migrate", "grant"} and {item.arn for item in job.task.secrets} & seen:
            raise ReleaseRejected("shared_secret_bundle", f"jobs.{job.id}")
