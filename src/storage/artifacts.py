"""Select the report artifact backend from explicit configuration.

Existing entrypoints keep their behavior: with ``ARTIFACT_BACKEND`` unset or
``s3`` they use the shared ``S3StorageManager``. ``ARTIFACT_BACKEND=r2`` selects
Cloudflare R2. A process started by the Cloudflare entrypoint sets
``SENTRYSEARCH_PLATFORM=cloudflare`` and must then also set
``ARTIFACT_BACKEND=r2``; it never falls back to S3. Unknown values fail.
Errors name the setting, never its value.
"""

from __future__ import annotations

from collections.abc import Mapping
import os
from pathlib import Path

from release_cloudflare.r2_client import R2ClientRejected, R2Target

from .artifact_store import ArtifactStore
from .r2_artifacts import R2ArtifactStore, R2Credentials

PLATFORMS = ("", "cloudflare")
BACKENDS = ("", "s3", "r2")


class ArtifactConfigurationError(ValueError):
    """Artifact storage settings are missing, contradictory or malformed."""


def artifact_store_from_environment(environ: Mapping[str, str] | None = None) -> ArtifactStore:
    env = os.environ if environ is None else environ
    platform = env.get("SENTRYSEARCH_PLATFORM", "")
    backend = env.get("ARTIFACT_BACKEND", "")
    if platform not in PLATFORMS:
        raise ArtifactConfigurationError("SENTRYSEARCH_PLATFORM must be unset or cloudflare")
    if backend not in BACKENDS:
        raise ArtifactConfigurationError("ARTIFACT_BACKEND must be s3 or r2")
    if platform == "cloudflare" and backend != "r2":
        raise ArtifactConfigurationError("The Cloudflare entrypoint requires ARTIFACT_BACKEND=r2")
    if backend == "r2":
        return r2_store_from_environment(env)
    from .s3_manager import s3_manager

    return s3_manager


def r2_store_from_environment(env: Mapping[str, str]) -> R2ArtifactStore:
    try:
        target = R2Target(
            account_id=env.get("R2_ACCOUNT_ID", ""),
            bucket=env.get("R2_ARTIFACT_BUCKET", ""),
            jurisdiction=env.get("R2_JURISDICTION") or None,
        )
    except R2ClientRejected as error:
        raise ArtifactConfigurationError(f"Invalid R2 artifact setting: {error.reason}") from None
    try:
        credentials = R2Credentials(
            access_key_id=env.get("R2_ACCESS_KEY_ID", ""),
            secret_access_key=env.get("R2_SECRET_ACCESS_KEY", ""),
        )
    except ValueError:
        raise ArtifactConfigurationError(
            "R2_ACCESS_KEY_ID and R2_SECRET_ACCESS_KEY are required"
        ) from None
    ca_bundle = env.get("R2_CA_BUNDLE") or None
    if ca_bundle is not None and not (Path(ca_bundle).is_absolute() and Path(ca_bundle).is_file()):
        raise ArtifactConfigurationError(
            "R2_CA_BUNDLE must be the absolute path of a readable file"
        )
    return R2ArtifactStore(target, credentials, ca_bundle=ca_bundle)
