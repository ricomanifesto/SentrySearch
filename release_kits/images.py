"""Push a local platform manifest by digest to an ECR repository, unchanged.

The source is the image's OCI archive that the build recorded (its SHA-256 is in
the verified image bindings). The kit reads the platform manifest blob named by
the binding, checks every blob against its digest, uploads the config and layers
through the ECR API with the isolated client, and puts the manifest's exact bytes
with ``imageDigest`` set, so the registry refuses a manifest that would hash
differently. It then reads the image back by digest and fails unless the stored
bytes still hash to the local digest. Nothing is tagged: repositories are
immutable and releases pin digests.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import tarfile
from typing import Any

from botocore.exceptions import ClientError

PLATFORM_MEDIA_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}
# ECR's UploadLayerPart limit is 20 MiB per part; parts after the first are ordered.
PART_BYTES = 10 * 1024 * 1024


class PushRefused(Exception):
    """The archive, a blob or the registry's answer is not the bound image."""


def digest_of(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class PlatformImage:
    """The bytes of one platform manifest and the blobs it names, all verified."""

    digest: str
    media_type: str
    manifest: bytes
    blobs: dict[str, bytes]

    @property
    def layers(self) -> list[str]:
        document = json.loads(self.manifest)
        return [document["config"]["digest"], *(layer["digest"] for layer in document["layers"])]


def read_archive(path: Path, *, archive_sha256: str, platform_manifest: str) -> PlatformImage:
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != archive_sha256:
        raise PushRefused(f"{path.name} is not the archive the bindings name")
    with tarfile.open(path) as archive:

        def blob(digest: str) -> bytes:
            algorithm, _, hexdigest = digest.partition(":")
            if algorithm != "sha256" or len(hexdigest) != 64:
                raise PushRefused(f"unsupported digest {digest}")
            try:
                member = archive.extractfile(f"blobs/sha256/{hexdigest}")
            except KeyError:
                member = None
            if member is None:
                raise PushRefused(f"{path.name} lacks blob {digest}")
            content = member.read()
            if digest_of(content) != digest:
                raise PushRefused(f"blob {digest} does not match its digest")
            return content

        manifest = blob(platform_manifest)
        document = json.loads(manifest)
        media_type = document.get("mediaType")
        if media_type not in PLATFORM_MEDIA_TYPES:
            raise PushRefused(f"{platform_manifest} is not a platform manifest")
        names = [document["config"]["digest"], *(layer["digest"] for layer in document["layers"])]
        blobs = {name: blob(name) for name in names}
    return PlatformImage(platform_manifest, media_type, manifest, blobs)


def push(ecr: Any, image: PlatformImage, *, repository: str, registry_id: str) -> dict[str, Any]:
    """Upload what the registry lacks, put the manifest by digest, verify the read-back."""
    present = ecr.batch_check_layer_availability(
        registryId=registry_id, repositoryName=repository, layerDigests=image.layers
    )
    if present.get("failures") and any(
        failure.get("failureCode") != "MissingLayerDigest" for failure in present["failures"]
    ):
        raise PushRefused(f"{repository}: the registry could not check the layers")
    available = {layer["layerDigest"] for layer in present.get("layers", [])
                 if layer.get("layerAvailability") == "AVAILABLE"}  # fmt: skip
    uploaded = []
    for name in image.layers:
        if name in available:
            continue
        content = image.blobs[name]
        upload = ecr.initiate_layer_upload(registryId=registry_id, repositoryName=repository)
        upload_id = upload["uploadId"]
        for start in range(0, len(content), PART_BYTES):
            part = content[start : start + PART_BYTES]
            ecr.upload_layer_part(registryId=registry_id, repositoryName=repository,
                                  uploadId=upload_id, partFirstByte=start,
                                  partLastByte=start + len(part) - 1, layerPartBlob=part)  # fmt: skip
        done = ecr.complete_layer_upload(registryId=registry_id, repositoryName=repository,
                                         uploadId=upload_id, layerDigests=[name])  # fmt: skip
        if done.get("layerDigest") != name:
            raise PushRefused(f"{repository}: the registry stored {name} as another digest")
        uploaded.append(name)
    try:
        answer = ecr.put_image(registryId=registry_id, repositoryName=repository,
                               imageManifest=image.manifest.decode(),
                               imageManifestMediaType=image.media_type,
                               imageDigest=image.digest)  # fmt: skip
        stored = answer["image"]["imageId"]["imageDigest"]
    except ClientError as error:
        # A retry after a partial push: an image already stored at this digest counts
        # only once its stored bytes are read back below.
        if error.response.get("Error", {}).get("Code") != "ImageAlreadyExistsException":
            raise
        stored = image.digest
    if stored != image.digest:
        raise PushRefused(f"{repository}: the registry changed the manifest digest")
    read = ecr.batch_get_image(registryId=registry_id, repositoryName=repository,
                               imageIds=[{"imageDigest": image.digest}],
                               acceptedMediaTypes=[image.media_type])  # fmt: skip
    images = read.get("images") or []
    if len(images) != 1 or digest_of(images[0]["imageManifest"].encode()) != image.digest:
        raise PushRefused(f"{repository}: the stored manifest does not hash to {image.digest}")
    return {"repository": repository, "registry_digest": image.digest,
            "uploaded_blobs": uploaded, "already_present": sorted(available)}  # fmt: skip
