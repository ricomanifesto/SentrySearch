"""One-shot file-secret and scratch-volume initialization, never app startup.

Run as root before the non-root service, with fresh task-local volumes. A failed
or replaced task discards its volumes; this helper never overwrites or rotates
an existing task's files. AWS is used only with an explicitly selected version.
"""

from __future__ import annotations

import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import re
import ssl
import sys

import boto3

MAX_BYTES = 65536  # Secrets Manager SecretString ceiling; includes JSON overhead.
PROFILES = {
    "runtime": (
        65532,
        {"server-cert.pem", "server-key.pem", "runtime-ca.pem", "postgres-ca.pem", "probe-token"},
    ),
    "search": (10001, {"runtime-ca.pem", "postgres-ca.pem"}),
    "runtime-release": (65532, {"postgres-ca.pem"}),
    "search-release": (10001, {"postgres-ca.pem"}),
}


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate material key")
        value[key] = item
    return value


def _reject_password_prompt():
    raise ValueError("Encrypted private keys are not supported")


def _material(profile: str, payload: str) -> dict[str, str]:
    if len(payload.encode("utf-8")) > MAX_BYTES:
        raise ValueError("Oversized secret")
    material = json.loads(payload, object_pairs_hook=_unique_object)
    if not isinstance(material, dict) or set(material) != PROFILES[profile][1]:
        raise ValueError("Unexpected material keys")
    for name, value in material.items():
        if not isinstance(value, str) or not value or "\x00" in value:
            raise ValueError("Invalid material value")
        if name.endswith("-ca.pem"):
            try:
                ssl.create_default_context(cadata=value)
            except (ssl.SSLError, ValueError) as error:
                raise ValueError("Invalid CA material") from error
        elif name == "probe-token":
            if re.fullmatch(r"[A-Za-z0-9._~-]{32,4096}", value) is None:
                raise ValueError("Invalid token material")
        elif name == "server-cert.pem":
            try:
                ssl.PEM_cert_to_DER_cert(value)
            except ValueError as error:
                raise ValueError("Invalid certificate material") from error
        elif not value.startswith(
            (
                "-----BEGIN PRIVATE KEY-----\n",
                "-----BEGIN RSA PRIVATE KEY-----\n",
                "-----BEGIN EC PRIVATE KEY-----\n",
            )
        ):
            raise ValueError("Invalid unencrypted private key material")
    return material


def _directory(path: Path) -> int:
    # Open each ancestor without following symlinks, retaining the verified fd.
    # Mount roots must already exist; arbitrary directory creation is forbidden.
    if not path.is_absolute() or path == Path("/") or ".." in path.parts:
        raise ValueError("An absolute mounted directory is required")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open("/", flags)
    try:
        for part in path.parts[1:]:
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        if os.fstat(descriptor).st_uid != os.geteuid() or os.listdir(descriptor):
            raise ValueError("Only fresh empty initializer-owned volumes are supported")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def prepare(
    profile: str,
    payload: str,
    material_dir: Path,
    tmp_dir: Path | None = None,
    work_dir: Path | None = None,
) -> None:
    material = _material(profile, payload)
    if (profile == "search" and (tmp_dir is None or work_dir is None)) or (
        profile != "search" and (tmp_dir is not None or work_dir is not None)
    ):
        raise ValueError("Scratch volumes are required only for the search profile")
    paths = [material_dir, *([tmp_dir, work_dir] if profile == "search" else [])]
    for index, path in enumerate(paths):
        for other in paths[index + 1 :]:
            if path == other or path in other.parents or other in path.parents:
                raise ValueError("Mount roots must be independent")
    uid = PROFILES[profile][0]
    with ExitStack() as resources:
        directories = []
        for path in paths:
            descriptor = _directory(path)
            resources.callback(os.close, descriptor)
            directories.append(descriptor)
        identities = {(os.fstat(fd).st_dev, os.fstat(fd).st_ino) for fd in directories}
        if len(identities) != len(directories):
            raise ValueError("Mount roots must use distinct volume directories")
        # Validate every root before the first mutation. Failed partial writes
        # remain private and nonempty so a retry fails instead of mixing versions.
        for descriptor in directories:
            os.fchmod(descriptor, 0o700)
        files = {}
        for name, value in material.items():
            descriptor = os.open(
                name,
                os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW,
                0o600,
                dir_fd=directories[0],
            )
            handle = resources.enter_context(os.fdopen(descriptor, "w+b"))
            handle.write(value.encode("utf-8"))
            handle.flush()
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o400)
            files[name] = descriptor
        if profile == "runtime":
            descriptor_root = "/proc/self/fd" if Path("/proc/self/fd").is_dir() else "/dev/fd"
            try:
                for descriptor in files.values():
                    os.lseek(descriptor, 0, os.SEEK_SET)
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(
                    f"{descriptor_root}/{files['server-cert.pem']}",
                    f"{descriptor_root}/{files['server-key.pem']}",
                    password=_reject_password_prompt,
                )
            except (ssl.SSLError, OSError) as error:
                raise ValueError("Invalid certificate/key pair") from error
        for descriptor in files.values():
            os.fchown(descriptor, uid, uid)
        for descriptor in directories:
            os.fchown(descriptor, uid, uid)


def fetch_secret(client, secret_id: str, version_id: str) -> str:
    if re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", version_id) is None:
        raise ValueError("An immutable UUID secret version is required")
    response = client.get_secret_value(SecretId=secret_id, VersionId=version_id)
    if response.get("VersionId") != version_id or not isinstance(response.get("SecretString"), str):
        raise ValueError("Expected exact SecretString version")
    return response["SecretString"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=PROFILES, required=True)
    parser.add_argument("--material-dir", type=Path, required=True)
    parser.add_argument("--tmp-dir", type=Path)
    parser.add_argument("--work-dir", type=Path)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--fixture-stdin", action="store_true", help="Disposable local proof only")
    source.add_argument("--secret-id")
    parser.add_argument("--version-id")
    parser.add_argument("--region")
    args = parser.parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise ValueError("Initializer must run as root")
        if args.fixture_stdin:
            if args.version_id or args.region:
                raise ValueError("AWS options are invalid for fixture mode")
            payload = sys.stdin.read(MAX_BYTES + 1)
        else:
            if not args.version_id or not args.region:
                raise ValueError("An exact version and region are required")
            if (
                re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d", args.region) is None
                or re.fullmatch(
                    rf"arn:aws:secretsmanager:{re.escape(args.region)}:\d{{12}}:secret:[A-Za-z0-9/_+=.@-]+",
                    args.secret_id,
                )
                is None
            ):
                raise ValueError("An explicit regional Secrets Manager ARN is required")
            payload = fetch_secret(
                boto3.client("secretsmanager", region_name=args.region),
                args.secret_id,
                args.version_id,
            )
        prepare(args.profile, payload, args.material_dir, args.tmp_dir, args.work_dir)
    except Exception:
        # SDK, JSON, TLS, and filesystem errors may contain sensitive inputs.
        # Deliberately do not emit exception details or the supplied material.
        print("Service volume initialization failed", file=sys.stderr)
        return 1
    print("Service volumes initialized")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
