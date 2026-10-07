"""Build the backend and SentryRuntime images, then prove their process contracts."""

import argparse
import os
from pathlib import Path
import re
import subprocess
import sys


def build(
    context: Path,
    tag: str,
    dockerfile: Path | None,
    build_ca: Path | None,
    *,
    target: str | None = None,
) -> str:
    command = ["docker", "build", "--tag", tag]
    if dockerfile is not None:
        command += ["--file", str(dockerfile)]
    if target is not None:
        command += ["--target", target]
    if build_ca is not None:
        # Optional complete PEM bundle for TLS-intercepting build egress only.
        command += ["--secret", f"id=build_ca,src={build_ca}"]
    subprocess.run([*command, str(context)], check=True)
    image_id = subprocess.run(
        ["docker", "image", "inspect", "--format", "{{.Id}}", tag],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise ValueError("Docker did not return an immutable image identity")
    print(f"{tag} {image_id}", flush=True)
    return image_id


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-repo", type=Path, required=True)
    parser.add_argument("--build-ca-file", type=Path)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    runtime_image = build(
        args.runtime_repo.resolve(), "sentryruntime:image-check", None, args.build_ca_file
    )
    search_image = build(
        repo, "sentrysearch:image-check", repo / "container" / "Dockerfile", args.build_ca_file
    )
    probe_image = build(
        repo,
        "sentrysearch:liblzma-test-tools",
        repo / "container" / "Dockerfile",
        args.build_ca_file,
        target="liblzma-test-tools",
    )
    # Containers receive only explicit disposable settings; never forward host secrets.
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("AWS_", "OPENROUTER_", "SUPABASE_", "DB_", "PG", "SENTRYRUNTIME_"))
    }
    env.update(
        {
            "PYTHON_DOTENV_DISABLED": "1",
            "SENTRYSEARCH_TEST_IMAGE": search_image,
            "SENTRYRUNTIME_TEST_IMAGE": runtime_image,
            "SENTRYRUNTIME_TEST_REPO": str(args.runtime_repo.resolve()),
            "SENTRYSEARCH_LIBLZMA_TEST_IMAGE": probe_image,
        }
    )
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "tests/service_images.py",
            "tests/platform_fit.py",
            "tests/liblzma_backport.py",
            "-v",
        ],
        cwd=repo,
        env=env,
        check=True,
    )


if __name__ == "__main__":
    main()
