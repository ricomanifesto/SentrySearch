"""Build the backend and SentryRuntime images, then prove their process contracts."""

import argparse
import os
from pathlib import Path
import subprocess
import sys


def build(context: Path, tag: str, dockerfile: Path | None, build_ca: Path | None) -> None:
    command = ["docker", "build", "--tag", tag]
    if dockerfile is not None:
        command += ["--file", str(dockerfile)]
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
    print(f"{tag} {image_id}", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-repo", type=Path, required=True)
    parser.add_argument("--build-ca-file", type=Path)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    search_image, runtime_image = "sentrysearch:image-check", "sentryruntime:image-check"
    build(args.runtime_repo.resolve(), runtime_image, None, args.build_ca_file)
    build(repo, search_image, repo / "container" / "Dockerfile", args.build_ca_file)
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
        }
    )
    subprocess.run(
        [sys.executable, "-m", "pytest", "tests/service_images.py", "-v"],
        cwd=repo,
        env=env,
        check=True,
    )


if __name__ == "__main__":
    main()
