"""Build release-tools and both service images, then prove the guarded jobs.

Disposable TLS PostgreSQL and a stand-in ECS metadata endpoint run on an internal
Docker network. No AWS request, registry push or real credential is involved.
"""

import argparse
import os
from pathlib import Path
import subprocess
import sys

from dev.check_service_images import build


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-repo", type=Path, required=True)
    parser.add_argument("--build-ca-file", type=Path)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    runtime_image = build(
        args.runtime_repo.resolve(), "sentryruntime:release-tools-check", None, args.build_ca_file
    )
    tools_image = build(
        repo,
        "sentrysearch:release-tools-check",
        repo / "container" / "release-tools.Dockerfile",
        args.build_ca_file,
    )
    search_image = build(
        repo,
        "sentrysearch:release-tools-product",
        repo / "container" / "Dockerfile",
        args.build_ca_file,
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
            "RELEASE_TOOLS_TEST_IMAGE": tools_image,
            "SENTRYRUNTIME_TEST_IMAGE": runtime_image,
            "SENTRYSEARCH_TEST_IMAGE": search_image,
        }
    )
    subprocess.run(
        [sys.executable, "-m", "pytest", "tests/release_tools_images.py", "-v"],
        cwd=repo,
        env=env,
        check=True,
    )


if __name__ == "__main__":
    main()
