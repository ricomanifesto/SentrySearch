"""Build/run a local, internal-network report canary. Never deploy or call AWS."""

import argparse
from pathlib import Path
import re
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dev.check_runtime_consistency import isolated_environment
from dev.check_service_images import build


def canary_environment() -> dict[str, str]:
    return {
        key: value
        for key, value in isolated_environment().items()
        if not key.startswith(("NEXT_PUBLIC_SUPABASE_", "SENTRYRUNTIME_TEST_"))
    }


def immutable_local_image(reference: str) -> str:
    identity = subprocess.run(
        ["docker", "image", "inspect", "--format", "{{.Id}}", reference],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", identity):
        raise ValueError("Docker did not resolve a local immutable image ID")
    return identity


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-repo", type=Path, required=True)
    parser.add_argument("--build-ca-file", type=Path)
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--search-image", default="sentrysearch:image-check")
    parser.add_argument("--runtime-image", default="sentryruntime:image-check")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    runtime_repo = args.runtime_repo.resolve()
    if not (runtime_repo / "db/roles/service.sql").is_file():
        parser.error("runtime repository must contain the canonical service-role grant script")
    if not args.skip_build:
        if shutil.disk_usage(repo).free < 3 * 1024**3:
            parser.error("at least 3 GiB of host disk headroom is required before building")
        build(runtime_repo, args.runtime_image, None, args.build_ca_file)
        build(repo, args.search_image, repo / "container/Dockerfile", args.build_ca_file)
    env = canary_environment()
    env.update(
        {
            "SENTRYSEARCH_TEST_IMAGE": immutable_local_image(args.search_image),
            "SENTRYRUNTIME_TEST_IMAGE": immutable_local_image(args.runtime_image),
            "SENTRYRUNTIME_TEST_REPO": str(runtime_repo),
        }
    )
    print(
        "Local canary image identities:",
        env["SENTRYSEARCH_TEST_IMAGE"],
        env["SENTRYRUNTIME_TEST_IMAGE"],
        flush=True,
    )
    subprocess.run(
        [sys.executable, "-m", "pytest", "tests/deterministic_canary.py", "-v", "-s"],
        cwd=repo,
        env=env,
        check=True,
    )


if __name__ == "__main__":
    main()
