"""Build and prove Fargate-shaped volumes locally; never contact AWS or deploy."""

import argparse
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dev.check_runtime_consistency import isolated_environment
from dev.check_service_images import build


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-repo", type=Path, required=True)
    parser.add_argument("--build-ca-file", type=Path)
    parser.add_argument(
        "--skip-build", action="store_true", help="Use existing local image-check tags"
    )
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    runtime_repo = args.runtime_repo.resolve()
    search_image, runtime_image = "sentrysearch:image-check", "sentryruntime:image-check"
    if not args.skip_build:
        build(runtime_repo, runtime_image, None, args.build_ca_file)
        build(repo, search_image, repo / "container/Dockerfile", args.build_ca_file)
    env = isolated_environment()
    env.update(
        {
            "SENTRYSEARCH_TEST_IMAGE": search_image,
            "SENTRYRUNTIME_TEST_IMAGE": runtime_image,
            "SENTRYRUNTIME_TEST_REPO": str(runtime_repo),
        }
    )
    subprocess.run(
        [sys.executable, "-m", "pytest", "tests/platform_fit.py", "-v"],
        cwd=repo,
        env=env,
        check=True,
    )


if __name__ == "__main__":
    main()
