"""Run the integrated release canary against built images and an S3 stand-in (AWS-06).

``tests/release_canary.py`` drives ``release_cli run`` through the real adapters:
container-backed ECS and Logs fakes run the real job, observer and service
containers on an internal Docker network, and the journal and lock live in an
S3-compatible stand-in. Start the stand-in yourself, from its own environment,
so its version is pinned and recorded:

    python -m venv /tmp/s3-standin && /tmp/s3-standin/bin/pip install 'moto[server]==5.2.3'
    /tmp/s3-standin/bin/moto_server -H 127.0.0.1 -p 47902

then pass ``--s3-endpoint http://127.0.0.1:47902 --s3-standin 'moto 5.2.3'``.
``--image-bindings`` names the JSON that binds each image's local index, platform
manifest and evidence hashes (a build's verified bindings), so the manifest pins
exactly the images that run. No AWS request, registry push or real credential is
involved.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-bindings", type=Path, required=True)
    parser.add_argument("--s3-endpoint", required=True)
    parser.add_argument("--s3-standin", required=True, help="product and version, recorded")
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("pytest_args", nargs="*")
    args = parser.parse_args()
    if not args.s3_endpoint.startswith(("http://127.0.0.1:", "http://localhost:")):
        raise SystemExit("the S3 stand-in must listen on loopback")
    repo = Path(__file__).resolve().parents[1]
    args.artifacts.mkdir(parents=True, exist_ok=True)
    # The stand-in a run's journals and locks lived in, kept with its evidence.
    (args.artifacts / "s3-standin.json").write_text(
        json.dumps({"product": args.s3_standin, "endpoint": args.s3_endpoint}, indent=1) + "\n"
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
            "CANARY_IMAGE_BINDINGS": str(args.image_bindings.resolve()),
            "CANARY_S3_ENDPOINT": args.s3_endpoint,
            "CANARY_S3_STANDIN": args.s3_standin,
            "CANARY_ARTIFACTS": str(args.artifacts.resolve()),
        }
    )
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/release_canary.py", "-v", *args.pytest_args],
        cwd=repo,
        env=env,
        check=False,
    )
    raise SystemExit(completed.returncode)


if __name__ == "__main__":
    main()
