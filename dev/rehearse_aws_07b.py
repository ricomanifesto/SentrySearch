"""Rehearse the AWS-07b kit end to end against loopback stand-ins (no AWS request).

``tests/release_kit_rehearsal.py`` runs the kit's ``init`` and all eleven steps:
moto answers ECR (through a layer-upload shim), S3, Secrets Manager, STS and IAM;
each Terraform step plans with the mocked provider (apply is not rehearsed); and
the run step drives ``release_cli run`` through the release canary's
container-backed ECS and Logs fakes with the built images. Start moto yourself,
from its own environment, in the staging account, so its version is pinned and
recorded:

    python -m venv /tmp/kit-moto && /tmp/kit-moto/bin/pip install 'moto[server]==5.2.3'
    MOTO_ACCOUNT_ID=111122223333 /tmp/kit-moto/bin/moto_server -H 127.0.0.1 -p 47903

then pass ``--moto-endpoint http://127.0.0.1:47903 --moto 'moto 5.2.3'``.
``--terraform`` is the pinned 1.16.5 binary and ``--plugin-dir`` a provider mirror
holding the locked AWS provider, so nothing is downloaded during the plans.
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
    parser.add_argument("--moto-endpoint", required=True)
    parser.add_argument("--moto", required=True, help="product and version, recorded")
    parser.add_argument("--terraform", type=Path, required=True)
    parser.add_argument("--plugin-dir", type=Path, required=True)
    parser.add_argument("--runtime-checkout", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("pytest_args", nargs="*")
    args = parser.parse_args()
    if not args.moto_endpoint.startswith(("http://127.0.0.1:", "http://localhost:")):
        raise SystemExit("the moto stand-in must listen on loopback")
    repo = Path(__file__).resolve().parents[1]
    args.artifacts.mkdir(parents=True, exist_ok=True)
    (args.artifacts / "moto-standin.json").write_text(
        json.dumps({"product": args.moto, "endpoint": args.moto_endpoint}, indent=1) + "\n"
    )
    # Containers and the kit receive only explicit settings; never forward host secrets.
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("AWS_", "OPENROUTER_", "SUPABASE_", "DB_", "PG", "SENTRYRUNTIME_"))
    }
    env.update(
        {
            "PYTHON_DOTENV_DISABLED": "1",
            "CANARY_IMAGE_BINDINGS": str(args.image_bindings.resolve()),
            # The canary's evidence reader looks for the journal in the same stand-in.
            "CANARY_S3_ENDPOINT": args.moto_endpoint,
            "CANARY_S3_STANDIN": args.moto,
            "CANARY_ARTIFACTS": str(args.artifacts.resolve()),
            "KIT_MOTO_ENDPOINT": args.moto_endpoint,
            "KIT_TERRAFORM": str(args.terraform.resolve()),
            "KIT_TERRAFORM_PLUGIN_DIR": str(args.plugin_dir.resolve()),
            "KIT_RUNTIME_CHECKOUT": str(args.runtime_checkout.resolve()),
        }
    )
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/release_kit_rehearsal.py", "-v", *args.pytest_args],
        cwd=repo,
        env=env,
        check=False,
    )
    raise SystemExit(completed.returncode)


if __name__ == "__main__":
    main()
