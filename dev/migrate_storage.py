"""Apply product release migrations, or check compatibility without DDL.

``--release-job`` runs the migration as a guarded release job (deadline, task
identity, verified bounded session and one receipt); see src/storage/release_job.py.
It reads only the task definition's environment and never loads a dotenv file.
"""

import argparse
import os
import sys

from dotenv import load_dotenv


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check", action="store_true", help="read-only check using application credentials"
    )
    mode.add_argument(
        "--release-job",
        action="store_true",
        help="guarded attended release job (receipt on stdout)",
    )
    args = parser.parse_args(argv)
    if args.release_job:
        from src.storage.release_job import main as release_job

        return release_job(dict(os.environ))
    load_dotenv()
    try:
        # Load settings only after dotenv. Migration credentials are supplied to
        # this separate process, never stored as a second application credential.
        from src.storage.database import db_manager

        if args.check:
            db_manager.require_schema()
        else:
            db_manager.migrate_schema()
        print("Storage schema ready")
        return 0
    except Exception:
        print(
            "Storage release check failed; verify configuration, schema and database role",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
