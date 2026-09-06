"""Apply product release migrations, or check compatibility without DDL."""

import argparse
import sys

from dotenv import load_dotenv


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true", help="read-only check using application credentials"
    )
    args = parser.parse_args(argv)
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
