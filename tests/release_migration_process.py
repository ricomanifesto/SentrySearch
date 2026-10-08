"""Run the Search migration release job in its own process for signal tests.

Usage: python tests/release_migration_process.py <ca-file>. The CA path is the
only change from production: the fixture cannot write /run/material. Signals,
exit and the environment are the real ones.
"""

from __future__ import annotations

import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.storage import release_job  # noqa: E402

release_job.CA_FILE = sys.argv[1]
raise SystemExit(release_job.main(dict(os.environ)))
