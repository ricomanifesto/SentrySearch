import os
import sys

from release_tools.jobs import main

raise SystemExit(main(sys.argv[1:], dict(os.environ)))
