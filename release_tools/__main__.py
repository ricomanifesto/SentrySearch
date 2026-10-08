import os
import sys

from release_tools import jobs, observe

command = sys.argv[1:]
program = observe.main if command[:1] and command[0] in observe.COMMANDS else jobs.main
raise SystemExit(program(command, dict(os.environ)))
