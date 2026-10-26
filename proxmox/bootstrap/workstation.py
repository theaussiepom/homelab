"""Keep separate Docker runs from writing the workstation state concurrently."""
from pathlib import Path
import subprocess
import sys

from bootstrap import Refused
from native import workspace_lock


def run(work, command, configuration=False):
    # Docker Desktop bind-mount locking is not sufficient between containers.
    # Hold the workstation's lock until the Docker command has terminated.
    """Keep the workstation lock held across the complete Docker operation."""
    with workspace_lock(work.resolve(), backup=configuration, name='.workstation.lock'):
        return subprocess.run(command, check=False).returncode


if __name__ == '__main__':
    try:
        args = sys.argv[1:]
        configuration = args[0] == '--configuration'
        if configuration:
            args = args[1:]
        raise SystemExit(run(Path(args[0]), args[1:], configuration=configuration))
    except (Refused, OSError) as exc:
        raise SystemExit(str(exc) if isinstance(exc, Refused) else 'Workstation execution failed; inspect private evidence')
