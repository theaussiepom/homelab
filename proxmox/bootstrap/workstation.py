"""Keep separate Docker runs from writing the workstation state concurrently."""
from pathlib import Path
import subprocess
import sys

from bootstrap import Refused
from native import workspace_lock


def run(work, command):
    # Docker Desktop bind-mount locking is not sufficient between containers.
    # Hold the workstation's lock until the Docker command has terminated.
    """Keep the workstation lock held across the complete Docker operation."""
    with workspace_lock(work.resolve(), name='.workstation.lock'):
        return subprocess.run(command, check=False).returncode


if __name__ == '__main__':
    try:
        raise SystemExit(run(Path(sys.argv[1]), sys.argv[2:]))
    except (Refused, OSError) as exc:
        raise SystemExit(str(exc) if isinstance(exc, Refused) else 'Workstation execution failed; inspect private evidence')
