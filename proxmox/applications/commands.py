"""Execute an exact argv with output confined to an owned private evidence log."""

import os
import subprocess
from private_io import private_writer


def is_ancestor(workspace, previous, selected):
    """Check private source ancestry locally without contacting any target."""
    return (
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", previous, selected],
            cwd=workspace,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
        == 0
    )


def quiet(command, environment, log, cwd=None, *, input_bytes=None, timeout=None):
    with private_writer(log, append=True) as output:
        os.set_blocking(output.fileno(), True)
        subprocess.run(
            command,
            env=environment,
            cwd=cwd,
            stdout=output,
            stderr=output,
            check=True,
            input=input_bytes,
            timeout=timeout,
        )
