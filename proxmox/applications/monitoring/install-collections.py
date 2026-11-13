"""Install only the pinned Zabbix API module dependencies from verified archives.

The native agent installer uses builtin Ansible tasks. Unused collection roles
and their Windows/database dependencies are deliberately not installed.
"""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from urllib.request import urlopen


def install(output, lock=None):
    output.mkdir(parents=True, exist_ok=True)
    lock = (
        json.loads(Path(__file__).with_name("collections.lock.json").read_text())
        if lock is None
        else lock
    )
    for name, expected in lock.items():
        destination = output / name
        if not destination.exists():
            with urlopen(
                "https://galaxy.ansible.com/api/v3/plugin/ansible/content/published/collections/artifacts/"
                + name,
                timeout=60,
            ) as response:
                content = response.read(4 * 1024 * 1024 + 1)
            if (
                len(content) > 4 * 1024 * 1024
                or hashlib.sha256(content).hexdigest() != expected
            ):
                raise SystemExit("Collection archive differs from its pinned digest")
            destination.write_bytes(content)
        if hashlib.sha256(destination.read_bytes()).hexdigest() != expected:
            raise SystemExit(
                "Retained collection archive differs from its pinned digest"
            )
        subprocess.run(
            [
                "ansible-galaxy",
                "collection",
                "install",
                "--no-deps",
                "-p",
                str(output),
                str(destination),
            ],
            check=True,
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    install(parser.parse_args().output)


if __name__ == "__main__":
    main()
