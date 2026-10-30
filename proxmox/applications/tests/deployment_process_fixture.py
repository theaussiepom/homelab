"""Disposable deployment processes; native guest operations are synthetic only."""

import json
import os
from pathlib import Path
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import deploy
import deployment_inputs as inputs
import private_io as io
from fixtures import guest


def checkpoint(name):
    print(name, flush=True)
    if sys.stdin.readline() != "continue\n":
        raise RuntimeError("Fixture checkpoint was not released")


def run(root, mode, phase, pause, run_id):
    cfg = guest(root)
    os.environ.update(
        GITHUB_RUN_ID=run_id,
        GITHUB_RUN_ATTEMPT="1",
        GITHUB_RUN_NUMBER=run_id,
        GITHUB_REPOSITORY="example/private-site",
        HOMELAB_DEPLOYMENT_WORKFLOW="example/private-site/.github/workflows/deploy.yml@refs/heads/main",
    )
    if mode == "prepare":
        original_directory, original_write = inputs.private_directory, inputs.write_new

        def directory(path, create=False):
            if create and path.name == "a" * 64 and pause == "create":
                checkpoint("create-ready")
            original_directory(path, create=create)

        def write(path, value):
            original_write(path, value)
            if path.name == "site.json" and pause == "partial":
                checkpoint("input-partial")

        with (
            patch.object(inputs, "private_directory", side_effect=directory),
            patch.object(inputs, "write_new", side_effect=write),
        ):
            inputs.prepare(root / "packet.json", root / "inputs")
    else:

        def operation(*args):
            with io.private_writer(root / "guest-operations", append=True) as stream:
                stream.write((phase + "\n").encode())
            if pause == "operation":
                checkpoint("operation-complete")
            return {
                "status": "passed",
                "created": False,
                "changed": False,
                "state_sha256": io.sha(root / "state/808/terraform.tfstate"),
            }

        with (
            patch.object(inputs, "prepare", return_value=(cfg, root / "site.json")),
            patch.object(
                inputs, "binding", return_value={"vmid": 808, "site_sha256": "a" * 64}
            ),
            patch.object(deploy.proxmox_guest, "infrastructure", side_effect=operation),
            patch.object(deploy.ansible_guest, "run_phase", side_effect=operation),
        ):
            deploy.run(phase, root / "packet.json")
    print(json.dumps({"status": "passed"}), flush=True)


if __name__ == "__main__":
    try:
        run(Path(sys.argv[1]), *sys.argv[2:])
    except Exception as error:
        print(type(error).__name__, flush=True)
        raise SystemExit(2) from None
