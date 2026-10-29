"""An existing unchanged guest needs neither apply nor new SSH trust."""

import copy
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import deployment_inputs
import proxmox_guest as pve
import private_io
from fixtures import guest
from test_plan import fixture as plan_fixture


class InfrastructureNoopTests(unittest.TestCase):
    def test_existing_guest_noop_does_not_apply_or_repin(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = guest(root)
            cfg["guest"]["vmid"] = cfg["app"]["vmid"] = 6100
            cfg["site"]["node"] = "pve-lab"
            work = root / "work"
            work.mkdir()
            operation = root / "attempt"
            operation.mkdir()
            state = work / "terraform.tfstate"
            state.write_bytes(b"existing authoritative backend")
            (root / "api").write_text("fixture@pve!deploy=synthetic")
            (root / "api").chmod(0o600)
            plan = plan_fixture()
            for row in plan["resource_changes"]:
                row["change"].update(
                    actions=["no-op"], before=copy.deepcopy(row["change"]["after"])
                )
            commands = []

            def quiet(args, environment, log):
                commands.append(args)
                if "plan" in args:
                    (operation / "guest.tfplan").write_bytes(b"saved no-op plan")

            with (
                patch.object(
                    deployment_inputs, "binding", return_value={"approved": True}
                ),
                patch.object(pve, "backup"),
                patch.object(pve, "quiet", side_effect=quiet),
                patch.object(
                    pve.subprocess,
                    "check_output",
                    return_value=json.dumps(plan).encode(),
                ),
                patch.object(pve.guest_identity, "pin") as pin,
            ):
                result = pve.infrastructure(
                    cfg, root / "site", work, operation, {"approved": True}
                )
            self.assertFalse(result["created"])
            self.assertFalse(result["changed"])
            self.assertFalse(any("apply" in command for command in commands))
            pin.assert_not_called()
            self.assertEqual(state.read_bytes(), b"existing authoritative backend")

    def test_pre_creation_backup_records_absence_without_fabricating_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = guest(root)
            backup = root / "backup"
            backup.mkdir(mode=0o700)

            @contextmanager
            def directory(cfg):
                fd = os.open(backup, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    yield fd
                finally:
                    os.close(fd)

            with patch.object(pve, "recovery_directory", directory):
                pve.backup(cfg, root / "absent", "before")
            files = list(backup.iterdir())
            self.assertEqual(len(files), 1)
            self.assertEqual(
                private_io.read_json(files[0], private=True),
                {"state": "not-created", "vmid": cfg["guest"]["vmid"]},
            )
