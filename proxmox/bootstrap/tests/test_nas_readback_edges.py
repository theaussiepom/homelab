"""Synthetic mount identities exercise refusal paths without mounting or restarting."""

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import host_nas as nas


class NasReadbackEdges(unittest.TestCase):
    def test_each_mount_and_restart_readback_is_required(self):
        scenarios = {
            "ready": None,
            "target-link": "symlink",
            "unmounted": "not empty",
            "export": "selected NAS export",
            "map": "ID map",
            "private-link": "must not be a symlink",
            "permissions": "permissions differ",
            "protection": "protection was not restored",
            "host": "host NAS mount identity",
            "restart-required": "needs a deployment-guest restart",
            "stop": "stop was not confirmed",
            "restart-failed": "did not activate",
            "guest-source": "unambiguous filesystem source",
            "restart": None,
        }
        for scenario, message in scenarios.items():
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                value = {
                    "server": "198.18.20.2",
                    "export": "/volume1/test",
                    "version": "4.1",
                    "directory": "bootstrap-state",
                }
                guest = {
                    "hostname": "deploy",
                    "unprivileged": 1,
                    "node": "pve",
                    "protection": 1 if scenario == "protection" else 0,
                }
                target = root / str(nas.HOST_MOUNT).lstrip("/")
                private = target / value["directory"]
                (root / "etc/systemd/system").mkdir(parents=True)
                if scenario == "target-link":
                    target.parent.mkdir(parents=True)
                    target.symlink_to(root, target_is_directory=True)
                elif scenario == "unmounted":
                    target.mkdir(parents=True)
                    (target / "unmanaged").write_text("preserve")
                if scenario in ("private-link", "permissions"):
                    target.mkdir(parents=True)
                    (
                        private.symlink_to(root, target_is_directory=True)
                        if scenario == "private-link"
                        else private.mkdir(mode=0o700)
                    )
                proc = root / "proc/123"
                proc.mkdir(parents=True)
                (root / "proc/self").mkdir()
                for kind in ("uid", "gid"):
                    (proc / (kind + "_map")).write_text(
                        "0 200000 65536\n" if scenario == "map" else "0 100000 65536\n"
                    )
                source = value["server"] + ":" + value["export"]
                (root / "proc/self/mountinfo").write_text(
                    "1 2 0:1 / /other rw - ext4 /dev/fixture rw\n2 1 0:2 / /mnt/homelab_backups rw - nfs4 "
                    + ("other:/export" if scenario == "host" else source)
                    + " rw\n"
                )
                needs_restart = scenario in (
                    "restart-required",
                    "stop",
                    "restart-failed",
                    "restart",
                )
                guest_mount = (
                    "3 1 0:2 /bootstrap-state /srv/homelab-backups rw - nfs4 "
                    + source
                    + " rw\n"
                )
                (proc / "mountinfo").write_text("" if needs_restart else guest_mount)
                owners = {}
                config = {"protection": guest["protection"]}
                calls = []
                real_stat = Path.stat

                def stat(path, *args, **kwargs):
                    if path == proc / "root/srv/homelab-backups":
                        path = private
                    result = real_stat(path, *args, **kwargs)
                    # Path.is_symlink() uses stat(follow_symlinks=False) on 3.13.
                    # Preserve that native result; calling it here recurses.
                    if path == private and kwargs.get("follow_symlinks", True):
                        fields = list(result)
                        fields[4:6] = owners.get(
                            path,
                            (0, 0) if scenario == "permissions" else (101000, 101000),
                        )
                        return os.stat_result(fields)
                    return result

                def execute(args):
                    calls.append(args)
                    if args[0] == "findmnt":
                        return (
                            "nfs4 other:/share"
                            if scenario == "export"
                            else "nfs4 " + source
                        )
                    if args[0] == "lxc-info":
                        return "123"
                    if args[:2] == ["pct", "exec"]:
                        if args[4] == "id":
                            return "1000"
                        return (
                            "ambiguous"
                            if scenario == "guest-source"
                            else "nfs4 " + source + "[/bootstrap-state]"
                        )
                    if args[:2] == ["pct", "set"]:
                        if args[3] == "--mp0":
                            config["mp0"] = args[4]
                        else:
                            config["protection"] = (
                                0 if scenario == "protection" else int(args[4])
                            )
                    if args[:2] == ["pvesh", "get"]:
                        return json.dumps(config)
                    if args[:2] == ["pct", "status"]:
                        return (
                            "status: running"
                            if scenario == "stop"
                            else "status: stopped"
                        )
                    if args[:2] == ["pct", "start"] and scenario != "restart-failed":
                        (proc / "mountinfo").write_text(guest_mount)
                    return ""

                with (
                    patch.object(
                        nas.os.path, "ismount", return_value=scenario != "unmounted"
                    ),
                    patch.object(
                        nas.os,
                        "chown",
                        side_effect=lambda path, uid, gid: owners.update(
                            {path: (uid, gid)}
                        ),
                    ),
                    patch.object(Path, "stat", stat),
                ):
                    if message is None:
                        result = nas.ensure(
                            value, 900, guest, execute, root, restart=True
                        )
                        self.assertEqual(result["mapped_uid"], 101000)
                        self.assertEqual(
                            result["backup_source"], source + "[/bootstrap-state]"
                        )
                    else:
                        with self.assertRaisesRegex(RuntimeError, message):
                            nas.ensure(
                                value,
                                900,
                                guest,
                                execute,
                                root,
                                restart=scenario != "restart-required",
                                unprotect=scenario == "protection",
                            )
                self.assertFalse(any(args[:2] == ["pct", "stop"] for args in calls))
                if scenario == "stop":
                    self.assertFalse(
                        any(args[:2] == ["pct", "start"] for args in calls)
                    )

    def test_nas_contract_is_closed(self):
        with self.assertRaisesRegex(RuntimeError, "server, export"):
            nas.validate({})
