"""The host capability cannot widen authority or replace existing hardware."""

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import host_device_helper as helper
import host_devices as client
import plan_policy
from test_plan import existing_fixture


def policy():
    return {
        "schema": helper.SCHEMA,
        "node": "fixture-pve",
        "vmid": 209,
        "hostname": "radio",
        "mac": "02:00:00:00:00:09",
        "device": helper.device_spec("/dev/serial/by-id/usb-fixture"),
    }


class HostDeviceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.policy = policy()
        self.config = {
            "hostname": "radio",
            "unprivileged": 1,
            "protection": 1,
            "net0": "hwaddr=02:00:00:00:00:09,bridge=vmbr0",
            "digest": "a" * 40,
        }
        self.calls = []
        self.pending = []

    def execute(self, argv):
        self.calls.append(argv)
        if argv[0] == "/usr/bin/pvesh":
            if argv[2].endswith("/pending"):
                return json.dumps(self.pending)
            return json.dumps(self.config)
        if argv[1] == "set":
            self.config["dev0"] = argv[4]
        return ""

    def perform(self, action="attach", request=None, execute=None):
        with (
            patch.object(helper.socket, "gethostname", return_value="fixture-pve"),
            patch.object(
                helper.os, "stat", return_value=SimpleNamespace(st_mode=stat.S_IFCHR)
            ),
        ):
            return helper.perform(
                self.policy,
                action,
                self.policy if request is None else request,
                self.execute if execute is None else execute,
            )

    def test_check_is_read_only_and_attach_is_exact_idempotent_and_running(self):
        self.assertFalse(self.perform("check")["changed"])
        self.assertEqual(self.calls, [])
        first = self.perform()
        self.assertTrue(first["changed"])
        self.assertEqual(
            first["policy_sha256"],
            hashlib.sha256(helper.encoded(self.policy)).hexdigest(),
        )
        self.assertFalse(self.perform()["changed"])
        changes = [c for c in self.calls if c[1] == "set"]
        self.assertEqual(
            changes,
            [
                [
                    "/usr/sbin/pct",
                    "set",
                    "209",
                    "--dev0",
                    "/dev/serial/by-id/usb-fixture,uid=0,gid=20,mode=0660,deny-write=0",
                    "--digest",
                    "a" * 40,
                ]
            ],
        )
        self.assertIn(
            [
                "/usr/sbin/pct",
                "exec",
                "209",
                "--",
                "/usr/bin/test",
                "-c",
                "/dev/serial/by-id/usb-fixture",
            ],
            self.calls,
        )

    def test_request_cannot_change_action_host_guest_or_physical_identity(self):
        for change in (
            {"vmid": 210},
            {"node": "other"},
            {"hostname": "other"},
            {"extra": True},
            {"device": helper.device_spec("/dev/serial/by-id/usb-other")},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.perform(request=dict(self.policy, **change))
        self.assertRaises(ValueError, self.perform, "shell")
        with patch.object(helper.socket, "gethostname", return_value="wrong"):
            self.assertRaises(
                ValueError,
                helper.perform,
                self.policy,
                "check",
                self.policy,
                self.execute,
            )
        with (
            patch.object(helper.socket, "gethostname", return_value="fixture-pve"),
            patch.object(
                helper.os, "stat", return_value=SimpleNamespace(st_mode=stat.S_IFREG)
            ),
        ):
            self.assertRaises(
                ValueError,
                helper.perform,
                self.policy,
                "check",
                self.policy,
                self.execute,
            )
        self.assertEqual(self.calls, [])

    def test_current_guest_identity_and_digest_are_required_before_attachment(self):
        for field, value in [
            ("hostname", "wrong"),
            ("unprivileged", 0),
            ("protection", 0),
            ("net0", "hwaddr=02:00:00:00:00:08"),
            ("digest", "wrong"),
        ]:
            before = copy.deepcopy(self.config)
            self.config[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.perform()
            self.config = before
        self.assertFalse(any(c[1] == "set" for c in self.calls))

    def test_existing_devices_are_never_replaced_removed_or_normalized(self):
        for field, value in [
            ("dev1", "/dev/serial/by-id/usb-other"),
            ("dev0", "/dev/serial/by-id/usb-other,uid=0,gid=20,mode=0660"),
            ("dev0", "/dev/serial/by-id/usb-fixture,uid=0,gid=20,mode=0666"),
            ("dev0", "/dev/serial/by-id/usb-fixture,uid=0,uid=0,gid=20,mode=0660"),
        ]:
            self.config[field] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.perform()
            self.config.pop(field)
        self.assertFalse(any(c[1] == "set" for c in self.calls))
        self.config["dev0"] = "/dev/serial/by-id/usb-fixture,uid=0,gid=20,mode=0660"
        self.assertFalse(self.perform()["changed"])

    def test_failed_apply_or_failed_live_readback_never_reports_success(self):
        def unchanged(argv):
            if argv[0] == "/usr/bin/pvesh":
                if argv[2].endswith("/pending"):
                    return "[]"
                return json.dumps(self.config)
            return ""

        self.assertRaises(ValueError, self.perform, execute=unchanged)

        def failed(argv):
            raise subprocess.CalledProcessError(1, argv)

        self.assertRaises(subprocess.CalledProcessError, self.perform, execute=failed)

    def test_pending_device_changes_are_preserved_before_attachment(self):
        for pending in (
            [{"key": "dev0", "pending": "/dev/serial/by-id/usb-other"}],
            [{"key": "dev1", "delete": 1}],
            [{"key": "dev0", "pending": ""}],
            {},
            [{}],
            [None],
        ):
            self.pending = pending
            with (
                self.subTest(pending=pending),
                self.assertRaisesRegex(ValueError, "pending device"),
            ):
                self.perform()
        self.assertFalse(any(c[1] == "set" for c in self.calls))
        self.pending = [{"key": "memory", "value": "4096"}]
        self.assertTrue(self.perform()["changed"])

    def test_policy_schema_duplicates_and_shell_metacharacters_are_refused(self):
        for change in (
            {"schema": "old"},
            {"extra": 1},
            {"vmid": True},
            {"vmid": 900},
            {"node": "-option"},
            {"mac": "00:00:00:00:00:09"},
            {"device": dict(self.policy["device"], uid=False)},
            {"device": None},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                helper.validate(dict(self.policy, **change))
        for path in (
            "/dev/ttyACM0",
            "/dev/serial/by-id/usb-x,uid=0",
            "/dev/serial/by-id/../../etc/passwd",
            None,
        ):
            self.assertRaises(ValueError, helper.device_spec, path)
        self.assertRaises(ValueError, helper.decode, '{"a":1,"a":2}')

    def test_policy_read_requires_root_private_regular_single_link_files(self):
        folder = self.root / "policy"
        folder.mkdir(mode=0o700)
        source = folder / "209.json"
        source.write_bytes(helper.encoded(self.policy))
        source.chmod(0o600)
        actual_lstat = Path.lstat
        actual_fstat = os.fstat

        def root_stat(path):
            value = actual_lstat(path)
            return SimpleNamespace(st_mode=value.st_mode, st_uid=0)

        def root_file(fd):
            value = actual_fstat(fd)
            return SimpleNamespace(
                st_mode=value.st_mode,
                st_uid=0,
                st_nlink=value.st_nlink,
                st_size=value.st_size,
            )

        with (
            patch.object(helper.os, "getuid", return_value=0),
            patch.object(Path, "lstat", root_stat),
            patch.object(helper.os, "fstat", side_effect=root_file),
        ):
            self.assertEqual(helper.read_policy(source), self.policy)
            source.chmod(0o644)
            self.assertRaises(ValueError, helper.read_policy, source)
            source.chmod(0o600)
            os.link(source, folder / "retained")
            self.assertRaises(ValueError, helper.read_policy, source)
        with patch.object(helper.os, "getuid", return_value=1000):
            self.assertRaises(ValueError, helper.read_policy, source)
        with patch.object(helper.os, "getuid", return_value=0):
            folder.chmod(0o755)
            self.assertRaises(ValueError, helper.read_policy, source)

    def test_capability_cli_is_bounded_and_never_prints_private_errors(self):
        for data, failed in [
            (helper.encoded(self.policy), False),
            (b"x" * 16385, True),
            (b"not-json", True),
        ]:
            stream = SimpleNamespace(buffer=io.BytesIO(data))
            with (
                patch.object(sys, "argv", ["helper", "--policy", "/policy/209.json"]),
                patch.object(sys, "stdin", stream),
                patch.object(helper, "read_policy", return_value=self.policy),
                patch.object(helper, "perform", return_value={"changed": False}),
                patch("sys.stdout", new_callable=io.StringIO) as output,
            ):
                if failed:
                    self.assertRaises(SystemExit, helper.main)
                else:
                    helper.main()
                    self.assertEqual(json.loads(output.getvalue()), {"changed": False})
        with patch.object(helper.subprocess, "check_output", return_value="ok") as run:
            self.assertEqual(helper.command(["example"]), "ok")
            self.assertEqual(run.call_args.kwargs["timeout"], 30)

    def cfg(self):
        key, hosts = self.root / "key", self.root / "hosts"
        for path in (key, hosts):
            path.write_bytes(b"synthetic")
            path.chmod(0o600)
        return {
            "site": {
                "node": "fixture-pve",
                "api_endpoint": "https://198.18.25.10:8006/",
            },
            "guest": {
                "vmid": 209,
                "hostname": "radio",
                "serial_device": {"path": self.policy["device"]["path"]},
            },
            "app": {"mac": self.policy["mac"]},
            "paths": {"host_device_key": str(key), "host_known_hosts": str(hosts)},
        }

    def test_runner_pins_transport_policy_and_response_and_preserves_receipts(self):
        cfg = self.cfg()
        answer = {
            "schema": helper.SCHEMA,
            "vmid": 209,
            "changed": False,
            "helper_sha256": helper.implementation_digest(),
            "policy_sha256": hashlib.sha256(helper.encoded(self.policy)).hexdigest(),
        }
        from private_io import write_new

        def response(raw):
            def quiet(argv, environment, log, **kwargs):
                write_new(log, raw)

            return quiet

        with patch.object(
            client, "quiet", side_effect=response(json.dumps(answer).encode())
        ) as run:
            client.check(cfg, self.root)
            self.assertFalse(client.attach(cfg, self.root))
            argv = run.call_args.args[0]
            self.assertIn("StrictHostKeyChecking=yes", argv)
            self.assertIn("IdentitiesOnly=yes", argv)
            self.assertEqual(argv[-2:], ["root@198.18.25.10", "attach"])
            self.assertEqual(
                helper.decode(run.call_args.kwargs["input_bytes"]), self.policy
            )
            self.assertEqual(run.call_args.kwargs["timeout"], 180)
            self.assertRaises(ValueError, client.check, cfg, self.root)
        self.assertEqual(
            json.loads((self.root / "host-device.json").read_text()), answer
        )
        self.assertIsNone(client.check({"guest": {}}, self.root))
        self.assertFalse(client.attach({"guest": {}}, self.root))
        variants = [
            dict(answer, vmid=210),
            dict(answer, changed=1),
            dict(answer, policy_sha256="0" * 64),
            dict(answer, helper_sha256="0" * 64),
            dict(answer, extra=1),
            dict(answer, changed=True),
        ]
        for index, raw in enumerate(
            [*(json.dumps(v).encode() for v in variants), b"x" * 16385]
        ):
            operation = self.root / str(index)
            operation.mkdir(mode=0o700)
            with patch.object(client, "quiet", side_effect=response(raw)):
                self.assertRaises(ValueError, client.invoke, cfg, "check", operation)
            self.assertEqual((operation / "host-device-check.log").read_bytes(), raw)
        cfg["site"]["api_endpoint"] = "https://-option:8006/"
        self.assertRaises(ValueError, client.invoke, cfg, "check", self.root)

    def test_failed_transport_keeps_original_evidence_and_cannot_replay(self):
        from private_io import write_new

        cfg = self.cfg()

        def failed(argv, environment, log, **kwargs):
            write_new(log, b"original private failure evidence")
            raise subprocess.CalledProcessError(255, argv)

        with patch.object(client, "quiet", side_effect=failed) as run:
            self.assertRaises(
                subprocess.CalledProcessError, client.check, cfg, self.root
            )
            self.assertRaises(ValueError, client.check, cfg, self.root)
            run.assert_called_once()
        self.assertEqual(
            (self.root / "host-device-check.log").read_bytes(),
            b"original private failure evidence",
        )

    def test_policy_compilation_cli_is_exclusive_and_offline(self):
        cfg = self.cfg()
        source = self.root / "packet.json"
        source.write_text(json.dumps({"files": {"site.json": json.dumps(cfg)}}))
        with patch.object(
            sys,
            "argv",
            [
                "policy",
                "--packet",
                str(source),
                "--output",
                str(self.root / "209.json"),
            ],
        ):
            client.main()
        self.assertEqual(json.loads((self.root / "209.json").read_text()), self.policy)
        with patch.object(
            sys,
            "argv",
            [
                "policy",
                "--packet",
                str(source),
                "--output",
                str(self.root / "209.json"),
            ],
        ):
            self.assertRaises(FileExistsError, client.main)

    def test_only_host_owned_device_drift_is_accepted_in_api_plans(self):
        selected = {"path": self.policy["device"]["path"]}
        drift = {
            "address": next(iter(plan_policy.RESOURCES)),
            "change": {
                "before": {
                    "node_name": "pve-lab",
                    "vm_id": 6100,
                    "device_passthrough": [],
                },
                "after": {
                    "node_name": "pve-lab",
                    "vm_id": 6100,
                    "device_passthrough": [self.policy["device"]],
                },
            },
        }
        self.assertTrue(
            plan_policy.allowed_guest_drift([drift], "pve-lab", 6100, selected)
        )
        for rows in (
            True,
            [None],
            [{"address": "other"}],
            [dict(drift, change={})],
            [dict(drift, change={"before": {}, "after": {}})],
        ):
            self.assertFalse(
                plan_policy.allowed_guest_drift(rows, "pve-lab", 6100, selected)
            )
        self.assertFalse(
            plan_policy.allowed_guest_drift([drift], "pve-lab", 6100, None)
        )
        value = existing_fixture()
        value["resource_drift"] = [drift]
        plan_policy.check_plan(
            value, "pve-lab", 6100, existing=True, serial_device=selected
        )
        drift["change"]["after"]["memory"] = 999
        self.assertRaises(
            ValueError,
            plan_policy.check_plan,
            value,
            "pve-lab",
            6100,
            existing=True,
            serial_device=selected,
        )

    def test_cli_entrypoints_and_growing_policy_inputs(self):
        with (
            patch.object(
                sys, "argv", ["helper", "--policy", str(self.root / "absent")]
            ),
            self.assertRaises(SystemExit),
        ):
            runpy.run_path(helper.__file__, run_name="__main__")
        cfg = self.cfg()
        source = self.root / "packet.json"
        source.write_text(json.dumps({"files": {"site.json": json.dumps(cfg)}}))
        with patch.object(
            sys,
            "argv",
            [
                "policy",
                "--packet",
                str(source),
                "--output",
                str(self.root / "cli-policy.json"),
            ],
        ):
            runpy.run_path(client.__file__, run_name="__main__")
        self.assertEqual(
            helper.decode((self.root / "cli-policy.json").read_bytes()), self.policy
        )
        folder = self.root / "policy"
        folder.mkdir(mode=0o700)
        source = folder / "209.json"
        source.write_bytes(b"x" * 16385)
        source.chmod(0o600)
        parent = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0)
        for size in (16385, 0):
            info = SimpleNamespace(
                st_mode=stat.S_IFREG | 0o600, st_uid=0, st_nlink=1, st_size=size
            )
            with (
                patch.object(helper.os, "getuid", return_value=0),
                patch.object(Path, "lstat", return_value=parent),
                patch.object(helper.os, "fstat", return_value=info),
            ):
                self.assertRaises(ValueError, helper.read_policy, source)

    def test_host_capability_files_participate_in_input_identity(self):
        import deployment_inputs

        cfg = self.cfg()
        ca = self.root / "ca"
        ca.write_bytes(b"fixture-ca")
        cfg["paths"]["ca_file"] = str(ca)
        before = deployment_inputs.input_hashes(cfg)
        (self.root / "key").write_bytes(b"changed retained key")
        self.assertNotEqual(before, deployment_inputs.input_hashes(cfg))
        self.assertIn(str(self.root / "hosts"), before)
