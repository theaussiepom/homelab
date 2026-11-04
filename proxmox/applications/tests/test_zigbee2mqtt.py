"""Active Zigbee deployment preserves network identity without freezing live databases."""

import copy
import io
import json
import os
from pathlib import Path
import runpy
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import zigbee2mqtt as zigbee
import plan_policy
import component_runtime
from test_plan import fixture as plan_fixture, existing_fixture


def runtime_app(selected):
    return {'id':'radio','adapter':'zigbee2mqtt','lifecycle':'retained',
        'identity':{'services':{'zigbee2mqtt':'coordinator'},'networks':{'default':'default'}},
        'containers':{'zigbee2mqtt':{'memory_mib':512,'cpu_limit':1,'pids_limit':256}},
        'software_selection':{'images':{'zigbee2mqtt':{'image':'ghcr.io/koenkk/zigbee2mqtt@sha256:'+'1'*64}}},
        'settings':copy.deepcopy(selected),
        'storage_paths':{'data':{'source':'/srv/homelab/data/zigbee2mqtt','target':'/app/data',
                                 'kind':'directory','read_only':False}},
        'listeners':{'web':{'service':'zigbee2mqtt','namespace':'app-network','interface':'private',
            'bind':'wildcard','protocol':'tcp','port':selected['frontend_port'],
            'publication_address':selected['bind_address'],
            'publish':{'scope':'guest-interface','interface':'web','port':selected['frontend_port']}}}}


def settings():
    return {
        "serial_device": "/dev/serial/by-id/usb-fixture",
        "bind_address": "198.18.30.22",
        "frontend_port": 8099,
        "adapter": "ember",
        "mqtt_server": "mqtt://broker.mqtt:1883",
        "mqtt_base_topic": "home",
    }


class ZigbeeTests(unittest.TestCase):
    def test_nested_user_namespace_can_bind_the_device_without_a_guest_tty_alias(self):
        app = runtime_app(self.selected)
        original = copy.deepcopy(app)
        device = self.selected["serial_device"]
        guest_nodes = {device: (166, 0)}
        application_path = yaml.safe_load(self.configuration.read_bytes())["serial"][
            "port"
        ]
        self.assertNotIn(application_path, guest_nodes)

        service = component_runtime._zigbee2mqtt(app,{'timezone':'Etc/UTC','memory_mib':2048})['zigbee2mqtt']
        self.assertEqual(len(service["devices"]), 1)
        host, container, access = service["devices"][0].split(":")
        self.assertIn(
            container, guest_nodes, "runc binds the OCI device path from the parent LXC"
        )
        self.assertEqual((host, container, access), (device, device, "rw"))
        aliases = [
            mount for mount in service["volumes"] if mount["target"] == application_path
        ]
        self.assertEqual(
            aliases,
            [
                {
                    "type": "bind",
                    "source": device,
                    "target": application_path,
                    "read_only": False,
                    "bind": {"create_host_path": False},
                }
            ],
        )
        self.assertEqual(guest_nodes[aliases[0]["source"]], (166, 0))
        self.assertEqual(
            [mount for mount in service["volumes"] if mount["target"] == "/app/data"],
            [
                {
                    "type": "bind",
                    "source": "/srv/homelab/data/zigbee2mqtt",
                    "target": "/app/data",
                    "bind": {"create_host_path": False},
                }
            ],
        )
        self.assertEqual(service["restart"], "always")
        for field in ("privileged", "cap_add", "device_cgroup_rules"):
            self.assertNotIn(field, service)
        self.assertEqual(app, original)

    def test_saved_plans_allow_only_the_declared_coordinator_and_preserve_existing_devices(
        self,
    ):
        device = {
            "path": "/dev/serial/by-id/usb-fixture",
            "uid": 0,
            "gid": 20,
            "mode": "0660",
            "deny_write": False,
        }
        selected = {"path": device["path"]}
        for existing in (False, True):
            value = existing_fixture() if existing else plan_fixture()
            value["resource_changes"][0]["change"]["after"]["device_passthrough"] = []
            plan_policy.check_plan(
                value, "pve-lab", 6100, existing=existing, protected_guests=[9900,9914,9915,9920], serial_device=selected
            )
        value = existing_fixture()
        change = value["resource_changes"][0]["change"]
        change["before"]["device_passthrough"] = [copy.deepcopy(device)]
        change["after"]["device_passthrough"] = [copy.deepcopy(device)]
        change["after_unknown"] = {"device_passthrough": [{"path": False}]}
        plan_policy.check_plan(
            value, "pve-lab", 6100, existing=True, protected_guests=[9900,9914,9915,9920], serial_device=selected
        )
        for mutate in (
            lambda c: c["after"]["device_passthrough"].append(dict(device)),
            lambda c: c.update(after_unknown={"device_passthrough": True}),
            lambda c: c.update(after_unknown={"device_passthrough": [{"path": True}]}),
            lambda c: c["after"].update(started=False),
            lambda c: c["after"]["device_passthrough"][0].update(mode="0666"),
            lambda c: c["before"]["device_passthrough"][0].update(
                path="/dev/serial/by-id/usb-other"
            ),
        ):
            changed = copy.deepcopy(value)
            mutate(changed["resource_changes"][0]["change"])
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                plan_policy.check_plan(
                    changed, "pve-lab", 6100, existing=True, protected_guests=[9900,9914,9915,9920], serial_device=selected
                )

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.selected = settings()
        self.value = {
            "serial": {"port": "/dev/ttyACM0", "adapter": "ember", "baudrate": 115200},
            "mqtt": {"server": "mqtt://broker.mqtt:1883", "base_topic": "home"},
            "frontend": {"enabled": True, "port": 8099},
            "advanced": {
                "network_key": list(range(16)),
                "pan_id": 12345,
                "ext_pan_id": list(range(8)),
                "channel": 20,
            },
        }
        self.configuration = self.root / "configuration.yaml"
        (self.root / "database.db").write_text("retained devices")
        (self.root / "coordinator_backup.json").write_text('{"retained":true}')
        self.receipt = self.root / "identity.json"
        self.save()
        native_stat = os.stat

        def device_stat(path, *args, **kwargs):
            if str(path).startswith("/dev/serial/by-id/usb-") and kwargs.get(
                "follow_symlinks", True
            ):
                return SimpleNamespace(st_mode=stat.S_IFCHR)
            return native_stat(path, *args, **kwargs)

        patcher = patch.object(zigbee.os, "stat", side_effect=device_stat)
        patcher.start()
        self.addCleanup(patcher.stop)

    def save(self):
        self.configuration.write_text(yaml.safe_dump(self.value))

    def check(self, healthy=False):
        return zigbee.check(self.root, self.selected, self.receipt, healthy)

    def test_prepared_network_is_recorded_and_mutable_state_can_change(self):
        self.assertTrue(self.check()["healthy"])
        before = self.receipt.read_bytes()
        self.assertEqual(self.receipt.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(b"network_key", before)
        for name in ("database.db", "coordinator_backup.json"):
            (self.root / name).write_text("new legitimate live counters")
        self.assertTrue(self.check()["healthy"])
        self.assertEqual(self.receipt.read_bytes(), before)

    def test_network_key_pan_channel_and_coordinator_drift_preserve_original_record(
        self,
    ):
        self.check()
        before = self.receipt.read_bytes()
        original = copy.deepcopy(self.value)
        for field, value in (
            ("network_key", [1] * 16),
            ("pan_id", 54321),
            ("ext_pan_id", [1] * 8),
            ("channel", 25),
        ):
            with self.subTest(field=field):
                self.value = copy.deepcopy(original)
                self.value["advanced"][field] = value
                self.save()
                with self.assertRaisesRegex(ValueError, "recorded Zigbee"):
                    self.check()
                self.assertEqual(self.receipt.read_bytes(), before)
        self.value = original
        self.save()
        self.selected["serial_device"] = "/dev/serial/by-id/usb-different"
        with self.assertRaisesRegex(ValueError, "recorded Zigbee"):
            self.check()

    def test_existing_private_receipt_permissions_and_ownership_are_preserved(self):
        self.check()
        before = self.receipt.read_bytes()
        self.receipt.chmod(0o644)
        with self.assertRaises(ValueError):
            self.check()
        self.assertEqual(self.receipt.stat().st_mode & 0o777, 0o644)
        self.receipt.chmod(0o600)
        with (
            patch.object(zigbee.os, "geteuid", return_value=os.geteuid() + 1),
            self.assertRaises(ValueError),
        ):
            self.check()
        self.assertEqual(self.receipt.read_bytes(), before)

    def test_private_key_reference_is_read_without_execution(self):
        key = self.root / "secrets.yaml"
        key.write_text(yaml.safe_dump({"network_key": list(range(16))}))
        self.value["advanced"]["network_key"] = "!secrets.yaml network_key"
        self.save()
        self.check()
        for value in ("GENERATE", "!../secret.yaml key", "!secret.yaml key", [1] * 15):
            self.value["advanced"]["network_key"] = value
            self.save()
            with self.subTest(value=value), self.assertRaises((ValueError, OSError)):
                self.check()
        self.value["advanced"]["network_key"] = "!secrets.yaml network_key"
        self.save()
        key.write_text("network_key: GENERATE\n")
        with self.assertRaises(ValueError):
            self.check()

    def test_missing_changed_or_generated_configuration_is_not_normalized(self):
        original = copy.deepcopy(self.value)
        for section, key, value in (
            ("serial", "port", "/dev/ttyUSB1"),
            ("serial", "adapter", "zstack"),
            ("mqtt", "server", "mqtt://wrong:1883"),
            ("mqtt", "base_topic", "other"),
            ("frontend", "enabled", False),
            ("frontend", "port", 8080),
            ("advanced", "pan_id", 0),
            ("advanced", "ext_pan_id", [0] * 7),
        ):
            self.value = copy.deepcopy(original)
            self.value[section][key] = value
            self.save()
            before = self.configuration.read_bytes()
            with self.subTest(section=section, key=key), self.assertRaises(ValueError):
                self.check()
            self.assertEqual(self.configuration.read_bytes(), before)
        self.configuration.write_text("advanced: !execute secret\n")
        with self.assertRaises(ValueError):
            self.check()
        for name in ("database.db", "coordinator_backup.json"):
            path = self.root / name
            before = path.read_bytes()
            path.write_bytes(b"")
            with self.assertRaisesRegex(ValueError, "database and coordinator"):
                self.check()
            path.write_bytes(before)

    def test_only_the_declared_character_device_and_live_frontend_succeed(self):
        with (
            patch.object(zigbee.stat, "S_ISCHR", return_value=False),
            self.assertRaises(ValueError),
        ):
            self.check()
        self.assertFalse(self.receipt.exists())
        with self.assertRaisesRegex(ValueError, "before starting"):
            self.check(healthy=True)
        self.check()
        response = MagicMock()
        response.__enter__.return_value.status = 200
        with patch.object(
            zigbee.urllib.request, "urlopen", return_value=response
        ) as request:
            self.assertTrue(self.check(healthy=True)["healthy"])
        request.assert_called_once_with("http://198.18.30.22:8099/", timeout=5)
        response.__enter__.return_value.status = 503
        with (
            patch.object(zigbee.urllib.request, "urlopen", return_value=response),
            self.assertRaises(ValueError),
        ):
            self.check(healthy=True)

    def test_settings_and_deployment_bind_one_device_and_backend(self):
        for patch_value in (
            {"extra": True},
            {"serial_device": "/dev/ttyACM0"},
            {"adapter": "x y"},
            {"frontend_port": True},
            {"frontend_port": 0},
            {"bind_address": "127.0.0.1"},
            {"mqtt_server": "mqtt://user:secret@broker.mqtt:1883"},
            {"mqtt_server": "http://broker.mqtt:1883"},
            {"mqtt_base_topic": "#"},
            {"adapter": None},
        ):
            with self.subTest(value=patch_value), self.assertRaises(ValueError):
                zigbee.validate(dict(self.selected, **patch_value))
        with self.assertRaises(ValueError):
            zigbee.validate(None)
        app=runtime_app(self.selected)
        for key,value in [('bind_address','198.18.30.99'),('frontend_port',8100)]:
            changed=copy.deepcopy(app);changed['settings'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):
                component_runtime._zigbee2mqtt(changed,{'timezone':'Etc/UTC','memory_mib':2048})

    def test_file_boundaries_and_cli_never_emit_configuration_or_key(self):
        selected = self.root / "settings.json"
        selected.write_text(json.dumps(self.selected))
        argv = [
            "zigbee2mqtt.py",
            "validate",
            "--settings",
            str(selected),
            "--data",
            str(self.root),
            "--identity",
            str(self.receipt),
        ]
        with (
            patch.object(sys, "argv", argv),
            patch("sys.stdout", new_callable=io.StringIO) as output,
        ):
            runpy.run_path(str(Path(zigbee.__file__)), run_name="__main__")
        self.assertEqual(
            json.loads(output.getvalue()), {"healthy": True, "radio_opened": False}
        )
        selected.write_text("invalid JSON")
        with patch.object(sys, "argv", argv), self.assertRaises(SystemExit):
            zigbee.main()
        for value in (b"", b"x" * (1024 * 1024 + 1)):
            selected.write_bytes(value)
            with self.assertRaises(ValueError):
                zigbee.read(selected)
        link = self.root / "link"
        link.symlink_to(self.configuration)
        with self.assertRaises(OSError):
            zigbee.read(link)
        with self.assertRaises(ValueError):
            zigbee.configuration(link, self.selected)
        stream = MagicMock()
        stream.__enter__.return_value.read.return_value = b"x" * (1024 * 1024 + 1)
        with (
            patch.object(zigbee.os, "open", return_value=123),
            patch.object(zigbee.os, "fdopen", return_value=stream),
            patch.object(
                zigbee.os,
                "fstat",
                return_value=SimpleNamespace(st_mode=stat.S_IFREG, st_size=1),
            ),
            self.assertRaises(ValueError),
        ):
            zigbee.read(selected)
