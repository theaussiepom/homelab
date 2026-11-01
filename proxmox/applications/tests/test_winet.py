"""WiNet is optional, isolated from the coordinator and bound to private inputs."""
import copy
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import guest_contract
import render
import winet
from test_render import fixture, image


def selected(path):
    cfg = fixture("zigbee2mqtt")
    cfg["services"]["winet"] = image()
    cfg["winet"] = {
        "configuration_file": str(path), "inverter_address": "198.19.107.23",
        "mqtt_server": "mqtt://broker.mqtt:1883", "mqtt_prefix": "homeassistant",
    }
    return cfg


def options():
    return {"winet_host": "198.19.107.23", "winet_user": "fixture",
            "winet_pass": "synthetic-$-password", "mqtt_url": "mqtt://fixture:synthetic@broker.mqtt:1883",
            "mqtt_prefix": "homeassistant", "poll_interval": 10, "analytics": True,
            "ssl": True, "site_totals": True, "additional_winets": []}


class WinetTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.path = self.root / "private.json"
        self.write(options())
        self.cfg = selected(self.path)

    def write(self, value):
        self.path.write_text(json.dumps(value))
        self.path.chmod(0o600)

    def test_existing_radio_is_byte_equivalent_and_optional_phase_is_explicit(self):
        old = fixture("zigbee2mqtt")
        before = render.compose(old)
        after = render.compose(self.cfg)
        self.assertEqual(before["services"]["zigbee2mqtt"], after["services"]["zigbee2mqtt"])
        self.assertIsNone(winet.validate(old))
        self.assertEqual(winet.source_files(old), [])
        cfg = {"app": {"kind": "zigbee2mqtt", "service_health_checks": {"zigbee2mqtt": [{}]}},
               "deployment": {"contract": 2, "capabilities": ["linux", "docker"]}}
        self.assertEqual(guest_contract.phases(cfg), ["preparation", "zigbee2mqtt"])
        cfg["app"]["service_health_checks"]["winet"] = [{}]
        self.assertEqual(guest_contract.phases(cfg), ["preparation", "zigbee2mqtt", "winet"])

    def test_real_cli_accepts_winet_but_the_runner_refuses_it_for_another_guest(self):
        import deploy
        from fixtures import guest
        with patch.object(sys, "argv", ["deploy", "--phase", "winet", "--packet", str(self.path)]), \
             patch.object(deploy, "run", return_value={"status": "fixture"}) as run, \
             contextlib.redirect_stdout(io.StringIO()):
            deploy.main()
        run.assert_called_once_with("winet", self.path)
        with patch.object(deploy, "bootstrap_closed"), \
             patch.object(deploy.deployment_inputs, "prepare", return_value=(guest(self.root), self.path)), \
             patch.object(deploy, "DeploymentAttempt") as attempt, \
             self.assertRaisesRegex(ValueError, "this guest"):
            deploy.run("winet", self.path)
        attempt.assert_not_called()

    def test_options_stay_in_private_file_with_readonly_mount_and_no_radio_access(self):
        cfg = copy.deepcopy(self.cfg)
        document = render.compose(cfg)
        service = document["services"]["winet"]
        self.assertEqual(cfg, self.cfg)
        self.assertEqual(winet.source_files(cfg), [str(self.path)])
        self.assertEqual(winet.options(cfg), options())
        self.assertEqual(winet.files(cfg), [{"path": "winet-options.json", "uid": 0, "gid": 0,
                                          "mode": "0600", "content": json.dumps(options(), sort_keys=True) + "\n"}])
        self.assertEqual(service["volumes"], [{"type": "bind", "source": winet.RUNTIME,
                                             "target": "/data/options.json", "read_only": True,
                                             "bind": {"create_host_path": False}}])
        self.assertEqual(service["network_mode"], "host")
        self.assertEqual(service["restart"], "always")
        self.assertNotIn("devices", service)
        self.assertNotIn("privileged", service)
        self.assertNotIn("synthetic", json.dumps(document))
        self.assertEqual(service["healthcheck"]["test"], ["CMD", "node", "-e", winet.HEALTH])

    def test_native_selection_and_input_identity_include_winet_without_changing_radio(self):
        import deployment_inputs
        import zigbee2mqtt
        cfg = {"guest": {"vmid": 209, "serial_device": {"path": self.cfg["zigbee"]["serial_device"]},
                         "interfaces": [{"ipv4": "198.18.30.22/24"}]},
               "paths": {"ca_file": str(self.root / "ca"), "host_device_key": str(self.root / "device-key"),
                         "host_known_hosts": str(self.root / "device-hosts")},
               "app": {"kind": "zigbee2mqtt", "stack_config": str(self.root / "stack.json")}}
        zigbee2mqtt.validate_deployment(cfg, self.cfg)
        # The source identity binds external private options as well as stack JSON.
        (self.root / "ca").write_text("synthetic public CA")
        (self.root / "device-key").write_text("synthetic host-device key")
        (self.root / "device-hosts").write_text("synthetic pinned host")
        (self.root / "stack.json").write_text(json.dumps(self.cfg))
        before = deployment_inputs.input_hashes(cfg)
        self.assertIn(str(self.path), before)
        updated = options()
        updated["poll_interval"] = 15
        self.write(updated)
        after = deployment_inputs.input_hashes(cfg)
        self.assertNotEqual(before[str(self.path)], after[str(self.path)])
        self.assertEqual(before[str(self.root / "stack.json")], after[str(self.root / "stack.json")])

    def test_missing_malformed_or_override_selection_refuses_before_target_access(self):
        for change in (
            lambda c: c.pop("winet"),
            lambda c: c.update(kind="automation"),
            lambda c: c.update(winet=[]),
            lambda c: c["winet"].update(unknown=True),
            lambda c: c["services"].pop("winet"),
            lambda c: c["winet"].update(configuration_file="relative.json"),
            lambda c: c["winet"].update(configuration_file="/tmp/../bad"),
            lambda c: c["winet"].update(configuration_file=1),
            *(lambda c, address=a: c["winet"].update(inverter_address=address)
              for a in ("0.0.0.0", "127.0.0.1", "224.0.0.1", "169.254.0.1", "hostname")),
            *(lambda c, url=u: c["winet"].update(mqtt_server=url)
              for u in ("http://broker:1883", "mqtt://:1883", "mqtt://broker:1884", "mqtt://user@broker:1883",
                        "mqtt://user:pass@broker:1883", "mqtt://broker:1883/", "mqtt://broker:1883?query", "mqtt://broker:1883#fragment")),
            lambda c: c["winet"].update(mqtt_prefix="#"),
            lambda c: c["winet"].update(mqtt_prefix=1),
            *(lambda c, field=f: c["services"]["winet"].update({field: "override"})
              for f in ("environment", "extra_mounts", "command", "entrypoint", "user")),
        ):
            cfg = copy.deepcopy(self.cfg)
            change(cfg)
            with self.subTest(change=change), self.assertRaises((ValueError, TypeError)):
                winet.validate(cfg)

    def test_private_options_refuse_endpoint_or_identity_drift_and_custom_certificate_options(self):
        for change in (
            lambda v: v.update(custom_ca="old-custom-image-only"),
            lambda v: v.update(winet_host="198.19.107.24"),
            lambda v: v.update(ssl=False),
            lambda v: v.update(additional_winets=[{"host": "198.19.107.24"}]),
            lambda v: v.update(additional_winets={}),
            lambda v: v.update(additional_winets=None),
            *(lambda v, key=k: v.update({key: ""}) for k in ("winet_user", "winet_pass")),
            lambda v: v.update(winet_pass="bad\ncredential"),
            lambda v: v.update(winet_user=1),
            *(lambda v, url=u: v.update(mqtt_url=url)
              for u in ("mqtt://other:1883", "mqtt://broker.mqtt:1884", "http://broker.mqtt:1883",
                        "mqtt://broker.mqtt:1883/", "mqtt://broker.mqtt:1883?x", "mqtt://broker.mqtt:1883#x")),
            lambda v: v.update(mqtt_prefix="different"),
            *(lambda v, poll=n: v.update(poll_interval=poll) for n in (True, "10", 0, 3601)),
            lambda v: v.update(analytics="true"),
            lambda v: v.pop("site_totals"),
        ):
            value = options()
            change(value)
            self.write(value)
            with self.subTest(change=change), self.assertRaises(ValueError):
                winet.files(self.cfg)
        self.write([])
        with self.assertRaises(ValueError):
            winet.files(self.cfg)

    def test_options_permission_or_symlink_drift_is_a_hold(self):
        self.path.chmod(0o644)
        with self.assertRaises(ValueError):
            winet.files(self.cfg)
        self.path.chmod(0o600)
        link = self.root / "link.json"
        link.symlink_to(self.path)
        self.cfg["winet"]["configuration_file"] = str(link)
        with self.assertRaises(OSError):
            winet.files(self.cfg)

    def test_renderer_emits_only_bounded_private_runtime_artifacts(self):
        path = self.root / "stack.json"
        path.write_text(json.dumps(self.cfg))
        output = self.root / "rendered"
        with patch.object(sys, "argv", ["render", "--config", str(path), "--output", str(output)]):
            render.main()
        self.assertEqual(json.loads((output / "winet-options.json").read_text()), options())
        self.assertEqual((output / "winet-options.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads((output / "runtime-files.json").read_text()),
                         [{"path": "winet-options.json", "uid": 0, "gid": 0, "mode": "0600"}])

    def test_second_phase_never_starts_or_recreates_the_coordinator(self):
        import yaml
        from jinja2 import Environment
        tasks = yaml.safe_load((Path(render.__file__).parent / "ansible/tasks/compose.yml").read_text())
        start = next(t for t in tasks if t["name"] == "Start exactly this guest stack")
        expression = start["ansible.builtin.command"]["argv"].strip()[2:-2].strip()
        environment = Environment()
        environment.filters["bool"] = bool
        for changed in (False, True):
            argv = environment.compile_expression(expression)(app={"kind": "zigbee2mqtt"},
                    foundation_runtime_install={"changed": changed}, application_service="winet")
            self.assertEqual(argv[-2:], ["--no-deps", "winet"])
            self.assertNotIn("zigbee2mqtt", argv)
            self.assertEqual("--force-recreate" in argv, changed)
        install = next(t for t in tasks if t["name"].startswith("Install only the selected service-readable"))
        self.assertIn("application_service == 'winet'", install["when"])
        radio = next(t for t in tasks if t["name"].startswith("Check the existing Zigbee"))
        self.assertIn("application_service == 'zigbee2mqtt'", radio["when"])


if __name__ == "__main__":
    unittest.main()
