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
import winet
import component_input_secrets


def selected(path):
    return {'configuration_file':str(path),'inverter_address':'198.19.107.23',
            'mqtt_server':'mqtt://broker.mqtt:1883','mqtt_prefix':'homeassistant'}


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
                winet.options_bytes(self.path.read_bytes(),self.cfg)
        self.write([])
        with self.assertRaises(ValueError):
            winet.options_bytes(self.path.read_bytes(),self.cfg)

    def test_options_permission_or_symlink_drift_is_a_hold(self):
        sources={'options':{'type':'file','path':str(self.path)}}
        self.path.chmod(0o644)
        with self.assertRaises(ValueError):component_input_secrets.selected('winet',sources,{})
        self.path.chmod(0o600)
        self.assertEqual(component_input_secrets.selected('winet',sources,{})['options'],self.path.read_bytes())
        link=self.root/'link.json';link.symlink_to(self.path)
        sources['options']['path']=str(link)
        with self.assertRaises(OSError):component_input_secrets.selected('winet',sources,{})


if __name__=='__main__':unittest.main()
