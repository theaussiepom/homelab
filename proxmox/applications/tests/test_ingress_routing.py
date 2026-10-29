"""Reject wrong interfaces or foreign policy before a routing command can write."""

import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ingress_routing as routing


class IngressRoutingTests(unittest.TestCase):

    def setUp(self):
        self.settings = {
            "address": "10.88.40.33/24",
            "gateway": "10.88.40.1",
            "mac": "02:00:00:00:40:33",
        }
        self.links = [
            {
                "ifname": "eth2",
                "address": self.settings["mac"],
                "flags": ["UP"],
                "addr_info": [{"local": "10.88.40.33", "prefixlen": 24}],
            }
        ]
        self.rules = [
            {"priority": 0, "src": "all", "table": "local"},
            {"priority": 32766, "src": "all", "table": "main"},
        ]
        self.routes = []
        self.writes = []
        self.patch = patch.object(routing, "command", side_effect=self.command)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def command(self, argv):
        if argv == ["-j", "address", "show"]:
            return json.dumps(
                [
                    {key: value for key, value in row.items() if key != "address"}
                    for row in self.links
                ]
            )
        if argv == ["-j", "link", "show"]:
            return json.dumps(self.links)
        if argv == ["-j", "rule", "show"]:
            return json.dumps(self.rules)
        if argv == ["-j", "route", "show", "table", "all"]:
            return json.dumps(self.routes)
        self.writes.append(argv)
        if argv[:2] == ["route", "add"]:
            row = {
                "dst": argv[2],
                "dev": "eth2",
                "prefsrc": "10.88.40.33",
                "table": 10040,
                "scope": "global",
            }
            if argv[2] == "default":
                row["gateway"] = "10.88.40.1"
            else:
                row["scope"] = "link"
            self.routes.append(row)
        elif argv[:2] == ["rule", "add"]:
            self.rules.append({"priority": 10040, "src": "10.88.40.33", "table": 10040})
        else:
            raise AssertionError(argv)
        return ""

    def test_apply_reads_back_and_repeat_and_verify_never_change_the_main_routes(self):
        self.assertTrue(routing.run(self.settings, apply=True)["changed"])
        self.assertEqual(len(self.writes), 3)
        self.writes.clear()
        self.assertFalse(routing.run(self.settings, apply=True)["changed"])
        routing.run(self.settings)
        self.assertEqual(self.writes, [])

    def test_missing_policy_fails_read_only_verification(self):
        with self.assertRaises(ValueError):
            routing.run(self.settings)
        self.assertEqual(self.writes, [])

    def test_wrong_address_mac_down_link_or_prefix_prevents_any_write(self):
        for key, value in [("address", "02:00:00:00:40:34"), ("flags", [])]:
            before = copy.deepcopy(self.links)
            self.links[0][key] = value
            with self.assertRaises(ValueError):
                routing.run(self.settings, apply=True)
            self.links = before
        self.links[0]["addr_info"][0]["prefixlen"] = 25
        with self.assertRaises(ValueError):
            routing.run(self.settings, apply=True)
        self.assertEqual(self.writes, [])

    def test_foreign_reserved_route_or_rule_is_preserved_without_mutation(self):
        self.routes = [
            {"table": 10040, "dst": "default", "gateway": "10.88.40.99", "dev": "eth2"}
        ]
        with self.assertRaises(ValueError):
            routing.run(self.settings, apply=True)
        self.routes = []
        self.rules.append({"priority": 10040, "src": "all", "table": 10040})
        with self.assertRaises(ValueError):
            routing.run(self.settings, apply=True)
        self.assertEqual(self.writes, [])

    def test_routing_scope_rejects_arbitrary_tables_public_or_foreign_gateways(self):
        for key, value in [
            ("table", 254),
            ("gateway", "10.88.25.1"),
            ("gateway", "10.88.40.33"),
            ("address", "10.88.40.33/32"),
        ]:
            cfg = dict(self.settings)
            cfg[key] = value
            with self.assertRaises(ValueError):
                routing.validate(cfg)
