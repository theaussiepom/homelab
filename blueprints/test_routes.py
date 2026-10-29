"""Endpoint ownership and global routing/DNS resolution precede packet sealing."""

import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import routes as r


def fixture():
    def cfg(kind):
        return {
            "app": {"service_health_checks": {kind: []}},
            "guest": {"interfaces": [{"ipv4": "198.18.30.20/24"}]},
        }

    app = cfg("web")
    app["app"]["endpoints"] = {"web": {"ui": "http://198.18.30.20:80"}}
    return {
        "native": (app, None, {}),
        "ingress": (
            cfg("traefik"),
            {
                "foundation": {"bind_address": "198.18.40.33"},
                "routing": {"middlewares": {"limits": {"rateLimit": {"average": 5}}}},
            },
            {},
        ),
    }


class RoutesTests(unittest.TestCase):
    def test_runtime_independent_endpoints_and_external_origins_use_one_route_contract(
        self,
    ):
        cfg = fixture()
        selected = {
            "app": {
                "host": "app.invalid",
                "target": {"endpoint": "native.web.ui"},
                "aliases": ["alias.invalid"],
                "middlewares": ["limits"],
            },
            "nas": {"host": "nas.invalid", "target": {"url": "http://192.168.1.2:80"}},
        }
        before = copy.deepcopy(selected)
        records = r.bind(cfg, selected)
        self.assertEqual(selected, before)
        self.assertEqual(
            records,
            {
                "app.invalid": "198.18.40.33",
                "alias.invalid": "198.18.40.33",
                "nas.invalid": "198.18.40.33",
            },
        )
        self.assertEqual(
            cfg["native"][0]["routes"]["app"]["url"], "http://198.18.30.20:80"
        )
        self.assertEqual(set(cfg["ingress"][1]["routing"]["routes"]), {"nas"})
        self.assertNotIn("external_routes", cfg["ingress"][0])
        self.assertEqual(r.bind(fixture(), {}), {})
        self.assertEqual(r.bind({}, {}), {})

    def test_invalid_global_targets_and_undeclared_policies_fail_before_packet_creation(
        self,
    ):
        route = {"host": "app.invalid", "target": {"endpoint": "native.web.ui"}}
        for value in [
            [],
            {"app": []},
            {"app": {}},
            {"app": dict(route, target=[])},
            {"app": dict(route, target={})},
            {"app": dict(route, target={"url": "http://198.18.30.20:80"})},
            {"app": dict(route, target={"endpoint": "absent"})},
            {"app": dict(route, target={"endpoint": []})},
            {
                "app": dict(
                    route,
                    target={"endpoint": "native.web.ui", "url": "http://10.1.1.1"},
                )
            },
            {"app": dict(route, url="http://10.1.1.1")},
            {"app": dict(route, middlewares=["missing"])},
            {"app": route, "other": route},
        ]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                r.bind(fixture(), value)
        for mutation in [
            "missing-ingress",
            "raw-routes",
            "foreign-application",
            "bad-endpoints",
            "bad-named",
            "foreign-interface",
            "raw-external",
        ]:
            cfg = fixture()
            if mutation == "missing-ingress":
                cfg.pop("ingress")
            elif mutation == "raw-routes":
                cfg["native"][0]["routes"] = {}
            elif mutation == "raw-external":
                cfg["ingress"][1]["routing"]["routes"] = {}
            elif mutation == "foreign-application":
                cfg["native"][0]["app"]["endpoints"] = {"unknown": {}}
            elif mutation == "bad-endpoints":
                cfg["native"][0]["app"]["endpoints"] = []
            elif mutation == "bad-named":
                cfg["native"][0]["app"]["endpoints"] = {"web": []}
            else:
                cfg["native"][0]["app"]["endpoints"]["web"][
                    "ui"
                ] = "http://198.18.30.21:80"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                r.bind(cfg, {"app": route})
