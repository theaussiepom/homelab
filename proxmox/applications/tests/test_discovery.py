"""The same route contract drives Notes and file-provider routers."""

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import discovery as d
import foundation
from test_foundation import fixture


def route():
    return {"host": "app.example.invalid", "url": "http://198.18.30.20:9000"}


class RoutingTests(unittest.TestCase):
    def test_notes_preserve_urls_aliases_order_and_tls_transport(self):
        selected = dict(
            route(),
            aliases=["alias.example.invalid"],
            url="https://198.18.30.20:9443/",
            transport="private-ca",
            middlewares=["security-headers", "login", "limits"],
        )
        cfg = {
            "guest": {"interfaces": [{"ipv4": "198.18.30.20/24"}]},
            "routes": {"app": selected},
        }
        before = copy.deepcopy(cfg)
        labels = d.labels(cfg)
        self.assertEqual(before, cfg)
        self.assertEqual(
            labels["traefik.http.routers.app.rule"],
            "(Host(`app.example.invalid`) || Host(`alias.example.invalid`))",
        )
        self.assertEqual(
            labels["traefik.http.routers.app.middlewares"],
            "security-headers@file,login@file,limits@file",
        )
        self.assertEqual(
            labels["traefik.http.services.app.loadbalancer.serverstransport"],
            "private-ca@file",
        )
        self.assertEqual(
            labels["traefik.http.services.app.loadbalancer.server.url"],
            "https://198.18.30.20:9443",
        )
        notes = "\n".join(f"{key}: {value}" for key, value in sorted(labels.items()))
        self.assertEqual(
            {
                key: value.strip()
                for key, value in (line.split(":", 1) for line in notes.splitlines())
            },
            labels,
        )
        cfg["routes"] = {"app": route()}
        labels = d.labels(cfg)
        self.assertEqual(
            labels["traefik.http.routers.app.rule"], "Host(`app.example.invalid`)"
        )
        self.assertEqual(
            labels["traefik.http.routers.app.tls.certresolver"], "letsencrypt"
        )
        cfg["routes"]["app"]["middlewares"] = []
        self.assertNotIn("traefik.http.routers.app.middlewares", d.labels(cfg))
        cfg.pop("routes")
        self.assertEqual(d.labels(cfg), {})
        cfg["guest"]["routing_labels"] = {}
        with self.assertRaisesRegex(ValueError, "arbitrary"):
            d.labels(cfg)

    def test_backend_validation_rejects_injection_credentials_and_non_private_destinations(
        self,
    ):
        for url in [
            None,
            [],
            "http://198.18.30.20:80\nsecret:bad",
            "http://198.18.30.20\\bad",
            "http://[invalid",
            "http://198.18.30.20:bad",
            "http://backend.invalid:80",
            "http://127.0.0.1:80",
            "http://8.8.8.8",
            "ftp://198.18.30.20",
            "http://user:secret@198.18.30.20",
            "http://198.18.30.20/path",
            "http://198.18.30.20?q=secret",
            "http://198.18.30.20#fragment",
            "http://198.18.30.20:65536",
            "http://198.18.30.20:0",
        ]:
            with self.subTest(url=url), self.assertRaises(ValueError):
                d.origin(url)
        for url in [
            "http://10.1.2.3",
            "https://192.168.1.2/",
            "http://172.20.1.1:65535",
            "http://198.19.1.2:80",
        ]:
            self.assertIsNotNone(d.origin(url))
        with self.assertRaises(ValueError):
            d.origin(route()["url"], {"198.18.30.21"})

    def test_closed_route_contract_and_global_hostname_uniqueness(self):
        invalid = [
            None,
            [],
            {str(i): route() for i in range(65)},
            {"bad\nname": route()},
            {"app": []},
            {"app": {"host": "app.example.invalid"}},
            {"app": dict(route(), password="secret")},
            {"app": dict(route(), aliases="bad")},
            {"app": dict(route(), aliases=["a.b"] * 9)},
            {"app": dict(route(), aliases=["app.example.invalid"])},
            {"app": dict(route(), middlewares="bad")},
            {"app": dict(route(), middlewares=["x"] * 17)},
            {"app": dict(route(), middlewares=["x", "x"])},
            {"app": dict(route(), middlewares=["x@file"])},
            {"app": dict(route(), transport="tls")},
            {"a": route(), "b": route()},
        ]
        for selected in invalid:
            with self.subTest(selected=selected), self.assertRaises(ValueError):
                d.validate_routes(selected)
        for host in [
            None,
            [],
            "localhost",
            "*.example.invalid",
            "bad..invalid",
            "a" * 254 + ".invalid",
            "UPPER.invalid",
            "a\n.invalid",
        ]:
            with self.subTest(host=host), self.assertRaises(ValueError):
                d.hostname(host)
        self.assertEqual(d.validate_routes({"a": route()}), {"app.example.invalid"})

    def test_middlewares_are_extensible_and_https_verification_cannot_be_disabled(self):
        settings = {
            "routes": {
                "nas": dict(
                    route(),
                    url="https://192.168.1.2:31764",
                    transport="nas",
                    middlewares=["login", "limits"],
                )
            },
            "middlewares": {
                "login": {"forwardAuth": {"address": "http://198.18.30.20:9000/auth"}},
                "limits": {"rateLimit": {"average": 20}},
            },
            "transports": {
                "nas": {
                    "server_name": "nas.example.invalid",
                    "ca_file": "/trust/nas.pem",
                },
                "system-trust": {"server_name": "backend.example.invalid"},
                "ca-only": {"ca_file": "/trust/ca.pem"},
            },
        }
        rendered = d.shared(settings)
        self.assertEqual(
            rendered["http"]["routers"]["nas"]["middlewares"],
            ["login@file", "limits@file"],
        )
        self.assertEqual(
            rendered["http"]["services"]["nas"]["loadBalancer"]["serversTransport"],
            "nas@file",
        )
        self.assertEqual(
            rendered["http"]["serversTransports"]["nas"],
            {
                "serverName": "nas.example.invalid",
                "rootCAs": ["/etc/ssl/certs/route-nas.pem"],
            },
        )
        self.assertNotIn("insecureSkipVerify", json.dumps(rendered))
        rendered["http"]["middlewares"]["security-headers"]["headers"].clear()
        self.assertTrue(d.DEFAULT_MIDDLEWARES["security-headers"]["headers"])
        rendered["http"]["middlewares"]["limits"]["rateLimit"].clear()
        self.assertEqual(
            settings["middlewares"]["limits"]["rateLimit"], {"average": 20}
        )
        self.assertEqual(
            d.shared({"middlewares": {"compress": {"compress": {}}}})["http"][
                "middlewares"
            ]["compress"],
            {"compress": {}},
        )
        self.assertEqual(
            d.shared({"routes": {"app": route()}})["http"]["services"]["app"][
                "loadBalancer"
            ]["servers"],
            [{"url": route()["url"]}],
        )
        self.assertEqual(d.shared({})["http"]["middlewares"], d.DEFAULT_MIDDLEWARES)
        for bad in [
            [],
            {"unknown": {}},
            {"middlewares": []},
            {"transports": []},
            {"middlewares": {"security-headers": {"headers": {"x": 1}}}},
            {"middlewares": {"x": {}}},
            {"middlewares": {"x": {"headers": []}}},
            {"transports": {"x": {}}},
            {"transports": {"x": {"insecureSkipVerify": True}}},
            {"transports": {"x": {"ca_file": "relative"}}},
            {"transports": {"x": {"ca_file": "/trust/../ca"}}},
            {"transports": {"x": {"ca_file": "/trust/bad\n"}}},
            {"routes": {"app": dict(route(), middlewares=["missing"])}},
            {
                "routes": {
                    "app": dict(route(), url="https://10.1.2.3", transport="missing")
                }
            },
        ]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                d.shared(bad)

    def test_foundation_stages_only_public_ca_certificates_and_mounts_them_read_only(
        self,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = fixture(tmp, "ingress")
            ca = cfg["foundation"]["pve_ca_file"]
            cfg["routing"] = {
                "transports": {
                    "pve": {"ca_file": ca},
                    "system": {"server_name": "example.invalid"},
                },
                "routes": {
                    "nas": dict(
                        route(), url="https://198.18.30.20:443", transport="pve"
                    )
                },
            }
            self.assertIn(ca, foundation.source_files(cfg))
            artifacts = {row["path"]: row for row in foundation.files(cfg)}
            self.assertEqual(
                artifacts["route-pve.pem"]["content"], Path(ca).read_text()
            )
            self.assertEqual(artifacts["route-pve.pem"]["mode"], "0400")
            compose = foundation.configure_compose(
                cfg, {"services": {"traefik": {"environment": {}}}}
            )
            mount = next(
                v
                for v in compose["services"]["traefik"]["volumes"]
                if v["target"] == d.ca_path("pve")
            )
            self.assertTrue(mount["read_only"])
            self.assertFalse(mount["bind"]["create_host_path"])
            self.assertIn(
                "nas", json.loads(artifacts["shared.yml"]["content"])["http"]["routers"]
            )
