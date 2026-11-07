"""The same route contract drives Notes and file-provider routers."""

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import discovery as d


def route():
    return {"host": "app.example.invalid", "url": "http://198.18.30.20:9000"}


class RoutingTests(unittest.TestCase):
    def test_public_trust_certificate_is_bounded_single_pem_and_never_disables_verification(self):
        pem = Path(__file__).with_name('transport-synthetic-public-certificate.txt').read_text()
        self.assertEqual(d.certificate(pem), pem)
        self.assertEqual(d.certificate(' \n' + pem + '\n '), ' \n' + pem + '\n ')
        selected = {'server_name': 'backend.example.invalid', 'certificate': pem}
        actual = d.shared({'transports': {'selected': selected}})['http']['serversTransports']['selected']
        self.assertEqual(actual, {'serverName': 'backend.example.invalid',
                                 'rootCAs': ['/etc/ssl/certs/route-selected.pem']})
        self.assertNotIn('insecureSkipVerify', actual)
        invalid = (None, b'bytes', '', '\x00', 'x' * 65537, '\u00e9' * 32768 + pem,
                   pem + pem, pem + '-----END CERTIFICATE-----', 'prefix' + pem,
                   pem + 'suffix', pem.replace('\n', '\nPRIVATE KEY\n', 1),
                   '-----BEGIN CERTIFICATE-----\ninvalid-der\n-----END CERTIFICATE-----')
        for value in invalid:
            with self.subTest(kind=type(value).__name__), self.assertRaises(ValueError):
                d.certificate(value)
        for selected in ({'certificate': None}, {'certificate': pem, 'ca_file': '/context.pem'},
                         {'certificate': pem, 'insecureSkipVerify': True}):
            with self.subTest(fields=list(selected)), self.assertRaises(ValueError):
                d.shared({'transports': {'selected': selected}})

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
            "a\n.invalid",
        ]:
            with self.subTest(host=host), self.assertRaises(ValueError):
                d.hostname(host)
        self.assertEqual(d.validate_routes({"a": route()}), {"app.example.invalid"})
        self.assertEqual(d.hostname("UPPER.invalid"),"UPPER.invalid")  # Typed DNS preserves authored case; collision keys casefold upstream.

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


    def test_pegaprox_http_backend_keeps_automatic_browser_https(self):
        selected = {'host':'pega.example.invalid', 'url':'http://198.18.25.34:5000'}
        cfg = {'guest':{'interfaces':[{'ipv4':'198.18.25.34/24'}]},
               'routes':{'pegaprox':selected}}
        labels = d.labels(cfg)
        self.assertEqual(labels['traefik.http.services.pegaprox.loadbalancer.server.url'], selected['url'])
        self.assertEqual(labels['traefik.http.routers.pegaprox.entrypoints'], 'websecure')
        self.assertEqual(labels['traefik.http.routers.pegaprox.tls'], 'true')
        self.assertEqual(labels['traefik.http.routers.pegaprox.tls.certresolver'], 'letsencrypt')
        self.assertNotIn('traefik.http.services.pegaprox.loadbalancer.serverstransport', labels)
        with self.assertRaises(ValueError):
            d.validate_routes({'pegaprox':dict(selected, transport='obsolete-backend-ca')})
