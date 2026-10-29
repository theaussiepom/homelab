"""Published endpoints are the authority for DNS and declared service consumers."""

import copy
import unittest

import service_bindings as service


def fixture():
    endpoint = {
        "hostname": "broker.mqtt",
        "addresses": {"frontend": "198.18.40.21", "backend": "198.18.30.21"},
        "dns_address": "frontend",
        "protocol": "tcp",
        "port": 1883,
    }
    return {
        "automation": (
            {
                "guest": {
                    "interfaces": [
                        {"ipv4": "198.18.40.21/24"},
                        {"ipv4": "198.18.30.21/24"},
                    ]
                },
                "app": {
                    "service_health_checks": {"mqtt": [{}]},
                    "published_services": {"mqtt": endpoint},
                },
            },
            None,
            {},
        ),
        "dns": (
            {"app": {"service_health_checks": {"pihole": []}, "health_checks": []}},
            {"kind": "dns", "dns_records": {"other.example": "198.18.40.99"}},
            {},
        ),
        "radio": (
            {
                "guest": {"interfaces": [{"ipv4": "198.18.30.22/24"}]},
                "app": {
                    "service_health_checks": {"zigbee2mqtt": [{}]},
                    "service_connections": {
                        "zigbee2mqtt": {
                            "service": "automation.mqtt",
                            "address": "backend",
                        }
                    },
                },
            },
            {
                "kind": "zigbee2mqtt",
                "zigbee": {},
                "services": {
                    "zigbee2mqtt": {
                        "extra_hosts": {"preserved.example": "198.18.40.98"}
                    }
                },
            },
            {},
        ),
    }


class ServiceBindingsTests(unittest.TestCase):
    def test_one_definition_binds_dns_consumers_and_actual_traffic(self):
        rows = fixture()
        service.bind(rows)
        self.assertEqual(
            rows["dns"][1]["dns_records"],
            {"broker.mqtt": "198.18.40.21", "other.example": "198.18.40.99"},
        )
        self.assertEqual(
            rows["radio"][1]["services"]["zigbee2mqtt"]["extra_hosts"],
            {"broker.mqtt": "198.18.30.21", "preserved.example": "198.18.40.98"},
        )
        self.assertEqual(len(rows["dns"][0]["app"]["health_checks"]), 2)
        connections = list(
            service.connections_for({name: row[0] for name, row in rows.items()})
        )
        self.assertEqual(
            [
                (c.source, c.target, c.source_address, c.target_address, c.port)
                for c in connections
            ],
            [("radio", "automation", "198.18.30.22", "198.18.30.21", 1883)],
        )

    def test_invalid_or_duplicate_publications_are_refused(self):
        for mutate in (
            lambda r: r["automation"][0]["app"].update(published_services=[]),
            lambda r: r["automation"][0]["app"]["published_services"].update(mqtt=[]),
            lambda r: r["automation"][0]["app"]["published_services"]["mqtt"].update(
                protocol="udp"
            ),
            lambda r: r["automation"][0]["app"]["published_services"]["mqtt"].update(
                port=True
            ),
            lambda r: r["automation"][0]["app"]["published_services"]["mqtt"].update(
                dns_address="missing"
            ),
            lambda r: r["automation"][0]["app"]["published_services"]["mqtt"][
                "addresses"
            ].update(backend="198.18.30.99"),
            lambda r: r.update(other=copy.deepcopy(r["automation"])),
        ):
            rows = fixture()
            mutate(rows)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                service.bind(rows)

    def test_missing_ambiguous_or_conflicting_consumer_selections_are_refused(self):
        for binding in (
            [],
            {"unknown": {}},
            {"zigbee2mqtt": "automation.mqtt"},
            {"zigbee2mqtt": {"service": "missing", "address": "backend"}},
            {"zigbee2mqtt": {"service": "automation.mqtt", "address": "missing"}},
        ):
            rows = fixture()
            rows["radio"][0]["app"]["service_connections"] = binding
            with self.subTest(binding=binding), self.assertRaises(ValueError):
                service.bind(rows)
        for field in ("alias", "dns", "port"):
            rows = fixture()
            if field == "alias":
                rows["radio"][1]["services"]["zigbee2mqtt"]["extra_hosts"][
                    "broker.mqtt"
                ] = "198.18.30.99"
            elif field == "dns":
                rows["dns"][1]["dns_records"]["broker.mqtt"] = "198.18.40.99"
            else:
                rows["automation"][0]["app"]["published_services"]["mqtt"][
                    "port"
                ] = 1884
            with self.subTest(field=field), self.assertRaises(ValueError):
                service.bind(rows)

    def test_non_docker_consumers_keep_the_same_declared_endpoint_connection(self):
        rows = fixture()
        rows["radio"] = (rows["radio"][0], None, {})
        service.bind(rows)
        self.assertEqual(
            len(
                list(
                    service.connections_for(
                        {name: row[0] for name, row in rows.items()}
                    )
                )
            ),
            1,
        )

    def test_dhcp_publication_and_consumer_use_qualified_ips_without_allocation_conversion(self):
        rows = fixture()
        for guest, index, endpoint in [("automation", 0, "198.18.40.21/27"), ("radio", 0, "198.18.30.22/27")]:
            rows[guest][0]["guest"]["interfaces"][index].update(ipv4="dhcp", ipv4_endpoint=endpoint, gateway=None)
        service.bind(rows)
        self.assertEqual(rows["dns"][1]["dns_records"]["broker.mqtt"], "198.18.40.21")
        flow = next(service.connections_for({name: row[0] for name, row in rows.items()}))
        self.assertEqual((flow.source_address, flow.target_address), ("198.18.30.22", "198.18.30.21"))
        self.assertEqual(rows["automation"][0]["guest"]["interfaces"][0]["ipv4"], "dhcp")
